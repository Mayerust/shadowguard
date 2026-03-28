import re, json, time, logging, os
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache, wraps

import numpy as np
import joblib
from flask import Flask, request, jsonify, Response, render_template
from flask_cors import CORS
import requests as req_lib



# Logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/shadowguard.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("ShadowGuard")

app = Flask(__name__)
CORS(app)




# Load ML Artifacts
try:
    model      = joblib.load("models/shadowguard_model.pkl")
    mc_model   = joblib.load("models/attack_type_model.pkl")
    label_enc  = joblib.load("models/label_encoder.pkl")
    with open("models/feature_columns.json") as f:
        FEATURE_COLS = json.load(f)
    with open("models/training_report.json") as f:
        train_report = json.load(f)
    # Fast inference mode
    clf = model.named_steps.get("clf")
    if hasattr(clf, "n_jobs"):
        clf.n_jobs = 1
    logger.info("Model loaded: %s | F1=%.4f | Threshold=%.2f",
                train_report.get("best_model"),
                train_report.get("final_metrics", {}).get("f1", 0),
                train_report.get("threshold", 0.60))
except Exception as e:
    logger.critical("Model load failed: %s — run 02_train_model.py first", e)
    model = mc_model = label_enc = None
    FEATURE_COLS = []
    train_report = {}

TARGET_APP_URL = os.environ.get("TARGET_APP_URL", "http://localhost:8080")



# ENHANCEMENT: Adaptive Threshold
BASE_THRESHOLD        = float(train_report.get("threshold", 0.60))
BLOCK_THRESHOLD       = BASE_THRESHOLD   # mutable at runtime
FAST_BLOCK_THRESHOLD  = 0.95

def update_adaptive_threshold(stats: dict):
    """Auto-tighten threshold when block rate spikes (DDoS / scan)."""
    global BLOCK_THRESHOLD
    total = max(stats["total"], 1)
    block_rate = stats["blocked"] / total
    if block_rate > 0.60:
        BLOCK_THRESHOLD = min(0.85, BASE_THRESHOLD + 0.15)  # fewer false positives during scans
    else:
        BLOCK_THRESHOLD = BASE_THRESHOLD


# ENHANCEMENT:IP Rate Limiter
rate_tracker: dict = defaultdict(list)
MAX_REQUESTS_PER_WINDOW = 30
RATE_WINDOW_SEC         = 10

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    rate_tracker[ip] = [t for t in rate_tracker[ip] if now - t < RATE_WINDOW_SEC]
    if len(rate_tracker[ip]) >= MAX_REQUESTS_PER_WINDOW:
        return True
    rate_tracker[ip].append(now)
    return False



#ENHANCEMENT: Auto IP Blacklist
blacklist: dict   = {}        # {ip: unban_timestamp}
attack_counts: dict = defaultdict(int)
BLACKLIST_THRESHOLD = 3       # attacks before ban
BLACKLIST_DURATION  = 300     # seconds (5 min)

def is_blacklisted(ip: str) -> bool:
    if ip in blacklist:
        if time.time() < blacklist[ip]:
            return True
        else:
            del blacklist[ip]
            attack_counts[ip] = 0
    return False

def register_attack(ip: str):
    attack_counts[ip] += 1
    if attack_counts[ip] >= BLACKLIST_THRESHOLD:
        blacklist[ip] = time.time() + BLACKLIST_DURATION
        logger.warning("IP BLACKLISTED: %s (attack count: %d)", ip, attack_counts[ip])




# ENHANCEMENT: GeoIP (optional)
geoip_reader = None
try:
    import geoip2.database
    if os.path.exists("GeoLite2-City.mmdb"):
        geoip_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        logger.info("GeoIP database loaded.")
except ImportError:
    pass

def get_country(ip: str) -> str:
    if not geoip_reader:
        return "Unknown"
    try:
        return geoip_reader.city(ip).country.name or "Unknown"
    except Exception:
        return "Unknown"



#OWASP Regex Rules (Fast Path)
OWASP_RULES = [
    (re.compile(r"\b(union|select|insert|delete|drop|create|alter|exec|execute|cast|convert|char|nchar|declare|table|cursor|having|waitfor|sleep|benchmark|load_file)\b", re.I),
     "SQLi – Keyword", "Critical", "sqli"),
    (re.compile(r"(--|\/\*|\*\/|#\s*$|;\s*$)", re.M),
     "SQLi – Comment/Terminator", "High", "sqli"),
    (re.compile(r"('|\")?\s*(or|and)\s+\d+=\d+", re.I),
     "SQLi – Tautology", "Critical", "sqli"),
    (re.compile(r"union.{0,30}select", re.I | re.S),
     "SQLi – UNION SELECT", "Critical", "sqli"),
    (re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.I),
     "XSS – Script Tag", "Critical", "xss"),
    (re.compile(r"on\w+\s*=\s*['\"]?[\w\s;()]+['\"]?", re.I),
     "XSS – Event Handler", "High", "xss"),
    (re.compile(r"javascript\s*:", re.I),
     "XSS – JS Protocol", "High", "xss"),
    (re.compile(r"<(iframe|frame|object|embed|applet)\b", re.I),
     "XSS – Dangerous Tag", "Medium", "xss"),
    (re.compile(r"\.\.[/\\]"),
     "Path Traversal", "Critical", "path_traversal"),
    (re.compile(r"%2e%2e[%2f5c]", re.I),
     "Path – URL Encoded", "Critical", "path_traversal"),
    (re.compile(r"(etc/passwd|etc/shadow|proc/self|boot\.ini)", re.I),
     "Path – Sensitive File", "Critical", "path_traversal"),
    (re.compile(r"[;|&`$()]\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh|cmd)\b", re.I),
     "CMD – Shell Command", "Critical", "cmd_injection"),
    (re.compile(r"\$\([^)]+\)|`[^`]+`"),
     "CMD – Command Substitution", "Critical", "cmd_injection"),
    (re.compile(r"\(\)\s*\{"),
     "Shellshock", "Critical", "header_attack"),
    (re.compile(r"\$\{jndi:", re.I),
     "Log4Shell", "Critical", "header_attack"),
    (re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nessus|acunetix)", re.I),
     "Scanner UA", "Medium", "scanner"),
]

def regex_fast_path(payload: str):
    for pattern, rule_name, severity, attack_cat in OWASP_RULES:
        if pattern.search(payload):
            return True, rule_name, severity, attack_cat
    return False, None, None, None




# Feature Extraction  (mirrors 01_prepare_dataset.py)
def _entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c/total)*np.log2(c/total) for c in counts.values())

def extract_features(url: str, body: str, method: str, ua: str) -> dict:
    payload = url + " " + body
    pl = payload.lower()
    f = {}
    f["url_length"]       = len(url)
    f["body_length"]      = len(body)
    f["payload_length"]   = len(payload)
    f["num_params"]       = url.count("=")
    f["count_single_quote"]   = payload.count("'")
    f["count_double_quote"]   = payload.count('"')
    f["count_semicolon"]      = payload.count(";")
    f["count_lt"]             = payload.count("<")
    f["count_gt"]             = payload.count(">")
    f["count_pipe"]           = payload.count("|")
    f["count_ampersand"]      = payload.count("&")
    f["count_dot"]            = payload.count(".")
    f["count_slash"]          = payload.count("/")
    f["count_backslash"]      = payload.count("\\")
    f["count_special"]        = len(re.findall(r"[^a-zA-Z0-9\s]", payload))
    f["ratio_special"]        = f["count_special"] / max(len(payload), 1)
    f["ratio_alpha"]          = sum(c.isalpha() for c in payload) / max(len(payload), 1)
    f["ratio_digit"]          = sum(c.isdigit() for c in payload) / max(len(payload), 1)
    sql_kw = r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute|cast|convert|declare|table|from|where|having|order|group|sleep|benchmark|load_file|null|or|and|not)\b"
    f["sql_keyword_count"]    = len(re.findall(sql_kw, pl))
    f["has_sql_comment"]      = int(bool(re.search(r"(--|\/\*|\*\/|#)", payload)))
    f["has_tautology"]        = int(bool(re.search(r"(\"|\')?\s*(or|and)\s+\d+=\d+", pl)))
    f["has_union_select"]     = int(bool(re.search(r"union.{0,20}select", pl)))
    f["has_sleep"]            = int(bool(re.search(r"sleep\s*\(\d+\)|benchmark\s*\(", pl)))
    f["has_hex_string"]       = int(bool(re.search(r"0x[0-9a-f]{4,}", pl)))
    f["has_script_tag"]       = int("<script" in pl)
    f["has_html_event"]       = int(bool(re.search(r"on\w+\s*=", pl)))
    f["has_javascript_proto"] = int("javascript:" in pl)
    f["has_iframe"]           = int("<iframe" in pl)
    f["has_onerror"]          = int("onerror" in pl or "onload" in pl)
    f["html_tag_count"]       = len(re.findall(r"<[^>]+>", payload))
    f["has_path_traversal"]   = int(bool(re.search(r"\.\.[/\\]", payload)))
    f["dotdot_count"]         = payload.count("..")
    f["has_etc_passwd"]       = int("etc/passwd" in pl)
    f["has_win_system"]       = int("windows" in pl and "system32" in pl)
    f["pct_encoded_traversal"]= int(bool(re.search(r"%2e%2e[%2f5c]", pl)))
    f["double_encoded"]       = int(bool(re.search(r"%25[2-9][0-9a-f]", pl)))
    f["has_cmd_separator"]    = int(bool(re.search(r"[;|&`$()]", payload)))
    f["has_shell_cmd"]        = int(bool(re.search(
        r"\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl)\b", pl)))
    f["has_backtick"]         = int("`" in payload)
    f["has_dollar_paren"]     = int("$(" in payload)
    f["has_shellshock"]       = int("() {" in payload or "(){" in payload)
    f["has_jndi"]             = int("jndi:" in pl)
    f["pct_encoded_chars"]    = len(re.findall(r"%[0-9a-fA-F]{2}", payload))
    f["hex_sequences"]        = len(re.findall(r"0x[0-9a-fA-F]+", pl))
    f["entropy"]              = _entropy(payload)
    f["url_entropy"]          = _entropy(url)
    f["is_post"]              = int(method.upper() == "POST")
    f["is_get"]               = int(method.upper() == "GET")
    f["has_scanner_ua"]       = int(bool(re.search(
        r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)", ua.lower())))
    return f




# ENHANCEMENT: LRU Cache for ML
@lru_cache(maxsize=10_000)
def cached_ml_binary(payload_key: str, url_key: str, method: str, ua: str):
    """Cache ML inference result keyed on the request payload."""
    feats  = extract_features(url_key, payload_key, method, ua)
    vector = [feats.get(col, 0) for col in FEATURE_COLS]
    return float(model.predict_proba([vector])[0][1])

def ml_classify(url: str, body: str, method: str, ua: str):
    if model is None:
        return False, 0.0
    proba = cached_ml_binary(body[:500], url[:500], method, ua[:200])
    return proba >= BLOCK_THRESHOLD, proba




# ENHANCEMENT: Multi-class Attack Type Classifier
def classify_attack_type(url: str, body: str, method: str, ua: str) -> str:
    if mc_model is None or label_enc is None:
        return "Unknown"
    feats  = extract_features(url, body, method, ua)
    vector = [feats.get(col, 0) for col in FEATURE_COLS]
    pred   = mc_model.predict([vector])[0]
    return str(label_enc.inverse_transform([pred])[0])



#Threat Info Builder

THREAT_DB = {
    "sqli": ("SQL Injection", "Critical",
        "Attacker injecting SQL to access or destroy your database.",
        ["Use parameterized queries / prepared statements",
         "Apply input validation with whitelist patterns",
         "Use least-privilege DB accounts",
         "Enable DB query auditing"]),
    "xss": ("Cross-Site Scripting", "High",
        "Script injection targeting user sessions and cookies.",
        ["Sanitize all user inputs before rendering",
         "Implement Content-Security-Policy header",
         "Use HTML-encoding for user-supplied content",
         "Set HttpOnly + Secure flags on cookies"]),
    "path_traversal": ("Path Traversal", "High",
        "Accessing files outside the web root.",
        ["Canonicalize and validate all file paths",
         "Allowlist permitted directories",
         "Run the web server with minimal OS privileges",
         "Disable directory listing"]),
    "cmd_injection": ("Command Injection", "Critical",
        "Executing OS commands on the server.",
        ["Never pass user input to system calls",
         "Use language-native APIs instead of shell",
         "Run app in a sandboxed container",
         "Implement strict input validation"]),
    "header_attack": ("Header Injection / Shellshock", "Critical",
        "Malicious code injected via HTTP headers.",
        ["Validate and sanitize all HTTP headers",
         "Update Bash (Shellshock) / Java (Log4Shell)",
         "Disable unused CGI features",
         "Apply WAF rule for () { pattern"]),
    "scanner": ("Scanner / Automated Attack Tool", "Medium",
        "Automated vulnerability scanning detected.",
        ["Implement rate limiting",
         "Block known scanner User-Agents",
         "Enable honeypot endpoints",
         "Monitor for scanning patterns"]),
}

def build_threat(attack_type: str, rule: str, severity: str, proba: float) -> dict:
    t = THREAT_DB.get(attack_type, (
        "Suspicious Request", "Medium",
        "Anomalous pattern detected by ML engine.",
        ["Review access logs", "Apply rate limiting", "Enable strict WAF mode"],
    ))
    return {
        "attack_type":    t[0],
        "severity":       severity or t[1],
        "description":    t[2],
        "recommendations": t[3],
        "triggered_rule": rule or "ML Anomaly Detection",
        "ml_confidence":  round(proba * 100, 1),
    }




# In-Memory State
attack_log    = []
recent_attacks= []           # Enhancement 7 — replay store
stats         = {"total": 0, "blocked": 0, "allowed": 0}
confidence_history = []      # Enhancement 10 — drift tracking
country_counts = defaultdict(int)  # Enhancement 6 — GeoIP stats


# ENHANCEMENT: Structured JSON Logging (SIEM-ready)

json_log_path = "logs/events.ndjson"

def write_json_log(entry: dict):
    try:
        with open(json_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass



# ENHANCEMENT: Dashboard Basic Auth
DASHBOARD_USER = os.environ.get("DASH_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASH_PASS", "admin")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == DASHBOARD_USER
                            and auth.password == DASHBOARD_PASS):
            return Response(
                "ShadowGuard — Login Required",
                401,
                {"WWW-Authenticate": 'Basic realm="ShadowGuard Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated






# Core Analysis Logic
def _inspect(url: str, body: str, method: str, ua: str, ip: str):
    """Full inspection pipeline. Returns log entry dict."""
    t0 = time.perf_counter()
    update_adaptive_threshold(stats)

    payload = url + " " + body + " " + ua

    #Pre-checks
    if is_blacklisted(ip):
        return _blocked_entry(url, body, method, ua, ip, payload,
                              "Blacklisted IP", "Critical", "blacklist",
                              1.0, t0)
    if is_rate_limited(ip):
        return _blocked_entry(url, body, method, ua, ip, payload,
                              "Rate Limit Exceeded", "Medium", "rate_limit",
                              0.9, t0, http_code=429)

    #Stage 1: Regex fast path
    regex_hit, rule_name, severity, attack_cat = regex_fast_path(payload)

    #Stage 2: ML classification
    ml_attack, proba = ml_classify(url, body, method, ua)
    if ml_attack and not regex_hit:
        attack_cat = classify_attack_type(url, body, method, ua)

    is_blocked = regex_hit or ml_attack
    detection_source = "regex" if regex_hit else ("ml" if ml_attack else "none")

    threat   = build_threat(attack_cat or "unknown", rule_name, severity, proba)
    risk     = int(max(proba, 0.95 if regex_hit else 0) * 100)
    latency  = round((time.perf_counter() - t0) * 1000, 2)
    country  = get_country(ip)



    #Confidence drift tracking
    confidence_history.append(proba)
    if len(confidence_history) > 200:
        confidence_history.pop(0)



    #Stats
    stats["total"] += 1
    if is_blocked:
        stats["blocked"] += 1
        register_attack(ip)
    else:
        stats["allowed"] += 1

    country_counts[country] += 1

    entry = {
        "id":               stats["total"],
        "timestamp":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":               ip,
        "country":          country,
        "method":           method,
        "url":              url,
        "payload":          payload[:500],
        "action":           "BLOCKED" if is_blocked else "ALLOWED",
        "status":           "danger" if is_blocked else "success",
        "risk_score":       risk,
        "attack_type":      threat["attack_type"],
        "attack_category":  attack_cat or "unknown",
        "severity":         threat["severity"],
        "description":      threat["description"],
        "recommendations":  threat["recommendations"],
        "triggered_rule":   threat["triggered_rule"],
        "ml_confidence":    threat["ml_confidence"],
        "detection_source": detection_source,
        "latency_ms":       latency,
        "threshold_used":   BLOCK_THRESHOLD,
        "http_code":        403 if is_blocked else 200,
    }

    attack_log.append(entry)
    if len(attack_log) > 500:
        attack_log.pop(0)

    if is_blocked:
        recent_attacks.append(payload[:500])    # Enhancement 7
        if len(recent_attacks) > 100:
            recent_attacks.pop(0)

    write_json_log(entry)                       # Enhancement 5

    if is_blocked:
        logger.warning("BLOCKED [%s/%s] %s %s | Rule=%s | Risk=%d",
                       ip, country, method, url, threat["triggered_rule"], risk)
    else:
        logger.info("ALLOWED [%s] %s %s | ML=%.2f | %dms", ip, method, url, proba, latency)

    return entry


def _blocked_entry(url, body, method, ua, ip, payload, rule, sev, cat, proba, t0, http_code=403):
    latency = round((time.perf_counter() - t0) * 1000, 2)
    stats["total"] += 1; stats["blocked"] += 1
    threat  = build_threat(cat, rule, sev, proba)
    entry = {
        "id": stats["total"], "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip, "country": get_country(ip), "method": method, "url": url,
        "payload": payload[:500], "action": "BLOCKED", "status": "danger",
        "risk_score": int(proba * 100), "attack_type": threat["attack_type"],
        "attack_category": cat, "severity": sev,
        "description": threat["description"], "recommendations": threat["recommendations"],
        "triggered_rule": rule, "ml_confidence": round(proba*100, 1),
        "detection_source": cat, "latency_ms": latency,
        "threshold_used": BLOCK_THRESHOLD, "http_code": http_code,
    }
    attack_log.append(entry)
    write_json_log(entry)
    return entry




# Routes: Analysis
@app.route("/api/analyze", methods=["POST"])
def analyze():
    data   = request.json or {}
    payload= data.get("payload", "")
    url    = data.get("url", "/")
    body   = data.get("body", payload)
    method = data.get("method", "GET")
    ua     = data.get("user_agent", request.headers.get("User-Agent", ""))
    ip     = request.remote_addr or "127.0.0.1"
    if not (payload or body):
        return jsonify({"error": "No payload"}), 400
    entry = _inspect(url, body, method, ua, ip)
    code  = entry["http_code"]
    return jsonify(entry), code



# Routes: Reverse Proxy
@app.route("/proxy", methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/proxy/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
def reverse_proxy(subpath=""):
    url    = request.full_path
    body   = request.get_data(as_text=True) or ""
    method = request.method
    ua     = request.headers.get("User-Agent", "")
    ip     = (request.headers.get("X-Real-IP") or
              request.headers.get("X-Forwarded-For", "").split(",")[0] or
              request.remote_addr or "127.0.0.1")

    
    
    #Include headers in analysis (catches Shellshock etc.)
    header_str = " ".join(f"{k}:{v}" for k, v in request.headers.items())
    combined_ua = ua + " " + header_str

    entry = _inspect(url, body, method, combined_ua, ip)

    if entry["action"] == "BLOCKED":
        return jsonify({
            "blocked": True,
            "rule":    entry["triggered_rule"],
            "risk":    entry["risk_score"],
        }), entry["http_code"]



    #Forward to target app
    try:
        target = TARGET_APP_URL + request.path
        resp = req_lib.request(
            method=method, url=target,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=body, params=request.args,
            timeout=10, allow_redirects=False,
        )
        stats["allowed"] += 1 if stats["total"] == 0 else 0  # idempotency guard
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        logger.error("Proxy forward error: %s", e)
        return jsonify({"error": "Target app unreachable", "detail": str(e)}), 502



# Routes: API
@app.route("/api/logs")
def get_logs():
    n = min(int(request.args.get("n", 50)), 200)
    return jsonify(attack_log[-n:][::-1])

@app.route("/api/stats")
def get_stats():
    total = max(stats["total"], 1)
    recent = attack_log[-100:]
    type_counts = Counter(e["attack_type"] for e in recent if e["action"] == "BLOCKED")
    return jsonify({
        **stats,
        "block_rate": round(stats["blocked"] / total * 100, 1),
        "top_attack_types": dict(type_counts.most_common(5)),
        "top_countries": dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
        "adaptive_threshold": BLOCK_THRESHOLD,
        "blacklisted_ips": len(blacklist),
        "model_info": {
            "name":      train_report.get("best_model", "Unknown"),
            "f1":        train_report.get("final_metrics", {}).get("f1", 0),
            "threshold": BLOCK_THRESHOLD,
        },
    })


# ENHANCEMENT: Model Drift
@app.route("/api/model_stats")
def model_stats():
    avg = sum(confidence_history) / max(len(confidence_history), 1)
    drift_flag = avg < 0.45  # model is unsure → potential drift
    return jsonify({
        "avg_ml_confidence":   round(avg, 4),
        "samples_tracked":     len(confidence_history),
        "drift_detected":      drift_flag,
        "current_threshold":   BLOCK_THRESHOLD,
        "base_threshold":      BASE_THRESHOLD,
        "cache_size":          cached_ml_binary.cache_info().currsize,
        "cache_hits":          cached_ml_binary.cache_info().hits,
        "cache_misses":        cached_ml_binary.cache_info().misses,
    })

# ENHANCEMENT: Replay API
@app.route("/api/replay")
def replay_attacks():
    return jsonify(recent_attacks[-50:])



# ENHANCEMENT: Blacklist management
@app.route("/api/blacklist")
def get_blacklist():
    now = time.time()
    return jsonify({ip: round(ts - now) for ip, ts in blacklist.items() if ts > now})

@app.route("/api/blacklist/<ip>", methods=["DELETE"])
def unban_ip(ip):
    if ip in blacklist:
        del blacklist[ip]; attack_counts[ip] = 0
        return jsonify({"unban": ip})
    return jsonify({"error": "not in blacklist"}), 404

@app.route("/api/health")
def health():
    return jsonify({
        "status": "operational",
        "model_loaded": model is not None,
        "geoip_loaded": geoip_reader is not None,
        "threshold": BLOCK_THRESHOLD,
        "timestamp": datetime.now().isoformat(),
    })



# Routes: Frontend
@app.route("/")
@app.route("/demo")
def demo():
    return render_template("demo.html")

@app.route("/dashboard")
@require_auth
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    print("\n" + "="*55)
    print("Starting ShadowGuard")
    print("="*55)
    print(f"  Dashboard : http://0.0.0.0:5000/dashboard  (admin/admin)")
    print(f"  Demo      : http://0.0.0.0:5000/demo")
    print(f"  API health: http://0.0.0.0:5000/api/health")
    print(f"  Proxy     : http://0.0.0.0:5000/proxy → {TARGET_APP_URL}")
    print(f"  Threshold : {BLOCK_THRESHOLD} (adaptive)")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)