"""
Architecture:
  Client → Nginx (port 80/443) → ShadowGuard (port 5000) → Target App (port 8080)

Run: gunicorn -w 4 -b 0.0.0.0:5000 app:app
Dev: python app.py
"""

import re
import json
import time
import logging
import numpy as np
import joblib
from collections import Counter
from datetime import datetime
from functools import lru_cache

from flask import Flask, request, jsonify, Response, render_template
from flask_cors import CORS
import requests as req_lib

# ─── Logging Setup ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/shadowguard.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("ShadowGuard")

# ─── App Init ──────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ─── Load ML Artifacts ─────────────────────────────────────────────────────
try:
    model = joblib.load("models/shadowguard_model.pkl")
    with open("models/feature_columns.json") as f:
        FEATURE_COLS = json.load(f)
    with open("models/training_report.json") as f:
        training_report = json.load(f)
    logger.info("ML model loaded | Model: %s | F1: %s",
                training_report.get("best_model"),
                training_report.get("final_metrics", {}).get("f1"))
except Exception as e:
    logger.critical("Failed to load model: %s — run 02_train_model.py first", e)
    model = None
    FEATURE_COLS = []

# ─── Config ────────────────────────────────────────────────────────────────
BLOCK_THRESHOLD = 0.75         # ML probability threshold for blocking
FAST_BLOCK_THRESHOLD = 0.95    # Skip analysis, block immediately
TARGET_APP_URL = "http://localhost:8080"  # Victim / target app

# In-memory state (replace with Redis in production)
attack_log = []
stats = {"total": 0, "blocked": 0, "allowed": 0}

# ─── OWASP Regex Rules (Fast Path) ─────────────────────────────────────────
OWASP_RULES = [
    # SQL Injection
    (re.compile(r"(\b(union|select|insert|delete|drop|create|alter|exec|execute|"
                r"cast|convert|char|nchar|declare|table|cursor|having|waitfor|"
                r"sleep|benchmark|load_file)\b)", re.I),
     "SQLi - Keyword", "Critical"),
    (re.compile(r"(--|\/\*|\*\/|#\s*$|;\s*$)", re.M),
     "SQLi - Comment/Terminator", "High"),
    (re.compile(r"('|\")?\s*(or|and)\s+\d+=\d+", re.I),
     "SQLi - Tautology", "Critical"),
    (re.compile(r"union.{0,30}select", re.I | re.S),
     "SQLi - UNION SELECT", "Critical"),

    # XSS
    (re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.I),
     "XSS - Script Tag", "Critical"),
    (re.compile(r"on\w+\s*=\s*['\"]?[\w\s;()]+['\"]?", re.I),
     "XSS - Event Handler", "High"),
    (re.compile(r"javascript\s*:", re.I),
     "XSS - javascript: Protocol", "High"),
    (re.compile(r"<(iframe|frame|object|embed|applet|link|base|form)\b", re.I),
     "XSS - Dangerous Tag", "Medium"),

    # Path Traversal
    (re.compile(r"\.\.[/\\]"),
     "Path Traversal - ../", "Critical"),
    (re.compile(r"%2e%2e[%2f5c]", re.I),
     "Path Traversal - URL Encoded", "Critical"),
    (re.compile(r"(etc/passwd|etc/shadow|proc/self|boot\.ini|win\.ini)", re.I),
     "Path Traversal - Sensitive File", "Critical"),

    # Command Injection
    (re.compile(r"[;|&`$()]\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh|cmd)\b", re.I),
     "CMD Injection - Shell Command", "Critical"),
    (re.compile(r"\$\([^)]+\)|`[^`]+`"),
     "CMD Injection - Command Substitution", "Critical"),

    # Shellshock / Log4Shell
    (re.compile(r"\(\)\s*\{"),
     "Shellshock", "Critical"),
    (re.compile(r"\$\{jndi:", re.I),
     "Log4Shell", "Critical"),

    # Scanner fingerprints
    (re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nessus|acunetix)", re.I),
     "Scanner Fingerprint", "Medium"),
]


def regex_fast_path(payload: str) -> tuple:
    """
    Run OWASP regex rules before invoking ML model.
    Returns (is_attack: bool, rule_name: str, severity: str)
    """
    for pattern, rule_name, severity in OWASP_RULES:
        if pattern.search(payload):
            return True, rule_name, severity
    return False, None, None


# ─── Feature Extraction (matches 01_prepare_dataset.py) ────────────────────
def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * np.log2(c / total) for c in counts.values())


def extract_features(url: str, body: str, method: str, ua: str) -> dict:
    payload = url + " " + body
    payload_lower = payload.lower()

    feats = {}
    feats["url_length"] = len(url)
    feats["body_length"] = len(body)
    feats["payload_length"] = len(payload)
    feats["num_params"] = url.count("=")
    feats["count_single_quote"] = payload.count("'")
    feats["count_double_quote"] = payload.count('"')
    feats["count_semicolon"] = payload.count(";")
    feats["count_lt"] = payload.count("<")
    feats["count_gt"] = payload.count(">")
    feats["count_pipe"] = payload.count("|")
    feats["count_ampersand"] = payload.count("&")
    feats["count_dot"] = payload.count(".")
    feats["count_slash"] = payload.count("/")
    feats["count_backslash"] = payload.count("\\")
    feats["count_special"] = len(re.findall(r"[^a-zA-Z0-9\s]", payload))
    feats["ratio_special"] = feats["count_special"] / max(len(payload), 1)
    feats["ratio_alpha"] = sum(c.isalpha() for c in payload) / max(len(payload), 1)
    feats["ratio_digit"] = sum(c.isdigit() for c in payload) / max(len(payload), 1)

    sql_kw = r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute|cast|convert|declare|table|from|where|having|order|group|by|or|and|not|null|sleep|benchmark|load_file)\b'
    feats["sql_keyword_count"] = len(re.findall(sql_kw, payload_lower))
    feats["has_sql_comment"] = int(bool(re.search(r'(--|\/\*|\*\/|#)', payload)))
    feats["has_tautology"] = int(bool(re.search(r"('|\")?\s*(or|and)\s+\d+=\d+", payload_lower)))
    feats["has_union_select"] = int(bool(re.search(r'union.{0,20}select', payload_lower)))
    feats["has_sleep"] = int(bool(re.search(r'sleep\s*\(\d+\)|benchmark\s*\(', payload_lower)))
    feats["has_script_tag"] = int("<script" in payload_lower)
    feats["has_html_event"] = int(bool(re.search(r'on\w+\s*=', payload_lower)))
    feats["has_javascript_proto"] = int("javascript:" in payload_lower)
    feats["has_iframe"] = int("<iframe" in payload_lower)
    feats["has_onerror"] = int("onerror" in payload_lower or "onload" in payload_lower)
    feats["html_tag_count"] = len(re.findall(r'<[^>]+>', payload))
    feats["has_path_traversal"] = int(bool(re.search(r'\.\.[/\\]', payload)))
    feats["dotdot_count"] = payload.count("..")
    feats["has_etc_passwd"] = int("etc/passwd" in payload_lower)
    feats["has_win_system"] = int("windows" in payload_lower and "system32" in payload_lower)
    feats["percent_encoded_traversal"] = int(bool(re.search(r'%2e%2e[%2f5c]', payload_lower)))
    feats["has_cmd_separator"] = int(bool(re.search(r'[;|&`$()]', payload)))
    feats["has_shell_cmd"] = int(bool(re.search(r'\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell)\b', payload_lower)))
    feats["has_backtick"] = int("`" in payload)
    feats["has_dollar_paren"] = int("$(" in payload)
    feats["has_shellshock"] = int("() {" in payload or "(){" in payload)
    feats["has_jndi"] = int("jndi:" in payload_lower)
    feats["pct_encoded_chars"] = len(re.findall(r'%[0-9a-fA-F]{2}', payload))
    feats["hex_sequences"] = len(re.findall(r'0x[0-9a-fA-F]+', payload_lower))
    feats["entropy"] = calculate_entropy(payload)
    feats["url_entropy"] = calculate_entropy(url)
    feats["is_post"] = int(method.upper() == "POST")
    feats["is_get"] = int(method.upper() == "GET")
    feats["has_scanner_ua"] = int(bool(re.search(r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)', ua.lower())))
    return feats


def ml_classify(feats: dict) -> tuple:
    """Run ML inference. Returns (is_attack, probability)."""
    if model is None:
        return False, 0.0
    vector = [feats.get(col, 0) for col in FEATURE_COLS]
    proba = model.predict_proba([vector])[0][1]
    return proba >= BLOCK_THRESHOLD, float(proba)


def build_threat_analysis(payload: str, rule: str, severity: str,
                           attack_type: str, proba: float) -> dict:
    """Generate human-readable threat analysis and recommendations."""
    payload_lower = payload.lower()

    type_map = {
        "sqli": ("SQL Injection", "Critical",
                 "Attacker injecting SQL commands to manipulate your database.",
                 ["Use parameterized queries / prepared statements",
                  "Implement strict input validation and whitelist patterns",
                  "Apply least-privilege to database accounts",
                  "Enable database activity monitoring"]),
        "xss": ("Cross-Site Scripting (XSS)", "High",
                "Malicious script injection targeting browser session/cookies.",
                ["Sanitize all user input before rendering",
                 "Implement a strong Content-Security-Policy header",
                 "Use HTML-encoding for user-supplied content",
                 "Enable HttpOnly and Secure flags on cookies"]),
        "path_traversal": ("Path Traversal", "High",
                           "Attacker trying to access files outside the web root.",
                           ["Canonicalize and validate all file paths",
                            "Use an allowlist for permitted file extensions",
                            "Run the web server with minimal OS privileges",
                            "Disable directory listing"]),
        "cmd_injection": ("Command Injection", "Critical",
                          "Attacker attempting to execute OS commands on the server.",
                          ["Never pass user input to system calls",
                           "Use language-native APIs instead of shell commands",
                           "Implement strict input validation",
                           "Run app in a sandboxed / containerized environment"]),
        "header_attack": ("Header Injection / Shellshock", "Critical",
                          "Malicious data injected via HTTP headers.",
                          ["Validate and sanitize all HTTP headers",
                           "Update Bash (Shellshock) / Java (Log4Shell)",
                           "Use a WAF rule to block () { patterns",
                           "Disable unused CGI features"]),
    }

    # Infer attack type from payload if not provided
    if attack_type == "ML_Detection":
        if re.search(r"union|select|'.*or.*'", payload_lower):
            attack_type = "sqli"
        elif "<script" in payload_lower or "javascript:" in payload_lower:
            attack_type = "xss"
        elif ".." in payload:
            attack_type = "path_traversal"
        elif re.search(r'[;|&`]', payload):
            attack_type = "cmd_injection"

    t = type_map.get(attack_type, (
        "Suspicious Request", "Medium",
        "Anomalous pattern detected by ML engine.",
        ["Review request logs for patterns",
         "Implement rate limiting",
         "Consider enabling strict OWASP rule set"],
    ))

    return {
        "attack_type": t[0],
        "severity": severity or t[1],
        "description": t[2],
        "recommendations": t[3],
        "triggered_rule": rule or "ML Anomaly Detection",
        "ml_confidence": round(proba * 100, 1),
    }


# ─── Core Analysis Endpoint ─────────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze an HTTP payload without proxying.
    Used by the dashboard and test suite.
    """
    data = request.json or {}
    payload_input = data.get("payload", "")
    url = data.get("url", "/")
    body = data.get("body", payload_input)
    method = data.get("method", "GET")
    ua = data.get("user_agent", "")

    if not payload_input and not body:
        return jsonify({"error": "No payload provided"}), 400

    return _analyze_and_respond(url, body, method, ua, payload_input)


def _analyze_and_respond(url, body, method, ua, raw_payload=""):
    t_start = time.perf_counter()
    payload = raw_payload or (url + " " + body)
    ip = request.remote_addr or "unknown"

    # Stage 1: Regex Fast Path
    regex_hit, rule_name, severity = regex_fast_path(payload)

    # Stage 2: ML Classification
    feats = extract_features(url, body, method, ua)
    ml_attack, proba = ml_classify(feats)

    is_blocked = regex_hit or ml_attack
    detection_source = "regex" if regex_hit else ("ml" if ml_attack else "none")
    attack_type = "ML_Detection" if ml_attack and not regex_hit else (
        "sqli" if rule_name and "SQL" in rule_name else
        "xss" if rule_name and "XSS" in rule_name else
        "path_traversal" if rule_name and "Path" in rule_name else
        "cmd_injection" if rule_name and "CMD" in rule_name else
        "header_attack"
    )

    threat = build_threat_analysis(payload, rule_name, severity, attack_type, proba)
    risk_score = int(max(proba, 0.95 if regex_hit else 0) * 100)
    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Update stats
    stats["total"] += 1
    if is_blocked:
        stats["blocked"] += 1
    else:
        stats["allowed"] += 1

    entry = {
        "id": stats["total"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": method,
        "url": url,
        "payload": payload[:500],
        "action": "BLOCKED" if is_blocked else "ALLOWED",
        "status": "danger" if is_blocked else "success",
        "risk_score": risk_score,
        "attack_type": threat["attack_type"],
        "severity": threat["severity"],
        "description": threat["description"],
        "recommendations": threat["recommendations"],
        "triggered_rule": threat["triggered_rule"],
        "ml_confidence": threat["ml_confidence"],
        "detection_source": detection_source,
        "latency_ms": latency_ms,
    }
    attack_log.append(entry)
    if len(attack_log) > 500:
        attack_log.pop(0)

    if is_blocked:
        logger.warning("BLOCKED [%s] %s %s | Risk=%d | Rule=%s",
                       ip, method, url, risk_score, threat["triggered_rule"])
    else:
        logger.info("ALLOWED [%s] %s %s | Risk=%d | ML=%.2f",
                    ip, method, url, risk_score, proba)

    return jsonify(entry)


# ─── Reverse Proxy Endpoint ─────────────────────────────────────────────────
@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def reverse_proxy():
    """
    Transparent reverse proxy with WAF inspection.
    All requests are analyzed; blocked ones never reach the target app.
    """
    url = request.args.get("target_path", request.path)
    body = request.get_data(as_text=True) or ""
    method = request.method
    ua = request.headers.get("User-Agent", "")

    # Reconstruct the full query string for analysis
    full_url = request.full_path

    # Combine headers + url + body for deep inspection
    header_str = " ".join(f"{k}:{v}" for k, v in request.headers.items())
    payload = full_url + " " + body + " " + header_str

    regex_hit, rule_name, severity = regex_fast_path(payload)
    feats = extract_features(full_url, body, method, ua)
    ml_attack, proba = ml_classify(feats)
    is_blocked = regex_hit or ml_attack

    if is_blocked:
        attack_type = "cmd_injection"  # default; refined below
        if rule_name and "SQL" in rule_name:
            attack_type = "sqli"
        elif rule_name and "XSS" in rule_name:
            attack_type = "xss"
        elif rule_name and "Path" in rule_name:
            attack_type = "path_traversal"
        threat = build_threat_analysis(payload, rule_name, severity, attack_type, proba)
        risk = int(max(proba, 0.95 if regex_hit else 0) * 100)
        stats["total"] += 1
        stats["blocked"] += 1
        logger.warning("BLOCKED [proxy] %s %s | %s", method, full_url, rule_name or "ML")
        return jsonify({
            "action": "BLOCKED",
            "risk_score": risk,
            "threat": threat,
        }), 403

    # Forward to target app
    try:
        target = TARGET_APP_URL + request.path
        resp = req_lib.request(
            method=method,
            url=target,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=body,
            params=request.args,
            timeout=10,
            allow_redirects=False,
        )
        stats["total"] += 1
        stats["allowed"] += 1
        return Response(
            resp.content,
            status=resp.status_code,
            headers=dict(resp.headers),
        )
    except Exception as e:
        logger.error("Proxy forward error: %s", e)
        return jsonify({"error": "Target app unreachable", "detail": str(e)}), 502


# ─── Dashboard API Endpoints ─────────────────────────────────────────────────
@app.route("/api/logs")
def get_logs():
    n = min(int(request.args.get("n", 50)), 200)
    return jsonify(attack_log[-n:][::-1])


@app.route("/api/stats")
def get_stats():
    total = stats["total"] or 1
    recent = attack_log[-100:]
    type_counts = Counter(e["attack_type"] for e in recent if e["action"] == "BLOCKED")
    hourly = Counter(e["timestamp"][:13] for e in recent)
    return jsonify({
        **stats,
        "block_rate": round(stats["blocked"] / total * 100, 1),
        "top_attack_types": dict(type_counts.most_common(5)),
        "hourly_activity": dict(hourly),
        "model_info": {
            "name": training_report.get("best_model", "Unknown") if model else "Not Loaded",
            "f1": training_report.get("final_metrics", {}).get("f1", 0),
        } if model else {},
    })


@app.route("/api/health")
def health():
    return jsonify({
        "status": "operational",
        "model_loaded": model is not None,
        "timestamp": datetime.now().isoformat(),
    })


# ─── Frontend ───────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/demo")
def demo():
    return render_template("demo.html")


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  🛡️  SHADOWGUARD WAF  — Starting")
    print("=" * 50)
    print(f"  Dashboard : http://0.0.0.0:5000/dashboard")
    print(f"  Demo App  : http://0.0.0.0:5000/demo")
    print(f"  API Docs  : http://0.0.0.0:5000/api/health")
    print(f"  Proxy     : http://0.0.0.0:5000/proxy → {TARGET_APP_URL}")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)