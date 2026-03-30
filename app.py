import re
import os
import json
import time
import logging
import numpy as np
import joblib
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache, wraps

from flask import Flask, request, jsonify, Response, render_template
from flask_cors import CORS
import requests as req_lib


#Setup

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

TARGET_APP_URL = os.environ.get("TARGET_APP_URL", "http://localhost:8080")
DASH_USER = os.environ.get("DASH_USER", "admin")
DASH_PASS = os.environ.get("DASH_PASS", "admin")


#Load ML Artifacts

try:
    _model = joblib.load("models/shadowguard_model.pkl")
    #Fast inference: single-threaded predict for low latency
    _clf = _model.named_steps.get("clf") if hasattr(_model, "named_steps") else _model
    if hasattr(_clf, "n_jobs"):
        _clf.n_jobs = 1

    with open("models/feature_columns.json") as f:
        FEATURE_COLS = json.load(f)
    with open("models/training_report.json") as f:
        _train_report = json.load(f)

    ML_AVAILABLE = True
    logger.info("Model loaded: %s | F1=%.4f | Features=%d",
                _train_report.get("best_model", "?"),
                _train_report.get("final_metrics", {}).get("f1", 0),
                len(FEATURE_COLS))
except Exception as e:
    _model = None
    _clf = None
    FEATURE_COLS = []
    _train_report = {}
    ML_AVAILABLE = False
    logger.warning("ML model not loaded (%s). WAF runs on rules only.", e)


#In-Memory State

_log: list   = []
_stats       = {"total": 0, "blocked": 0, "allowed": 0, "ml_invoked": 0}
_json_log    = "logs/events.ndjson"

#Rate limiter + blacklist
_rate_track: dict = defaultdict(list)
_blacklist:  dict = {}
_hit_counts: dict = defaultdict(int)
RATE_MAX = 30
RATE_WIN = 10
BAN_AFTER = 5
BAN_SECS  = 300


#TIER 0: SAFE PASS PATTERNS

#Extensions that are always static assets: never need WAF inspection
_STATIC_EXT = re.compile(
    r'\.(css|js|jsx|ts|tsx|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|'
    r'webp|avif|mp4|mp3|pdf|map|json|xml)(\?.*)?$', re.I)

#Characters that are ALWAYS safe: cannot possibly form an attack
#If payload contains ONLY these characters, skip all analysis
_SAFE_CHARS = re.compile(r'^[a-zA-Z0-9\s,._\-+@:/=%&?#\[\]{}()\'"!*~]*$')

#Patterns that are specifically safe (common normal params)
_SAFE_PATTERNS = [
    re.compile(r'^[a-zA-Z0-9\s]+$'),             # pure text, no special chars
    re.compile(r'^\d+$'),                          # pure integer ID
    re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'),  # email
    re.compile(r'^https?://[a-zA-Z0-9._/\-?=&%]+$'),  # clean URL
]


def _is_static_asset(url: str) -> bool:
    return bool(_STATIC_EXT.search(url))


def _compute_attack_surface(payload: str) -> int:
    """
    Count how many attack-relevant characters the payload contains.
    If this returns 0, skip all analysis → ALLOW.
    This is NOT the soft score — it's just a quick pre-filter.
    """
    surface = 0
    surface += payload.count("'")          # SQL injection
    surface += payload.count('"')          # SQL injection
    surface += payload.count("<")          # XSS
    surface += payload.count(">")          # XSS
    surface += payload.count(";")          # SQL terminator / CMD
    surface += payload.count("|")          # CMD injection
    surface += payload.count("`")          # CMD substitution
    surface += 1 if "$(" in payload else 0  # CMD substitution
    surface += 1 if "(){" in payload or "() {" in payload else 0  # Shellshock
    surface += 1 if "${" in payload else 0  # Log4Shell
    surface += payload.count("..")          # Path traversal
    surface += 1 if "\x00" in payload or "%00" in payload else 0  # Null byte
    return surface



#TIER 1: HARD BLOCK RULES (no ML, definitive attacks)

# hese patterns are NEVER legitimate in HTTP request parameters.
#False positive risk: essentially zero for each of these.

_HARD_RULES = [

    #SQL Injection
    #UNION SELECT together (handles /**/comments and ALL keyword)
    (re.compile(
        r"union\s*(?:\/\*.*?\*\/\s*|--[^\n]*\n)?(?:all\s+)?select\b",
        re.I | re.S),
     "SQLi – UNION SELECT", "Critical", "sqli"),

    #Classic tautology: ' OR '1'='1 or ' OR 1=1
    (re.compile(r"'\s*(or|and)\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+['\"]?", re.I),
     "SQLi – Tautology (quote)", "Critical", "sqli"),

    #Quote followed immediately by SQL comment = injection terminator
    (re.compile(r"'\s*(?:--|#|\/\*)", re.I),
     "SQLi – Quote + Comment", "Critical", "sqli"),

    #Stacked query: '; DROP/DELETE/INSERT/UPDATE
    (re.compile(r"';\s*(drop|delete|insert|update|create|alter|exec|truncate)\b", re.I),
     "SQLi – Stacked Query", "Critical", "sqli"),

    #Sleep/benchmark in function call (time-based blind SQLi)
    (re.compile(r"\b(sleep|benchmark|waitfor\s+delay)\s*\(", re.I),
     "SQLi – Time-Based Blind", "Critical", "sqli"),

    #XSS
    #<script in any form (case-insensitive, handles spaces/newlines)
    (re.compile(r"<\s*script[\s>\/]", re.I),
     "XSS – Script Tag", "Critical", "xss"),

    #HTML tag with event handler (onclick=, onerror=, onload=, etc.)
    (re.compile(r"<[a-z][^>]*\s+on[a-z]+\s*=", re.I),
     "XSS – Event Handler", "Critical", "xss"),

    #javascript: or vbscript: protocol handler
    (re.compile(r"(?:javascript|vbscript|data)\s*:", re.I),
     "XSS – JS Protocol", "Critical", "xss"),

    #<iframe, <frame, <object, <embed — injection vectors
    (re.compile(r"<\s*(?:iframe|frame|object|embed|applet|meta\s+http-equiv)\b", re.I),
     "XSS – Dangerous Tag", "High", "xss"),

    #expression() CSS injection
    (re.compile(r"expression\s*\(", re.I),
     "XSS – CSS Expression", "High", "xss"),

    #Path Traversal
    #2+ levels of ../ or ..\
    (re.compile(r"(?:\.\.[/\\]){2,}"),
     "Path Traversal – Multi-Level", "Critical", "path_traversal"),

    #URL-encoded traversal: %2e%2e%2f or %2e%2e%5c
    (re.compile(r"(?:%2e%2e|%252e%252e)[/%5c]", re.I),
     "Path Traversal – URL Encoded", "Critical", "path_traversal"),

    #Direct sensitive file references
    (re.compile(
        r"(?:etc/(?:passwd|shadow|group|hosts)|/proc/self|boot\.ini|"
        r"win\.ini|web\.config|\.htaccess|\.htpasswd|/etc/cron)", re.I),
     "Path Traversal – Sensitive File", "Critical", "path_traversal"),

    #Command Injection
    #Shell separator followed by a known shell command
    (re.compile(
        r"[;|&`]\s*(?:ls|cat|id|whoami|wget|curl|nc|netcat|bash|sh|"
        r"python|perl|ruby|php|powershell|cmd\.exe|/bin/)\b", re.I),
     "CMD – Shell Command After Separator", "Critical", "cmd_injection"),

    #Command substitution: $(cmd) or `cmd`
    (re.compile(r"\$\([^)]{1,100}\)|`[^`]{1,100}`"),
     "CMD – Command Substitution", "Critical", "cmd_injection"),

    #Reverse shell patterns
    (re.compile(
        r"(?:/dev/tcp/|nc\s+\S+\s+\d+|bash\s+-i|python.*socket|"
        r"perl\s+-e|ruby\s+-e)\s", re.I),
     "CMD – Reverse Shell", "Critical", "cmd_injection"),

    #Header Attacks
    #Shellshock: () { :; }; or variants
    (re.compile(r"\(\)\s*\{[^}]*:;\s*\}", re.I | re.S),
     "Shellshock", "Critical", "header_attack"),

    #Log4Shell and variants (obfuscated ${jndi:...})
    (re.compile(r"\$\{(?:[^\}]{0,10}:){0,3}(?:ldap|rmi|dns|iiop|http)[s]?://", re.I),
     "Log4Shell", "Critical", "header_attack"),

    #Special Attacks
    #Null byte injection
    (re.compile(r"\x00|%00"),
     "Null Byte Injection", "Critical", "special"),

    #Long hex string (shellcode / hex-encoded payload)
    (re.compile(r"0x[0-9a-fA-F]{20,}", re.I),
     "Shellcode – Long Hex String", "High", "special"),

    #XXE: XML external entity
    (re.compile(r"<!(?:ENTITY|DOCTYPE)[^>]*SYSTEM\s+['\"]", re.I),
     "XXE – XML External Entity", "Critical", "xxe"),

    #SSRF: Internal network access via URL param
    (re.compile(
        r"(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|"
        r"169\.254\.|192\.168\.|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.)",
        re.I),
     "SSRF – Internal Network Access", "High", "ssrf"),
]

#Scanner/tool User-Agent fingerprints (checked separately against UA only)
_SCANNER_UA = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei|"
    r"nessus|acunetix|burpsuite|zaproxy|wfuzz|ffuf|hydra|metasploit)",
    re.I)


def hard_block(payload: str, ua: str = "") -> tuple:
    """
    Run hard block rules against payload.
    Returns (is_attack, rule_name, severity, attack_category)
    """
    #Check User-Agent for scanners first (cheap check)
    if ua and _SCANNER_UA.search(ua):
        return True, "Scanner/Tool Fingerprint", "Medium", "scanner"

    #Run payload through hard rules
    for pattern, rule_name, severity, category in _HARD_RULES:
        if pattern.search(payload):
            return True, rule_name, severity, category

    return False, None, None, None



#TIER 2: SOFT SCORE (accumulates suspicion)

#Each pattern adds points to a suspicion score.
#Score == 0 → clean, ALLOW without ML.
#Score >= ML_INVOKE_THRESHOLD → invoke ML.

_SOFT_RULES = [
    #SQL-related (lower confidence: could be natural language)
    (re.compile(r"'"),                                       2, "single_quote"),
    (re.compile(r"\bselect\b", re.I),                        2, "sql_select"),
    (re.compile(r"\bunion\b",  re.I),                        2, "sql_union"),
    (re.compile(r"\binsert\b|\bdelete\b|\bdrop\b", re.I),    3, "sql_dml"),
    (re.compile(r"\bexec\b|\bexecute\b", re.I),              3, "sql_exec"),
    (re.compile(r"--"),                                       3, "sql_comment_dash"),
    (re.compile(r"\/\*"),                                     2, "sql_comment_block"),
    (re.compile(r"\bor\b\s+\w+\s*=", re.I),                  3, "or_equals"),
    (re.compile(r"\band\b\s+\w+\s*=", re.I),                 3, "and_equals"),

    #XSS-related
    (re.compile(r"<[a-zA-Z]"),                               2, "html_tag_open"),
    (re.compile(r"on[a-z]{2,15}\s*=", re.I),                 3, "event_handler"),

    #Path traversal related
    (re.compile(r"\.\."),                                     2, "dotdot"),
    (re.compile(r"%2e%2e", re.I),                             3, "encoded_dotdot"),

    #Command injection related
    (re.compile(r"[;|`]"),                                    3, "cmd_separator"),
    (re.compile(r"\$\{"),                                     3, "template_injection"),
    (re.compile(r"\beval\b|\bexec\b|\bsystem\b", re.I),      3, "dangerous_function"),

    #Encoding anomalies
    (re.compile(r"%(?:27|22|3c|3e|3b|7c|60)", re.I),         3, "encoded_special"),
    (re.compile(r"0x[0-9a-fA-F]{4,19}", re.I),               2, "short_hex"),
]

ML_INVOKE_THRESHOLD = 4   #need this many soft-score points to call ML

#Adaptive ML threshold based on soft score
def _ml_threshold(soft_score: int) -> float:
    if soft_score >= 11:
        return 0.62
    if soft_score >= 7:
        return 0.72
    return 0.82   #soft_score 4–6: need strong ML confidence


def soft_score(payload: str) -> tuple:
    """
    Returns (total_score: int, triggered: list[str])
    """
    total = 0
    triggered = []
    for pattern, points, name in _SOFT_RULES:
        if pattern.search(payload):
            total += points
            triggered.append(name)
    return total, triggered



#TIER 3: ML GATE

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return -sum((c/total)*np.log2(c/total) for c in counts.values())


#Pre-compile feature extraction regexes
_FE_SQL_KW = re.compile(
    r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute|'
    r'cast|convert|declare|table|from|where|having|order|group|by|or|and|'
    r'not|null|sleep|benchmark|load_file|information_schema)\b', re.I)
_FE_SQL_CMT   = re.compile(r'(--|\/\*|\*\/|#)', re.M)
_FE_TAUT      = re.compile(r"('|\")?\s*(or|and)\s+\w+=\w+", re.I)
_FE_UNION_SEL = re.compile(r'union.{0,30}select', re.I | re.S)
_FE_SLEEP     = re.compile(r'sleep\s*\(\d+\)|benchmark\s*\(', re.I)
_FE_SCRIPT    = re.compile(r'<script', re.I)
_FE_HTMLEVT   = re.compile(r'on\w{2,15}\s*=', re.I)
_FE_DOTDOT    = re.compile(r'\.\.[/\\]')
_FE_PCT_TRAV  = re.compile(r'%2e%2e[%2f5c]', re.I)
_FE_SENS      = re.compile(r'(etc/passwd|etc/shadow|proc/self|boot\.ini)', re.I)
_FE_CMD_SEP   = re.compile(r'[;|&`]')
_FE_CMD_SUB   = re.compile(r'\$\([^)]+\)|`[^`]+`')
_FE_SHELL     = re.compile(
    r'\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)\b', re.I)
_FE_SHELLSHK  = re.compile(r'\(\)\s*\{')
_FE_JNDI      = re.compile(r'\$\{jndi:', re.I)
_FE_PCT       = re.compile(r'%[0-9a-fA-F]{2}')
_FE_HEX       = re.compile(r'0x[0-9a-fA-F]+', re.I)
_FE_SCANNER   = re.compile(r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)', re.I)
_FE_SPEC      = re.compile(r"[^a-zA-Z0-9\s]")

#v3 extra features (only used if model was trained with them)
_FE_SQL_NGRAMS = ['un', 'io', 'se', 'le', 'ct', 'fr', 'om', 'wh', 'er', 'dr', 'op']
_FE_SUSP_PATH  = re.compile(r'/(admin|config|backup|db|phpmyadmin|wp-admin|cgi-bin)(/|$|\?)', re.I)
_FE_SENS2      = re.compile(r'(etc/passwd|etc/shadow|proc/self|boot\.ini|\.htaccess|\.env|config\.php)', re.I)
_FE_DATA_URI   = re.compile(r'data\s*:\s*text/html', re.I)
_FE_CMD_SUB2   = re.compile(r'\$\([^)]+\)|`[^`]+`')
_FE_HEX2       = re.compile(r'0x[0-9a-fA-F]{2,}', re.I)


def extract_features(url: str, body: str, method: str, ua: str) -> dict:
    """
    Extract all security features from an HTTP request.
    Compatible with both v1 (47 features) and v3 (58 features) models.
    FEATURE_COLS loaded from JSON controls which features are used.
    """
    payload = url + " " + body
    pl      = payload.lower()
    plen    = max(len(payload), 1)

    f = {}

    #Length
    f["url_length"]     = len(url)
    f["body_length"]    = len(body)
    f["payload_length"] = len(payload)
    f["num_params"]     = url.count("=")
    f["num_url_params"] = len(re.findall(r'[?&][^=&]+=[^&]*', url))

    #Special chars
    f["count_single_quote"]  = payload.count("'")
    f["count_double_quote"]  = payload.count('"')
    f["count_semicolon"]     = payload.count(";")
    f["count_lt"]            = payload.count("<")
    f["count_gt"]            = payload.count(">")
    f["count_pipe"]          = payload.count("|")
    f["count_ampersand"]     = payload.count("&")
    f["count_dot"]           = payload.count(".")
    f["count_slash"]         = payload.count("/")
    f["count_backslash"]     = payload.count("\\")
    f["count_special"]       = len(_FE_SPEC.findall(payload))
    f["ratio_special"]       = f["count_special"] / plen
    f["ratio_alpha"]         = sum(c.isalpha() for c in payload) / plen
    f["ratio_digit"]         = sum(c.isdigit() for c in payload) / plen

    #SQL
    sql_matches              = _FE_SQL_KW.findall(pl)
    f["sql_keyword_count"]   = len(sql_matches)
    f["sql_keyword_density"] = len(sql_matches) / plen * 100
    f["has_sql_comment"]     = int(bool(_FE_SQL_CMT.search(payload)))
    f["has_tautology"]       = int(bool(_FE_TAUT.search(pl)))
    f["has_union_select"]    = int(bool(_FE_UNION_SEL.search(pl)))
    f["has_sleep"]           = int(bool(_FE_SLEEP.search(pl)))
    f["sqli_char_count"]     = payload.count("'") + payload.count('"') + payload.count(";")
    f["has_hex_escape"]      = int(bool(_FE_HEX2.search(pl)))

    #SQL n-gram detector (v3)
    letters = re.sub(r'[^a-z]', '', pl)
    ngram_hits = sum(1 for ng in _FE_SQL_NGRAMS if ng in letters)
    f["sql_ngram_hits"]    = ngram_hits
    f["sql_ngram_density"] = ngram_hits / max(len(letters), 1) * 100

    #XSS
    f["has_script_tag"]       = int(bool(_FE_SCRIPT.search(pl)))
    f["has_html_event"]       = int(bool(_FE_HTMLEVT.search(pl)))
    f["has_javascript_proto"] = int("javascript:" in pl)
    f["has_iframe"]           = int("<iframe" in pl)
    f["has_onerror"]          = int("onerror" in pl or "onload" in pl)
    f["html_tag_count"]       = len(re.findall(r'<[^>]+>', payload))
    f["has_data_uri"]         = int(bool(_FE_DATA_URI.search(pl)))

    #Path traversal
    f["has_path_traversal"]        = int(bool(_FE_DOTDOT.search(payload)))
    f["dotdot_count"]              = payload.count("..")
    f["has_etc_passwd"]            = int("etc/passwd" in pl or "etc\\passwd" in pl)
    f["has_win_system"]            = int("windows" in pl and "system32" in pl)
    f["percent_encoded_traversal"] = int(bool(_FE_PCT_TRAV.search(pl)))
    f["has_sensitive_file"]        = int(bool(_FE_SENS2.search(pl)))
    f["has_suspicious_path"]       = int(bool(_FE_SUSP_PATH.search(url.lower())))

    #CMD injection
    f["has_cmd_separator"]    = int(bool(_FE_CMD_SEP.search(payload)))
    f["has_cmd_substitution"] = int(bool(_FE_CMD_SUB2.search(payload)))
    f["has_shell_cmd"]        = int(bool(_FE_SHELL.search(pl)))
    f["has_backtick"]         = int("`" in payload)
    f["has_dollar_paren"]     = int("$(" in payload)

    #Header attacks
    f["has_shellshock"] = int(bool(_FE_SHELLSHK.search(payload)))
    f["has_jndi"]       = int(bool(_FE_JNDI.search(pl)))

    #Encoding
    f["pct_encoded_chars"]  = len(_FE_PCT.findall(payload))
    f["pct_encode_density"] = f["pct_encoded_chars"] / plen * 100
    f["hex_sequences"]      = len(_FE_HEX.findall(pl))
    f["entropy"]            = _entropy(payload)
    f["url_entropy"]        = _entropy(url)
    f["body_entropy"]       = _entropy(body)

    #Composite score (v3) — pre-computed for model
    f["composite_attack_score"] = (
        f["sql_keyword_count"]   * 3 +
        f["has_union_select"]    * 5 +
        f["has_tautology"]       * 5 +
        f["has_script_tag"]      * 4 +
        f["has_html_event"]      * 3 +
        f["has_path_traversal"]  * 4 +
        f["has_shell_cmd"]       * 3 +
        f["has_shellshock"]      * 5 +
        f["has_jndi"]            * 5 +
        f["sqli_char_count"]     * 1
    )

    #HTTP metadata
    f["is_post"]        = int(method.upper() == "POST")
    f["is_get"]         = int(method.upper() == "GET")
    f["has_scanner_ua"] = int(bool(_FE_SCANNER.search(ua.lower())))

    return f


@lru_cache(maxsize=8192)
def _ml_predict_cached(payload_key: str) -> float:
    """
    Cached ML prediction. Key is truncated payload string.
    Cache avoids recomputing for identical payloads (common in scanners).
    """
    #Re-extract features from payload key
    #We cache on the raw payload key, extract features fresh
    #(can't cache the full feature dict easily)
    
    feats  = extract_features(payload_key, "", "GET", "")
    vector = [feats.get(col, 0) for col in FEATURE_COLS]
    return float(_model.predict_proba([vector])[0][1])


def ml_gate(url: str, body: str, method: str, ua: str,
            soft_score_val: int) -> tuple:
    """
    Run ML model and apply adaptive threshold based on soft_score.
    Returns (is_attack: bool, proba: float)
    """
    if not ML_AVAILABLE or not FEATURE_COLS:
        #No model loaded: if we've reached tier 3, be conservative
        return soft_score_val >= 8, float(soft_score_val) / 15.0

    _stats["ml_invoked"] += 1
    threshold = _ml_threshold(soft_score_val)

    #Use full features for the actual prediction (not cached — different url/body/method)
    feats  = extract_features(url, body, method, ua)
    vector = [feats.get(col, 0) for col in FEATURE_COLS]
    proba  = float(_model.predict_proba([vector])[0][1])

    return proba >= threshold, proba



#Rate Limiting + Auto-Blacklist

def _rate_limited(ip: str) -> bool:
    now = time.time()
    _rate_track[ip] = [t for t in _rate_track[ip] if now - t < RATE_WIN]
    if len(_rate_track[ip]) >= RATE_MAX:
        return True
    _rate_track[ip].append(now)
    return False


def _is_banned(ip: str) -> bool:
    if ip in _blacklist:
        if time.time() < _blacklist[ip]:
            return True
        del _blacklist[ip]
        _hit_counts[ip] = 0
    return False


def _register_attack(ip: str):
    _hit_counts[ip] += 1
    if _hit_counts[ip] >= BAN_AFTER:
        _blacklist[ip] = time.time() + BAN_SECS
        logger.warning("AUTO-BANNED: %s (%d attacks)", ip, _hit_counts[ip])



#Threat Info Database

_THREAT_DB = {
    "sqli": (
        "SQL Injection",
        "Attacker attempting to manipulate database queries to access, modify, or destroy data.",
        ["Use parameterized queries (prepared statements) — never string-concatenate user input into SQL",
         "Apply input validation with strict allowlists for each field type",
         "Use an ORM (SQLAlchemy, Hibernate) instead of raw SQL",
         "Restrict DB user to minimum privileges (no DROP, no GRANT)",
         "Enable database query logging and alerting"]),
    "xss": (
        "Cross-Site Scripting (XSS)",
        "Malicious script injection targeting other users' browsers — can steal sessions, cookies, or credentials.",
        ["HTML-encode all user input before rendering (use templating engines' auto-escaping)",
         "Implement a strict Content-Security-Policy (CSP) header",
         "Set HttpOnly and Secure flags on all session cookies",
         "Validate input on both client and server side",
         "Use DOMPurify or similar library before inserting into DOM"]),
    "path_traversal": (
        "Path Traversal",
        "Attempt to access files outside the webroot — can expose /etc/passwd, config files, source code.",
        ["Canonicalize file paths and reject any containing '..'",
         "Use os.path.realpath() and validate the result starts with the allowed base directory",
         "Run the web server process as a non-root user with minimal file permissions",
         "Disable directory listing",
         "Never construct file paths directly from user input"]),
    "cmd_injection": (
        "Command Injection",
        "Attempting to execute OS commands on the server — highest severity, can lead to full system compromise.",
        ["Never pass user input to shell commands (subprocess, os.system, exec)",
         "If shell calls are necessary, use subprocess with a list (not string) and shell=False",
         "Whitelist allowed characters strictly",
         "Run the application in a container or chroot jail",
         "Apply the principle of least privilege — app should not run as root"]),
    "header_attack": (
        "Header Injection / Shellshock / Log4Shell",
        "Malicious payload in HTTP headers attempting to execute code via server-side vulnerabilities.",
        ["Update Bash immediately (CVE-2014-6271 Shellshock)",
         "Update Log4j to 2.17.1+ (CVE-2021-44228 Log4Shell)",
         "Validate and strip dangerous characters from all HTTP headers",
         "Disable unused CGI/FastCGI features",
         "Apply virtual patching rules in your WAF"]),
    "scanner": (
        "Automated Scanner / Attack Tool",
        "Automated vulnerability scanner or exploit framework detected.",
        ["Implement CAPTCHA or challenge-response for suspicious IPs",
         "Block the detected tool's User-Agent at the reverse proxy level",
         "Enable IP rate limiting and automatic banning",
         "Monitor for scanning patterns in your SIEM",
         "Review scan findings as they may indicate real vulnerabilities"]),
    "ssrf": (
        "Server-Side Request Forgery (SSRF)",
        "Attempting to make the server issue requests to internal services.",
        ["Validate and allowlist URLs before making any outbound requests",
         "Block requests to private IP ranges (127.x, 192.168.x, 10.x, 169.254.x)",
         "Use a dedicated egress proxy for all outbound HTTP",
         "Disable URL schemes you don't need (file://, gopher://, dict://)",
         "Apply network segmentation — web servers should not reach internal services directly"]),
    "special": (
        "Special Payload / Encoding Attack",
        "Unusual encoding, null bytes, or obfuscation techniques detected.",
        ["Normalize and decode all input before validation",
         "Reject null bytes and invalid encoding sequences",
         "Apply defense-in-depth — multiple validation layers",
         "Log and alert on unusual encoding patterns"]),
    "xxe": (
        "XML External Entity (XXE)",
        "Attempting to exploit XML parsers to read internal files or make SSRF requests.",
        ["Disable external entity processing in your XML parser",
         "Use a safe XML library (defusedxml in Python)",
         "Validate and sanitize all XML input",
         "Apply least-privilege to processes that parse XML"]),
    "rate_limit": (
        "Rate Limit Exceeded",
        "Too many requests from this IP address in a short time window.",
        ["This IP is being temporarily throttled",
         "Implement client-side exponential backoff",
         "If this is a legitimate API client, contact the administrator"]),
    "blacklist": (
        "Banned IP Address",
        "This IP has been automatically banned due to repeated attack attempts.",
        ["This IP has been blocked for 5 minutes due to multiple attack attempts",
         "Contact the administrator if you believe this is an error"]),
    "unknown": (
        "ML-Detected Anomaly",
        "Request pattern classified as anomalous by the ML engine.",
        ["Review this request pattern in your application logs",
         "Consider whether this endpoint expects this type of input",
         "Add specific regex rules if this attack type becomes frequent"]),
}


def _build_response(
    url: str, body: str, method: str, ua: str, ip: str,
    is_blocked: bool, rule: str, severity: str, category: str,
    proba: float, soft: int, tier: int, latency: float
) -> dict:
    t = _THREAT_DB.get(category, _THREAT_DB["unknown"])
    risk = min(100, int(max(proba, 0.95 if tier == 1 else 0) * 100))

    _stats["total"] += 1
    if is_blocked:
        _stats["blocked"] += 1
        _register_attack(ip)
    else:
        _stats["allowed"] += 1

    entry = {
        "id":              _stats["total"],
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":              ip,
        "method":          method,
        "url":             url,
        "payload":         (url + " " + body)[:400],
        "action":          "BLOCKED" if is_blocked else "ALLOWED",
        "status":          "danger" if is_blocked else "success",
        "risk_score":      risk,
        "attack_type":     t[0],
        "attack_category": category,
        "severity":        severity or ("Safe" if not is_blocked else "Medium"),
        "description":     t[1],
        "recommendations": t[2],
        "triggered_rule":  rule or ("ML Anomaly Detection" if tier == 3 else "Clean Request"),
        "ml_confidence":   round(proba * 100, 1),
        "soft_score":      soft,
        "detection_tier":  tier,
        "detection_source":("rule" if tier <= 2 else ("ml" if tier == 3 else "allow")),
        "latency_ms":      latency,
        "http_code":       403 if is_blocked else 200,
    }
    _log.append(entry)
    if len(_log) > 500:
        _log.pop(0)

    try:
        with open(_json_log, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    if is_blocked:
        logger.warning("BLOCKED [T%d] [%s] %s %s | %s | risk=%d",
                       tier, ip, method, url[:80], rule, risk)
    else:
        logger.info("ALLOWED [T%d] [%s] %s %s | soft=%d | ml=%.0f%%",
                    tier, ip, method, url[:80], soft, proba * 100)

    return entry



#Core Inspection Engine

def inspect(url: str, body: str, method: str, ua: str, ip: str) -> dict:
    """
    Main WAF inspection function.
    Runs through all tiers and returns a result dict.
    """
    t0 = time.perf_counter()

    #Pre-checks
    if _is_banned(ip):
        return _build_response(url, body, method, ua, ip,
                               True, "Banned IP", "Critical", "blacklist",
                               1.0, 0, 0, round((time.perf_counter()-t0)*1000, 2))

    if _rate_limited(ip):
        return _build_response(url, body, method, ua, ip,
                               True, "Rate Limit Exceeded", "Medium", "rate_limit",
                               0.85, 0, 0, round((time.perf_counter()-t0)*1000, 2))

    #Static assets: always safe
    if _is_static_asset(url):
        return _build_response(url, body, method, ua, ip,
                               False, "Static Asset", "Safe", "allow",
                               0.0, 0, 0, round((time.perf_counter()-t0)*1000, 2))

    #Build inspection payload
    #Analyze: URL path + query string + request body
    #Normalize: decode common percent-encoding to catch evasion
    inspection = (url + " " + body).strip()

    #TIER 0: Attack Surface Check
    surface = _compute_attack_surface(inspection)
    ua_hit  = bool(ua and _SCANNER_UA.search(ua))

    if surface == 0 and not ua_hit:
        #Zero attack-relevant characters → absolutely safe, skip everything
        return _build_response(url, body, method, ua, ip,
                               False, "Safe Pass (no attack surface)", "Safe", "allow",
                               0.0, 0, 0, round((time.perf_counter()-t0)*1000, 2))

    #TIER 1: Hard Block Rules
    blocked, rule, severity, category = hard_block(inspection, ua)
    if blocked:
        return _build_response(url, body, method, ua, ip,
                               True, rule, severity, category,
                               0.97, 0, 1, round((time.perf_counter()-t0)*1000, 2))

    #TIER 2: Soft Score
    score, soft_triggers = soft_score(inspection)

    if score < ML_INVOKE_THRESHOLD:
        #Not suspicious enough to invoke ML: allow
        return _build_response(url, body, method, ua, ip,
                               False, f"Low Suspicion (score={score})", "Safe", "allow",
                               float(score) / 15.0, score, 2,
                               round((time.perf_counter()-t0)*1000, 2))

    #TIER 3: ML Gate
    ml_blocked, proba = ml_gate(url, body, method, ua, score)

    return _build_response(url, body, method, ua, ip,
                           ml_blocked,
                           (f"ML + Soft({','.join(soft_triggers[:3])})" if ml_blocked
                            else f"ML Passed (p={proba:.2f})"),
                           "High" if ml_blocked else "Safe",
                           "unknown" if ml_blocked else "allow",
                           proba, score, 3,
                           round((time.perf_counter()-t0)*1000, 2))



#Dashboard Auth

def _require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != DASH_USER or auth.password != DASH_PASS:
            return Response("Login required", 401,
                            {"WWW-Authenticate": 'Basic realm="ShadowGuard"'})
        return f(*args, **kwargs)
    return decorated


#Routes: WAF API

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze a payload directly (used by demo page and test suite).
    Inspects ONLY the provided payload — not the routing URL of this endpoint.
    This is the correct behavior: the demo sends a test string, we analyze that string.
    """
    data   = request.json or {}
    #The test payload sent from the demo page
    raw    = data.get("payload", "").strip()
    url    = data.get("url", "/test")
    body   = data.get("body", raw)
    method = data.get("method", "GET")
    ua     = data.get("user_agent", request.headers.get("User-Agent", ""))
    ip     = request.remote_addr or "127.0.0.1"

    if not raw and not body:
        return jsonify({"error": "No payload provided"}), 400

    #For the analyze endpoint, use the raw payload as both url and body context
    #so inspection focuses on what was actually sent, not the routing metadata
    entry = inspect(url, body, method, ua, ip)
    return jsonify(entry), entry.get("http_code", 200)


@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/proxy/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def reverse_proxy(subpath=""):
    """
    Transparent reverse proxy with full WAF inspection.
    Analyzes the actual incoming request — URL, body, and headers.
    """
    url    = request.full_path
    body   = request.get_data(as_text=True) or ""
    method = request.method
    ua     = request.headers.get("User-Agent", "")
    ip     = (request.headers.get("X-Real-IP") or
              request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
              request.remote_addr or "127.0.0.1")

    #Include critical security-relevant headers in inspection
    #(catches Shellshock in User-Agent, Log4Shell in any header)
    headers_inspect = " ".join(
        f"{v}" for k, v in request.headers
        if k.lower() in {"user-agent", "referer", "x-forwarded-for",
                         "x-real-ip", "accept", "content-type", "authorization"}
    )
    full_inspection_url = url + " " + headers_inspect

    entry = inspect(full_inspection_url, body, method, ua, ip)

    if entry["action"] == "BLOCKED":
        return jsonify({
            "blocked":  True,
            "rule":     entry["triggered_rule"],
            "risk":     entry["risk_score"],
            "category": entry["attack_category"],
        }), 403

    #Forward clean request to target app
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
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        logger.error("Proxy forward error: %s", e)
        return jsonify({"error": "Target unreachable", "detail": str(e)}), 502



#Routes: Dashboard API

@app.route("/api/logs")
def api_logs():
    n = min(int(request.args.get("n", 50)), 200)
    return jsonify(_log[-n:][::-1])


@app.route("/api/stats")
def api_stats():
    total  = max(_stats["total"], 1)
    recent = _log[-100:]
    type_counts = Counter(e["attack_type"] for e in recent if e["action"] == "BLOCKED")
    tier_counts = Counter(e["detection_tier"] for e in recent)
    return jsonify({
        **_stats,
        "block_rate":      round(_stats["blocked"] / total * 100, 1),
        "top_attack_types": dict(type_counts.most_common(5)),
        "tier_breakdown":  dict(tier_counts),
        "blacklisted_ips": len(_blacklist),
        "ml_invoke_rate":  round(_stats["ml_invoked"] / total * 100, 1),
        "model_info": {
            "name":      _train_report.get("best_model", "Unknown"),
            "f1":        _train_report.get("final_metrics", {}).get("f1", 0),
            "loaded":    ML_AVAILABLE,
            "features":  len(FEATURE_COLS),
            "threshold_adaptive": f"{_ml_threshold(4):.0%}–{_ml_threshold(11):.0%}",
        },
    })


@app.route("/api/health")
def api_health():
    return jsonify({
        "status":       "operational",
        "ml_loaded":    ML_AVAILABLE,
        "features":     len(FEATURE_COLS),
        "logs_stored":  len(_log),
        "banned_ips":   len(_blacklist),
        "timestamp":    datetime.now().isoformat(),
        "architecture": {
            "tier_0": "Safe Pass (no attack surface) — no regex, no ML",
            "tier_1": f"Hard Block ({len(_HARD_RULES)} rules) — no ML",
            "tier_2": f"Soft Score ({len(_SOFT_RULES)} indicators, threshold={ML_INVOKE_THRESHOLD})",
            "tier_3": "ML Gate (adaptive threshold 62%–82%)",
        },
    })


@app.route("/api/blacklist")
def api_blacklist():
    now = time.time()
    return jsonify({ip: round(ts - now) for ip, ts in _blacklist.items() if ts > now})


@app.route("/api/blacklist/<ip>", methods=["DELETE"])
def api_unban(ip):
    if ip in _blacklist:
        del _blacklist[ip]
        _hit_counts[ip] = 0
        return jsonify({"unbanned": ip})
    return jsonify({"error": "IP not in blacklist"}), 404


@app.route("/api/model_stats")
def api_model_stats():
    recent_proba = [e["ml_confidence"] / 100 for e in _log[-200:] if e["detection_tier"] == 3]
    avg_conf = sum(recent_proba) / max(len(recent_proba), 1)
    return jsonify({
        "ml_available":        ML_AVAILABLE,
        "avg_ml_confidence":   round(avg_conf, 4),
        "ml_invocations":      _stats["ml_invoked"],
        "total_requests":      _stats["total"],
        "ml_invoke_rate_pct":  round(_stats["ml_invoked"] / max(_stats["total"], 1) * 100, 1),
        "cache_info":          str(_ml_predict_cached.cache_info()),
        "note": "ML is called only for ambiguous requests (soft_score >= {})".format(ML_INVOKE_THRESHOLD),
    })



#Routes:Frontend

@app.route("/")
@app.route("/demo")
def demo():
    return render_template("demo.html")


@app.route("/dashboard")
@_require_auth
def dashboard():
    return render_template("dashboard.html")



#Startup

if __name__ == "__main__":
    
    print("Shadowguard Starting...")
    
    #print(f"  Architecture : Three-Tier (Safe→Hard Block→Soft→ML)")
    print(f"  Hard rules   : {len(_HARD_RULES)} patterns")
    print(f"  Soft rules   : {len(_SOFT_RULES)} indicators")
    print(f"  ML available : {ML_AVAILABLE}")
    if ML_AVAILABLE:
        print(f"  ML features  : {len(FEATURE_COLS)}")
        print(f"  ML threshold : 62%–82% adaptive")
        print(f"  ML invoked   : only when soft_score ≥ {ML_INVOKE_THRESHOLD}")
    print(f"  Dashboard    : http://0.0.0.0:5000/dashboard  [{DASH_USER}/****]")
    print(f"  Demo         : http://0.0.0.0:5000/demo")
    print(f"  Target app   : {TARGET_APP_URL}")
   
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)