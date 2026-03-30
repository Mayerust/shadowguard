# ShadowGuard — ML-Powered Web Application Firewall

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![Nginx](https://img.shields.io/badge/Nginx-Reverse%20Proxy-009639?style=flat-square&logo=nginx)
![ML](https://img.shields.io/badge/Random%20Forest-F1%200.88-success?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**A production-grade, hybrid Machine Learning Web Application Firewall**
built from scratch, trained on the CSIC 2010 HTTP dataset,
deployed as a Docker reverse proxy, with a real-time threat dashboard.

[Architecture](#architecture) · [Features](#features) · [Quick Start](#quick-start) · [API](#api-reference) · [LAN Testing](#lan-testing) · [Metrics](#model-performance)

</div>

---

## What Is This

ShadowGuard is a Web Application Firewall (WAF) that combines **deterministic rule-based detection** with **machine learning anomaly detection** to identify and block common web attacks in real time.

Unlike commercial WAFs that are black boxes, ShadowGuard is built from first principles — every design decision is documented and every component is reproducible.

**Attacks it detects:**
SQL Injection (Union, Boolean Blind, Time-Based) · Cross-Site Scripting (Reflected, Stored, DOM) · Path Traversal · Command Injection · Shellshock · Log4Shell · XXE · SSRF · Null Byte Injection · Automated Scanner Traffic

---

## Architecture

Traffic flows through a **four-tier inspection pipeline**. Each tier only invokes the next when it cannot make a confident decision — clean requests exit early without touching the ML model.

```
Client Request
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Nginx (Port 80)                                    │
│  Rate limiting · Security headers · SSL termination │
└───────────────────────┬─────────────────────────────┘
                        │ proxy_pass
                        ▼
┌─────────────────────────────────────────────────────┐
│  ShadowGuard WAF (Port 5000)                        │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  TIER 0 — Safe Pass          < 1ms           │   │
│  │  Zero attack-surface chars → ALLOW           │   │
│  │  ~85% of legitimate traffic exits here       │   │
│  └──────────────────┬───────────────────────────┘   │
│                     │ if any attack chars present   │
│  ┌──────────────────▼───────────────────────────┐   │
│  │  TIER 1 — Hard Block         < 3ms           │   │
│  │  25 precision regex rules (OWASP-based)      │   │
│  │  Blocks 90%+ of real attacks here            │   │
│  └──────────────────┬───────────────────────────┘   │
│                     │ if no hard rule triggered     │
│  ┌──────────────────▼───────────────────────────┐   │
│  │  TIER 2 — Soft Score         < 4ms           │   │
│  │  18 indicators accumulate suspicion points   │   │
│  │  Score < 4 → ALLOW (no ML needed)            │   │
│  └──────────────────┬───────────────────────────┘   │
│                     │ if soft_score ≥ 4             │
│  ┌──────────────────▼───────────────────────────┐   │
│  │  TIER 3 — ML Gate            < 20ms          │   │
│  │  Random Forest (58 features, F1=0.88)        │   │
│  │  Adaptive threshold: 62%–82%                 │   │
│  │  Handles ambiguous/obfuscated payloads        │  │
│  └──────────────────┬───────────────────────────┘   │
│                     │ if ALLOWED                    │
└─────────────────────┼───────────────────────────────┘
                      ▼
             Target Application (Port 8080)
```

**Why this design prevents false positives on safe traffic:**
The ML model is only invoked when a request scores ≥ 4 suspicion points across multiple weak indicators. A clean search query like `q=python+tutorial` has zero attack-surface characters and exits at Tier 0 without ever touching regex or ML.

---

## Features

### Detection Engine
- **Hybrid architecture**: Deterministic rules handle known patterns; ML handles novel, obfuscated, and zero-day variants
- **Four-tier pipeline**: Safe Pass → Hard Block → Soft Score → ML Gate
- **Adaptive ML threshold**: Confidence requirement adjusts based on how many soft indicators fired (62%–82%)
- **LRU cache**: Repeated identical payloads (common in automated scans) are cached and don't re-invoke the model

### Machine Learning Core
- Trained on **HTTP CSIC 2010** dataset (real e-commerce HTTP traffic, labelled attacks)
- **58 security-specific features**: Shannon entropy, SQL keyword density, n-gram SQL fragments, composite attack score, encoding anomaly detection, and more
- **Random Forest** classifier (best F1 across 5-model comparison)
- **5-fold stratified cross-validation** + GridSearchCV hyperparameter tuning
- F1 Score: **0.88** · AUC-ROC: **0.94** · Recall: **0.91** (catches 91% of attacks)

### Operational Features
- **Auto IP blacklisting**: IPs that trigger 5+ attacks are banned for 5 minutes
- **Rate limiting**: 30 requests / 10 seconds per IP → HTTP 429
- **Structured JSON logging** (`logs/events.ndjson`) — ready for Splunk/ELK SIEM ingestion
- **Real-time dashboard** with live request feed, attack type breakdown, tier statistics
- **Dashboard HTTP Basic Auth** (configurable via environment variables)
- **Reverse proxy mode**: Sits transparently in front of any web application

### Deployment
- **Full Docker Compose stack**: Nginx + ShadowGuard + Target App in one command
- **Container security hardening**: Non-root user, capabilities dropped, no-new-privileges
- **LAN-ready**: Accessible to any device on the same network after `docker-compose up`

---

## Model Performance

Trained on CSIC 2010 HTTP dataset (10,000 normal + 10,000 attack samples, balanced).

| Metric | Score |
|--------|-------|
| F1 Score | **0.88** |
| AUC-ROC | **0.94** |
| Recall (attack detection rate) | **0.91** |
| Precision | **0.86** |
| False Positive Rate | ~9% (safe requests wrongly flagged by ML alone) |

> **Note on FPR**: The 9% ML false positive rate applies only to requests that reach Tier 3. Because Tiers 0–2 filter out ~95% of clean traffic before ML is invoked, the *effective* false positive rate on real traffic is well under 1%.

**Top features by importance:**
1. `composite_attack_score` — hand-engineered combination of all attack signals
2. `sql_keyword_density` — SQL keywords per character (catches buried injections)
3. `entropy` / `url_entropy` — randomness indicating obfuscation
4. `sql_ngram_hits` — n-gram fragments catching `UN/**/ION SE/**/LECT` variants
5. `has_union_select`, `has_tautology` — structural SQL attack indicators

---

## Quick Start

### Prerequisites
- Python 3.10+
- Docker + Docker Compose (for production deployment)
- Git

### Option A — Docker (Recommended, LAN-ready)

```bash
# 1. Clone repository
git clone https://github.com/Mayerust/ShadowGuard.git
cd ShadowGuard

# 2. Train the model first (required before Docker build)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python 01_prepare_dataset.py
python 02_train_model.py
# This creates models/ — needed by the WAF container

# 3. Launch full stack (Nginx → WAF → Target App)
docker-compose up --build

# 4. Open in browser
# Dashboard: http://localhost/dashboard  (admin / admin)
# Demo:      http://localhost/demo
# LAN:       http://YOUR_LAN_IP/dashboard
```

### Option B — Dev Mode (no Docker)

```bash
# Terminal 1
python target_app.py       # Vulnerable app on :8080

# Terminal 2
python app.py              # WAF on :5000

# Open: http://localhost:5000/demo
```

### Environment Variables

```bash
# Copy and edit
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_APP_URL` | `http://localhost:8080` | URL of the app being protected |
| `DASH_USER` | `admin` | Dashboard username |
| `DASH_PASS` | `admin` | Dashboard password |

---

## Training Your Own Model

The training pipeline is fully reproducible. Run these in order:

```bash
# Step 1 — Prepare dataset
# Downloads CSIC 2010 or uses synthetic fallback if files missing
python 01_prepare_dataset.py

# Step 2 — Train and evaluate
# Compares 5 models, runs 5-fold CV, tunes winner, saves .pkl
python 02_train_model.py

# Output:
# models/shadowguard_model.pkl    ← serialized model (not in repo)
# models/feature_columns.json    ← feature list (not in repo)
# models/training_report.json    ← metrics + confusion matrix
# models/training_report.png     ← charts
```

**Dataset source (CSIC 2010):**
```bash
# Option A — Official
wget http://www.isi.csic.es/dataset/http_dataset_csic_2010.zip
unzip http_dataset_csic_2010.zip -d data/raw/

# Option B — Kaggle mirror
kaggle datasets download -d kukurupupu/http-csic-2010-http-dataset
unzip *.zip -d data/raw/

# If neither works: 01_prepare_dataset.py auto-generates synthetic data
```

---

## API Reference

All endpoints available at `http://localhost:5000`.

### `POST /api/analyze`
Analyze a payload string through the full WAF pipeline.

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload": "'\'' OR '\''1'\''='\''1", "url": "/login", "method": "POST"}'
```

**Response:**
```json
{
  "action": "BLOCKED",
  "attack_type": "SQL Injection",
  "attack_category": "sqli",
  "severity": "Critical",
  "risk_score": 97,
  "detection_tier": 1,
  "triggered_rule": "SQLi – Tautology (quote)",
  "ml_confidence": 0.0,
  "soft_score": 0,
  "latency_ms": 1.2,
  "recommendations": ["Use parameterized queries...", "..."]
}
```

### `GET /api/stats`
Live statistics — block rate, top attack types, ML invoke rate, tier breakdown.

### `GET /api/logs?n=50`
Last N request logs in reverse chronological order.

### `GET /api/health`
WAF health check — model status, architecture description, banned IP count.

### `GET /api/model_stats`
ML-specific metrics — invocation rate, average confidence, cache statistics.

---

## LAN Testing

See **[GUIDE.md](GUIDE.md)** for the complete step-by-step LAN attack testing walkthrough, including:
- Direct LAN cable connection setup (no router needed)
- Static IP configuration on Windows and Kali Linux
- Running the attack test suite from the attacker machine
- Using sqlmap, Nikto, and Burp Suite against a live WAF
- Interpreting dashboard results in real time

```bash
# From attacker machine (Machine B)
python lan_attack_test.py --target 192.168.1.1 --port 80 --mode full
```

---

## Project Structure

```
ShadowGuard/
├── 01_prepare_dataset.py   ← Feature engineering + SMOTE pipeline
├── 02_train_model.py       ← Model training, CV, tuning
├── lan_attack_test.py      ← LAN attack test suite
├── Dockerfile              ← Container build (non-root, hardened)
├── docker-compose.yml      ← Full stack: Nginx + WAF + Target
├── nginx/nginx.conf        ← Reverse proxy + security headers
├── requirements.txt        ← Python dependencies
├── README.md               ← This file
├── GUIDE.md                ← LAN testing walkthrough
├── .env.example            ← Environment variable template
│
├── templates/              ← HTML frontend
│   ├── dashboard.html      ← Live threat dashboard
│   └── demo.html           ← Interactive WAF demo
│
├── models/                 ← NOT in repo (trained locally)
│   ├── shadowguard_model.pkl
│   ├── feature_columns.json
│   └── training_report.json
│
├── data/                   ← NOT in repo (dataset files)
│   ├── raw/                ← CSIC 2010 .txt files
│   └── processed/          ← Generated CSVs
│
└── logs/                   ← NOT in repo (runtime logs)
    ├── shadowguard.log
    └── events.ndjson       ← SIEM-ready structured log
```

> **Security note**: `app.py` and `target_app.py` are intentionally excluded from this repository. The WAF's detection logic — regex patterns, soft-score thresholds, and feature extraction — would assist adversaries in crafting bypass payloads if published. The training pipeline, architecture, and all infrastructure code are fully open.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Ingress | Nginx | Reverse proxy, rate limiting, SSL termination |
| WAF Engine | Python + Flask | Request inspection pipeline |
| ML Model | Scikit-learn (Random Forest) | Anomaly detection |
| Feature Engineering | NumPy + Regex | 58 security features from raw HTTP |
| Dataset | CSIC 2010 HTTP | Labelled web attack traffic |
| Balancing | imbalanced-learn (SMOTE) | Handles class imbalance |
| Containerization | Docker Compose | Reproducible deployment |
| Dashboard | Vanilla JS + Chart.js | Real-time visualization |

---

## Limitations & Future Work

- **Dataset scope**: Trained on CSIC 2010 (2010-era e-commerce traffic). Novel attack patterns introduced after this date may not be in the training distribution.
- **HTTPS inspection**: Currently performs SSL termination at Nginx. Deep inspection of encrypted body requires the WAF to hold the server's private key.
- **No model retraining pipeline**: Active learning / feedback loop from dashboard false-positive reports is not yet implemented.
- **IPv6**: Rate limiting and blacklisting operate on IPv4 only.

**Planned:**
- [ ] LSTM-based sequence model for detecting slow/distributed attacks
- [ ] IP reputation feed integration (AbuseIPDB)
- [ ] Prometheus metrics endpoint for Grafana dashboards
- [ ] Active learning: admin-labelled false positives retrain the model


---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built as part of the <strong>#100DaysOfCode</strong> challenge · Days 1–100<br>
<a href="https://www.linkedin.com/in/mayerust/">#CyberSecurity</a> · <a href="https://www.linkedin.com/in/mayerust/">#MachineLearning</a> · <a href="https://www.linkedin.com/in/mayerust/">#DevSecOps</a>
</div>
