# ShadowGuard: Complete End-to-End Setup Guide
## From zero to deployed WAF with LAN attack testing

## TABLE OF CONTENTS
1. Prerequisites & System Setup
2. Project Directory Setup
3. Dataset Downloads
4. Python Environment
5. Run the Training Pipeline
6. Run the WAF (Dev Mode)
7. Docker Deployment (Production)
8. LAN Attack Testing
9. GitHub Push
10. Troubleshooting

## PART 1: PREREQUISITES

### On Kali Linux / Debian Distros

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Core tools
sudo apt install -y \
  python3 python3-pip python3-venv \
  git curl wget unzip \
  docker.io docker-compose \
  net-tools iproute2 \
  sqlmap nikto \
  build-essential libssl-dev libffi-dev python3-dev

# Start Docker daemon
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
# LOG OUT AND BACK IN after this, then verify:
docker ps

# Verify Python
python3 --version   # Need 3.9+
pip3 --version
git --version
```

### On Windows 10/11

```powershell
# Run PowerShell as Administrator

# 1. Install Chocolatey (Windows package manager)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install core tools via Chocolatey
choco install -y python git curl wget 7zip docker-desktop

# 3. Restart PowerShell then verify
python --version      # Need 3.9+
git --version
pip --version

# 4. Add Python to PATH (if not already)
# Search "Environment Variables" in Start Menu
# Add C:\Users\<you>\AppData\Local\Programs\Python\Python311\ to PATH
# Add C:\Users\<you>\AppData\Local\Programs\Python\Python311\Scripts\ to PATH

# 5. Docker Desktop — start it from the Start Menu
# Enable WSL2 backend when prompted
```

## PART 2: PROJECT DIRECTORY SETUP [agar clone krliya ho toh skip this]

### Kali Linux

```bash
# Create project tree
mkdir -p ~/shadowguard/{data/{raw,cic_ids,processed},models,logs,nginx,templates}
cd ~/shadowguard

# Verify structure
ls -R ~/shadowguard
```

### Windows (PowerShell)

```powershell
# Create project tree
$base = "$env:USERPROFILE\shadowguard"
New-Item -ItemType Directory -Force -Path @(
  "$base\data\raw", "$base\data\cic_ids", "$base\data\processed",
  "$base\models", "$base\logs", "$base\nginx", "$base\templates"
)
cd $base
```

## PART 3: DATASET DOWNLOADS [Final day pull mein no need]

### Dataset 1: CSIC 2010 (REQUIRED)

#### Kali Linux

```bash
cd ~/shadowguard/data/raw

# Method A: Official (may be slow)
wget http://www.isi.csic.es/dataset/http_dataset_csic_2010.zip
unzip http_dataset_csic_2010.zip

# Method B: If official is down, use backup Git mirror
git clone https://github.com/Minyus/CSIC2010-http-dataset .
# OR
pip3 install kaggle
kaggle datasets download -d kukurupupu/http-csic-2010-http-dataset
unzip http-csic-2010-http-dataset.zip

# Verify files exist
ls data/raw/
# Should see: normalTrafficTraining.txt  normalTrafficTest.txt  anomalousTrafficTest.txt
```

#### Windows (PowerShell)

```powershell
cd "$env:USERPROFILE\shadowguard\data\raw"

# Download (Method A)
Invoke-WebRequest -Uri "http://www.isi.csic.es/dataset/http_dataset_csic_2010.zip" -OutFile "csic.zip"
Expand-Archive csic.zip -DestinationPath .

# Method B: via kaggle CLI
pip install kaggle
# Place kaggle.json in C:\Users\<you>\.kaggle\
kaggle datasets download -d kukurupupu/http-csic-2010-http-dataset
Expand-Archive http-csic-2010-http-dataset.zip -DestinationPath .

# Verify
Get-ChildItem
```

---

### Dataset 2: CIC-IDS-2017 (adds realism)

**NOTE:** Download ONLY `MachineLearningCSV.zip` — the full PCAP version is 50GB+.

#### Kali Linux

```bash
# Go to https://www.unb.ca/cic/datasets/ids-2017.html
# Click "Download Data"  →  Download "MachineLearningCSV.zip"
# Then:
mv ~/Downloads/MachineLearningCSV.zip ~/shadowguard/data/cic_ids/
cd ~/shadowguard/data/cic_ids/
unzip MachineLearningCSV.zip

# You should see CSV files like:
# Tuesday-WorkingHours.pcap_ISCX.csv
# Wednesday-workingHours.pcap_ISCX.csv  etc.
ls data/cic_ids/
```

#### Windows (PowerShell)

```powershell
# Manual download from browser:
# https://www.unb.ca/cic/datasets/ids-2017.html
# Save MachineLearningCSV.zip to Downloads

Move-Item "$env:USERPROFILE\Downloads\MachineLearningCSV.zip" `
          "$env:USERPROFILE\shadowguard\data\cic_ids\"
cd "$env:USERPROFILE\shadowguard\data\cic_ids"
Expand-Archive MachineLearningCSV.zip -DestinationPath .
```

---

### Dataset 3: Quick Backup (if above fail) [No Need Specifically]

#### Kali Linux

```bash
cd ~/shadowguard/data/raw
wget https://raw.githubusercontent.com/shreyagopal/Injection-Attacks-Dataset/master/sql_injection.csv
wget https://raw.githubusercontent.com/shreyagopal/XSS-Dataset/master/xss_dataset.csv
```

#### Windows (PowerShell)

```powershell
cd "$env:USERPROFILE\shadowguard\data\raw"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shreyagopal/Injection-Attacks-Dataset/master/sql_injection.csv" -OutFile "sql_injection.csv"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shreyagopal/XSS-Dataset/master/xss_dataset.csv" -OutFile "xss_dataset.csv"
```


## PART 4: PYTHON ENVIRONMENT

### Kali Linux

```bash
cd ~/shadowguard

# Create virtual environment
python3 -m venv venv

# Activate
source venv/bin/activate
# Prompt should show: (venv) user@kali:~/shadowguard$

# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt

# Verify key packages
python3 -c "
import sklearn, xgboost, flask, imblearn, pandas, numpy, joblib
print('All packages OK')
print('Scikit-learn:', sklearn.__version__)
print('XGBoost:', xgboost.__version__)
print('Flask:', flask.__version__)
"
```

### Windows (PowerShell)

```powershell
cd "$env:USERPROFILE\shadowguard"

# Create virtual environment
python -m venv venv

# Activate
.\venv\Scripts\Activate.ps1
# If execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1

# Prompt should show: (venv) PS C:\Users\...>

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Verify
python -c "import sklearn, xgboost, flask, imblearn; print('All OK')"
```

**requirements.txt** (place in project root):
```
flask==3.0.3
flask-cors==4.0.0
gunicorn==22.0.0
pandas==2.2.2
numpy==1.26.4
scikit-learn==1.5.1
xgboost==2.0.3
imbalanced-learn==0.12.3
joblib==1.4.2
matplotlib==3.9.0
seaborn==0.13.2
requests==2.32.3
werkzeug==3.0.3
geoip2==4.8.0
```


## PART 5:TRAINING PIPELINE [Final Day Pull - no need]

### Step 5A: Prepare Dataset (both OS same commands)

```bash
# Kali: make sure venv is active
source venv/bin/activate   # Kali
# or: .\venv\Scripts\Activate.ps1    # Windows

# Run dataset prep
python 01_prepare_dataset.py

# Expected output:
#   CSIC  →  36,000 records (if files present)
#   Synth →   3,940 records
#   CIC   →   5,000 records (if files present)
#   MERGED total: ~44,940
#   47 features extracted
#   After SMOTE: balanced dataset saved
```

### Step 5B: Train Model

```bash
python 02_train_model.py

# Expected output (approx):
#   Logistic Regression  F1=0.9210
#   Naive Bayes          F1=0.8940
#   SVM (RBF)            F1=0.9430
#   Random Forest        F1=0.9731  ← WINNER
#   XGBoost              F1=0.9698
#
#   Winner: Random Forest
#   Final F1:    0.9731
#   AUC-ROC:     0.9904
#   Threshold:   0.60
#   Top feature: entropy, sql_keyword_count, count_single_quote...

# Check output files
ls models/
#   shadowguard_model.pkl
#   attack_type_model.pkl
#   label_encoder.pkl
#   feature_columns.json
#   training_report.json
#   training_report.png
```

**Windows note:** replace `ls` with `dir models\`

---

## PART 6: RUN THE WAF (DEV MODE)

### Terminal 1: Start Target App

```bash
# Kali
source venv/bin/activate
python target_app.py
# Listens on http://0.0.0.0:8080

# Windows
.\venv\Scripts\Activate.ps1
python target_app.py
```

### Terminal 2: Start ShadowGuard WAF

```bash
# Kali
source venv/bin/activate
python app.py

# Windows
.\venv\Scripts\Activate.ps1
python app.py

# Open in browser:
#   http://localhost:5000/dashboard   (login: admin / admin)
#   http://localhost:5000/demo
#   http://localhost:5000/api/health
```

### Quick smoke test

```bash
# Test from a third terminal (Kali)
# SQLi — should be BLOCKED (403)
curl -s -w "\nHTTP %{http_code}\n" \
  -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload":"'\'' OR '\''1'\''='\''1"}'

# Safe — should be ALLOWED (200)
curl -s -w "\nHTTP %{http_code}\n" \
  -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload":"search=laptop&page=1"}'

# Windows PowerShell equivalent
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/analyze" `
  -ContentType "application/json" `
  -Body '{"payload":"search=laptop"}' | ConvertTo-Json
```

---

## PART 7: DOCKER DEPLOYMENT

### Step 7A: Build & Run

```bash
# Kali
cd ~/shadowguard

# Build and start the full stack
docker-compose up --build

# In background (production)
docker-compose up --build -d

# Watch logs
docker-compose logs -f shadowguard

# Check running containers
docker-compose ps
```

### Windows (PowerShell — Docker Desktop must be running)

```powershell
cd "$env:USERPROFILE\shadowguard"
docker-compose up --build
# OR background:
docker-compose up --build -d
docker-compose logs -f shadowguard
```

### Step 7B: Get Your LAN IP

```bash
# Kali / Linux
ip addr show | grep "inet " | grep -v 127.0.0.1
# Example: inet 192.168.1.105/24 brd 192.168.1.255 scope global wlan0

# Windows PowerShell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} | Select IPAddress
```

### Step 7C: Access from LAN

```
# From any device on the same WiFi/LAN:
Dashboard:  http://192.168.1.105/dashboard   (admin / admin)
Demo:       http://192.168.1.105/demo
API:        http://192.168.1.105/api/health
```

### Stop / Remove containers

```bash
docker-compose down           # stop
docker-compose down -v        # stop + remove volumes
docker system prune -f        # clean unused images
```

---

## PART 8: LAN ATTACK TESTING

### Machine A (WAF Host): already running docker-compose

### Machine B (Attacker): any machine on same WiFi

#### Setup on Machine B (Kali)

```bash
# Install sqlmap + nikto (already on Kali)
sudo apt install -y sqlmap nikto curl python3-requests

# Get the WAF machine's IP (from Machine A)
# e.g. 192.168.1.105
```

#### Test 1 — Automated Test Suite

```bash
# Copy lan_attack_test.py to Machine B
# Then run:
python3 lan_attack_test.py --target 192.168.1.105 --port 80

# Expected output:
#   ✓ SQLi — Union Select  → BLOCKED (HTTP 403)  ✓ PASS
#   ✓ XSS — Script Tag     → BLOCKED (HTTP 403)  ✓ PASS
#   ✓ Safe — Normal search → ALLOWED (HTTP 200)  ✓ PASS
#   ...
#   Detection Rate: 95.7%
```

#### Test 2: SQLMap (Real Attack Tool)

```bash
# Attack WITHOUT WAF (direct to port 8080 — will succeed)
sqlmap -u "http://192.168.1.105:8080/search?q=test" --dbs --batch --level=3
# You'll see DB dumped!

# Attack WITH WAF (port 80 — should block)
sqlmap -u "http://192.168.1.105/search?q=test" --dbs --batch --level=3
# WAF should return 403 for all injection attempts
```

#### Test 3: Nikto Scanner

```bash
# Through WAF (port 80)
nikto -h http://192.168.1.105 -port 80 -maxtime 60s
# Dashboard should show "Scanner Fingerprint" detections
```

#### Test 4: Manual curl Attacks

```bash
WAF="http://192.168.1.105"

echo "=== SQL Injection ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$WAF/search?q=' OR '1'='1"

echo "=== XSS ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$WAF/search?q=<script>alert(1)</script>"

echo "=== Path Traversal ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$WAF/file?path=../../etc/passwd"

echo "=== Shellshock ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "User-Agent: () { :; }; echo test" "$WAF/"

echo "=== Safe Request ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$WAF/search?q=laptop"
```

#### Test 5: Rate Limit + Blacklist

```bash
# Spam 50 requests fast — should trigger 429 then blacklist
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " "$WAF/search?q=test"
done
echo ""
# First 30: 200, then: 429, eventually: 403 (blacklisted)

# Check blacklist via API
curl http://192.168.1.105/api/blacklist

# Check model drift
curl http://192.168.1.105/api/model_stats
```

#### Windows (PowerShell) equivalents

```powershell
$WAF = "http://192.168.1.105"

# SQLi test
(Invoke-WebRequest -Uri "$WAF/search?q=' OR '1'='1" -SkipHttpErrorCheck).StatusCode

# XSS test
(Invoke-WebRequest -Uri "$WAF/search?q=<script>alert(1)</script>" -SkipHttpErrorCheck).StatusCode

# Safe request
(Invoke-WebRequest -Uri "$WAF/search?q=laptop").StatusCode

# Rate limit test
1..40 | ForEach-Object { (Invoke-WebRequest -Uri "$WAF/search?q=test" -SkipHttpErrorCheck).StatusCode }
```

---

## PART 9: GITHUB PUSH

### Initial Setup

```bash
# Kali / Windows Git Bash
cd ~/shadowguard

# Init repository
git init
git config user.name "Your Name"
git config user.email "your@email.com"
```

### Create .gitignore

```bash
cat > .gitignore << 'EOF'
venv/
__pycache__/
*.pyc
*.pyo
*.pkl
*.ndjson
*.log
data/raw/
data/cic_ids/
data/processed/
logs/
.env
GeoLite2-City.mmdb
models/training_report.png
EOF
```

**NOTE:** Don't push the `.pkl` model files publicly if they are large.
Instead, push the training scripts so anyone can reproduce the model.
If you want to share the model, use Git LFS:

```bash
# Install Git LFS (optional, for pushing model files)
sudo apt install git-lfs    # Kali
git lfs install
git lfs track "*.pkl"
git add .gitattributes
```

### Create Repository on GitHub

```bash
# Go to https://github.com/new
# Name: ShadowGuard
# Description: ML-powered Web Application Firewall | OWASP + Random Forest hybrid
# Public
# DO NOT initialize with README (we have one)
```

### Push to GitHub

```bash
cd ~/shadowguard

# Stage everything
git add .

# First commit
git commit -m "Initial commit: ShadowGuard Enhanacement ML-WAF

- Merged dataset pipeline: CSIC 2010 + CIC-IDS-2017 + Synthetic
- 47-feature engineering (entropy, SQL keywords, XSS patterns)
- 5-model comparison + GridSearchCV tuning (RF F1=0.97)
- Hybrid detection: OWASP regex + ML Random Forest
- 10 WAF enhancements: rate limiting, blacklisting, caching, GeoIP
- Docker Compose deployment: Nginx → WAF → Target App
- LAN attack test suite"

# Link to GitHub
git remote add origin https://github.com/YOUR_USERNAME/ShadowGuard.git
git branch -M main
git push -u origin main
```

### Windows (PowerShell)

```powershell
cd "$env:USERPROFILE\shadowguard"
git init
git config user.name "Your Name"
git config user.email "your@email.com"

# Create .gitignore
@"
venv/
__pycache__/
*.pkl
data/raw/
data/cic_ids/
data/processed/
logs/
.env
"@ | Out-File .gitignore -Encoding UTF8

git add .
git commit -m "Initial commit: ShadowGuard v2"
git remote add origin https://github.com/YOUR_USERNAME/ShadowGuard.git
git branch -M main
git push -u origin main
```

### Future commits (daily push workflow)

```bash
# After making changes each day:
git add .
git commit -m "Day 42: Add SMOTE balancing + feature importance analysis"
git push
```

---

## PART 10 — TROUBLESHOOTING

### "Model not found" error

```bash
# Always run scripts in order:
python 01_prepare_dataset.py
python 02_train_model.py
python app.py              # only after models/ folder has .pkl files
```

### Port already in use

```bash
# Kali
sudo lsof -ti:5000 | xargs kill -9
sudo lsof -ti:8080 | xargs kill -9

# Windows PowerShell
netstat -ano | findstr :5000
taskkill /PID <PID_NUMBER> /F
```

### Docker "permission denied"

```bash
sudo usermod -aG docker $USER
newgrp docker
# or simply: sudo docker-compose up --build
```

### "Can't connect to WAF from LAN"

```bash
# Check firewall (Kali)
sudo ufw status
sudo ufw allow 80/tcp
sudo ufw allow 5000/tcp

# Or disable firewall for lab testing
sudo ufw disable

# Check Nginx is running
docker-compose ps
docker-compose logs nginx
```

### "SMOTE failed — k_neighbors"

```bash
# Dataset too small — reduce k
# In 01_prepare_dataset.py change:
smote = SMOTE(random_state=42, k_neighbors=3)  # reduce from 5 to 3
```

### Slow training (SVM takes too long)

```bash
# Remove SVM from models dict in 02_train_model.py
# Or add this to limit training time:
"SVM (RBF)": Pipeline([
    ("scaler", StandardScaler()),
    ("clf", SVC(kernel="rbf", probability=True, max_iter=1000,
                class_weight="balanced", random_state=42)),
]),
```

### Windows: "flask not found" after pip install

```powershell
# Make sure venv is activated
.\venv\Scripts\Activate.ps1

# Verify flask is installed
pip show flask

# If missing:
pip install flask flask-cors gunicorn
```

---

## QUICK REFERENCE CARD

```
KALI LINUX — Full Run from Scratch
════════════════════════════════════════
cd ~/shadowguard
source venv/bin/activate
python 01_prepare_dataset.py        # ~2 min
python 02_train_model.py            # ~5 min
python target_app.py &              # background
python app.py                       # foreground
# OR:
docker-compose up --build           # single command

WINDOWS — Full Run from Scratch
════════════════════════════════════════
cd $env:USERPROFILE\shadowguard
.\venv\Scripts\Activate.ps1
python 01_prepare_dataset.py
python 02_train_model.py
Start-Process python -ArgumentList "target_app.py"
python app.py
# OR:
docker-compose up --build

ATTACK TESTING (Machine B)
════════════════════════════════════════
python3 lan_attack_test.py --target 192.168.1.X --port 80
sqlmap -u "http://192.168.1.X/search?q=test" --dbs --batch
nikto -h http://192.168.1.X -port 80

GITHUB
════════════════════════════════════════
git add . && git commit -m "Day XX: description" && git push
```

---
