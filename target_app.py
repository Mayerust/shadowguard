

import sqlite3, os, re, subprocess
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB  = "/tmp/shadowguard_target.db"


def init_db():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, email TEXT, role TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, price REAL, description TEXT, category TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, product_id INTEGER, quantity INTEGER, total REAL
    )""")
    users = [
        ("admin",  "supersecret123", "admin@corp.internal", "admin"),
        ("alice",  "password1",      "alice@corp.internal", "user"),
        ("bob",    "letmein",        "bob@corp.internal",   "user"),
        ("charlie","qwerty123",      "charlie@corp.internal","moderator"),
    ]
    c.executemany("INSERT OR IGNORE INTO users(username,password,email,role) VALUES(?,?,?,?)", users)
    products = [
        ("Laptop Pro",  1299.99, "Business-grade laptop",    "electronics"),
        ("Phone X",      599.99, "Latest smartphone",         "electronics"),
        ("Tablet Mini",  349.99, "Lightweight tablet",        "electronics"),
        ("Headphones",    89.99, "Noise-cancelling",          "accessories"),
        ("USB-C Hub",     49.99, "7-in-1 hub",                "accessories"),
    ]
    c.executemany("INSERT OR IGNORE INTO products(name,price,description,category) VALUES(?,?,?,?)", products)
    conn.commit()
    conn.close()

init_db()


BASE = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Corp Internal App</title>
<style>
body{font-family:sans-serif;background:#f0f4f8;padding:20px;max-width:960px;margin:0 auto}
h1{color:#1e3a5f}
nav a{margin-right:12px;color:#2563eb;text-decoration:none}
.panel{background:#fff;border:1px solid #d1d5db;border-radius:8px;padding:20px;margin:16px 0}
input,select{padding:8px 12px;border:1px solid #cbd5e1;border-radius:6px;width:250px;margin-right:8px}
button{padding:8px 16px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:10px}
th{background:#f1f5f9;padding:8px;text-align:left;font-size:13px}
td{padding:8px;border-bottom:1px solid #f1f5f9;font-size:13px}
.vuln{background:#fef2f2;color:#b91c1c;padding:2px 8px;border-radius:4px;font-size:11px}
.out{background:#1e293b;color:#7dd3fc;padding:12px;border-radius:6px;font-family:monospace;
     font-size:12px;margin-top:10px;word-break:break-all;white-space:pre-wrap}
</style></head>
<body>
<h1>Corp Internal Web App <small style="color:#64748b;font-size:14px">(WAF Target — Port 8080)</small></h1>
<nav>
  <a href="/">Home</a>
  <a href="/search">Search</a>
  <a href="/login">Login</a>
  <a href="/file">Files</a>
  <a href="/ping">Ping</a>
  <a href="/profile">Profile</a>
  <a href="/comment">Comments</a>
  <a href="/fetch">Fetch</a>
  <a href="/xml">XML</a>
  <a href="/api/users">Users API</a>
</nav>
<p style="color:#dc2626;font-size:13px;margin-top:8px">
  Every endpoint is intentionally vulnerable.
  Access this through ShadowGuard WAF (:80) — not directly (:8080).
</p>
{content}
</body></html>"""


def page(content):
    return BASE.format(content=content)


#Home
@app.route("/")
def index():
    return page("""
    <div class="panel">
      <h2>Vulnerable Endpoints</h2>
      <table>
        <tr><th>Endpoint</th><th>Vulnerability</th><th>Attack Example</th></tr>
        <tr><td>/search</td><td><span class="vuln">SQL Injection</span></td>
            <td><code>' UNION SELECT username,password FROM users--</code></td></tr>
        <tr><td>/login</td><td><span class="vuln">SQLi Auth Bypass</span></td>
            <td><code>username: admin'--</code></td></tr>
        <tr><td>/file</td><td><span class="vuln">Path Traversal</span></td>
            <td><code>path=../../etc/passwd</code></td></tr>
        <tr><td>/ping</td><td><span class="vuln">Command Injection</span></td>
            <td><code>host=127.0.0.1; id</code></td></tr>
        <tr><td>/profile</td><td><span class="vuln">Reflected XSS</span></td>
            <td><code>name=&lt;script&gt;alert(1)&lt;/script&gt;</code></td></tr>
        <tr><td>/comment</td><td><span class="vuln">Stored XSS</span></td>
            <td><code>content=&lt;img src=x onerror=alert(1)&gt;</code></td></tr>
        <tr><td>/fetch</td><td><span class="vuln">SSRF</span></td>
            <td><code>url=http://169.254.169.254/latest/meta-data/</code></td></tr>
        <tr><td>/xml</td><td><span class="vuln">XXE</span></td>
            <td><code>DOCTYPE with ENTITY file:///etc/passwd</code></td></tr>
        <tr><td>/api/users</td><td><span class="vuln">SQL Injection (JSON API)</span></td>
            <td><code>role=' OR '1'='1</code></td></tr>
      </table>
    </div>""")


#SQL Injection: Product Search
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results, error = None, None
    if q:
        try:
            conn = sqlite3.connect(DB)
            # VULNERABLE: string interpolation
            sql = f"SELECT id,name,price,description,category FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
            results = conn.execute(sql).fetchall()
            conn.close()
        except Exception as e:
            error = str(e)

    rows = ""
    if results:
        rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>${r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>" for r in results)
    error_html = f'<div class="out">DB Error: {error}</div>' if error else ""

    return page(f"""
    <div class="panel">
      <h2>Product Search <span class="vuln">SQLi Vulnerable</span></h2>
      <form method="GET">
        <input name="q" value="{q}" placeholder="Search products...">
        <button>Search</button>
      </form>
      {error_html}
      {"<table><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th><th>Category</th></tr>" + rows + "</table>" if rows else ""}
    </div>""")


#SQL Injection: Authentication Bypass
@app.route("/login", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        try:
            conn = sqlite3.connect(DB)
            #VULNERABLE: direct concatenation
            sql = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
            row = conn.execute(sql).fetchone()
            conn.close()
            if row:
                result = f'<div class="out">LOGIN SUCCESS\nWelcome: {row[1]}\nRole: {row[4]}\nEmail: {row[3]}</div>'
            else:
                result = '<div class="out">Login failed: invalid credentials</div>'
        except Exception as e:
            result = f'<div class="out">DB Error: {e}</div>'

    return page(f"""
    <div class="panel">
      <h2>User Login <span class="vuln">SQLi Auth Bypass</span></h2>
      <p>Try: username=<code>admin'--</code> password=<em>anything</em></p>
      <form method="POST">
        <input name="username" placeholder="Username"><br><br>
        <input name="password" type="text" placeholder="Password"><br><br>
        <button>Login</button>
      </form>
      {result}
    </div>""")


#Path Traversal
@app.route("/file")
def file_view():
    path    = request.args.get("path", "readme.txt")
    content = ""
    try:
        #VULNERABLE: no path sanitization
        with open(path, "r", errors="replace") as f:
            content = f.read(3000)
    except Exception as e:
        content = f"Error: {e}"

    return page(f"""
    <div class="panel">
      <h2>File Viewer <span class="vuln">Path Traversal</span></h2>
      <p>Try: <code>path=../../etc/passwd</code></p>
      <form method="GET">
        <input name="path" value="{path}" style="width:400px">
        <button>View</button>
      </form>
      <div class="out">{content}</div>
    </div>""")


#Command Injection
@app.route("/ping")
def ping():
    host   = request.args.get("host", "8.8.8.8")
    result = ""
    try:
        #VULNERABLE: shell=True + unsanitized input
        result = subprocess.check_output(
            f"ping -c 2 {host}", shell=True,
            stderr=subprocess.STDOUT, timeout=5
        ).decode()
    except Exception as e:
        result = str(e)

    return page(f"""
    <div class="panel">
      <h2>Network Ping Tool <span class="vuln">Command Injection</span></h2>
      <p>Try: <code>host=8.8.8.8; id</code> or <code>host=127.0.0.1 | cat /etc/passwd</code></p>
      <form method="GET">
        <input name="host" value="{host}">
        <button>Ping</button>
      </form>
      <div class="out">{result}</div>
    </div>""")


#Reflected XSS 
@app.route("/profile")
def profile():
    name = request.args.get("name", "Guest")
    # VULNERABLE: renders user input directly into HTML without escaping
    return page(f"""
    <div class="panel">
      <h2>User Profile <span class="vuln">Reflected XSS</span></h2>
      <p>Try: <code>name=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></p>
      <form method="GET">
        <input name="name" value="" placeholder="Enter your name">
        <button>View Profile</button>
      </form>
      <h3>Welcome, {name}!</h3>
    </div>""")


#Stored XSS
@app.route("/comment", methods=["GET", "POST"])
def comment():
    msg = ""
    if request.method == "POST":
        author  = request.form.get("author", "Anonymous")
        content = request.form.get("content", "")
        try:
            conn = sqlite3.connect(DB)
            #VULNERABLE: stores raw HTML in DB, renders without escaping
            conn.execute("INSERT INTO comments(author,content) VALUES(?,?)", (author, content))
            conn.commit()
            conn.close()
            msg = "Comment posted!"
        except Exception as e:
            msg = str(e)

    conn     = sqlite3.connect(DB)
    comments = conn.execute("SELECT author,content,timestamp FROM comments ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    #VULNERABLE: renders content directly — stored XSS
    comment_html = "".join(
        f"<tr><td>{c[0]}</td><td>{c[1]}</td><td>{c[2]}</td></tr>"
        for c in comments
    )

    return page(f"""
    <div class="panel">
      <h2>Comments Board <span class="vuln">Stored XSS</span></h2>
      <p>Try: content=<code>&lt;img src=x onerror=alert('XSS')&gt;</code></p>
      <form method="POST">
        <input name="author" placeholder="Your name"><br><br>
        <input name="content" placeholder="Your comment" style="width:400px"><br><br>
        <button>Post</button>
      </form>
      {"<p style='color:green'>" + msg + "</p>" if msg else ""}
      <table><tr><th>Author</th><th>Content</th><th>Time</th></tr>{comment_html}</table>
    </div>""")


#SSRF
@app.route("/fetch")
def fetch_url():
    import urllib.request
    url    = request.args.get("url", "")
    result = ""
    if url:
        try:
            #VULNERABLE: fetches any URL including internal/cloud metadata
            with urllib.request.urlopen(url, timeout=3) as resp:
                result = resp.read(2000).decode("utf-8", errors="replace")
        except Exception as e:
            result = str(e)

    return page(f"""
    <div class="panel">
      <h2>URL Fetcher <span class="vuln">SSRF Vulnerable</span></h2>
      <p>Try: <code>url=http://169.254.169.254/latest/meta-data/</code> (AWS metadata)</p>
      <p>Or: <code>url=http://localhost:8080/api/status</code> (internal service)</p>
      <form method="GET">
        <input name="url" value="{url}" style="width:400px" placeholder="https://example.com">
        <button>Fetch</button>
      </form>
      <div class="out">{result}</div>
    </div>""")


#XXE (simulated)
@app.route("/xml", methods=["GET", "POST"])
def xml_parse():
    result = ""
    if request.method == "POST":
        xml_data = request.data.decode("utf-8", errors="replace") or request.form.get("xml", "")
        try:
            #VULNERABLE: uses defusedxml is NOT used — lxml with resolve_entities
            import xml.etree.ElementTree as ET
            root   = ET.fromstring(xml_data)
            result = ET.tostring(root, encoding="unicode")
        except Exception as e:
            result = str(e)

    sample = """<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

    return page(f"""
    <div class="panel">
      <h2>XML Parser <span class="vuln">XXE Vulnerable</span></h2>
      <p>POST XML with external entity reference to read files</p>
      <form method="POST" enctype="text/plain">
        <textarea name="xml" rows="8" style="width:500px;font-family:monospace;font-size:12px">{sample}</textarea><br><br>
        <button>Parse XML</button>
      </form>
      <div class="out">{result}</div>
    </div>""")


#SQL Injection in JSON API
@app.route("/api/users")
def api_users():
    role = request.args.get("role", "user")
    try:
        conn = sqlite3.connect(DB)
        #VULNERABLE: SQL injection in API endpoint
        sql  = f"SELECT id,username,email,role FROM users WHERE role='{role}'"
        rows = conn.execute(sql).fetchall()
        conn.close()
        return jsonify([{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


#Health 
@app.route("/api/status")
def status():
    return jsonify({
        "status":    "running",
        "app":       "ShadowGuard Target",
        "port":      8080,
        "endpoints": ["/search", "/login", "/file", "/ping",
                      "/profile", "/comment", "/fetch", "/xml", "/api/users"],
        "warning":   "This app is intentionally vulnerable. Use behind ShadowGuard WAF only."
    })


if __name__ == "__main__":
    
    print("TARGET APP  (Intentionally Vulnerable)")
    print("=" * 55)
    print("  Direct URL : http://0.0.0.0:8080  ← UNPROTECTED")
    print("  Via WAF    : http://0.0.0.0:80    ← PROTECTED")
    print("  Endpoints  : /search /login /file /ping")
    print("               /profile /comment /fetch /xml")
    print("               /api/users /api/status")
    
    app.run(host="0.0.0.0", port=8080, debug=False)