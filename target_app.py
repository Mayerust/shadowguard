import sqlite3
import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB_PATH = "/tmp/shadowguard_demo.db"



#Init vulnerable SQLite DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        role TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )""")
    # Seed data
    users = [
        ("admin", "supersecret123", "admin@corp.com", "admin"),
        ("alice", "password1", "alice@corp.com", "user"),
        ("bob", "letmein", "bob@corp.com", "user"),
    ]
    c.executemany("INSERT OR IGNORE INTO users VALUES (NULL,?,?,?,?)", users)
    products = [
        ("Laptop", 999.99, "Business laptop"),
        ("Phone", 499.99, "Smartphone"),
        ("Tablet", 299.99, "10-inch tablet"),
    ]
    c.executemany("INSERT OR IGNORE INTO products VALUES (NULL,?,?,?)", products)
    conn.commit()
    conn.close()

init_db()

TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Corp Web App — Target</title>
<style>
body{font-family:sans-serif;background:#f0f4f8;padding:24px;max-width:900px;margin:0 auto}
h1{color:#1e3a5f}.panel{background:#fff;border:1px solid #d1d5db;border-radius:10px;padding:20px;margin-bottom:20px}
input{padding:8px 12px;border:1px solid #cbd5e1;border-radius:6px;width:300px;margin-right:8px}
button{padding:8px 16px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:10px}
th{background:#f1f5f9;padding:8px;text-align:left;font-size:13px}
td{padding:8px;border-bottom:1px solid #f1f5f9;font-size:13px}
.vuln-badge{display:inline-block;background:#fef2f2;color:#b91c1c;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px}
.result-box{background:#1e293b;color:#7dd3fc;padding:12px;border-radius:6px;font-family:monospace;font-size:12px;margin-top:10px;word-break:break-all}
</style></head>
<body>
<h1>Corp Internal Web App <span style="font-size:14px;color:#64748b">(Target App — Port 8080)</span></h1>
<p style="color:#64748b;font-size:14px">This app is intentionally vulnerable. ShadowGuard should be protecting it.</p>

<div class="panel">
  <h3>Product Search <span class="vuln-badge">SQLi Vulnerable</span></h3>
  <form action="/search" method="GET">
    <input name="q" placeholder="Search products..." value="{{query}}">
    <button>Search</button>
  </form>
  {% if results %}
  <table><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
  {% for r in results %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3]}}</td></tr>{% endfor %}
  </table>
  {% endif %}
  {% if error %}<div class="result-box">Error: {{error}}</div>{% endif %}
</div>

<div class="panel">
  <h3>User Login <span class="vuln-badge">SQLi Vulnerable</span></h3>
  <form action="/login" method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="text" placeholder="Password">
    <button>Login</button>
  </form>
  {% if login_result %}<div class="result-box">{{login_result}}</div>{% endif %}
</div>

<div class="panel">
  <h3>File Viewer <span class="vuln-badge">Path Traversal Vulnerable</span></h3>
  <form action="/file" method="GET">
    <input name="path" placeholder="Enter file path..." value="readme.txt">
    <button>View</button>
  </form>
  {% if file_content %}<div class="result-box">{{file_content}}</div>{% endif %}
</div>

<div class="panel">
  <h3>Ping Tool <span class="vuln-badge">Command Injection Vulnerable</span></h3>
  <form action="/ping" method="GET">
    <input name="host" placeholder="Hostname or IP..." value="8.8.8.8">
    <button>Ping</button>
  </form>
  {% if ping_result %}<div class="result-box">{{ping_result}}</div>{% endif %}
</div>

<p style="font-size:12px;color:#94a3b8;text-align:center;margin-top:20px">
  ShadowGuard WAF is listening on :5000 and should block malicious requests before they reach this app.
</p>
</body></html>"""


@app.route("/")
def index():
    return render_template_string(TEMPLATE, query="", results=None, error=None,
                                  login_result=None, file_content=None, ping_result=None)




#INTENTIONALLY VULNERABLE: SQL Injection via string concat
@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        conn = sqlite3.connect(DB_PATH)

        #!!! NOT TO DO this in production

        sql = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%'"
        rows = conn.execute(sql).fetchall()
        conn.close()
        return render_template_string(TEMPLATE, query=q, results=rows, error=None,
                                      login_result=None, file_content=None, ping_result=None)
    except Exception as e:
        return render_template_string(TEMPLATE, query=q, results=None, error=str(e),
                                      login_result=None, file_content=None, ping_result=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    try:
        conn = sqlite3.connect(DB_PATH)
        # !!! VULNERABLE: direct string interpolation !!!
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        row = conn.execute(sql).fetchone()
        conn.close()
        if row:
            result = f"LOGIN SUCCESS: Welcome {row[1]} (role={row[4]})"
        else:
            result = "LOGIN FAILED: Invalid credentials"
        return render_template_string(TEMPLATE, login_result=result, query="",
                                      results=None, error=None, file_content=None, ping_result=None)
    except Exception as e:
        return render_template_string(TEMPLATE, login_result=f"DB Error: {e}",
                                      query="", results=None, error=None, file_content=None, ping_result=None)


#INTENTIONALLY VULNERABLE: Path Traversal
@app.route("/file")
def file_view():
    path = request.args.get("path", "readme.txt")
    try:
        # !!! VULNERABLE: no path sanitization !!!
        with open(path, "r", errors="replace") as f:
            content = f.read(2000)
        return render_template_string(TEMPLATE, file_content=content, query="",
                                      results=None, error=None, login_result=None, ping_result=None)
    except Exception as e:
        return render_template_string(TEMPLATE, file_content=f"Error: {e}",
                                      query="", results=None, error=None, login_result=None, ping_result=None)


#INTENTIONALLY VULNERABLE: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "8.8.8.8")
    try:
        import subprocess
        
        
        #VULNERABLE: direct shell injection

        result = subprocess.check_output(
            f"ping -c 2 {host}",
            shell=True, stderr=subprocess.STDOUT, timeout=5,
        ).decode()
    except Exception as e:
        result = str(e)
    return render_template_string(TEMPLATE, ping_result=result, query="",
                                  results=None, error=None, login_result=None, file_content=None)


@app.route("/api/status")
def status():
    return jsonify({"status": "running", "app": "target", "port": 8080})


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("This is a TARGET APP  (Intentionally Vulnerable)")
    print("=" * 50)
    print("URL: http://0.0.0.0:8080")
    print("Deploy ShadowGuard WAF on : 5000 in front of this.")
    print("All traffic should go through the WAF first.")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=8080, debug=False)