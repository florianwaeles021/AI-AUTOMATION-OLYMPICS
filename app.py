import hashlib
import os
import pickle
import sqlite3
import subprocess
import base64

import yaml
from flask import Flask, abort, redirect, render_template, request, send_file, session

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
DB = "insurance.db"
BASE = os.path.dirname(os.path.abspath(__file__))


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, ssn TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS policies (id INTEGER PRIMARY KEY, number TEXT, type TEXT, coverage INTEGER, premium INTEGER, owner INTEGER);
    CREATE TABLE IF NOT EXISTS claims (id INTEGER PRIMARY KEY, policy_id INTEGER, description TEXT, status TEXT);
    """)
    if not c.execute("SELECT 1 FROM users").fetchone():
        # SEEDED: MD5 password hashes (CWE-327)
        md5 = lambda s: hashlib.md5(s.encode()).hexdigest()
        c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", [
            (1, "Alice Martin", "alice@example.com", md5("alice-pass"), "123-45-6789", "customer"),
            (2, "Bob Keller", "bob@example.com", md5("bob-pass"), "987-65-4321", "customer"),
            (3, "Admin", "admin@safeharbor.test", md5("admin-pass"), "000-00-0000", "admin")])
        c.executemany("INSERT INTO policies VALUES (?,?,?,?,?,?)", [
            (1, "SH-1001", "Home", 350000, 1180, 1), (2, "SH-2001", "Auto", 60000, 940, 1), (3, "SH-3001", "Life", 500000, 720, 2)])
        c.executemany("INSERT INTO claims VALUES (?,?,?,?)", [
            (1, 1, "Water damage in kitchen", "Under review"), (2, 3, "Beneficiary update", "Pending")])
    c.commit()


def me():
    return session.get("uid")


@app.route("/")
def index():
    return redirect("/dashboard" if me() else "/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email, pw = request.form["email"], request.form["password"]
        pwh = hashlib.md5(pw.encode()).hexdigest()
        # SEEDED: SQL injection (CWE-89)
        q = "SELECT * FROM users WHERE email = '%s' AND password = '%s'" % (email, pwh)
        try:
            u = db().execute(q).fetchone()
        except sqlite3.Error as e:
            return "SQL error: %s" % e, 500
        if u:
            session["uid"], session["name"], session["role"] = u["id"], u["name"], u["role"]
            r = redirect(request.args.get("next", "/dashboard"))  # SEEDED: open redirect (CWE-601)
            r.set_cookie("role", u["role"])  # SEEDED: client-side role cookie trusted later (CWE-565)
            return r
        error = "Invalid email or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if not me():
        return redirect("/login")
    pol = db().execute("SELECT * FROM policies WHERE owner = ?", (me(),)).fetchall()
    return render_template("dashboard.html", policies=pol)


@app.route("/policy/<int:pid>")
def policy(pid):
    if not me():
        return redirect("/login")
    # SEEDED: IDOR - no ownership check (CWE-639)
    p = db().execute("""SELECT p.*, u.name AS holder, u.email, '1985-04-12' AS dob FROM policies p
                        JOIN users u ON u.id = p.owner WHERE p.id = ?""", (pid,)).fetchone()
    if not p:
        abort(404)
    return render_template("policy.html", p=p)


@app.route("/claims", methods=["GET", "POST"])
def claims():
    if not me():
        return redirect("/login")
    c = db()
    if request.method == "POST":
        c.execute("INSERT INTO claims (policy_id, description, status) VALUES (?,?,?)",
                  (request.form["policy_id"], request.form["description"], "Submitted"))
        c.commit()
        return redirect("/claims")
    pol = c.execute("SELECT * FROM policies WHERE owner = ?", (me(),)).fetchall()
    rows = c.execute("""SELECT c.id, c.description, c.status, p.number FROM claims c
                        JOIN policies p ON p.id = c.policy_id WHERE p.owner = ?""", (me(),)).fetchall()
    return render_template("claims.html", policies=pol, claims=rows)  # SEEDED: stored XSS via |safe in template (CWE-79)


@app.route("/claims/search")
def claim_search():
    if not me():
        return redirect("/login")
    q = request.args.get("q", "")
    rows = db().execute("SELECT c.id, c.description FROM claims c JOIN policies p ON p.id = c.policy_id "
                        "WHERE p.owner = ? AND c.description LIKE ?", (me(), "%" + q + "%")).fetchall()
    return render_template("results.html", q=q, rows=rows)  # SEEDED: reflected XSS via |safe in template (CWE-79)


@app.route("/documents/download")
def download():
    if not me():
        return redirect("/login")
    # SEEDED: path traversal (CWE-22)
    return send_file(os.path.join(BASE, "documents", request.args["file"]))


@app.route("/quote")
def quote():
    if not me():
        return redirect("/login")
    return render_template("quote.html")


@app.route("/api/quote")
def api_quote():
    # SEEDED: eval on user input (CWE-95)
    return "Estimated premium: $%s" % eval(request.args["formula"])


@app.route("/admin")
def admin():
    # SEEDED: broken access control - trusts a client-controlled cookie (CWE-285/565)
    if request.cookies.get("role") != "admin":
        abort(403)
    users = db().execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/backup")
def backup():
    if request.cookies.get("role") != "admin":
        abort(403)
    label = request.args.get("label", "nightly")
    # SEEDED: OS command injection (CWE-78)
    out = subprocess.run("echo backup-%s" % label, shell=True, capture_output=True, text=True)
    return "<pre>%s</pre>" % out.stdout


@app.route("/admin/import-rates", methods=["POST"])
def import_rates():
    if request.cookies.get("role") != "admin":
        abort(403)
    # SEEDED: unsafe YAML load (CWE-502)
    return "<pre>%s</pre>" % yaml.load(request.form["data"], Loader=yaml.Loader)


@app.route("/api/session/restore", methods=["POST"])
def restore():
    # SEEDED: pickle deserialization of user data (CWE-502)
    return str(pickle.loads(base64.b64decode(request.get_data())))


if __name__ == "__main__":
    init_db()
    # SEEDED: debug on, all interfaces (CWE-489)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=config.DEBUG)
