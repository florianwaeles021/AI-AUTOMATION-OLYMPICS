import ast
import ipaddress
import json
import operator
import re
import socket
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, redirect, request, send_from_directory, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "app.db"

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def db():
    return sqlite3.connect(DB)


def init_db():
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT UNIQUE, password TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner INTEGER, body TEXT)")
    conn.commit()


@app.route("/register", methods=["POST"])
def register():
    # FIX CWE-327/328: salted, slow password hash (scrypt via werkzeug)
    pw = generate_password_hash(request.form["password"])
    conn = db()
    try:
        conn.execute("INSERT INTO users (name, password) VALUES (?, ?)", (request.form["name"], pw))
        conn.commit()
    except sqlite3.IntegrityError:
        return "name taken", 409
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    # FIX CWE-89: parameterized query; verify hash in Python
    row = db().execute(
        "SELECT id, password FROM users WHERE name = ?", (request.form["name"],)
    ).fetchone()
    if row and check_password_hash(row[1], request.form["password"]):
        session.clear()
        session["uid"] = row[0]
        return "welcome"
    return "denied", 401


@app.route("/search")
def search():
    # FIX CWE-79/1336: no template built from user input; output is HTML-escaped
    return "<h1>Results for %s</h1>" % escape(request.args.get("q", ""))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX CWE-78: strict allow-list validation, no shell, argv list, "--" ends options
    if not HOST_RE.match(host):
        abort(400)
    out = subprocess.run(
        ["ping", "-c", "1", "--", host], capture_output=True, text=True, timeout=10, check=False
    )
    return "<pre>%s</pre>" % escape(out.stdout or out.stderr)


@app.route("/download")
def download():
    # FIX CWE-22: send_from_directory confines the path to UPLOAD_DIR
    return send_from_directory(config.UPLOAD_DIR, request.args["file"])


@app.route("/redirect")
def go():
    # FIX CWE-601: only same-site relative paths (backslashes normalised first,
    # then reject anything carrying a scheme or host)
    url = request.args.get("url", "/").replace("\\", "")
    p = urlparse(url)
    if p.scheme or p.netloc or not url.startswith("/") or url.startswith("//"):
        abort(400)
    return redirect(url)


def _is_public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


@app.route("/fetch")
def fetch():
    # FIX CWE-918: https only, explicit host allow-list, public IPs only, no redirects
    u = urlparse(request.args["url"])
    if u.scheme != "https" or u.hostname not in config.FETCH_ALLOWED_HOSTS or not _is_public(u.hostname):
        abort(403)
    r = requests.get(u.geturl(), timeout=5, allow_redirects=False)
    return "<pre>%s</pre>" % escape(r.text)


@app.route("/import", methods=["POST"])
def import_cfg():
    # FIX CWE-502: safe_load only builds plain data types
    try:
        data = yaml.safe_load(request.data)
    except yaml.YAMLError:
        abort(400)
    return "<pre>%s</pre>" % escape(str(data))


@app.route("/restore", methods=["POST"])
def restore():
    # FIX CWE-502: JSON instead of pickle
    try:
        data = json.loads(request.data)
    except ValueError:
        abort(400)
    return "<pre>%s</pre>" % escape(str(data))


_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.USub: operator.neg,
}


def _calc(node):
    if isinstance(node, ast.Expression):
        return _calc(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    # FIX CWE-95: parse into an AST and evaluate arithmetic only; never eval()
    try:
        return str(_calc(ast.parse(request.args["expr"][:200], mode="eval")))
    except (ValueError, SyntaxError, ZeroDivisionError, RecursionError):
        abort(400)


@app.route("/note/<int:note_id>")
def note(note_id):
    # FIX CWE-639: authentication required and ownership enforced
    uid = session.get("uid")
    if uid is None:
        abort(401)
    row = db().execute(
        "SELECT body FROM notes WHERE id = ? AND owner = ?", (note_id, uid)
    ).fetchone()
    if not row:
        abort(404)
    return "<pre>%s</pre>" % escape(row[0])


if __name__ == "__main__":
    init_db()
    # FIX CWE-489: debugger off and loopback-only by default (opt in via env)
    app.run(host=config.HOST, debug=config.DEBUG)
