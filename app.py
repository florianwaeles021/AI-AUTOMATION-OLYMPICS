import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
DB = "app.db"


def db():
    return sqlite3.connect(DB)


def init_db():
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner INTEGER, body TEXT)")
    conn.commit()


@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    # SEEDED: weak password hashing, no salt (CWE-327/328)
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    conn = db()
    conn.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, pw))
    conn.commit()
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    # SEEDED: SQL injection via string formatting (CWE-89)
    q = "SELECT id FROM users WHERE name = '%s' AND password = '%s'" % (name, pw)
    row = db().execute(q).fetchone()
    return ("welcome %s" % row[0]) if row else ("denied", 401)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # SEEDED: reflected XSS via render_template_string with user input (CWE-79 / SSTI CWE-1336)
    return render_template_string("<h1>Results for " + term + "</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # SEEDED: OS command injection (CWE-78)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/download")
def download():
    # SEEDED: path traversal (CWE-22)
    return send_file(os.path.join("uploads", request.args["file"]))


@app.route("/redirect")
def go():
    # SEEDED: open redirect (CWE-601)
    return redirect(request.args.get("url", "/"))


@app.route("/fetch")
def fetch():
    # SEEDED: SSRF (CWE-918)
    return requests.get(request.args["url"], timeout=5).text


@app.route("/import", methods=["POST"])
def import_cfg():
    # SEEDED: unsafe YAML load (CWE-502)
    cfg = yaml.load(request.data)
    return str(cfg)


@app.route("/restore", methods=["POST"])
def restore():
    # SEEDED: insecure deserialization with pickle (CWE-502)
    return str(pickle.loads(request.data))


@app.route("/calc")
def calc():
    # SEEDED: eval on user input (CWE-95)
    return str(eval(request.args["expr"]))


@app.route("/note/<int:note_id>")
def note(note_id):
    # SEEDED: broken access control / IDOR, no auth check (CWE-639)
    row = db().execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
    return row[0] if row else ("not found", 404)


if __name__ == "__main__":
    init_db()
    # SEEDED: binds all interfaces with debugger on (CWE-489)
    app.run(host="0.0.0.0", debug=config.DEBUG)
