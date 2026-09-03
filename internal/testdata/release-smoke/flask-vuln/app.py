"""Flask vulnerable fixture: f-string SQL and SSRF via requests.
PF-FLASK-SQLI-002 should fire on the f-string SQL.
PF-FLASK-SSRF-002 should fire on the user-controlled URL fetch.
"""
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: f-string SQL injection
    cursor = app.db.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
    return jsonify([row for row in cursor.fetchall()])


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # VULNERABLE: SSRF — user-controlled URL
    resp = requests.get(url)
    return resp.text
