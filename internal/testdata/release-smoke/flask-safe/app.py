"""Flask safe fixture: parameterized SQLAlchemy ORM query.
The safe pattern "select(" should suppress PF-FLASK-SQLI-002 -IP false positives.
"""
from flask import Flask, request, jsonify
from sqlalchemy import select
from sqlalchemy.orm import Session

app = Flask(__name__)


class User:
    name: str
    id: int


@app.route("/users")
def search_users():
    name = request.args.get("name", "")
    # SAFE: parameterized SQLAlchemy ORM select
    stmt = select(User).where(User.name == name)
    result = app.db_session.execute(stmt)
    return jsonify([u.name for u in result.scalars()])
