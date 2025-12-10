#!/usr/bin/env python3
from flask import Flask, request, jsonify
import sqlite3, os
from pathlib import Path


DB_PATH = "/tmp/data/test.db"
app = Flask(__name__)


def init_db():
    """Create table if it doesn't exist."""
    db_dir = Path(os.path.dirname(DB_PATH))
    db_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS value_store (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            value TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

init_db()

@app.route("/value", methods=["POST"])
def set_value():
    """
    Accepts a string value and stores it in SQLite.
    You can send it as JSON: {"value": "hello"}
    or as form data: value=hello
    """
    data = request.get_json(silent=True) or {}
    value = data.get("value") or request.form.get("value")

    if value is None:
        return jsonify({"error": "Missing 'value'"}), 400

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Always store in row with id=1
    cur.execute(
        "INSERT OR REPLACE INTO value_store (id, value) VALUES (1, ?)",
        (value,),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "value": value}), 200


@app.route("/value", methods=["GET"])
def get_value():
    """Returns the current stored value."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM value_store WHERE id = 1")
    row = cur.fetchone()
    conn.close()

    if row is None:
        return jsonify({"value": None, "message": "No value set yet"}), 200

    return jsonify({"value": row[0]}), 200

@app.route("/version", methods=["GET"])
def get_version():
    return "VERSION1", 200

@app.route("/", methods=["GET"])
def index():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

