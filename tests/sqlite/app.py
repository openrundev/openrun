#!/usr/bin/env python3
from flask import Flask, request, jsonify
import sqlite3, os
from pathlib import Path


# When run with a sqlite service binding, the database path comes from the
# binding env vars; standalone runs (mounts/kubernetes suites) keep the old
# fixed path.
DB_PATH = os.environ.get("SQLITE_DB_PATH", "/tmp/data/test.db")
DB_DIR = os.environ.get("SQLITE_DIR", os.path.dirname(DB_PATH))
EXTRA_DB_PATH = os.path.join(DB_DIR, "extra.db")
app = Flask(__name__)


def connect(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """Create table if it doesn't exist."""
    db_dir = Path(os.path.dirname(DB_PATH))
    db_dir.mkdir(parents=True, exist_ok=True)

    conn = connect(DB_PATH)
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

    conn = connect(DB_PATH)
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
    conn = connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM value_store WHERE id = 1")
    row = cur.fetchone()
    conn.close()

    if row is None:
        return jsonify({"value": None, "message": "No value set yet"}), 200

    return jsonify({"value": row[0]}), 200


@app.route("/extra", methods=["POST"])
def set_extra():
    """Stores a value in a second database file in the binding directory,
    exercising litestream's directory watcher discovery of new databases."""
    data = request.get_json(silent=True) or {}
    value = data.get("value") or request.form.get("value")
    if value is None:
        return jsonify({"error": "Missing 'value'"}), 400

    conn = connect(EXTRA_DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS extra_store (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL)")
    cur.execute("INSERT OR REPLACE INTO extra_store (id, value) VALUES (1, ?)", (value,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "value": value}), 200


@app.route("/extra", methods=["GET"])
def get_extra():
    if not os.path.exists(EXTRA_DB_PATH):
        return jsonify({"value": None, "message": "No extra db"}), 200
    conn = connect(EXTRA_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM extra_store WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    return jsonify({"value": row[0] if row else None}), 200


@app.route("/dbpath", methods=["GET"])
def get_dbpath():
    return DB_PATH, 200

@app.route("/version", methods=["GET"])
def get_version():
    return "VERSION1", 200

@app.route("/", methods=["GET"])
def index():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
