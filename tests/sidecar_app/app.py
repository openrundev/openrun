import os
import socket

from flask import Flask

CACHE_ADDR = os.environ["CL_SIDECAR_CACHE_ADDR"]


def cache_call(lines, expect_end):
    host, port = CACHE_ADDR.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=2) as conn:
        conn.sendall("".join(lines).encode())
        data = b""
        while expect_end not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode()


def cache_set(key, value):
    return cache_call([f"set {key} 0 0 {len(value)}\r\n", f"{value}\r\n"], b"STORED")


def cache_get(key):
    resp = cache_call([f"get {key}\r\n"], b"END")
    lines = resp.split("\r\n")
    if len(lines) >= 2 and lines[0].startswith("VALUE"):
        return lines[1]
    return ""


# The sidecar cache must be up before the app container starts: fail the
# container start (and the deploy) if it is not reachable at import time
cache_call(["version\r\n"], b"VERSION")

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "hello"


@app.route("/cache")
def cache():
    cache_set("k", "v1")
    return "cache ok: " + cache_get("k")


@app.route("/worker")
def worker():
    return "worker: " + cache_get("worker_heartbeat")


@app.route("/env")
def env():
    return "cache_addr=%s port=%s" % (CACHE_ADDR, os.environ.get("PORT", "-"))
