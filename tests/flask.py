import os

from flask import Flask
from flask import request

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "hello"


@app.route("/allow")
def allow():
    return "forward auth allowed"


@app.route("/forward")
def forward_auth():
    checks = {
        "X-Forwarded-Method": "GET",
        "X-Forwarded-Proto": "http",
        "X-Forwarded-Host": os.environ["EXPECTED_FORWARD_HOST"],
        "X-Openrun-User": "admin",
        "X-Openrun-User-Stripped": "admin",
        "X-Openrun-Rbac-Enabled": "false",
    }
    for header, expected in checks.items():
        got = request.headers.get(header, "")
        if got != expected:
            return f"{header}: got {got}, want {expected}", 403

    if "X-Openrun-Perms" not in request.headers:
        return "missing X-Openrun-Perms", 403
    if not request.headers.get("Authorization", "").startswith("Basic "):
        return "missing Authorization", 403

    forwarded_uri = request.headers.get("X-Forwarded-Uri", "")
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    real_ip = request.headers.get("X-Real-Ip", "")
    if not forwarded_for:
        return "missing X-Forwarded-For", 403
    if real_ip != forwarded_for:
        return f"X-Real-IP: got {real_ip}, want {forwarded_for}", 403

    if forwarded_uri == "/forwardtarget/allow":
        return "", 204
    if forwarded_uri == "/forwardtarget/disallow":
        return "forward auth denied", 403
    return f"unexpected X-Forwarded-Uri: {forwarded_uri}", 403
