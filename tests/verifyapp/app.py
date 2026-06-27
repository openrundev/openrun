from flask import Flask

app = Flask(__name__)


@app.route("/")
def health():
    return "ok", 200


@app.route("/version")
def version():
    return "V1"
