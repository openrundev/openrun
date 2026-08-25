param("port", type=INT,
      description="The port the flask app is listening on (inside the container)", default=5000)

param("app_name", description="The name for the app", default="Flask App")

param("preserve_host", type=BOOLEAN, description="Whether to preserve the original Host header", default=False)

param("secrets", description="The secrets which are allowed to be passed to the container", type=LIST, default=[["regex:.*"]])

param("dev_command",
      description="The command used to start the app in dev mode, run with the app source mounted",
      default="""export PATH=/app/.venv/bin:$PATH; if [ -f uv.lock ]; then uv sync --locked; elif [ -f requirements.txt ]; then [ -d .venv ] || uv venv .venv; uv pip install -q -r requirements.txt; fi; python -c 'import watchdog' 2>/dev/null || uv pip install -q watchdog; exec python -m flask run --host=0.0.0.0 --reload""")

param("dev_reload",
      description="What a source change does in dev mode: none (the flask --reload file watcher reloads on its own, the default), restart (restart container) or recreate",
      default="none")
