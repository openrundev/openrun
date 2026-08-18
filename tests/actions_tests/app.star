load("exec.in", "exec")
load("fs.in", "fs")

# Test app exercising every feature of OpenRun actions: multiple actions
# (switcher), all param display types, list-options and suggest based
# dropdowns, validate/suggest buttons, param errors, all report types
# (TABLE/TEXT/JSON/AUTO/DOWNLOAD/IMAGE/custom template), file upload,
# hidden params, custom permits and handler errors.

REGIONS = ["us-east-1", "us-west-2", "eu-central-1", "ap-south-1"]

def deploy_run(dry_run, args):
    errors = {}
    if args.replicas < 1:
        errors["replicas"] = "at least 1 replica is required"
    if args.replicas > 10:
        errors["replicas"] = "at most 10 replicas are supported"
    if not args.region:
        errors["region"] = "region is required, use Suggest to pick one"
    if args.env == "prod" and not args.api_token:
        errors["api_token"] = "an API token is required for prod deploys"
    if errors:
        return ace.result("Validation failed", param_errors=errors)
    if dry_run:
        return ace.result("Validation passed, ready to deploy %s to %s" % (args.app_name, args.env))

    ace.audit("deploy", args.app_name, "%s to %s/%s" % (args.app_name, args.env, args.region))
    values = []
    for i in range(args.replicas):
        values.append({
            "unit": "%s-%d" % (args.app_name, i),
            "env": args.env,
            "region": args.region,
            "state": "running",
            "notified": args.notify,
        })
    return ace.result("Deployed %s to %s (%d replicas)" % (args.app_name, args.env, args.replicas),
                      values, ace.TABLE)

def deploy_suggest(args):
    if not args.region:
        return {"region": REGIONS, "replicas": 3}
    if args.env == "prod" and not args.api_token:
        return {"env": ["prod", "staging"]}
    return "Suggestions complete, ready to run"

def logs_run(dry_run, args):
    lines = ["%s [%s] request handled path=/api/orders status=200" % (args.app_name, args.env)]
    lines.append("%s [%s] cache refresh took 12ms" % (args.app_name, args.env))
    lines.append("%s [%s] request handled path=/api/orders/42 status=404" % (args.app_name, args.env))
    lines.append("%s [%s] scheduled job completed rows=1042" % (args.app_name, args.env))
    return ace.result("Recent logs for " + args.app_name, lines, ace.TEXT)

def inspect_run(dry_run, args):
    info = {
        "app": args.app_name,
        "env": args.env,
        "spec": {
            "image": "ghcr.io/example/%s:v1.4.2" % args.app_name,
            "ports": [8080, 9090],
            "resources": {"cpu": "500m", "memory": "512Mi"},
        },
        "conditions": [
            {"type": "Available", "status": True},
            {"type": "Progressing", "status": True},
        ],
    }
    return ace.result("Runtime details for " + args.app_name, [info], ace.AUTO)

def notes_run(dry_run, args):
    if not args.notes:
        return ace.result("Validation failed", param_errors={"notes": "release notes cannot be empty"})
    value = {
        "app": args.app_name,
        "env": args.env,
        "notes": args.notes,
    }
    return ace.result("Release notes for " + args.app_name, [value], "release_notes")

def upload_run(dry_run, args):
    if not args.upload:
        return ace.result("Validation failed", param_errors={"upload": "a file has to be uploaded"})
    # The uploaded temp file is deleted when the handler returns, so the
    # download must serve a NEW file: nl writes the numbered output to a
    # fresh temp file (stdout_file=True) which serve_tmp_file exposes
    run_ret = exec.run("nl", [args.upload], stdout_file=True)
    if run_ret.error:
        return ace.result(run_ret.error)
    ret = fs.serve_tmp_file(run_ret.value, name="numbered_" + args.upload.rsplit("/", 1)[-1])
    if ret.error:
        return ace.result(ret.error)
    return ace.result("File is ready for download", [ret.value], ace.DOWNLOAD)

def image_run(dry_run, args):
    # Relative url: the action page is at <app>/image, so this resolves to
    # <app>/static/openrun-logo.png
    return ace.result("Generated the logo image",
                      [{"name": "openrun-logo.png", "url": "static/openrun-logo.png"}], ace.IMAGE)

def restricted_run(dry_run, args):
    return ace.result("Restricted action ran for " + args.app_name)

def fail_run(dry_run, args):
    fail("intentional failure, testing action error handling")

app = ace.app("Actions Kitchen Sink",
              actions=[
                  ace.action("Deploy", "/", deploy_run, suggest=deploy_suggest,
                             description="Deploy an app: list and suggest dropdowns, int/bool/password params, validate support and a table report",
                             hidden=["notes", "upload", "audit_tag"], show_validate=True),
                  ace.action("Logs", "/logs", logs_run,
                             description="Fetch recent logs, shown as a text report",
                             hidden=["region", "replicas", "notify", "api_token", "notes", "upload", "audit_tag"]),
                  ace.action("Inspect", "/inspect", inspect_run,
                             description="Show runtime details, auto-rendered as a JSON tree report",
                             hidden=["region", "replicas", "notify", "api_token", "notes", "upload", "audit_tag"]),
                  ace.action("Release Notes", "/notes", notes_run,
                             description="Publish release notes, rendered with a custom template",
                             hidden=["region", "replicas", "notify", "api_token", "upload", "audit_tag"]),
                  ace.action("Process File", "/upload", upload_run,
                             description="Upload a file and download the processed result",
                             hidden=["app_name", "env", "region", "replicas", "notify", "api_token", "notes", "audit_tag"]),
                  ace.action("Logo Image", "/image", image_run,
                             description="Generate an image report",
                             hidden=["app_name", "env", "region", "replicas", "notify", "api_token", "notes", "upload", "audit_tag"]),
                  ace.action("Restricted", "/restricted", restricted_run,
                             description="Runs only with the ops_admin custom permission granted through RBAC",
                             hidden=["env", "region", "replicas", "notify", "api_token", "notes", "upload", "audit_tag"],
                             permit=["ops_admin"]),
                  ace.action("Fail", "/fail", fail_run,
                             description="Always fails, testing the action error path",
                             hidden=["env", "region", "replicas", "notify", "api_token", "notes", "upload", "audit_tag"]),
              ],
              permissions=[
                  ace.permission("exec.in", "run", ["nl"]),
                  ace.permission("fs.in", "serve_tmp_file"),
              ],
       )
