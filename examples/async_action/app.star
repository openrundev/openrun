# Async actions sample: every action here runs in the background
# (is_async=True) and shows up in the Runs list of its page, except the
# last one, a sync action for comparison. Deploy with
#
#   openrun app create --dev --approve ./examples/async_action /async_action
#
# then open /async_action in the browser, or use the CLI:
#
#   openrun action list /async_action
#   openrun action run --wait /async_action report rows=5   # the root action, named from its name
#   openrun action run --follow /async_action build steps=10
#   openrun action runs /async_action
#
# See docs/content/docs/Actions.md "Async Actions" and
# arch/docs/async-actions.md

load("exec.in", "exec")


def report(dry_run, args):
    # A values result: validated (param errors fail the run, or show inline
    # with the Validate button), then a TABLE stored with the run. print()
    # output goes to the run output
    if args.rows < 1:
        return ace.result("Validation failed", param_errors={"rows": "rows must be at least 1"})
    if args.rows > 100000:
        return ace.result("Validation failed", param_errors={"rows": "at most 100000 rows"})
    if dry_run:
        return ace.result("Ready to build %d rows" % args.rows)
    print("building %d rows with status %s" % (args.rows, args.status))
    values = [{"id": i + 1, "status": args.status, "amount": (i * 37) % 100} for i in range(args.rows)]
    return ace.result("Built %d rows" % args.rows, values, ace.TABLE)


def build(dry_run, args):
    # A streamed command: the output is recorded as it is produced and can
    # be watched on the run page while the run executes (close and reopen
    # the page, the output is still there). steps seconds long; a non zero
    # exit_code fails the run with that code. Cancel from the run page or
    # with "openrun action cancel <run-id>"
    if dry_run:
        return ace.result("Ready to build %d steps" % args.steps)
    script = "for i in $(seq 1 %d); do echo \"step $i of %d\"; sleep 1; done; echo done; exit %d" % (
        args.steps, args.steps, args.exit_code)
    return ace.result("Building", stream=exec.run("sh", ["-c", script], stream=True))


def slow(dry_run, args):
    # The action timeout (timeout="10s" below) ends a run which takes
    # longer: the run is recorded as timed_out
    return ace.result("Sleeping", stream=exec.run("sh", ["-c", "echo started; sleep %d; echo finished" % args.steps], stream=True))


def big_output(dry_run, args):
    # A command printing megabytes: the first and last action.output_head_bytes /
    # action.output_tail_bytes (10MB each by default) are kept, the middle is
    # dropped and marked. Lower the limits to see it with a small run:
    #   openrun app update conf --promote 'action.output_head_bytes=4096' 'action.output_tail_bytes=4096' /async_action
    script = "i=0; while [ $i -lt %d ]; do i=$((i+1)); echo \"line $i of %d: $(head -c 60 /dev/zero | tr '\\0' x)\"; done" % (
        args.lines, args.lines)
    return exec.run("sh", ["-c", script], stream=True)


def big_result(dry_run, args):
    # A large values result: up to action.result_max_bytes (100MB) of JSON is
    # stored, whole rows beyond that are dropped and the run says so. The run
    # page renders the first action.display_rows (1000) rows and offers the
    # stored document as a download
    values = [{"id": i + 1, "payload": "x" * 200} for i in range(args.rows)]
    return ace.result("%d rows" % args.rows, values, ace.JSON)


def crash(dry_run, args):
    # A handler error fails the run with the error message
    if dry_run:
        return ace.result("Will fail when run")
    print("about to fail")
    fail("something went wrong in the handler")


def ping(dry_run, args):
    # A sync action beside the async ones: runs inside the request, no run
    # record
    return ace.result("pong from " + args.status)


app = ace.app("Async Actions",
              actions=[
                  ace.action("Report", "/", report, is_async=True, show_validate=True,
                             description="Builds a table in the background, stored with the run",
                             hidden=["steps", "exit_code", "lines"]),
                  ace.action("Build", "/build", build, is_async=True, show_validate=True,
                             description="Streams a command's output; watch it on the run page, cancel it",
                             hidden=["rows", "status", "lines"]),
                  ace.action("Slow", "/slow", slow, is_async=True, timeout="10s",
                             description="Times out after 10s (set steps above 10)",
                             hidden=["rows", "status", "exit_code", "lines"]),
                  ace.action("Big Output", "/big-output", big_output, is_async=True,
                             description="Prints many lines; the stored output keeps the head and the tail",
                             hidden=["rows", "status", "steps", "exit_code"]),
                  ace.action("Big Result", "/big-result", big_result, is_async=True,
                             description="Returns many rows; the stored result is capped",
                             hidden=["status", "steps", "exit_code", "lines"]),
                  ace.action("Crash", "/crash", crash, is_async=True, show_validate=True,
                             description="Fails in the handler; the run records the error",
                             hidden=["rows", "status", "steps", "exit_code", "lines"]),
                  ace.action("Ping", "/ping", ping,
                             description="A sync action, for comparison",
                             hidden=["rows", "steps", "exit_code", "lines"]),
              ],
              permissions=[ace.permission("exec.in", "run", ["sh"])])
