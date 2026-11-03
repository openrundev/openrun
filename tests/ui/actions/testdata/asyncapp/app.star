# Fixture for the async action run browser test (TestAsyncRun): one async
# action whose run is recorded with a TABLE result

def rows(dry_run, args):
    if dry_run:
        return ace.result("Arguments are valid")
    return ace.result("Built %d rows" % args.count, [{"id": i + 1, "label": args.label} for i in range(args.count)], ace.TABLE)

app = ace.app("Async Test App", actions=[ace.action("Build Rows", "/rows", rows, is_async=True)])
