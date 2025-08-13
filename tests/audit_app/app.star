load("openrun.in", "openrun")

def handler(req):
    ret = openrun.list_audit_events(app_glob="/audittestapp")
    events = ret.value
    if len(events) != 2:
        return "Error: expected 2 audit events, got %d %s" % (len(events), events)
    if events[0]["operation"] != "testop2" or events[0]["target"] != "testtarget2" or events[0]["detail"] != "did op 2":
        return "Invalid event1 %s" % events[0]

    ret = openrun.list_audit_events(target="invalid")
    events = ret.value
    if len(events) != 0:
        return "Error: expected no audit events, got %d %s" % (len(events), events)

    ret = openrun.list_audit_events(operation="reload_apps")
    events = ret.value
    if len(events) == 0:
        return "Error: expected some audit events, got %d %s" % (len(events), events)
    if events[0]["operation"] != "reload_apps_promote":
        return "Invalid event2 %s" % events[0]

    return "OK"


def audit_handler(req):
    ace.audit("testop1", "testtarget2", "did op 1")
    ace.audit("testop2", "testtarget2", "did op 2")
    return "OK"

app = ace.app("audit app",
              routes = [
               ace.api("/", type=ace.TEXT),
               ace.api("/audit", audit_handler, type=ace.TEXT)
              ],
              permissions = [ace.permission("openrun.in", "list_audit_events")],
            )
