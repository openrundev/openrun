load("build.in", "build")

SESSION_ID = "bld_ses_starlarkapi1"


def error_text(response):
    error = response.error
    return "" if error == None else error


def reads(req):
    sessions = build.list_sessions(all_users=False).value
    session = build.get_session(id=SESSION_ID).value
    messages = build.get_messages(id=SESSION_ID).value
    files = build.list_files(id=SESSION_ID).value
    content = build.read_file(id=SESSION_ID, path="app.star").value
    activity = build.list_activity(id=SESSION_ID, limit=10).value
    publish = build.get_publish_config(session_id=SESSION_ID).value
    publish_without_session = build.get_publish_config().value
    checked = build.check_publish_path(id=SESSION_ID, path="/new-app").value
    return {
        "session_count": len(sessions),
        "session": session,
        "messages": messages,
        "files": files,
        "content": content,
        "activity": activity,
        "publish": publish,
        "publish_without_session": publish_without_session,
        "checked": checked,
    }


def events(req):
    return {"error": error_text(build.session_events(id=SESSION_ID))}


def actions(req):
    create_error = error_text(build.create_session(
        name="Created from Starlark",
        prompt="Build a small app",
        services=[],
    ))
    send_error = error_text(build.send_message(id=SESSION_ID, message="Continue"))
    cancel_error = error_text(build.cancel_turn(id=SESSION_ID))
    stop_error = error_text(build.stop_session(id=SESSION_ID))
    resume_error = error_text(build.resume_session(id=SESSION_ID))
    publish_error = error_text(build.publish_app(
        id=SESSION_ID,
        path="/published-app",
        commit_msg="Test publish",
    ))
    unpublish_error = error_text(build.unpublish_app(
        id=SESSION_ID,
        commit_msg="Test unpublish",
    ))
    checks = build.verify_config(test_prompt=False).value
    return {
        "create": create_error,
        "send": send_error,
        "cancel": cancel_error,
        "stop": stop_error,
        "resume": resume_error,
        "publish": publish_error,
        "unpublish": unpublish_error,
        "checks": checks,
    }


def source(req):
    result = build.get_source_zip(id=SESSION_ID)
    if not result:
        return result.error
    return ace.response(
        result.value["content"],
        download=result.value["name"],
        content_type="application/zip",
    )


def delete(req):
    return {"error": error_text(build.delete_session(id=SESSION_ID))}


app = ace.app(
    "Builder API coverage app",
    routes=[
        ace.api("/reads", handler=reads),
        ace.api("/events", handler=events),
        ace.api("/actions", handler=actions),
        ace.api("/source", handler=source),
        ace.api("/delete", handler=delete),
    ],
    permissions=[
        ace.permission("build.in", "list_sessions"),
        ace.permission("build.in", "get_session"),
        ace.permission("build.in", "get_messages"),
        ace.permission("build.in", "session_events"),
        ace.permission("build.in", "list_files"),
        ace.permission("build.in", "read_file"),
        ace.permission("build.in", "get_source_zip"),
        ace.permission("build.in", "get_publish_config"),
        ace.permission("build.in", "list_activity"),
        ace.permission("build.in", "create_session"),
        ace.permission("build.in", "send_message"),
        ace.permission("build.in", "cancel_turn"),
        ace.permission("build.in", "stop_session"),
        ace.permission("build.in", "resume_session"),
        ace.permission("build.in", "delete_session"),
        ace.permission("build.in", "check_publish_path"),
        ace.permission("build.in", "publish_app"),
        ace.permission("build.in", "unpublish_app"),
        ace.permission("build.in", "verify_config"),
    ],
)
