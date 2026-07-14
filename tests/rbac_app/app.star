load("openrun.in", "openrun")
load("openrun_admin.in", "openrun_admin")

# Test app for RBAC API enforcement. This app is created with rbac:none auth, so
# requests run as the anonymous user and management plugin calls are RBAC checked
# when RBAC is enabled in the dynamic config.


def handler(req):
    return "rbacapp ok"


def list_handler(req):
    ret = openrun.list_apps()
    if ret.error:
        return "ERROR: " + ret.error
    paths = sorted([app["path"] for app in ret.value])
    return "APPS: " + ",".join(paths)


def perms_handler(req):
    ret = openrun.get_permissions("/rbacapp")
    if ret.error:
        return "ERROR: " + ret.error
    return "PERMS: " + ",".join(sorted(ret.value))


def perms_child_handler(req):
    ret = openrun.get_permissions("/anonapp1")
    if ret.error:
        return "ERROR: " + ret.error
    return "PERMS: " + ",".join(sorted(ret.value))


def create_handler(req):
    # anonymous has app:create granted on /anonapp*. The child app needs no
    # plugin approvals, so approve is not set
    ret = openrun_admin.create_app(path="/anonapp1", source_url="./rbac_child_app", auth="none")
    if ret.error:
        return "ERROR: " + ret.error
    return "CREATED"


def create_approve_handler(req):
    # The approve flag needs approve, which anonymous does not have; the
    # app:create grant alone is not enough
    ret = openrun_admin.create_app(path="/anonapp2", source_url="./rbac_child_app", auth="none", approve=True)
    if ret.error:
        return "ERROR: " + ret.error
    return "CREATED"


def create_bad_handler(req):
    # No app:create grant for /otherapp, this should fail
    ret = openrun_admin.create_app(path="/otherapp", source_url="./rbac_child_app", auth="none")
    if ret.error:
        return "ERROR: " + ret.error
    return "CREATED"


def delete_handler(req):
    # anonymous created /anonapp1, the owner rule allows the delete
    ret = openrun_admin.delete_apps(path_glob="/anonapp1")
    if ret.error:
        return "ERROR: " + ret.error
    return "DELETED"


def delete_other_handler(req):
    # /protected is owned by admin and has no grants for anonymous, this should fail
    ret = openrun_admin.delete_apps(path_glob="/protected")
    if ret.error:
        return "ERROR: " + ret.error
    return "DELETED"


def reload_ok_handler(req):
    # anonymous has app:reload granted on /protected
    ret = openrun_admin.reload_apps(path_glob="/protected", approve=False, promote=False)
    if ret.error:
        return "ERROR: " + ret.error
    return "RELOADED"


def reload_promote_handler(req):
    # reload with promote also needs app:promote, which anonymous does not have
    ret = openrun_admin.reload_apps(path_glob="/protected", approve=False, promote=True)
    if ret.error:
        return "ERROR: " + ret.error
    return "RELOADED"


def approve_other_handler(req):
    # approve is operator only, anonymous has no approve grant on /protected
    ret = openrun_admin.approve_apps(path_glob="/protected")
    if ret.error:
        return "ERROR: " + ret.error
    return "APPROVED"


app = ace.app("rbac test app",
              custom_layout=True,
              routes=[
                  ace.api("/", type=ace.TEXT),
                  ace.api("/list", list_handler, type=ace.TEXT),
                  ace.api("/perms", perms_handler, type=ace.TEXT),
                  ace.api("/perms_child", perms_child_handler, type=ace.TEXT),
                  ace.api("/create", create_handler, type=ace.TEXT),
                  ace.api("/create_approve", create_approve_handler, type=ace.TEXT),
                  ace.api("/create_bad", create_bad_handler, type=ace.TEXT),
                  ace.api("/delete", delete_handler, type=ace.TEXT),
                  ace.api("/delete_other", delete_other_handler, type=ace.TEXT),
                  ace.api("/reload_ok", reload_ok_handler, type=ace.TEXT),
                  ace.api("/reload_promote", reload_promote_handler, type=ace.TEXT),
                  ace.api("/approve_other", approve_other_handler, type=ace.TEXT),
              ],
              permissions=[
                  ace.permission("openrun.in", "list_apps"),
                  ace.permission("openrun.in", "get_permissions"),
                  ace.permission("openrun_admin.in", "create_app"),
                  ace.permission("openrun_admin.in", "delete_apps"),
                  ace.permission("openrun_admin.in", "reload_apps"),
                  ace.permission("openrun_admin.in", "approve_apps"),
              ],
              )
