# Minimal app with no plugin permissions, used as the source for apps created
# by the rbac_app test app


def handler(req):
    return "child ok"


app = ace.app("rbac child app",
              custom_layout=True,
              routes=[ace.api("/", type=ace.TEXT)],
              )
