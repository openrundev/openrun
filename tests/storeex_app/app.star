load("store.ex", "store")

def setup(req):
    store.delete(table.entry, {})
    myt = doc.entry(name="first", val=10)
    ret = store.insert(table.entry, myt)
    if not ret:
        return {"error": ret.error}
    return {"id": ret.value}

def get(req):
    ret = store.select_one(table.entry, {"name": "first"})
    if not ret:
        return {"error": ret.error}
    return {"name": ret.value.name, "val": ret.value.val, "creator": ret.value._created_by}

def count(req):
    ret = store.count(table.entry, {})
    if not ret:
        return {"error": ret.error}
    return {"count": ret.value}

def txn_commit(req):
    store.begin()
    store.insert(table.entry, doc.entry(name="txn", val=20))
    store.commit()
    return {}

def txn_abandon(req):
    store.begin()
    store.insert(table.entry, doc.entry(name="abandoned", val=30))
    # No commit: the transaction rolls back at request end
    return {}

def rows(req):
    ret = store.select(table.entry, {}, sort=["val:asc"])
    names = []
    for row in ret.value:
        names.append(row.name)
    return {"names": names}

def leak(req):
    store.select(table.entry, {})
    # Cursor never read: the request must fail as a leaked resource
    return {}

app = ace.app("storeex test",
    custom_layout=True,
    routes=[
        ace.api("/setup", handler=setup),
        ace.api("/get", handler=get),
        ace.api("/count", handler=count),
        ace.api("/txn_commit", handler=txn_commit),
        ace.api("/txn_abandon", handler=txn_abandon),
        ace.api("/rows", handler=rows),
        ace.api("/leak", handler=leak),
    ],
    permissions=[
        ace.permission("store.ex", "insert"),
        ace.permission("store.ex", "delete"),
        ace.permission("store.ex", "select_one"),
        ace.permission("store.ex", "count"),
        ace.permission("store.ex", "begin"),
        ace.permission("store.ex", "commit"),
        ace.permission("store.ex", "select"),
    ],
)
