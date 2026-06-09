from datetime import datetime, timezone
from urllib.parse import urlencode

import sqlalchemy as sa
from fasthtml.common import Div, H1, Link, Main, NotStr, P, Script, Span, Title, fast_app
from fastsql import *
from fastsql.core import flexiclass

from model import Project, Todo, db_url, ensure_search_indexes, search_like_pattern


db = Database(db_url())

todos = None
projects = None

FILTERS = ("all", "active", "done")


def reset_connection():
    """Roll back the shared fastsql connection.

    fastsql reuses a single long-lived connection for every query. If a write
    fails (e.g. the binding account lacks write access), the transaction is left
    aborted and every later query — including reads — fails with "current
    transaction is aborted". Rolling back recovers the connection so the app
    keeps working instead of returning 500s.
    """
    try:
        db.conn.rollback()
    except Exception:
        pass


def configure_tables(create=False):
    global todos, projects
    if create:
        todos = db.create(Todo)
        projects = db.create(Project)
        ensure_search_indexes(db, todos.table, projects.table)
    else:
        flexiclass(Todo)
        flexiclass(Project)
        todos = db.t.todo
        projects = db.t.project
        todos.cls = Todo
        projects.cls = Project
    return todos, projects


def app_base(req):
    return (req.scope.get("root_path") or "").rstrip("/")


def rel(base, path, **params):
    url = f"{base}/{path.lstrip('/')}" if base else path
    vals = {
        k: v
        for k, v in params.items()
        if v not in ("", None)
        and not (k == "selected" and not v)
        and not (k == "view" and v == "all")
        and not (k == "project" and v == "all")
    }
    return f"{url}?{urlencode(vals)}" if vals else url


def clean_text(v):
    return (v or "").strip()


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fmt_time(value):
    """Render a stored ISO timestamp as a short, readable label."""
    value = clean_text(value)
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%b %-d, %Y %H:%M")


def current_user(req, default="unknown", headers_order=None):
    headers = getattr(req, "headers", {})
    headers_order = headers_order or ("X-Openrun-User-Email", "X-Openrun-User", "X-Openrun-User-Id")
    for header in headers_order:
        user = clean_text(headers.get(header, ""))
        if user:
            return user
    return default


def is_logged_in(req):
    headers = getattr(req, "headers", {})
    user = clean_text(headers.get("X-Openrun-User", "")) or current_user(req)
    return user.lower() not in ("", "anonymous", "unknown")


def stamp_created(item, user):
    ts = now_iso()
    item.created_by = user
    item.updated_by = user
    item.createTime = ts
    item.updateTime = ts
    return item


def stamp_updated(item, user):
    ts = now_iso()
    if not clean_text(getattr(item, "created_by", "")):
        item.created_by = user
    if not clean_text(getattr(item, "createTime", "")):
        item.createTime = ts
    item.updated_by = user
    item.updateTime = ts
    return item


def metadata_text(item):
    created_by = clean_text(getattr(item, "created_by", ""))
    updated_by = clean_text(getattr(item, "updated_by", ""))
    create_time = clean_text(getattr(item, "createTime", ""))
    update_time = clean_text(getattr(item, "updateTime", ""))
    parts = []
    if created_by or create_time:
        parts.append(" ".join(p for p in (f"Created by {created_by}" if created_by else "Created", fmt_time(create_time)) if p))
    if updated_by or update_time:
        parts.append(" ".join(p for p in (f"Updated by {updated_by}" if updated_by else "Updated", fmt_time(update_time)) if p))
    return "  •  ".join(parts)


def all_project_records():
    return [p for p in projects(order_by="name") if clean_text(p.name)]


def all_project_names():
    return [p.name for p in all_project_records()]


def all_todos():
    return list(todos(order_by="priority"))


def valid_project_name(name):
    name = clean_text(name)
    if not name:
        return ""
    existing = {p.name.lower(): p.name for p in all_project_records()}
    return existing.get(name.lower(), "")


def safe_project(id):
    if not id:
        return None
    try:
        return projects[id]
    except Exception:
        return None


def safe_todo(id):
    if not id:
        return None
    try:
        return todos[id]
    except Exception:
        return None


def _search(q, *columns):
    """Build a case-insensitive LIKE condition matching q against all columns."""
    joined = []
    for c in columns:
        joined += [sa.func.coalesce(c, ""), sa.literal(" ")]
    text = sa.func.lower(sa.func.concat(*joined[:-1]))
    return text.like(search_like_pattern(q), escape="\\")


def _fetch(cls, stmt):
    with db.engine.begin() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [cls(**dict(row)) for row in rows]


def todo_query(view="all", q="", project="all"):
    t = todos.table
    stmt = sa.select(t).order_by(t.c.priority)
    if view == "active":
        stmt = stmt.where(t.c.done == sa.false())
    elif view == "done":
        stmt = stmt.where(t.c.done == sa.true())
    project = valid_project_name(project) if project != "all" else ""
    if project:
        stmt = stmt.where(t.c.name == project)
    q = clean_text(q)
    if q:
        stmt = stmt.where(_search(q, t.c.title, t.c.name, t.c.details))
    return _fetch(Todo, stmt)


def todo_counts():
    t = todos.table
    done_sum = sa.func.sum(sa.case((t.c.done == sa.true(), 1), else_=0))
    with db.engine.begin() as conn:
        total, done = conn.execute(sa.select(sa.func.count(), done_sum)).one()
    total, done = int(total or 0), int(done or 0)
    return total, total - done, done


def project_query(q=""):
    t = projects.table
    stmt = sa.select(t).order_by(t.c.name)
    q = clean_text(q)
    if q:
        stmt = stmt.where(_search(q, t.c.name, t.c.notes, t.c.created_by, t.c.updated_by, t.c["createTime"], t.c["updateTime"]))
    return _fetch(Project, stmt)


def next_todo_priority():
    return max((t.priority or 0 for t in all_todos()), default=-1) + 1


def _insert_row(table, cls, item):
    """Insert a row with a generated id, portable across postgres and mysql.

    SQLAlchemy core handles dialect-specific identifier quoting, and the id is
    derived from max(id)+1 within the transaction (no postgres-only advisory lock).
    """
    values = {c.name: getattr(item, c.name) for c in table.columns}
    with db.engine.begin() as conn:
        values["id"] = conn.execute(sa.select(sa.func.coalesce(sa.func.max(table.c.id), 0) + 1)).scalar_one()
        conn.execute(sa.insert(table).values(**values))
    return cls(**values)


def insert_project(project):
    return _insert_row(projects.table, Project, project)


def insert_todo(todo):
    return _insert_row(todos.table, Todo, todo)


# --- Shared UI helpers (header, app factory, top bar) ---

ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E"
        "%3Crect width='16' height='16' rx='3' fill='%234f46e5'/%3E%3Cpath d='M4 8.2 6.5 11 12 5' "
        "stroke='white' stroke-width='2' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")

BASE_HDRS = (
    Link(rel="icon", href=ICON),
    Link(href="https://cdn.jsdelivr.net/npm/daisyui@5", rel="stylesheet", type="text/css"),
    Script(src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"),
)

_MARK = NotStr(
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' class='h-5 w-5'>"
    "<rect width='16' height='16' rx='3' fill='currentColor'/>"
    "<path d='M4 8.2 6.5 11 12 5' stroke='white' stroke-width='2' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>"
)


def make_app(title, *extra_hdrs):
    """Create a fasthtml app with the shared headers, light theme and 404 page."""
    def not_found(req, exc):
        return Title(title), Main(Div(H1("Page not found"), P("That page could not be found."), cls="p-10 text-center text-base-content/60"))
    return fast_app(pico=False, exception_handlers={404: not_found}, hdrs=BASE_HDRS + extra_hdrs, htmlkw=dict(lang="en", data_theme="light"))


def Brand(title, subtitle):
    return Div(
        Span(_MARK, cls="grid h-9 w-9 place-items-center rounded-lg bg-primary text-primary-content"),
        Div(Span(title, cls="text-base font-bold leading-none"),
            Span(subtitle, cls="text-xs uppercase tracking-wide text-base-content/50"),
            cls="flex flex-col gap-1"),
        cls="flex items-center gap-3")


def TopBar(brand, right, max_w="max-w-5xl"):
    return Div(
        Div(brand, right, cls=f"mx-auto flex w-full {max_w} items-center justify-between gap-4 px-4 md:px-6"),
        cls="sticky top-0 z-20 border-b border-base-300 bg-base-100/90 py-3 backdrop-blur")
