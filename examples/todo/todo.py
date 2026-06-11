import common

common.configure_tables(create=False)

from common import (
    Brand, FILTERS, Todo, TopBar, all_project_names, app_base, clean_text,
    current_user as common_current_user, insert_todo, is_logged_in, make_app,
    metadata_text, next_todo_priority, rel, reset_connection, safe_todo,
    stamp_created, stamp_updated, todo_counts, todo_query, todos, valid_project_name,
)
from fasthtml.common import *

all_projects = all_project_names
valid_project = valid_project_name

WRITE_ERROR = "Could not save changes — this app may not have write access to tasks."

# Shared htmx attributes for swapping the app shell.
SWAP = dict(hx_target="#app-shell", hx_swap="outerHTML")
OPEN = dict(hx_target="#app-shell", hx_swap="outerHTML show:top")

app, rt = make_app("Todo", SortableJS(".sortable"), MarkdownJS(".markdown"))


def run_write(action):
    """Run a mutating DB action, recovering the shared connection on failure.

    Returns "" on success or a user-facing error if the write failed (e.g. the
    binding account is read-only); the connection is rolled back either way so
    later reads keep working instead of returning 500s.
    """
    try:
        action()
        return ""
    except Exception:
        reset_connection()
        return WRITE_ERROR


def current_user(req):
    return common_current_user(req, default="anonymous",
                               headers_order=("X-Openrun-User", "X-Openrun-User-Email", "X-Openrun-User-Id"))


def ProjectSelect(projects, project):
    return Select(
        Option("All projects", value="all", selected=(project == "all")),
        *(Option(p, value=p, selected=(project == p)) for p in projects),
        name="project", cls="select select-bordered w-full md:w-48")


def ProjectAssignmentSelect(projects, name=""):
    active = valid_project(name)
    return Select(
        Option("No project", value="", selected=(not active)),
        *(Option(p, value=p, selected=(p == active)) for p in projects),
        name="name", cls="select select-bordered w-full")


def FilterButton(base, label, val, view, q, project, selected):
    return Button(label, hx_get=rel(base, "dashboard", view=val, q=q, project=project, selected=selected), **SWAP,
                  cls="btn join-item btn-sm " + ("btn-primary" if view == val else "btn-outline"), type="button")


def Stat(label, val):
    return Div(Div(label, cls="stat-title"), Div(val, cls="stat-value text-primary text-2xl"), cls="stat")


def TaskRow(base, todo, view, q, project, selected, can_sort, can_edit):
    task_project = valid_project(todo.name)
    details = clean_text(todo.details)
    audit = metadata_text(todo)
    sel = " bg-primary/10" if todo.id == selected else ""
    if can_edit:
        status = Input(type="checkbox", checked=todo.done, title="Mark active" if todo.done else "Mark done",
                       hx_post=rel(base, "toggle", id=todo.id, view=view, q=q, project=project, selected=selected),
                       **SWAP, cls="checkbox checkbox-success mt-1")
    else:
        status = Input(type="checkbox", checked=todo.done, disabled=True, cls="checkbox mt-1")
    open_url = rel(base, "dashboard", view=view, q=q, project=project, selected=todo.id)
    title_cls = "btn btn-ghost h-auto min-h-0 w-full justify-start px-0 py-0 text-left text-base font-semibold normal-case "
    title_cls += "text-base-content/50 line-through" if todo.done else "text-base-content"
    return Li(
        status,
        Div(
            Button(todo.title, title="Open task", hx_get=open_url, **OPEN, cls=title_cls, type="button"),
            Div(details, cls="mt-1 line-clamp-2 text-sm text-base-content/60") if details else "",
            Div(Span(task_project, cls="badge badge-outline badge-sm"), cls="mt-2 flex flex-wrap gap-2") if task_project else "",
            Div(audit, cls="mt-1 text-xs text-base-content/50") if audit else "",
            cls="min-w-0"),
        Div(
            Span("::", title="Drag to reorder", cls="hidden cursor-grab select-none px-1 text-lg font-black text-base-content/40 md:inline") if can_sort else "",
            Button("Edit" if can_edit else "Open", hx_get=open_url, **OPEN, cls="btn btn-ghost btn-sm", type="button"),
            cls="flex items-center justify-end gap-1 md:gap-2"),
        Input(type="hidden", name="id", value=todo.id) if can_sort else "",
        id=f"todo-{todo.id}",
        cls=f"grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 border-b border-base-300 p-4 last:border-b-0{sel}")


def TaskList(base, items, view, q, project, selected, can_edit):
    can_sort = can_edit and view == "all" and not q and project == "all" and len(items) > 1
    if not items:
        return Div(P("No tasks match this view." if q or view != "all" else "No tasks yet."), cls="p-10 text-center text-base-content/60")
    attrs = dict(id="todo-list", cls="sortable" if can_sort else "")
    if can_sort:
        attrs.update(hx_post=rel(base, "reorder", view=view, q=q, project=project, selected=selected), hx_trigger="end", **SWAP)
    return Form(Ul(*(TaskRow(base, t, view, q, project, selected, can_sort, can_edit) for t in items), **attrs), method="post")


def DetailPanel(base, todo, view, q, project, projects, can_edit):
    if not todo:
        return ""
    task_project = valid_project(todo.name)
    meta = metadata_text(todo)
    form = ""
    if can_edit:
        form = Form(
            Input(type="hidden", name="id", value=todo.id),
            Label(Span("Title", cls="label-text"), Input(id="title", name="title", value=todo.title, required=True, cls="input input-bordered w-full"), cls="form-control"),
            Label(Span("Project", cls="label-text"), ProjectAssignmentSelect(projects, todo.name), cls="form-control"),
            Label(Span("Notes", cls="label-text"), Textarea(todo.details or "", id="details", name="details", rows=8, placeholder="Add context, links, or a checklist", cls="textarea textarea-bordered w-full"), cls="form-control"),
            Input(type="hidden", name="view", value=view),
            Input(type="hidden", name="q", value=q),
            Input(type="hidden", name="project", value=project),
            Div(
                Button("Save", type="submit", cls="btn btn-primary"),
                Div(
                    Button("Mark active" if todo.done else "Mark done", hx_post=rel(base, "toggle", id=todo.id, view=view, q=q, project=project, selected=todo.id), **SWAP, cls="btn btn-outline btn-sm", type="button"),
                    Button("Cancel", hx_get=rel(base, "dashboard", view=view, q=q, project=project), **SWAP, cls="btn btn-ghost btn-sm", type="button"),
                    cls="flex flex-wrap gap-2"),
                cls="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between"),
            hx_post=rel(base, "replace", selected=todo.id), **SWAP, cls="grid gap-3")
    detail = Div(
        Div(
            Div(P("Selected task", cls="mb-1 text-xs font-bold uppercase text-primary"),
                H2(todo.title, cls="card-title break-words text-2xl"), cls="min-w-0"),
            Div(Span("Done" if todo.done else "Active", cls="badge " + ("badge-success" if todo.done else "badge-info")),
                Span(task_project, cls="badge badge-outline") if task_project else "",
                cls="flex shrink-0 flex-wrap justify-end gap-2"),
            cls="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"),
        P(meta, cls="text-xs text-base-content/50") if meta else "",
        Div(todo.details or "No notes yet.", cls="markdown min-h-24 break-words rounded-box bg-base-200 p-4 text-base-content/70"),
        Div(cls="divider my-2") if can_edit else "",
        form)
    return Section(Div(detail, cls="card-body gap-4"), id="detail-panel", cls="card scroll-mt-4 border border-primary/30 bg-base-100 shadow-sm")


def AppShell(base="", view="all", q="", project="all", selected=0, can_edit=False, error=""):
    view = view if view in FILTERS else "all"
    q = clean_text(q)
    project = clean_text(project) or "all"
    names = all_projects()
    if project != "all" and project not in names:
        project = "all"
    total, active, done = todo_counts()
    visible = todo_query(view, q, project)
    selected_todo = safe_todo(selected)
    if selected_todo and selected_todo.id not in {t.id for t in visible}:
        selected_todo = None
    badge = Span("Editing" if can_edit else "Read only", cls="badge badge-sm " + ("badge-primary" if can_edit else "badge-ghost"))
    add_form = Form(
        Input(name="title", id="new-title", placeholder="Add a task", required=True, cls="input input-bordered w-full"),
        ProjectAssignmentSelect(names),
        Input(type="hidden", name="view", value=view),
        Input(type="hidden", name="q", value=q),
        Input(type="hidden", name="project", value=project),
        Button("Add task", type="submit", cls="btn btn-primary"),
        hx_post=rel(base, "create"), **SWAP, cls="grid gap-3 md:grid-cols-[1fr_14rem_auto]")
    search_form = Form(
        Input(type="search", name="q", value=q, placeholder="Search tasks", cls="input input-bordered w-full"),
        Input(type="hidden", name="view", value=view),
        ProjectSelect(names, project),
        Button("Search", type="submit", cls="btn btn-outline"),
        hx_get=rel(base, "dashboard"), **SWAP, cls="grid w-full gap-2 md:max-w-3xl md:grid-cols-[1fr_12rem_auto]")
    filters = Div(*(FilterButton(base, lbl, val, view, q, project, selected) for lbl, val in (("All", "all"), ("Active", "active"), ("Done", "done"))), cls="join")
    return Main(
        Div(
            TopBar(Brand("Todo", "Work queue"), badge),
            Div(
                Div(
                    Div(P("Tasks", cls="mb-1 text-xs font-bold uppercase tracking-wide text-primary"), H1("Work queue", cls="m-0 text-3xl font-bold leading-tight")),
                    Div(Stat("Total", total), Stat("Active", active), Stat("Done", done), cls="stats w-full overflow-hidden rounded-box border border-base-300 bg-base-100 shadow-sm md:w-auto"),
                    cls="flex flex-col gap-4 md:flex-row md:items-end md:justify-between"),
                Div(Span(error), role="alert", cls="alert alert-error shadow-sm") if error else "",
                DetailPanel(base, selected_todo, view, q, project, names, can_edit),
                Section(
                    Div(add_form, cls="border-b border-base-300 p-4") if can_edit else "",
                    Div(search_form, filters, cls="flex flex-col gap-3 border-b border-base-300 p-4 md:flex-row md:items-center md:justify-between"),
                    TaskList(base, visible, view, q, project, selected, can_edit),
                    Div(Span(f"{len(visible)} shown"), cls="flex items-center justify-between border-t border-base-300 p-4 text-sm text-base-content/60"),
                    cls="card overflow-hidden border border-base-300 bg-base-100 shadow-sm"),
                cls="mx-auto flex w-full max-w-5xl flex-col gap-4 px-4 py-6 md:px-6"),
            id="app-shell", hx_select="#app-shell", cls="min-h-screen bg-base-200 text-base-content"))


@rt("/")
def get(req, view: str = "all", q: str = "", project: str = "all", selected: int = 0):
    return Title("Todo"), AppShell(app_base(req), view, q, project, selected, is_logged_in(req))


@rt
def dashboard(req, view: str = "all", q: str = "", project: str = "all", selected: int = 0):
    return AppShell(app_base(req), view, q, project, selected, is_logged_in(req))


@rt
def reorder(req, id: list[int], view: str = "all", q: str = "", project: str = "all", selected: int = 0):
    if not is_logged_in(req):
        return AppShell(app_base(req), view, q, project, selected, False)
    user = current_user(req)
    def do():
        for i, id_ in enumerate(id):
            todo = todos[id_]
            todo.priority = i
            todos.update(stamp_updated(todo, user))
    error = run_write(do)
    return AppShell(app_base(req), view, q, project, selected, True, error)


@rt
def create(req, title: str = "", name: str = "", view: str = "all", q: str = "", project: str = "all"):
    if not is_logged_in(req):
        return AppShell(app_base(req), view, q, project, 0, False)
    title = clean_text(title)
    if not title:
        return AppShell(app_base(req), view, q, project, 0, True)
    todo = stamp_created(Todo(title=title, name=valid_project(name), priority=next_todo_priority(), done=False, details=""), current_user(req))
    new_id = 0
    def do():
        nonlocal new_id
        new_id = insert_todo(todo).id or todo.id
    error = run_write(do)
    active_project = todo.name if project != "all" and todo.name else project
    return AppShell(app_base(req), view, q, active_project, new_id, True, error)


@rt
def toggle(req, id: int, view: str = "all", q: str = "", project: str = "all", selected: int = 0):
    if not is_logged_in(req):
        return AppShell(app_base(req), view, q, project, selected, False)
    def do():
        todo = todos[id]
        todo.done = not todo.done
        todos.update(stamp_updated(todo, current_user(req)))
    error = run_write(do)
    return AppShell(app_base(req), view, q, project, selected, True, error)


@rt
def replace(req, id: int, title: str = "", name: str = "", details: str = "", view: str = "all", q: str = "", project: str = "all", selected: int = 0):
    if not is_logged_in(req):
        return AppShell(app_base(req), view, q, project, selected, False)
    title = clean_text(title)
    if not title:
        return AppShell(app_base(req), view, q, project, selected, True)
    existing = todos[id]
    existing.title, existing.name, existing.details = title, valid_project(name), clean_text(details)
    error = run_write(lambda: todos.update(stamp_updated(existing, current_user(req))))
    active_project = existing.name if project != "all" and existing.name else project
    return AppShell(app_base(req), view, q, active_project, selected or id, True, error)


serve()
