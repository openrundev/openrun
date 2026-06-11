import common

common.configure_tables(create=True)

from common import (
    Brand, FILTERS, Project, Todo, TopBar, all_project_names, all_project_records,
    all_todos, app_base, clean_text, current_user, fmt_time, insert_project,
    insert_todo, make_app, metadata_text, next_todo_priority, project_query, projects,
    rel, safe_project, safe_todo, stamp_created, stamp_updated, todo_counts,
    todo_query, todos, valid_project_name,
)
import json

from fasthtml.common import *

all_projects = all_project_records

# Shared htmx attributes: SWAP swaps the shell, NAV also pushes the URL.
SWAP = dict(hx_target="#admin-shell", hx_swap="outerHTML")
NAV = dict(**SWAP, hx_push_url="true")
PROJECT_TODO_DELETE_ACTIONS = ("clear", "delete", "move")

app, rt = make_app("Todo Admin")


def selected_ids(ids):
    if ids is None:
        return []
    return [ids] if isinstance(ids, int) else list(ids)


def AuditCell(by, when):
    by = clean_text(by)
    date_part, _, clock = fmt_time(when).rpartition(" ")
    return Td(
        Div(date_part or "—", cls="whitespace-nowrap text-sm text-base-content/80"),
        Div(clock, cls="whitespace-nowrap text-xs text-base-content/50") if clock else "",
        Div(by, cls="whitespace-nowrap text-xs text-base-content/40") if by else "",
        cls="hidden w-px whitespace-nowrap align-top md:table-cell")


def ProjectFilter(names, project):
    return Select(
        Option("All projects", value="all", selected=(project == "all")),
        *(Option(name, value=name, selected=(project == name)) for name in names),
        name="project", cls="select select-bordered w-full")


def project_target_options(excluded_ids=()):
    excluded = set(excluded_ids or ())
    return [p for p in all_projects() if p.id not in excluded]


def ProjectTodoDeleteControls(target_projects):
    return Div(
        Label(
            Span("Todos in deleted projects", cls="label-text"),
            Select(
                Option("Clear project", value="clear", selected=True),
                Option("Delete todos", value="delete"),
                Option("Move to another project", value="move"),
                name="todo_action", cls="select select-bordered w-full"),
            cls="form-control min-w-0 flex-1"),
        Label(
            Span("Move todos to target project", cls="label-text"),
            Select(
                Option("Choose target", value=""),
                *(Option(p.name, value=p.name) for p in target_projects),
                name="target_project", cls="select select-bordered w-full"),
            cls="form-control min-w-0 flex-1"),
        cls="grid gap-3 sm:grid-cols-2")


def delete_project(project, user, todo_action="clear", target_project=""):
    old_name = clean_text(project.name)
    todo_action = todo_action if todo_action in PROJECT_TODO_DELETE_ACTIONS else "clear"
    target_project = valid_project_name(target_project) if todo_action == "move" else ""
    affected = 0
    for todo in all_todos():
        if clean_text(todo.name).lower() == old_name.lower():
            affected += 1
            if todo_action == "delete":
                todos.delete(todo.id)
            else:
                todo.name = target_project
                todos.update(stamp_updated(todo, user))
    projects.delete(project.id)
    return affected


def AdminNav(base, page):
    def item(label, route, active):
        return A(label, href=rel(base, route), hx_get=rel(base, route), **NAV,
                 cls="tab " + ("tab-active font-semibold" if active else ""))
    return Div(
        item("Todos", "todo_admin", page == "todos"),
        item("Projects", "project_admin", page == "projects"),
        role="tablist", cls="tabs tabs-boxed bg-base-200")


def ProjectEditor(base, selected_project_id=0, pq="", project_mode="create"):
    selected = safe_project(selected_project_id)
    title = "Create project"
    content = Form(
        Input(name="name", placeholder="Project name", required=True, cls="input input-bordered w-full"),
        Textarea(name="notes", placeholder="Project notes", rows=2, cls="textarea textarea-bordered w-full"),
        Input(type="hidden", name="pq", value=pq),
        Button("Create project", type="submit", cls="btn btn-primary"),
        hx_post=rel(base, "project_create"), **SWAP, cls="grid gap-2")
    if project_mode == "bulk_delete":
        title = "Delete projects"
        content = Div(
            P("Select projects in the table and choose how assigned todos should be handled.", cls="text-sm text-base-content/60"),
            Button("New project", hx_get=rel(base, "project_admin", pq=pq), **NAV, cls="btn btn-ghost w-full sm:w-auto", type="button"),
            cls="grid gap-3")
    elif selected and project_mode == "delete":
        title = "Delete project"
        content = Form(
            Input(type="hidden", name="id", value=selected.id),
            Input(type="hidden", name="pq", value=pq),
            ProjectTodoDeleteControls(project_target_options([selected.id])),
            Div(
                Button("Delete project", type="submit", hx_confirm="Delete this project?", cls="btn btn-error w-full sm:w-auto"),
                Button("Back to edit", hx_get=rel(base, "project_admin", project_id=selected.id, pq=pq), **NAV, cls="btn btn-ghost w-full sm:w-auto", type="button"),
                cls="flex flex-wrap gap-2"),
            hx_post=rel(base, "project_delete"), **SWAP, cls="grid gap-3")
    elif selected:
        title = "Edit project"
        content = Form(
            Input(type="hidden", name="id", value=selected.id),
            Input(type="hidden", name="pq", value=pq),
            Label(Span("Project name", cls="label-text"), Input(name="name", value=selected.name, required=True, cls="input input-bordered w-full"), cls="form-control"),
            Label(Span("Notes", cls="label-text"), Textarea(getattr(selected, "notes", "") or "", name="notes", rows=8, cls="textarea textarea-bordered w-full"), cls="form-control"),
            Div(
                Button("Save project", type="submit", cls="btn btn-primary w-full sm:w-auto"),
                Button("Delete project", hx_get=rel(base, "project_admin", project_id=selected.id, pq=pq, project_mode="delete"), **NAV, cls="btn btn-error w-full sm:w-auto", type="button"),
                Button("New project", hx_get=rel(base, "project_admin", pq=pq), **NAV, cls="btn btn-ghost w-full sm:w-auto", type="button"),
                cls="flex flex-wrap gap-2"),
            hx_post=rel(base, "project_update"), **SWAP, cls="grid gap-3")
    return Section(
        Div(H2(title, cls="card-title"), content, cls="card-body gap-4"),
        cls="card min-w-0 border border-base-300 bg-base-100 shadow-sm")


def ProjectRow(base, project, assigned, selected_id, pq, selectable=False):
    notes = clean_text(getattr(project, "notes", ""))
    open_attrs = dict(hx_get=rel(base, "project_admin", project_id=project.id, pq=pq), **NAV, type="button")
    return Tr(
        Td(Input(type="checkbox", name="ids", value=project.id, cls="checkbox checkbox-sm")) if selectable else "",
        Td(
            Button(project.name, **open_attrs, cls="link link-hover font-semibold normal-case"),
            Div(notes, cls="mt-1 line-clamp-2 max-w-2xl text-sm text-base-content/60") if notes else "",
            cls="align-top"),
        Td(Span(str(assigned), title="Assigned todos", cls="badge badge-ghost badge-sm"), cls="align-top"),
        AuditCell(getattr(project, "created_by", ""), getattr(project, "createTime", "")),
        AuditCell(getattr(project, "updated_by", ""), getattr(project, "updateTime", "")),
        Td(Button("Edit", **open_attrs, cls="btn btn-ghost btn-xs"), cls="align-top text-right"),
        cls="bg-primary/5" if project.id == selected_id else "")


def ProjectManager(base, pq="", project_id=0, project_mode="create"):
    if project_id and project_mode == "create":
        project_mode = "edit"
    bulk_delete = project_mode == "bulk_delete"
    todo_items = all_todos()
    project_items = all_projects()
    visible = project_query(pq)
    rows = [
        ProjectRow(base, p, sum(1 for t in todo_items if clean_text(t.name).lower() == p.name.lower()), project_id, pq, bulk_delete)
        for p in visible
    ]
    header = Thead(Tr(
        Th("") if bulk_delete else "",
        Th("Project", cls="w-full"), Th("Todos"),
        Th("Created", cls="hidden md:table-cell"), Th("Updated", cls="hidden md:table-cell"), Th("")))
    body = Tbody(*rows) if rows else Tbody(Tr(Td(
        "No projects match this search." if pq else "No projects yet.",
        colspan=6 if bulk_delete else 5, cls="py-10 text-center text-base-content/60")))
    table = Div(Table(header, body, cls="table table-zebra table-sm"), cls="w-full overflow-x-auto")
    if bulk_delete:
        table_block = Form(
            Div(
                ProjectTodoDeleteControls(project_target_options()),
                Button("Delete selected", type="submit", hx_confirm="Delete selected projects and apply the selected todo handling?", cls="btn btn-error w-full sm:w-auto"),
                cls="grid gap-3 border-b border-base-300 p-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end"),
            table,
            Input(type="hidden", name="pq", value=pq),
            hx_post=rel(base, "project_bulk_delete"), **SWAP, cls="min-w-0 overflow-hidden rounded-box border border-base-300")
    else:
        table_block = Div(
            Div(Button("Bulk delete", hx_get=rel(base, "project_admin", pq=pq, project_mode="bulk_delete"), **NAV, cls="btn btn-error w-full sm:w-auto", type="button"),
                cls="flex justify-end border-b border-base-300 p-4") if project_mode == "create" else "",
            table,
            cls="min-w-0 overflow-hidden rounded-box border border-base-300")
    return Section(
        Div(
            Div(
                Div(Div("Projects", cls="stat-title"), Div(len(project_items), cls="stat-value text-2xl"), cls="stat"),
                Div(Div("Matching", cls="stat-title"), Div(len(visible), cls="stat-value text-primary text-2xl"), cls="stat"),
                cls="stats stats-horizontal rounded-box bg-base-200"),
            Form(
                Input(type="search", name="pq", value=pq, placeholder="Search projects", cls="input input-bordered w-full"),
                Button("Search", type="submit", cls="btn btn-outline"),
                hx_get=rel(base, "project_admin"), **NAV, cls="grid gap-2 md:grid-cols-[1fr_auto]"),
            table_block,
            cls="card-body gap-4"),
        cls="card min-w-0 border border-base-300 bg-base-100 shadow-sm")


def TodoEditor(base, todo_id=0, view="all", q="", project="all"):
    names = all_project_names()
    todo = safe_todo(todo_id)
    current_project = valid_project_name(todo.name) if todo else ""
    action = "todo_update" if todo else "todo_create"
    return Section(
        Div(
            H2("Todo item", cls="card-title"),
            P(metadata_text(todo), cls="text-xs text-base-content/50") if todo and metadata_text(todo) else "",
            Form(
                Input(type="hidden", name="id", value=todo.id) if todo else "",
                Input(type="hidden", name="view", value=view),
                Input(type="hidden", name="q", value=q),
                Input(type="hidden", name="project", value=project),
                Label(Span("Title", cls="label-text"), Input(name="title", value=todo.title if todo else "", placeholder="Task title", required=True, cls="input input-bordered w-full"), cls="form-control"),
                Label(
                    Span("Project", cls="label-text"),
                    Select(
                        Option("No project", value="", selected=(not current_project)),
                        *(Option(name, value=name, selected=(current_project == name)) for name in names),
                        name="name", cls="select select-bordered w-full"),
                    cls="form-control"),
                Label(Span("Priority", cls="label-text"), Input(type="number", name="todo_priority", value=todo.priority if todo else next_todo_priority(), cls="input input-bordered w-full"), cls="form-control"),
                Label(Span("Notes", cls="label-text"), Textarea(todo.details if todo else "", name="details", rows=3, cls="textarea textarea-bordered w-full"), cls="form-control"),
                Label(Span("Mark as done", cls="label-text"), Input(type="checkbox", name="done", value="1", checked=bool(todo.done) if todo else False, cls="toggle toggle-success"), cls="label cursor-pointer justify-between rounded-box border border-base-300 px-4 py-3"),
                Div(
                    Button("Update todo" if todo else "Create todo", type="submit", cls="btn btn-primary"),
                    Button("Delete todo", hx_post=rel(base, "todo_delete", id=todo.id, view=view, q=q, project=project), hx_confirm="Delete this todo?", **SWAP, cls="btn btn-error", type="button") if todo else "",
                    Button("New todo", hx_get=rel(base, "todo_admin", view=view, q=q, project=project), **NAV, cls="btn btn-ghost", type="button") if todo else "",
                    cls="flex flex-wrap gap-2"),
                hx_post=rel(base, action), **SWAP, cls="grid gap-3"),
            cls="card-body gap-4"),
        cls="card border border-base-300 bg-base-100 shadow-sm")


def FilterButton(base, label, val, view, q, project):
    return Button(label, hx_get=rel(base, "todo_admin", view=val, q=q, project=project), **NAV,
                  cls="btn join-item btn-sm " + ("btn-primary" if view == val else "btn-outline"), type="button")


def TodoRow(base, todo, view, q, project, active_id):
    assigned_project = valid_project_name(todo.name)
    return Tr(
        Td(Input(type="checkbox", name="ids", value=todo.id, cls="checkbox checkbox-sm"), cls="align-top"),
        Td(
            Button(todo.title, hx_get=rel(base, "todo_admin", todo_id=todo.id, view=view, q=q, project=project), **NAV, cls="link link-hover font-semibold normal-case", type="button"),
            Div(todo.details, cls="mt-1 line-clamp-2 max-w-2xl text-sm text-base-content/60") if clean_text(todo.details) else "",
            Div(
                Span(assigned_project, cls="badge badge-ghost badge-sm") if assigned_project else "",
                Span(f"Priority {todo.priority}", cls="badge badge-ghost badge-sm"),
                cls="mt-2 flex flex-wrap gap-1 md:hidden"),
            cls="align-top"),
        Td(Span(assigned_project, cls="badge badge-ghost badge-sm") if assigned_project else Span("—", cls="text-base-content/40"), cls="hidden align-top md:table-cell"),
        Td(Span("Done" if todo.done else "Active", cls="badge badge-sm " + ("badge-success" if todo.done else "badge-info")), cls="align-top"),
        Td(str(todo.priority), cls="hidden align-top tabular-nums md:table-cell"),
        AuditCell(getattr(todo, "created_by", ""), getattr(todo, "createTime", "")),
        AuditCell(getattr(todo, "updated_by", ""), getattr(todo, "updateTime", "")),
        cls="bg-primary/5" if todo.id == active_id else "")


def TodoManager(base, view="all", q="", project="all", todo_id=0):
    names = all_project_names()
    visible = todo_query(view, q, project)
    total, active, done = todo_counts()
    body = Tbody(*(TodoRow(base, t, view, q, project, todo_id) for t in visible)) if visible else Tbody(
        Tr(Td("No todo items match this view.", colspan=7, cls="py-10 text-center text-base-content/60")))
    return Section(
        Div(
            Div(
                Div(Div("Total", cls="stat-title"), Div(total, cls="stat-value text-2xl"), cls="stat"),
                Div(Div("Active", cls="stat-title"), Div(active, cls="stat-value text-info text-2xl"), cls="stat"),
                Div(Div("Done", cls="stat-title"), Div(done, cls="stat-value text-success text-2xl"), cls="stat"),
                cls="stats stats-horizontal rounded-box bg-base-200"),
            Form(
                Input(type="search", name="q", value=q, placeholder="Search todos", cls="input input-bordered w-full"),
                Input(type="hidden", name="view", value=view),
                ProjectFilter(names, project),
                Button("Search", type="submit", cls="btn btn-outline"),
                hx_get=rel(base, "todo_admin"), **NAV, cls="grid gap-2 md:grid-cols-[1fr_14rem_auto]"),
            Div(*(FilterButton(base, lbl, val, view, q, project) for lbl, val in (("All", "all"), ("Active", "active"), ("Done", "done"))), cls="join"),
            Form(
                Div(
                    Select(
                        Option("No change for Status", value=""),
                        Option("Mark active", value="active"),
                        Option("Mark done", value="done"),
                        name="status", cls="select select-bordered min-w-40 flex-1"),
                    Select(
                        Option("No change for Project", value=""),
                        Option("Clear project", value="__clear__"),
                        *(Option(name, value=name) for name in names),
                        name="bulk_project", cls="select select-bordered min-w-48 flex-1"),
                    Label(Input(type="checkbox", name="delete", value="1", cls="checkbox checkbox-error"), Span("Delete selected", cls="label-text whitespace-nowrap"), cls="label min-h-12 cursor-pointer justify-start gap-3 px-0"),
                    Button("Apply bulk update", type="submit", cls="btn btn-primary w-full sm:w-auto"),
                    cls="flex flex-col gap-2 border-b border-base-300 p-4 sm:flex-row sm:flex-wrap sm:items-center"),
                Div(
                    Table(
                        Thead(Tr(Th(""), Th("Todo", cls="w-full"), Th("Project", cls="hidden md:table-cell"), Th("Status"), Th("Priority", cls="hidden md:table-cell"), Th("Created", cls="hidden md:table-cell"), Th("Updated", cls="hidden md:table-cell"))),
                        body, cls="table table-zebra table-sm"),
                    cls="w-full overflow-x-auto"),
                Input(type="hidden", name="view", value=view),
                Input(type="hidden", name="q", value=q),
                Input(type="hidden", name="project", value=project),
                hx_post=rel(base, "todo_bulk_update"), **SWAP, cls="min-w-0 overflow-hidden rounded-box border border-base-300"),
            cls="card-body gap-4"),
        cls="card min-w-0 border border-base-300 bg-base-100 shadow-sm")


def TwoColumn(editor, manager):
    return Div(editor, manager, cls="grid items-start gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]")


def TodoAdminPage(base, view="all", q="", project="all", todo_id=0):
    view = view if view in FILTERS else "all"
    q = clean_text(q)
    project = clean_text(project) or "all"
    if project != "all" and project not in all_project_names():
        project = "all"
    return TwoColumn(TodoEditor(base, todo_id, view, q, project), TodoManager(base, view, q, project, todo_id))


def ProjectAdminPage(base, pq="", project_id=0, project_mode="create"):
    pq = clean_text(pq)
    selected = safe_project(project_id)
    selected_id = selected.id if selected else 0
    if selected_id and project_mode == "create":
        project_mode = "edit"
    return TwoColumn(ProjectEditor(base, selected_id, pq, project_mode), ProjectManager(base, pq, selected_id, project_mode))


def AdminShell(base="", page="todos", view="all", q="", project="all", todo_id=0, project_id=0, pq="", project_mode="create", notice="", push_url=""):
    page = "projects" if page == "projects" else "todos"
    if page == "projects":
        title, subtitle = "Project Admin", "Manage projects and reassign their todos."
        content = ProjectAdminPage(base, pq, project_id, project_mode)
    else:
        title, subtitle = "Todo Admin", "Create, edit, and bulk-update todo items."
        content = TodoAdminPage(base, view, q, project, todo_id)
    return Main(
        Div(
            TopBar(Brand("Todo Console", "Admin"), AdminNav(base, page), max_w="max-w-6xl"),
            Div(
                Div(H1(title, cls="m-0 text-2xl font-bold leading-tight"), P(subtitle, cls="mt-1 text-sm text-base-content/60")),
                Div(Span(notice, cls="text-sm"), cls="alert alert-success py-2 shadow-sm") if notice else "",
                Script(f"history.pushState(null, '', {json.dumps(push_url)});") if push_url else "",
                content,
                cls="mx-auto flex w-full max-w-6xl flex-col gap-4 px-4 py-6 md:px-6"),
            id="admin-shell", hx_select="#admin-shell", cls="min-h-screen bg-base-200 text-base-content"))


@rt("/")
def get(req, view: str = "all", q: str = "", project: str = "all", todo_id: int = 0):
    return Title("Todo Admin"), AdminShell(app_base(req), "todos", view, q, project, todo_id)


@rt
def todo_admin(req, view: str = "all", q: str = "", project: str = "all", todo_id: int = 0):
    return Title("Todo Admin"), AdminShell(app_base(req), "todos", view, q, project, todo_id)


@rt
def project_admin(req, pq: str = "", project_id: int = 0, project_mode: str = "create"):
    return Title("Project Admin"), AdminShell(app_base(req), "projects", project_id=project_id, pq=pq, project_mode=project_mode)


@rt
def dashboard(req, view: str = "all", q: str = "", project: str = "all", todo_id: int = 0):
    return Title("Todo Admin"), AdminShell(app_base(req), "todos", view, q, project, todo_id)


@rt
def project_create(req, name: str = "", notes: str = "", pq: str = ""):
    name = clean_text(name)
    if not name:
        return AdminShell(app_base(req), "projects", pq=pq, notice="Project name is required.")
    existing = {p.name.lower(): p for p in all_projects()}
    if name.lower() in existing:
        return AdminShell(app_base(req), "projects", project_id=existing[name.lower()].id, pq=pq, notice="Project already exists.")
    insert_project(stamp_created(Project(name=name, notes=clean_text(notes)), current_user(req)))
    return AdminShell(app_base(req), "projects", pq=pq, notice="Project created.")


@rt
def project_update(req, id: int, name: str = "", notes: str = "", pq: str = ""):
    project = safe_project(id)
    new_name = clean_text(name)
    if not project or not new_name:
        return AdminShell(app_base(req), "projects", pq=pq, notice="Project could not be updated.")
    if any(p.id != id and p.name.lower() == new_name.lower() for p in all_projects()):
        return AdminShell(app_base(req), "projects", project_id=id, pq=pq, notice="Another project already uses that name.")
    user = current_user(req)
    old_name = clean_text(project.name)
    project.name = new_name
    project.notes = clean_text(notes)
    projects.update(stamp_updated(project, user))
    for todo in all_todos():
        if clean_text(todo.name).lower() == old_name.lower():
            todo.name = new_name
            todos.update(stamp_updated(todo, user))
    return AdminShell(app_base(req), "projects", project_id=id, pq=pq, notice="Project updated.")


@rt
def project_delete(req, id: int, pq: str = "", todo_action: str = "clear", target_project: str = ""):
    project = safe_project(id)
    if not project:
        return AdminShell(app_base(req), "projects", pq=pq, notice="Project could not be deleted.")
    if todo_action == "move":
        target = valid_project_name(target_project)
        if not target or target.lower() == clean_text(project.name).lower():
            return AdminShell(app_base(req), "projects", project_id=id, pq=pq, project_mode="delete", notice="Choose another project to move todos into.")
        target_project = target
    affected = delete_project(project, current_user(req), todo_action, target_project)
    notice = f"Project deleted. Updated {affected} assigned todo{'' if affected == 1 else 's'}."
    return AdminShell(app_base(req), "projects", pq=pq, notice=notice, push_url=rel(app_base(req), "project_admin", pq=pq))


@rt
def project_bulk_delete(req, ids: list[int] | None = None, pq: str = "", todo_action: str = "clear", target_project: str = ""):
    ids = selected_ids(ids)
    if not ids:
        return AdminShell(app_base(req), "projects", pq=pq, notice="Select at least one project.")
    selected_projects = [p for id in ids if (p := safe_project(id))]
    selected_names = {clean_text(p.name).lower() for p in selected_projects}
    if todo_action == "move":
        target = valid_project_name(target_project)
        if not target or target.lower() in selected_names:
            return AdminShell(app_base(req), "projects", pq=pq, notice="Choose a project outside the delete selection to move todos into.")
        target_project = target
    user = current_user(req)
    affected = sum(delete_project(p, user, todo_action, target_project) for p in selected_projects)
    deleted = len(selected_projects)
    notice = f"Deleted {deleted} project{'' if deleted == 1 else 's'}. Updated {affected} assigned todo{'' if affected == 1 else 's'}."
    return AdminShell(app_base(req), "projects", pq=pq, notice=notice, push_url=rel(app_base(req), "project_admin", pq=pq))


@rt
def todo_create(req, title: str = "", name: str = "", details: str = "", todo_priority: int = 0, done: bool = False, view: str = "all", q: str = "", project: str = "all"):
    title = clean_text(title)
    if not title:
        return AdminShell(app_base(req), "todos", view, q, project, notice="Todo title is required.")
    todo = stamp_created(Todo(title=title, done=bool(done), name=valid_project_name(name), details=clean_text(details), priority=todo_priority), current_user(req))
    new_id = insert_todo(todo).id or todo.id
    return AdminShell(app_base(req), "todos", view, q, project, new_id, notice="Todo created.",
                      push_url=rel(app_base(req), "todo_admin", todo_id=new_id, view=view, q=q, project=project))


@rt
def todo_update(req, id: int, title: str = "", name: str = "", details: str = "", todo_priority: int = 0, done: bool = False, view: str = "all", q: str = "", project: str = "all"):
    todo = safe_todo(id)
    title = clean_text(title)
    if not todo or not title:
        return AdminShell(app_base(req), "todos", view, q, project, id, notice="Todo could not be updated.")
    todo.title, todo.name, todo.details = title, valid_project_name(name), clean_text(details)
    todo.priority, todo.done = todo_priority, bool(done)
    todos.update(stamp_updated(todo, current_user(req)))
    return AdminShell(app_base(req), "todos", view, q, project, id, notice="Todo updated.")


@rt
def todo_delete(req, id: int, view: str = "all", q: str = "", project: str = "all"):
    if safe_todo(id):
        todos.delete(id)
    return AdminShell(app_base(req), "todos", view, q, project, notice="Todo deleted.",
                      push_url=rel(app_base(req), "todo_admin", view=view, q=q, project=project))


@rt
def todo_bulk_update(req, ids: list[int] | None = None, status: str = "", bulk_project: str = "", delete: bool = False, view: str = "all", q: str = "", project: str = "all"):
    ids = selected_ids(ids)
    if not ids:
        return AdminShell(app_base(req), "todos", view, q, project, notice="Select at least one todo.")
    user = current_user(req)
    for id in ids:
        todo = safe_todo(id)
        if not todo:
            continue
        if delete:
            todos.delete(id)
            continue
        if status in ("active", "done"):
            todo.done = status == "done"
        if bulk_project == "__clear__":
            todo.name = ""
        elif bulk_project:
            todo.name = valid_project_name(bulk_project)
        todos.update(stamp_updated(todo, user))
    return AdminShell(app_base(req), "todos", view, q, project, notice="Bulk update applied.")


serve()
