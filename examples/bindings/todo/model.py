import os
from urllib.parse import urlsplit, urlunsplit

import sqlalchemy as sa


def db_url():
    """Build a SQLAlchemy URL from the openrun database binding.

    A postgres binding exposes POSTGRES_URL and a mysql binding exposes
    MYSQL_URL, so the same app works against either without code changes.
    """
    pg = os.getenv("POSTGRES_URL")
    if pg:
        return pg.replace("postgres://", "postgresql+psycopg://", 1)
    my = os.getenv("MYSQL_URL")
    if my:
        parts = urlsplit(my)
        # Drop driver-specific query params (e.g. parseTime) that the Go
        # driver understands but the Python driver does not.
        return urlunsplit(("mysql+pymysql", parts.netloc, parts.path or "/", "", ""))
    raise RuntimeError("No database binding found: set POSTGRES_URL or MYSQL_URL")


def _create_index(db, table, name, *columns):
    try:
        sa.Index(name, *columns).create(db.engine, checkfirst=True)
    except Exception:
        pass


def ensure_search_indexes(db, todo_table=None, project_table=None):
    todo_table = todo_table if todo_table is not None else db.meta.tables.get("todo")
    project_table = project_table if project_table is not None else db.meta.tables.get("project")
    if todo_table is not None:
        _create_index(db, todo_table, "idx_todo_priority", todo_table.c.priority)
        _create_index(db, todo_table, "idx_todo_done_priority", todo_table.c.done, todo_table.c.priority)
        _create_index(db, todo_table, "idx_todo_name_priority", todo_table.c.name, todo_table.c.priority)
        _create_index(db, todo_table, "idx_todo_title", todo_table.c.title)
    if project_table is not None:
        _create_index(db, project_table, "idx_project_name", project_table.c.name)


def search_like_pattern(value):
    value = (value or "").strip().lower()
    value = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{value}%"


class Todo:
    id:int|None=None
    title:str=''
    done:bool=False
    name:str=''
    details:str=''
    priority:int=0
    created_by:str=''
    updated_by:str=''
    createTime:str=''
    updateTime:str=''


class Project:
    id:int|None=None
    name:str=''
    notes:str=''
    created_by:str=''
    updated_by:str=''
    createTime:str=''
    updateTime:str=''
