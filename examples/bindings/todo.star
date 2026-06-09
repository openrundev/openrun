# Declarative app config for bindings demo, install by running
#    openrun apply --approve github.com/openrundev/openrun/examples/bindings/todo.star

# Admin is the base binding
admin_data = binding("/todo-data/admin", config("default_database", "postgres"))
app("/todo/admin", "github.com/openrundev/openrun/examples/bindings/todo", auth="system", 
    spec="python-fasthtml", params={"APP_MODULE":"admin:app"}, bindings=[admin_data.path])

# App data is the binding for the app, it has read on all tables and full access to the todo data
app_data = binding("/todo-data/app", admin_data.path, grants =["read:*", "full:todo"])
app("/todo/app", "github.com/openrundev/openrun/examples/bindings/todo", auth="system",
    spec="python-fasthtml", params={"APP_MODULE":"todo:app"}, bindings=[app_data.path])

# Readonly data is the binding for the view app, it has read on all tables, no write access
readonly_data = binding("/todo-data/view", admin_data.path, grants =["read:*"])
app("/todo/view", "github.com/openrundev/openrun/examples/bindings/todo", spec="python-fasthtml",
    params={"APP_MODULE":"todo:app"}, bindings=[readonly_data.path])
