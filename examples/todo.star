# Declarative app config for bindings demo, install by running
#    openrun apply --approve github.com/openrundev/openrun/examples/todo.star

default_database = config("default_database", "postgres")

# Two installation of the todo app, each gets it own database binding
# The default auto generated binding is used for both installations
app("/todo1", "github.com/openrundev/openrun/examples/todo", auth="system", 
    spec="python-fasthtml", params={"APP_MODULE":"admin:app"}, bindings=[default_database])

app("/todo2", "github.com/openrundev/openrun/examples/todo", auth="system", 
    spec="python-fasthtml", params={"APP_MODULE":"admin:app"}, bindings=[default_database])