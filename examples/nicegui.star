# Declarative app config for NiceGUI apps, install by running
#    openrun apply --approve --promote github.com/openrundev/openrun/examples/nicegui.star

ng_args = {"container_opts": {"cpus": "2", "memory": "512m"}, "spec": "python-nicegui"}
app("/nicegui/3d_scene", "https://github.com/zauberzeug/nicegui/examples/3d_scene", **ng_args)
app("/nicegui/chat_app", "https://github.com/zauberzeug/nicegui/examples/chat_app", **ng_args)
app("/nicegui/fullcalendar", "https://github.com/zauberzeug/nicegui/examples/fullcalendar", **ng_args)
app("/nicegui/infinite_scroll", "https://github.com/zauberzeug/nicegui/examples/infinite_scroll", **ng_args)
app("/nicegui/lightbox", "https://github.com/zauberzeug/nicegui/examples/lightbox", **ng_args)
app("/nicegui/todo_list", "https://github.com/zauberzeug/nicegui/examples/todo_list", **ng_args)
