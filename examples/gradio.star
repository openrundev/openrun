# Declarative app config for Gradio apps, install by running
#    openrun apply --approve --promote github.com/openrundev/openrun/examples/gradio.star

gr_args = {"container_opts": {"cpus": "2", "memory": "512m"}, "spec": "python-gradio"}
app("/gradio/plot", "github.com/gradio-app/gradio/demo/bar_plot", **gr_args)
app("/gradio/blocks_group", "github.com/gradio-app/gradio/demo/blocks_group", **gr_args)
app("/gradio/count_generator", "github.com/gradio-app/gradio/demo/count_generator", **gr_args)

