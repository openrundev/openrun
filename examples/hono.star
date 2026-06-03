hono_args = {"container_opts": {"cpus": "2", "memory": "512m"}, "spec": "js-hono"}

app("basic.:", "github.com/honojs/examples/basic", **hono_args)

app("blog.:", "github.com/honojs/examples/jsx-ssr", **hono_args)
