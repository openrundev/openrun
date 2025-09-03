# Declarative app config for Reflex apps, install by running
#    openrun apply --approve --promote github.com/openrundev/openrun/examples/reflex.star

rf_args = {"container_opts": {"cpus": "2", "memory": "512m"}, "spec": "python-reflex"}
app("counter.:", "github.com/reflex-dev/reflex-examples/counter", **rf_args)
app("clock.:", "github.com/reflex-dev/reflex-examples/clock", **rf_args)
app("quiz.:", "github.com/reflex-dev/reflex-examples/quiz", **rf_args)
