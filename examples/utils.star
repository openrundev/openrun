
# Declarative app config, install by running
#    openrun apply --approve github.com/openrundev/openrun/examples/utils.star

# Install couple of Hypermedia based apps
app("/utils/bookmarks", "github.com/openrundev/apps/utils/bookmarks")
app("/utils/disk_usage", "github.com/openrundev/apps/system/disk_usage")

# Install a proxy app and a static file app
app("openrun.:", "-", spec="proxy", params={"url": "https://openrun.dev"}) # defaults to / on openrun.localhost domain
app("/misc/event_planner", "github.com/simonw/tools", spec="static_single", params={"index": "event-planner.html"})

# Install container based apps (python and go)
limits = {"cpus": "2", "memory": "512m"} # Set limits (optional)
app("/misc/streamlit_example", "github.com/streamlit/streamlit-example", git_branch="master",
    spec="python-streamlit", container_opts=limits)
app("fasthtml.:", "github.com/AnswerDotAI/fasthtml/examples",
    spec="python-fasthtml",  params={"APP_MODULE":"basic_ws:app"}, container_opts=limits)
app("/misc/go_example", "github.com/golang/example/helloserver", git_branch="master",
    spec="go", params={"port": "8080", "APP_ARGS":"-addr 0.0.0.0:8080"}, container_opts=limits)
