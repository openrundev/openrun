load("proxy.in", "proxy")
load("container.in", "container")

def star_job(dry_run, args):
    # A Starlark job: the action handler shape, called in the OpenRun process
    return ace.result("star ok greeting=%s" % args.greeting)

app = ace.app("jobs app",
              routes=[
                  ace.proxy("/", proxy.config(container.URL))
              ],
              container=container.config(container.AUTO, port=param.port),
              jobs=[
                  ace.job("migrate", command=["python", "jobs.py", "migrate"], trigger=ace.before_deploy(), timeout="5m"),
                  ace.job("tick", command=["python", "jobs.py", "tick"], trigger=ace.cron("* * * * *"), timeout="2m"),
                  ace.job("hello", command=["python", "jobs.py", "hello"], params=["greeting"], description="prints the greeting"),
                  ace.job("sleep", command=["python", "jobs.py", "sleep"], timeout="3m"),
                  ace.job("shell", command=["echo shell=$CL_JOB_NAME image=foreign"], shell=True,
                          image="image:python:3.14-slim-bookworm"),
                  ace.job("star", run=star_job, params=["greeting"]),
              ],
              permissions=[
                  ace.permission("proxy.in", "config", [container.URL]),
                  ace.permission("container.in", "config", [container.AUTO]),
              ]
       )
