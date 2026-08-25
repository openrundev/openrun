load("proxy.in", "proxy")
load("container.in", "container")

app = ace.app(param.app_name,
              routes=[
                  ace.proxy("/", proxy.config(container.URL, preserve_host=param.preserve_host))
              ],
              container=container.config(container.AUTO, port=param.port,
                                         dev_settings={
                                             "target": "builder",
                                             "command": param.dev_command,
                                             "dir": "/app",
                                             "reload": param.dev_reload,
                                             "env_files": ["requirements.txt", "pyproject.toml", "uv.lock"],
                                             "additional_mounts": ["venv:/app/.venv", "uv-cache:/root/.cache/uv"],
                                         }
                                         ),
              permissions=[
                  ace.permission("proxy.in", "config", [container.URL]),
                  ace.permission("container.in", "config", [container.AUTO], secrets=param.secrets)
              ]
       ) 
