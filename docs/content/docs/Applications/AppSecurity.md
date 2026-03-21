---
title: "Application Security"
weight: 300
summary: "Application Security and sandboxing model for OpenRun"
---

OpenRun applications run in a sandbox environment with no direct access to the system or OpenRun service. All access is through plugins. When an application is installed, the admin can audit the application for what access is being requested. Only the permissions which are approved are allowed at runtime.

## Security Model

The security model used by OpenRun is:

- The application code written in Starlark(python) and HTML templates is untrusted.
- The OpenRun service and plugin code (in Go) are trusted.
- The admin can audit and approve the access required by the untrusted application code when the app is being installed.
- After installation, further application code updates do not require any further audit, as long as no new permissions are required. If the updated app code requires any new permission, the new plugin call will fail at runtime with a permission error.

The trust boundary is about what the application can do in the backend. The frontend code is sandboxed by the browser, there is no additional auditing implemented for the frontend code.

For apps which make calls to external programs (using `exec` plugin) and containerized apps, the external program runs as usual. The OpenRun security model applies for Starlark apps. For other apps, the security model allows control on which program to run and what args to pass and which container to use. But there is no restriction on what the external program or container itself can do.

## Usecases

This security model allows for the following:

- Users can download applications and run on their machine, without worrying about what operations the app can do on their system outside the audited permissions.
- Operations teams can install and approve applications. Further application updates can be handled by the development team, without requiring the operational admins to verify the updated code. As long as the application works within the originally defined permission boundary, application updates will continue to work.
- Application developers can use LLM powered automated code generation tools without worrying about the side-effects of the code. If the generated code tries to perform any operation not previously approved, it will fail.

## Sample Application

As an example, the disk usage analysis app requires [two permissions](https://github.com/openrundev/openrun/blob/8b8975cea2d650c9f80dab6eb70cc5b2ddbe5c40/examples/disk_usage/app.star#L42)

```python {filename="app.star"}
app = ace.app("Disk Usage",
              routes=[ace.html("/", partial="du_table_block")],
              permissions=[
                  ace.permission("exec.in", "run", ["du"]),
                  ace.permission("exec.in", "run", ["readlink"])
              ],
              style=ace.style("https://unpkg.com/mvp.css@1.14.0/mvp.css"),
              )
```

It requests permission to use the `exec.in` plugin to `run` two CLI commands, first being `du` and other being `readlink`. When installing the app

```bash
$ openrun app create ./examples/disk_usage/ /utils/disk_usage
App audit results /utils/disk_usage : app2WPQHwr5ZpKELqh0TvP5YMSnbab
  Plugins :
    exec.in
  Permissions:
    exec.in.run [du]
    exec.in.run [readlink]
App created. Permissions need to be approved
```

an audit report is shown with these requests. To approve the requested permissions, the admin can do

```bash
$ openrun app approve /utils/disk_usage
App audit: /utils/disk_usage
  Plugins :
    exec.in
  Permissions:
    exec.in.run [du]
    exec.in.run [readlink]
App permissions have been approved.
```

The approval can be done during the app create itself, in that case the app is installed and approved immediately. None of the plugin code runs during the app creation, even for calls at the global scope. If the audit report does not match expectations, the app can be deleted.

```bash
$ openrun app create --approve ./examples/disk_usage/ /utils/disk_usage
App audit results /utils/disk_usage : app2WPQpws6C1mWb6BujYGOdWMnF1C
  Plugins :
    exec.in
  Permissions:
    exec.in.run [du]
    exec.in.run [readlink]
App created. Permissions have been approved

$ openrun app delete /utils/disk_usage
App deleted /utils/disk_usage
```

Once the app is created, if the application code is updated to change [the line](https://github.com/openrundev/openrun/blob/8b8975cea2d650c9f80dab6eb70cc5b2ddbe5c40/examples/disk_usage/app.star#L9) from

```python {filename="app.star"}
    ret = exec.run("readlink", ["-f", current], process_partial=True)
```

to

```python {filename="app.star"}
    ret = exec.run("rm", ["-f", current], process_partial=True)
```

The app will fail at runtime with an error like

```
app /utils/disk_usage is not permitted to call exec.in.run with argument 0 having value "rm", expected "readlink". Update the app or audit and approve permissions
```

The app cannot be run until either the code change is reverted or the admin approves the new call to rm.
