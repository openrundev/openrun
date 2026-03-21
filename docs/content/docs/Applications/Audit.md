---
title: "Audit Events"
weight: 400
summary: "Auditing and viewing events"
---

OpenRun automatically creates audit events for all operations. See [demo](https://audit.demo.clace.io/) for a demo of events viewing.

## Introduction

All operations against the OpenRun server are automatically logged in a database. The default location for this database is `$OPENRUN_HOME/metadata/openrun_audit.db`. This can be configured by setting the property

```toml {filename="openrun.toml"}
[metadata]
audit_db_connection = "sqlite:$OPENRUN_HOME/metadata/openrun_audit.db"
```

The events which are logged are

- All HTTP request except GET, HEAD and OPTIONS
- System events, like app updates and any metadata changes
- Action invocations (suggest, validate and exec)
- Custom events, as defined in app code

## Configuration

The configurable options related to audit events are:

- `app_config.audit.redact_url`: Set to true to redact the API path for HTTP events. By default, the API path, except for query string, is logged
- `app_config.audit.skip_http_events`: Set to true to skip HTTP event logging

The app config options can be set globally in the openrun.toml. It can also be set individually for an app by setting the app metadata. For example,

```sh
openrun app update conf --promote 'audit.redact_url=true' /myapp
```

The retention for audit events is configurable globally. The config settings in `openrun.toml` are:

- `system.http_event_retention_days` : Number of days to retain http events, default 90
- `system.non_http_event_retention_days` : Number of days to retain non-http events, default 180

## Custom Events

HTTP, System and Action events are generated automatically. Apps can also define custom events. To add a custom event, in a handler function, add a call to `ace.audit`. The parameters for `ace.audit` are:

| Property  | Optional |  Type  | Default |                   Notes                   |
| :-------: | :------: | :----: | :-----: | :---------------------------------------: |
| operation |  false   | string |         |         The operation type to log         |
|  target   |  false   | string |         | The target the operation is being done on |
|  detail   |   true   | string |         |       Detailed info about the event       |

For example, the dictionary app [does](https://github.com/openrundev/apps/blob/4e7722235b62c1d22308dc55ce8b65c812354177/misc/dictionary/app.star#L18):

```python
   ace.audit("word_lookup", args.word)
```

This will enable [searching](https://audit.demo.clace.io/?operation=word_lookup) the audit events (using the Viewer app) for all operation of type "word_lookup".

Only the last call to `ace.audit` from a handler function is logged.

## Event Viewer

Events can be viewed by admin using the Event Viewer app [code](https://github.com/openrundev/apps/tree/main/openrun/audit_viewer): [demo](https://audit.demo.clace.io/). To install the app on your instance, run

```sh
openrun app create --approve github.com/openrundev/apps/openrun/audit_viewer /events
```

The event viewer shows events for all apps. This app can be installed with access by admins only.
