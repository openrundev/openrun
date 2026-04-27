---
title: "Telemetry"
weight: 700
summary: "Export OpenTelemetry traces and metrics from OpenRun using OTLP HTTP."
---

OpenRun can export OpenTelemetry traces and metrics to an OTLP HTTP collector. Telemetry is disabled by default and is configured in `openrun.toml` under `[telemetry]`.

```toml {filename="openrun.toml"}
[telemetry]
enabled = true
service_name = "openrun-prod"
environment = "prod"
endpoint = "http://otel-collector:4318"
headers = {}
traces = true
metrics = true
plugin_spans = false
```

Use the collector base URL for `endpoint`, such as `http://localhost:4318` or `https://otel.example.com:4318`. OpenRun uses the OTLP HTTP exporters, so traces and metrics are sent to the standard OTLP HTTP paths. If `endpoint` is not set, the OpenTelemetry exporters use the standard `OTEL_EXPORTER_OTLP_*` environment variables.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enables OpenTelemetry setup. |
| `service_name` | `openrun` | Sets the exported `service.name`. If empty, `OTEL_SERVICE_NAME` is used before falling back to `openrun`. |
| `environment` | `""` | Adds `deployment.environment.name` to the exported resource. |
| `endpoint` | `""` | OTLP HTTP endpoint. Use the collector base URL unless you intentionally need a custom signal URL. |
| `headers` | `{}` | Headers sent to the OTLP exporter. Header values can use secret references. |
| `traces` | `true` | Enables trace export when telemetry is enabled. |
| `metrics` | `true` | Enables metric export when telemetry is enabled. |
| `plugin_spans` | `false` | Adds spans around Starlark plugin calls. This can be expensive for apps with many plugin calls. |

## Exported Data

When traces are enabled, OpenRun records spans for OpenRun-owned HTTP routes, app requests, outbound HTTP calls, Starlark handlers, template rendering and container delegate requests. App request spans avoid recording client-supplied paths and query strings directly. If an app has `audit.skip_http_events = true`, OpenRun skips app request spans for that app. If `audit.redact_url = true`, app request spans use a redacted span name.

When metrics are enabled, OpenRun records:

- `openrun.app.request`: app request counters by app and request kind.
- `openrun.app.response`: app response counters by app and status bucket.
- `openrun.app.proxy.bytes`: app reverse proxy bytes by direction.
- `openrun.container.call.duration`: container manager operation latency.
- `openrun.db.call.duration`: database driver operation latency.

Telemetry resources include `service.name`, `service.version`, `service.instance.id`, `openrun.commit` and `openrun.server_id`. If `environment` is set, resources also include `deployment.environment.name`.

## Collector Headers and Secrets

Use `headers` when your collector requires authentication:

```toml {filename="openrun.toml"}
[telemetry]
enabled = true
endpoint = "https://otel.example.com:4318"
headers = { Authorization = 'Bearer {{ secret "OTEL_TOKEN" }}' }
```

Telemetry header values are resolved through the same secret mechanism used by other server config values. See [Secrets Management]({{< ref "secrets" >}}) for supported providers and the `secret_from` syntax.

## Grafana Dashboards

OpenRun includes starter Grafana dashboards for local testing and operations:

- `deploy/grafana/dashboards/openrun-metrics.json`
- `deploy/grafana/dashboards/openrun-traces.json`

The dashboard README in the repository shows a local `docker-otel-lgtm` setup and import commands.
