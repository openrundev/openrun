# OpenRun Grafana Dashboards

These dashboards are intended for local Grafana instances such as
`docker-otel-lgtm`.

## OpenRun config

Use OTLP HTTP export:

```toml
[telemetry]
enabled = true
service_name = "openrun-dev"
environment = "local"
endpoint = "http://localhost:4318"
headers = {}
traces = true
metrics = true
plugin_spans = false
```

If OpenRun runs inside Docker, use:

```toml
endpoint = "http://host.docker.internal:4318"
```

## Import

In Grafana, import:

- `openrun-metrics.json`
- `openrun-traces.json`

During import, select the Prometheus datasource for the metrics dashboard and
the Tempo datasource for the traces dashboard. Leave the `service` variable as
`openrun-dev` unless you changed `telemetry.service_name`.

To create the dashboards, run

```sh
  GRAFANA_URL=http://localhost:3000
  GRAFANA_USER=admin
  GRAFANA_PASS=admin

  for f in deploy/grafana/dashboards/openrun-*.json; do
    jq -n --argjson dashboard "$(cat "$f")" '{
      dashboard: $dashboard,
      overwrite: true,
      folderUid: null
    }' |
    curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
      -H "Content-Type: application/json" \
      -X POST "$GRAFANA_URL/api/dashboards/db" \
      -d @-
  done
```

## Notes

- The public HTTP/HTTPS server wrapper only traces OpenRun-owned routes such as
  `/_openrun/*`. App request visibility comes from app-level spans.
- Plugin call spans only appear when `plugin_spans = true`.
- DB and container panels require `metrics = true`.
- The traces dashboard includes an unfiltered `All Tempo Traces (Diagnostic)`
  panel. If that panel is empty, the collector has no traces for the selected
  time range. If it has traces but the OpenRun panels are empty, check the
  dashboard `service` variable against the trace resource `service.name`.

## Trace checks

When using `docker-otel-lgtm`, these commands help separate export problems
from dashboard query problems:

```sh
curl -s 'http://localhost:3200/api/search?limit=20' | jq
curl -s 'http://localhost:3200/api/search/tag/resource.service.name/values' | jq
curl -s 'http://localhost:3200/api/search/tag/service.name/values' | jq
```

The OpenRun log should also now report asynchronous exporter failures with the
message `OpenTelemetry error`.
