// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// chunkedReader returns its chunks one Read call at a time, simulating a
// pipe delivering partial writes
type chunkedReader struct {
	chunks []string
	pos    int
	closed bool
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.pos])
	c.chunks[c.pos] = c.chunks[c.pos][n:]
	if c.chunks[c.pos] == "" {
		c.pos++
	}
	return n, nil
}

func (c *chunkedReader) Close() error {
	c.closed = true
	return nil
}

func collectStream(t *testing.T, reader *chunkedReader) []string {
	t.Helper()
	cleaned := false
	stream := streamLogLines(reader, func() { cleaned = true })
	values := []string{}
	stream(func(v any, err error) bool {
		testutil.AssertNoError(t, err)
		values = append(values, v.(string))
		return true
	})
	testutil.AssertEqualsBool(t, "reader closed", true, reader.closed)
	testutil.AssertEqualsBool(t, "cleanup ran", true, cleaned)
	return values
}

func TestStreamLogLinesChunking(t *testing.T) {
	// Complete lines per read are yielded as one chunk without the trailing
	// newline; a partial line is held until its newline arrives
	reader := &chunkedReader{chunks: []string{
		"line1\nline2\npar", "tial\n", "tail no newline"}}
	values := collectStream(t, reader)

	expected := []string{"line1\nline2", "partial", "tail no newline"}
	testutil.AssertEqualsInt(t, "chunk count", len(expected), len(values))
	for i, want := range expected {
		testutil.AssertEqualsString(t, "chunk", want, values[i])
	}
}

func TestStreamLogLinesEmptyAndBlank(t *testing.T) {
	// Blank lines survive the round trip: each yielded value is terminated
	// with one newline by the response writer
	reader := &chunkedReader{chunks: []string{"\n", "a\n\nb\n"}}
	values := collectStream(t, reader)

	expected := []string{"", "a\n\nb"}
	testutil.AssertEqualsInt(t, "chunk count", len(expected), len(values))
	for i, want := range expected {
		testutil.AssertEqualsString(t, "chunk", want, values[i])
	}
}

func TestStreamLogLinesLongLineBounded(t *testing.T) {
	// A newline-less line longer than the cap is force-broken so the partial
	// buffer stays bounded
	long := strings.Repeat("x", maxLogChunkBytes+1000)
	reader := &chunkedReader{chunks: []string{long}}
	values := collectStream(t, reader)

	total := 0
	for _, v := range values {
		if len(v) > maxLogChunkBytes+64*1024 {
			t.Fatalf("chunk exceeds bound: %d bytes", len(v))
		}
		total += len(v)
	}
	testutil.AssertEqualsInt(t, "total bytes", len(long), total)
	if len(values) < 2 {
		t.Fatalf("expected a forced break, got %d chunks", len(values))
	}
}

func TestStreamLogLinesEarlyStop(t *testing.T) {
	// The consumer stopping early (client disconnect) still runs cleanup
	reader := &chunkedReader{chunks: []string{"a\n", "b\n", "c\n"}}
	cleaned := false
	stream := streamLogLines(reader, func() { cleaned = true })
	count := 0
	stream(func(v any, err error) bool {
		count++
		return false
	})
	testutil.AssertEqualsInt(t, "yields", 1, count)
	testutil.AssertEqualsBool(t, "reader closed", true, reader.closed)
	testutil.AssertEqualsBool(t, "cleanup ran", true, cleaned)
}

func TestContainerAPIsWithCommandRuntime(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	runtime := filepath.Join(t.TempDir(), "fake-runtime")
	script := `#!/bin/sh
case "$1" in
ps)
  echo '{"ID":"ctr-b","Names":"beta","Image":"img:b","State":"running","Status":"Up","Ports":"8080/tcp","CreatedAt":"2026-01-02T03:04:05Z","Labels":"dev.openrun.app.id=app_dev_beta,dev.openrun.app.path=/old"}'
  echo '{"ID":"ctr-a","Names":"alpha","Image":"img:a","State":"exited","Status":"Exited","Ports":"80/tcp","CreatedAt":"2026-01-01T03:04:05Z","Labels":"dev.openrun.app.id=app_prd_alpha,dev.openrun.app.path=/alpha"}'
  echo '{"ID":"kube","Names":"k8s_hidden","Labels":"dev.openrun.app.id=app_prd_hidden"}'
  ;;
inspect)
  echo '[{"Id":"ctr-b","Name":"/beta","Created":"2026-01-02T03:04:05Z","RestartCount":2,"SizeRw":12,"SizeRootFs":34,"Config":{"Image":"img:b","Entrypoint":["/bin/app"],"Cmd":["serve"],"Labels":{"dev.openrun.app.id":"app_dev_beta","dev.openrun.app.path":"/beta","dev.openrun.app.version":"7"}},"State":{"Status":"running","StartedAt":"2026-01-02T03:05:00Z","ExitCode":0,"Health":{"Status":"healthy"}},"NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"","HostPort":"18080"}],"9090/tcp":null}},"Mounts":[{"Type":"bind","Source":"/src","Destination":"/app","RW":true},{"Type":"volume","Name":"data","Destination":"/data","RW":false}]}]'
  ;;
stats)
  echo '{"CPUPerc":"1.2%","MemUsage":"10MiB / 1GiB","MemPerc":"1%","NetIO":"1kB / 2kB","BlockIO":"3kB / 4kB","PIDs":"5"}'
  ;;
logs)
  echo 'first log line'
  echo 'second log line'
  ;;
start|stop)
  ;;
*)
  echo "unexpected command" >&2
  exit 1
  ;;
esac
`
	if err := os.WriteFile(runtime, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	server.staticConfig.System.ContainerCommand = runtime

	infos, err := server.ListManagedContainers(ctx)
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	if len(infos) != 2 || infos[0].Name != "alpha" || infos[1].Env != "dev" ||
		infos[1].Runtime != filepath.Base(runtime) {
		t.Fatalf("container infos = %#v", infos)
	}

	detail, err := server.GetManagedContainer(ctx, "ctr-b", true)
	if err != nil {
		t.Fatalf("get container: %v", err)
	}
	if detail.Name != "beta" || detail.Command != "/bin/app serve" || detail.Health != "healthy" ||
		detail.Stats == nil || detail.Stats.CPUPercent != "1.2%" || len(detail.Mounts) != 2 ||
		len(detail.PortBindings) != 2 {
		t.Fatalf("container detail = %#v", detail)
	}

	logs, err := server.GetManagedContainerLogs(ctx, "ctr-b", 0)
	if err != nil || !strings.Contains(logs, "second log line") {
		t.Fatalf("container logs = %q, %v", logs, err)
	}
	stream, err := server.GetManagedContainerLogsStream(ctx, "ctr-b", 0, true)
	if err != nil {
		t.Fatalf("container log stream: %v", err)
	}
	streamed := []string{}
	stream(func(value any, err error) bool {
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		streamed = append(streamed, value.(string))
		return true
	})
	if len(streamed) != 1 || !strings.Contains(streamed[0], "first log line\nsecond log line") {
		t.Fatalf("streamed logs = %v", streamed)
	}

	if err := server.StartManagedContainer(ctx, "ctr-b"); err != nil {
		t.Fatalf("start container: %v", err)
	}
	if err := server.StopManagedContainer(ctx, "ctr-b"); err != nil {
		t.Fatalf("stop container: %v", err)
	}
	if stats := server.containerStats(ctx, runtime, "ctr-b"); stats == nil || stats.PIDs != "5" {
		t.Fatalf("container stats = %#v", stats)
	}

	server.staticConfig.System.ContainerCommand = ""
	if _, err := server.GetManagedContainer(context.Background(), "ctr-b", false); err == nil {
		t.Fatal("missing runtime was accepted")
	}
	server.staticConfig.System.ContainerCommand = types.CONTAINER_KUBERNETES
	if err := server.StartManagedContainer(ctx, "ctr-b"); err == nil ||
		!strings.Contains(err.Error(), "app reload") {
		t.Fatalf("Kubernetes lifecycle error = %v", err)
	}
}

func TestContainerAPIParsingAndKubernetesPodInfo(t *testing.T) {
	if entries, err := parseJSONObjects(nil); err != nil || entries != nil {
		t.Fatalf("empty parse = %#v, %v", entries, err)
	}
	array, err := parseJSONObjects([]byte(`[{"Id":"one"},{"Id":"two"}]`))
	if err != nil || len(array) != 2 {
		t.Fatalf("array parse = %#v, %v", array, err)
	}
	lines, err := parseJSONObjects([]byte("{\"Id\":\"one\"}\n\n{\"Id\":\"two\"}\n"))
	if err != nil || len(lines) != 2 {
		t.Fatalf("line parse = %#v, %v", lines, err)
	}
	for _, invalid := range [][]byte{[]byte("["), []byte("{bad}")} {
		if _, err := parseJSONObjects(invalid); err == nil {
			t.Fatalf("invalid JSON %q accepted", invalid)
		}
	}

	entry := map[string]any{
		"fallback": "value",
		"number":   float64(42),
		"flag":     true,
		"map":      map[string]any{"key": "value"},
		"slice":    []any{"one", float64(2), "three"},
		"Labels":   map[string]any{"a": "b", "ignored": float64(1)},
		"Names":    []any{"one", "two"},
		"Ports": []any{
			map[string]any{"host_port": float64(8080), "container_port": float64(80)},
			map[string]any{"container_port": float64(81)},
		},
		"Created": float64(1),
	}
	if entryString(entry, "missing", "fallback") != "value" || entryFloat(entry, "number") != 42 ||
		!entryBool(entry, "flag") || entryMap(entry, "map")["key"] != "value" ||
		len(entryStringSlice(entry, "slice")) != 2 || entryNames(entry) != "one, two" ||
		entryPorts(entry) != "8080->80" || entryCreatedAt(entry) == "" ||
		entryLabels(entry)["a"] != "b" {
		t.Fatalf("entry helpers produced unexpected values")
	}
	if labels := entryLabels(map[string]any{"Labels": "a=b,broken,c=d"}); labels["a"] != "b" || labels["c"] != "d" {
		t.Fatalf("string labels = %v", labels)
	}

	ready := kubernetesPodInfo(&container.WorkloadPod{
		Name: "pod", Phase: "Running", Ready: true, AppId: "app_prd_one", PodIP: "10.0.0.1",
	})
	if ready.State != "running" || ready.Status != "Running (ready)" {
		t.Fatalf("ready pod info = %#v", ready)
	}
	notReady := kubernetesPodInfo(&container.WorkloadPod{Name: "pod", Phase: "Running"})
	if notReady.Status != "Running (not ready)" {
		t.Fatalf("not-ready pod info = %#v", notReady)
	}
}
