// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func TestExecRunTempFileOwnership(t *testing.T) {
	for _, scenario := range []string{"failure", "success", "partial", "stream"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			t.Setenv("TMP", dir)
			t.Setenv("TEMP", dir)
			script := "echo output; exit 1"
			if scenario == "success" {
				script = "echo output"
			}
			call := execRunCall(
				sdk.Kwarg{Name: "path", Value: "sh"},
				sdk.Kwarg{Name: "args", Value: []any{"-c", script}},
				sdk.Kwarg{Name: "stdout_file", Value: true},
				sdk.Kwarg{Name: "process_partial", Value: scenario == "partial"},
				sdk.Kwarg{Name: "stream", Value: scenario == "stream"},
			)
			defer call.Session.End(context.Background()) //nolint:errcheck
			result, err := execCommand(context.Background(), call, nil)
			files, globErr := filepath.Glob(filepath.Join(dir, "openrun-exec-stdout-*"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if scenario == "failure" || scenario == "stream" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if len(files) != 0 {
					t.Fatalf("orphaned temp files: %v", files)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			name, ok := result.(string)
			if !ok || len(files) != 1 || files[0] != name {
				t.Fatalf("unexpected file result: %v, files %v", result, files)
			}
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "output\n" {
				t.Fatalf("file data = %q", data)
			}
		})
	}
}

func execRunCall(kwargs ...sdk.Kwarg) *sdk.Call {
	return &sdk.Call{Function: "run", Kwargs: kwargs, Session: sdk.NewSession("test")}
}

// An omitted env must give the command a clean environment, never the
// server's own environment (which carries server credentials and config).
func TestExecRunOmittedEnvIsEmpty(t *testing.T) {
	t.Setenv("OPENRUN_RUN_TEST_LEAK", "leaked")

	result, err := execCommand(context.Background(), execRunCall(
		sdk.Kwarg{Name: "path", Value: "env"},
		sdk.Kwarg{Name: "args", Value: []any{}},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines, ok := result.([]any)
	if !ok {
		t.Fatalf("result type = %T", result)
	}
	for _, line := range lines {
		s, _ := line.(string)
		if s != "" {
			t.Fatalf("expected empty environment, got %q", s)
		}
	}
}

// An explicit env is passed through as the complete environment.
func TestExecRunExplicitEnv(t *testing.T) {
	result, err := execCommand(context.Background(), execRunCall(
		sdk.Kwarg{Name: "path", Value: "env"},
		sdk.Kwarg{Name: "env", Value: []any{"RUN_TEST_VAR=explicit"}},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := result.([]any)
	if len(lines) != 1 || lines[0] != "RUN_TEST_VAR=explicit" {
		t.Fatalf("unexpected environment: %v", lines)
	}
}

// A child that inherits output pipes must not keep a canceled request or
// cursor stuck in Read/Scan after the shell is killed.
func TestExecCancellationReleasesInheritedPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := execRunCall(
				sdk.Kwarg{Name: "path", Value: "sh"},
				sdk.Kwarg{Name: "args", Value: []any{"-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", pidFile}},
				sdk.Kwarg{Name: "include_stderr", Value: false},
				sdk.Kwarg{Name: "stream", Value: stream},
			)
			defer call.Session.End(context.Background()) //nolint:errcheck
			done := make(chan error, 1)
			parent := ctx
			if stream {
				parent = context.Background()
			} // Next's cancellation must suffice.
			go func() {
				result, err := execCommand(parent, call, nil)
				if err == nil && stream {
					cursor := result.(*sdk.Cursor)
					defer cursor.Close(context.Background()) //nolint:errcheck
					_, _, err = cursor.Next(ctx, 1)
				}
				done <- err
			}()
			deadline := time.Now().Add(3 * time.Second)
			var pid int
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(pidFile)
				if err == nil {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
					if pid > 0 {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("command did not start child")
			}
			// Cleanup also releases the inherited pipes when running against the old code.
			defer func() {
				p, err := os.FindProcess(pid)
				if err == nil {
					_ = p.Kill()
					_ = p.Release()
				}
			}()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled command succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation left command reader blocked on descendant pipes")
			}
		})
	}
}

// The stream cursor delivers output as it is produced (a slow producer's
// line is not held back waiting for a batch), passes long lines intact,
// and reports a non-zero exit as the terminal error after all output
func TestExecStreamPromptDeliveryAndExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	call := execRunCall(
		sdk.Kwarg{Name: "path", Value: "sh"},
		sdk.Kwarg{Name: "args", Value: []any{"-c", "echo first; sleep 1; echo second; exit 7"}},
		sdk.Kwarg{Name: "stream", Value: true},
	)
	defer call.Session.End(context.Background()) //nolint:errcheck
	result, err := execCommand(context.Background(), call, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := result.(*sdk.Cursor)
	defer cursor.Close(context.Background()) //nolint:errcheck

	start := time.Now()
	items, done, err := cursor.Next(context.Background(), 100)
	if err != nil || done {
		t.Fatalf("first batch: items %v done %v err %v", items, done, err)
	}
	if len(items) != 1 || items[0] != "first" {
		t.Fatalf("first batch: %v", items)
	}
	if elapsed := time.Since(start); elapsed > 800*time.Millisecond {
		t.Fatalf("first line was held back for %s", elapsed)
	}

	var rest []any
	for {
		items, done, err = cursor.Next(context.Background(), 100)
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
				t.Fatalf("terminal error: %v", err)
			}
			break
		}
		rest = append(rest, items...)
		if done {
			t.Fatal("stream ended without the exit error")
		}
	}
	if len(rest) != 1 || rest[0] != "second" {
		t.Fatalf("remaining output: %v", rest)
	}
}

func TestExecStreamLongLineAndCleanExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	// A 200KB line exceeds the old scanner's 64KB token limit
	call := execRunCall(
		sdk.Kwarg{Name: "path", Value: "sh"},
		sdk.Kwarg{Name: "args", Value: []any{"-c", "head -c 200000 /dev/zero | tr '\\0' x; echo; echo tail"}},
		sdk.Kwarg{Name: "stream", Value: true},
	)
	defer call.Session.End(context.Background()) //nolint:errcheck
	result, err := execCommand(context.Background(), call, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := result.(*sdk.Cursor)
	defer cursor.Close(context.Background()) //nolint:errcheck

	var output strings.Builder
	for {
		items, done, err := cursor.Next(context.Background(), 100)
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		for _, item := range items {
			output.WriteString(item.(string))
			output.WriteString("\n")
		}
		if done {
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || len(lines[0]) != 200000 || lines[1] != "tail" {
		t.Fatalf("unexpected output: %d lines, first %d bytes, last %q", len(lines), len(lines[0]), lines[len(lines)-1])
	}
}

func TestExecStreamJSONLines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	call := execRunCall(
		sdk.Kwarg{Name: "path", Value: "sh"},
		sdk.Kwarg{Name: "args", Value: []any{"-c", `echo '{"a":1}'; echo '{"a":2}'`}},
		sdk.Kwarg{Name: "stream", Value: true},
		sdk.Kwarg{Name: "parse", Value: "jsonlines"},
	)
	defer call.Session.End(context.Background()) //nolint:errcheck
	result, err := execCommand(context.Background(), call, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := result.(*sdk.Cursor)
	defer cursor.Close(context.Background()) //nolint:errcheck

	var values []any
	for {
		items, done, err := cursor.Next(context.Background(), 100)
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		values = append(values, items...)
		if done {
			break
		}
	}
	if len(values) != 2 || values[0].(map[string]any)["a"] != float64(1) || values[1].(map[string]any)["a"] != float64(2) {
		t.Fatalf("unexpected values: %v", values)
	}
}

// A stream cursor closed before its first Next (the handler discarded it,
// or the response setup failed) must still kill and reap the command
func TestExecStreamCloseBeforeNextReaps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	call := execRunCall(
		sdk.Kwarg{Name: "path", Value: "sh"},
		sdk.Kwarg{Name: "args", Value: []any{"-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", pidFile}},
		sdk.Kwarg{Name: "stream", Value: true},
	)
	defer call.Session.End(context.Background()) //nolint:errcheck
	result, err := execCommand(context.Background(), call, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := result.(*sdk.Cursor)

	deadline := time.Now().Add(3 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("command did not start child")
	}
	defer func() {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
			_ = p.Release()
		}
	}()

	closed := make(chan error, 1)
	go func() { closed <- cursor.Close(context.Background()) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return")
	}
	// The child (process group) must be gone shortly after Close
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d still running after Close", pid)
}

// brokenPipe delivers some output, then fails the read
type brokenPipe struct {
	data   string
	served bool
}

func (b *brokenPipe) Read(p []byte) (int, error) {
	if !b.served {
		b.served = true
		return copy(p, b.data), nil
	}
	return 0, errors.New("pipe broke")
}

func (b *brokenPipe) Close() error { return nil }

// A read failure ends the exec stream with an error, not a clean exit
func TestExecStreamReadErrorIsTerminal(t *testing.T) {
	// The reader, cancellation hook, and Close can call reap concurrently.
	var reaped atomic.Bool
	cursor := streamCursor(context.Background(), exec.Command("true"), &brokenPipe{data: "a\nb\n"}, "",
		func() { reaped.Store(true) }, func() error { return nil })
	defer cursor.Close(context.Background()) //nolint:errcheck

	items, done, err := cursor.Next(context.Background(), 100)
	if err != nil || done || len(items) != 1 || items[0] != "a\nb" {
		t.Fatalf("first batch: items %v done %v err %v", items, done, err)
	}
	_, _, err = cursor.Next(context.Background(), 100)
	if err == nil || !strings.Contains(err.Error(), "pipe broke") {
		t.Fatalf("expected the read error, got %v", err)
	}
	if !reaped.Load() {
		t.Fatal("command was not reaped after the read failure")
	}
}
