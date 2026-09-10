// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/system"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

// execCommand runs a command (on the host, or in the app's container when
// containerHandler is set) and returns its output: a list of lines (or
// parsed JSON), the name of a temp file holding stdout, or a stream cursor.
// Shared by the exec and container modules.
func execCommand(ctx context.Context, call *sdk.Call, containerHandler *app.ContainerHandler) (any, error) {
	var path, parse, cwd string
	var cmdArgs, env []string
	var processPartial, stdoutToFile, stream bool
	includeStderr := true
	if err := sdk.UnpackArgs("run", call, "path", &path, "args?", &cmdArgs, "env?", &env,
		"process_partial?", &processPartial, "stdout_file?", &stdoutToFile, "parse?", &parse,
		"stream?", &stream, "include_stderr?", &includeStderr, "cwd?", &cwd); err != nil {
		return nil, err
	}
	if env == nil {
		// An omitted env means a clean environment. cmd.Env = nil would make
		// os/exec inherit the full server environment, exposing server
		// credentials and configuration to the command
		env = []string{}
	}

	// Validate output format options before starting the process so no error
	// path after Start has to clean up a running command
	if parse != "" && parse != "json" && parse != "jsonlines" {
		return nil, fmt.Errorf("unsupported format: %s", parse)
	}
	if parse == "json" && stream {
		return nil, errors.New("stream response is not supported for JSON output")
	}
	if stdoutToFile && stream {
		return nil, errors.New("stream response cannot be combined with stdout_file")
	}

	var cmd *exec.Cmd
	var err error
	if containerHandler != nil {
		cmd, err = containerHandler.Run(ctx, path, cmdArgs, env)
		if err != nil {
			return nil, fmt.Errorf("error running command in container: %w", err)
		}
		// cwd is not supported in container mode
	} else {
		cmd = exec.CommandContext(ctx, path, cmdArgs...)
		system.SetProcessGroup(cmd)
		cmd.Env = env
		if cwd != "" {
			cmd.Dir = cwd
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// A shell's children may inherit its pipes. Killing only the shell does
	// not interrupt our reads, and Wait can remain stuck copying stderr.
	kill := func() error {
		if containerHandler == nil {
			return system.KillGroup(cmd.Process)
		}
		return cmd.Process.Kill()
	}
	cmd.Cancel = func() error {
		_ = stdout.Close()
		return kill()
	}
	cmd.WaitDelay = 2 * time.Second
	var stderr bytes.Buffer
	if includeStderr {
		cmd.Stderr = cmd.Stdout
	} else {
		cmd.Stderr = &stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// The stream's cancellation callback and reader may finish concurrently.
	// Serialize Wait so the process is reaped exactly once.
	var waitOnce sync.Once
	var waitErr error
	wait := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	var reapOnce sync.Once
	reap := func() {
		reapOnce.Do(func() {
			_ = stdout.Close()
			_ = kill()
			_ = wait()
		})
	}

	var buf bytes.Buffer
	var tempFile *os.File
	keepTempFile := false

	if stdoutToFile {
		tempFile, err = os.CreateTemp("", "openrun-exec-stdout-*")
		if err != nil {
			reap()
			return nil, fmt.Errorf("error creating temporary file: %w", err)
		}
		// Ownership passes to the caller only when the file name is returned.
		defer func() {
			if !keepTempFile {
				_ = os.Remove(tempFile.Name())
			}
		}()
		defer tempFile.Close() //nolint:errcheck // close before removal, including on Windows
		_, err = io.Copy(tempFile, stdout)

		if err != nil && err != io.EOF {
			reap()
			return nil, err
		}
	}

	if stream {
		return streamCursor(ctx, cmd, stdout, parse, reap, wait), nil
	}

	if !stdoutToFile {
		_, err = io.CopyN(&buf, stdout, MAX_BYTES_STDOUT)
		if err != nil && err != io.EOF {
			reap()
			return nil, err
		}
		if err == nil {
			// Output reached the size cap; drain the rest so cmd.Wait does
			// not deadlock on the child blocked writing to a full pipe
			_, _ = io.Copy(io.Discard, stdout)
		}
	}
	runErr := wait()

	if !processPartial && runErr != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%s: %s", runErr, stderr.String())
		}
		return nil, runErr
	}

	if stdoutToFile {
		keepTempFile = true
		return tempFile.Name(), nil
	}

	if parse == "json" {
		var result map[string]any
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("error parsing JSON output: %w", err)
		}
		return []map[string]any{result}, nil
	}

	count := 0
	lines := []any{}
	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for scanner.Scan() {
		line := scanner.Bytes()
		count++
		if parse == "jsonlines" {
			var result map[string]any
			if err := json.Unmarshal(line, &result); err != nil {
				return nil, fmt.Errorf("error parsing JSON output: %w", err)
			}
			lines = append(lines, result)
		} else {
			lines = append(lines, string(line))
		}
	}

	if count == 0 && runErr != nil {
		// if no lines in stdout and there was an error (processPartial case), return the error
		return nil, runErr
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return lines, nil
}

// streamCursor wraps the command's output as a stream cursor: the app
// returns it from the handler (or an action returns it in ace.result) and
// the server streams the output to the client as it is produced. The
// producer reads the pipe in chunks of complete lines (system.StreamLines),
// so a slow command's single line is delivered promptly while a firehose
// arrives in 64KB chunks, and lines of any length pass through. Output items
// are plain strings, or one map per line for parse="jsonlines". When the
// output ends the exit status is checked: a non-zero exit is yielded as the
// stream's terminal error (wrapping *exec.ExitError, so consumers can
// recover the code) after all output has been delivered. The process is
// reaped when the consumer stops early or the cursor is closed
func streamCursor(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, parse string, reap func(), wait func() error) *sdk.Cursor {
	cursor := sdk.PushCursor(ctx, "exec output", fmt.Sprintf("exec_stream_%p", cmd), true,
		func(ctx context.Context, yield func(any, error) bool) {
			// A closed cursor (client disconnect) cancels this context: kill
			// the process so the pipe read returns
			stopCancel := context.AfterFunc(ctx, reap)
			defer stopCancel()

			completed := true
			system.StreamLines(stdout, nil)(func(v any, err error) bool {
				if err != nil {
					// A read failure cuts the stream: report it as the
					// terminal error rather than a clean exit
					reap()
					yield(nil, err)
					completed = false
					return false
				}
				chunk := v.(string)
				if parse != "jsonlines" {
					if !yield(chunk, nil) {
						completed = false
						return false
					}
					return true
				}
				for line := range strings.SplitSeq(chunk, "\n") {
					if line == "" {
						continue
					}
					var result map[string]any
					if err := json.Unmarshal([]byte(line), &result); err != nil {
						reap()
						yield(nil, fmt.Errorf("error parsing JSON output: %w", err))
						completed = false
						return false
					}
					if !yield(result, nil) {
						completed = false
						return false
					}
				}
				return true
			})
			if !completed {
				reap()
				return
			}
			if err := wait(); err != nil {
				yield(nil, fmt.Errorf("cmd failed: %w", err))
			}
		})
	// The process is already running when the cursor is created, but the
	// producer (and its cancel hook) only starts on the first Next. A
	// cursor closed before it is ever read (the handler returned another
	// result, or the response setup failed) must still reap the command
	innerClose := cursor.Close
	cursor.Close = func(ctx context.Context) error {
		err := innerClose(ctx)
		reap()
		return err
	}
	return cursor
}
