// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/openrundev/openrun/internal/app"
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
		cmd.Env = env
		if cwd != "" {
			cmd.Dir = cwd
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	if includeStderr {
		cmd.Stderr = cmd.Stdout
	} else {
		cmd.Stderr = &stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// reap kills the process and waits for it, for error paths that return
	// before the normal cmd.Wait; without the wait the child stays a zombie
	var reapOnce sync.Once
	reap := func() {
		reapOnce.Do(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}

	var buf bytes.Buffer
	var tempFile *os.File

	if stdoutToFile {
		tempFile, err = os.CreateTemp("", "openrun-exec-stdout-*")
		if err != nil {
			reap()
			return nil, fmt.Errorf("error creating temporary file: %w", err)
		}
		defer tempFile.Close() //nolint:errcheck
		_, err = io.Copy(tempFile, stdout)

		if err != nil && err != io.EOF {
			reap()
			os.Remove(tempFile.Name()) //nolint:errcheck
			return nil, err
		}
	}

	if stream {
		return streamCursor(cmd, stdout, parse, reap), nil
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
	runErr := cmd.Wait()

	if !processPartial && runErr != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%s: %s", runErr, stderr.String())
		}
		return nil, runErr
	}

	if stdoutToFile {
		return tempFile.Name(), nil
	}

	if parse == "json" {
		var result map[string]any
		if err := json.NewDecoder(&buf).Decode(&result); err != nil {
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
			if err := json.NewDecoder(bytes.NewReader(line)).Decode(&result); err != nil {
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
// returns it from the handler and the server streams the lines to the
// client, pulling batches lazily. The process is reaped when the consumer
// stops early or a scan/parse error aborts the stream.
func streamCursor(cmd *exec.Cmd, stdout io.Reader, parse string, reap func()) *sdk.Cursor {
	scanner := bufio.NewScanner(stdout)
	return &sdk.Cursor{
		TypeName: "exec output",
		LeakKey:  fmt.Sprintf("exec_stream_%p", cmd),
		Stream:   true,
		Next: func(ctx context.Context, max int) ([]any, bool, error) {
			items := make([]any, 0, max)
			for len(items) < max {
				if !scanner.Scan() {
					if scanner.Err() != nil {
						reap()
						return nil, false, fmt.Errorf("scanner error: %w", scanner.Err())
					}
					if err := cmd.Wait(); err != nil {
						return nil, false, fmt.Errorf("cmd failed: %w", err)
					}
					return items, true, nil
				}
				line := scanner.Bytes()
				if parse == "jsonlines" {
					var result map[string]any
					if err := json.NewDecoder(bytes.NewReader(line)).Decode(&result); err != nil {
						reap()
						return nil, false, fmt.Errorf("error parsing JSON output: %w", err)
					}
					items = append(items, result)
				} else {
					items = append(items, string(line))
				}
			}
			return items, false, nil
		},
		Close: func(ctx context.Context) error {
			reap()
			return nil
		},
	}
}
