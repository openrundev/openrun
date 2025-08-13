// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"go.starlark.net/starlark"
)

func execCommand(containerManager *app.ContainerManager, thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, parse, cwd starlark.String
	var cmdArgs *starlark.List
	var env *starlark.List
	var processPartial, stdoutToFile, stream starlark.Bool
	var includeStderr starlark.Bool = starlark.Bool(true)
	if err := starlark.UnpackArgs("run", args, kwargs, "path", &path, "args?", &cmdArgs, "env?", &env,
		"process_partial?", &processPartial, "stdout_file", &stdoutToFile, "parse", &parse, "stream", &stream,
		"include_stderr", &includeStderr, "cwd", &cwd); err != nil {
		return nil, err
	}
	if cmdArgs == nil {
		cmdArgs = starlark.NewList([]starlark.Value{})
	}
	if env == nil {
		env = starlark.NewList([]starlark.Value{})
	}

	pathStr := string(path)
	argsList := make([]string, 0, cmdArgs.Len())
	envList := make([]string, 0, env.Len())
	processPartialBool := bool(processPartial)
	stdoutToFileBool := bool(stdoutToFile)

	for i := 0; i < cmdArgs.Len(); i++ {
		value, ok := cmdArgs.Index(i).(starlark.String)
		if !ok {
			return nil, fmt.Errorf("args must be a list of strings")
		}
		argsList = append(argsList, string(value))
	}

	for i := 0; i < env.Len(); i++ {
		value, ok := env.Index(i).(starlark.String)
		if !ok {
			return nil, fmt.Errorf("env must be a list of strings")
		}
		envList = append(envList, string(value))
	}

	ctx := app.GetContext(thread)
	var cmd *exec.Cmd
	var err error
	if containerManager != nil {
		cmd, err = containerManager.Run(ctx, pathStr, argsList, envList)
		if err != nil {
			return nil, fmt.Errorf("error running command in container: %w", err)
		}
		// cwd is not supported in container mode
	} else {
		cmd = exec.CommandContext(ctx, pathStr, argsList...)
		cmd.Env = envList
		if cwd != "" {
			cmd.Dir = string(cwd)
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	if bool(includeStderr) {
		cmd.Stderr = cmd.Stdout
	} else {
		cmd.Stderr = &stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	var tempFile *os.File

	if stdoutToFileBool {
		tempFile, err = os.CreateTemp("", "openrun-exec-stdout-*")
		if err != nil {
			return nil, fmt.Errorf("error creating temporary file: %w", err)
		}
		defer tempFile.Close()
		_, err = io.Copy(tempFile, stdout)

		if err != nil && err != io.EOF {
			return nil, err
		}
	}

	var runErr error
	if !bool(stream) {
		if !stdoutToFileBool {
			_, err = io.CopyN(&buf, stdout, MAX_BYTES_STDOUT)
			if err != nil && err != io.EOF {
				return nil, err
			}
		}
		runErr = cmd.Wait()

		if !processPartialBool && runErr != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("%s: %s", runErr, stderr.String())
			}
			return nil, runErr
		}

		if stdoutToFileBool {
			return app.NewResponse(starlark.String(tempFile.Name())), nil
		}

		if parse == "json" {
			var result map[string]any
			err := json.NewDecoder(&buf).Decode(&result)
			if err != nil {
				return nil, fmt.Errorf("error parsing JSON output: %w", err)
			}
			return app.NewResponse([]map[string]any{result}), nil
		}
	}
	if parse == "json" && bool(stream) {
		return app.NewResponse(starlark.None), errors.New("stream response is not supported for JSON output")
	}
	if parse != "" && parse != "jsonlines" {
		return nil, fmt.Errorf("unsupported format: %s", parse)
	}

	count := 0
	lines := starlark.NewList([]starlark.Value{})

	if bool(stream) {
		scanner := bufio.NewScanner(stdout)
		// Stream the output to the client using RangeFunc
		rangeFunc := func(yield func(any, error) bool) {
			for scanner.Scan() {
				line := scanner.Bytes()
				count++
				if parse == "jsonlines" {
					var result map[string]any
					err := json.NewDecoder(bytes.NewReader(line)).Decode(&result)
					if err != nil {
						yield(nil, fmt.Errorf("error parsing JSON output: %w", err))
						return
					}
					val, err := starlark_type.MarshalStarlark(result)
					if err != nil {
						yield(nil, fmt.Errorf("error converting JSON output to starlark: %w", err))
						return
					}
					if !yield(val, nil) {
						return
					}
				} else {
					if !yield(starlark.String(line), nil) {
						return
					}
				}
			}

			if scanner.Err() != nil {
				yield(nil, fmt.Errorf("scanner error: %w", scanner.Err()))
				return
			}

			runErr = cmd.Wait()
			if runErr != nil {
				yield(nil, fmt.Errorf("cmd failed: %w", runErr))
			}
		}

		return app.NewStreamResponse(rangeFunc), nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for scanner.Scan() {
		line := scanner.Bytes()
		count++
		if parse == "jsonlines" {
			var result map[string]any
			err := json.NewDecoder(bytes.NewReader(line)).Decode(&result)
			if err != nil {
				return nil, fmt.Errorf("error parsing JSON output: %w", err)
			}
			val, err := starlark_type.MarshalStarlark(result)
			if err != nil {
				return nil, fmt.Errorf("error converting JSON output to starlark: %w", err)
			}
			lines.Append(val)
		} else {
			lines.Append(starlark.String(line))
		}
	}

	if count == 0 && runErr != nil {
		// if no lines in stdout and there was an error (processPartial case), return the error
		return nil, runErr
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return app.NewResponse(lines), nil
}
