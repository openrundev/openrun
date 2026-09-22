// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// The action commands run app actions through the management API, as the
// logged in user: the actions listed and the runs are authorized the way the
// app's form UI authorizes that user. Result data is written to stdout, the
// status line and the errors to stderr, so that the output can be piped

const (
	actionExitError      = 1 // the action or the request failed
	actionExitParamError = 2 // param validation errors
	actionTableCellLimit = 60
)

func initActionCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "action",
		Usage: "List and run app actions. Actions are the operations an app exposes, they run as the logged in user",
		Subcommands: []*cli.Command{
			actionListCommand(commonFlags, clientConfig),
			actionShowCommand(commonFlags, clientConfig),
			actionRunCommand(commonFlags, clientConfig),
			actionValidateCommand(commonFlags, clientConfig),
			actionSuggestCommand(commonFlags, clientConfig),
			actionOpenAPICommand(commonFlags, clientConfig),
		},
	}
}

const actionSelectHelp = `<action> is the action name as shown by "action list", or the action path (like /cancel).
It can be left out when the app has one action.`

const actionArgsHelp = `Args are passed as name=value, the value is converted to the type of the param
(true/false for booleans, JSON for lists and dicts). Params which are not passed use the
value configured for the app. name=@file uploads the file, for a file upload param.
--json passes the args as a JSON object (--json=@file reads it from a file, --json=- from
stdin); name=value args override its entries.`

func actionListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())

	return &cli.Command{
		Name:      "list",
		Usage:     "List the actions you can run, for the apps matching a path glob",
		Flags:     flags,
		ArgsUsage: "[<appPathGlob>]",
		UsageText: `args: [<appPathGlob>]

<appPathGlob> defaults to all. ` + PATH_SPEC_HELP + `

	Examples:
	  List all actions: openrun action list
	  List the actions of one app: openrun action list /orders`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one arg: <appPathGlob>")
			}
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPathGlob", cmp.Or(cCtx.Args().First(), "all"))

			var response types.ActionListResponse
			if err := client.Get("/_openrun/actions", values, &response); err != nil {
				return err
			}
			for _, warning := range response.Warnings {
				fmt.Fprintf(cCtx.App.ErrWriter, "warning: %s\n", warning) //nolint:errcheck
			}
			printActionList(cCtx, response.Actions, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printActionList(cCtx *cli.Context, actions []types.ActionInfo, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, actions, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, a := range actions {
			json.MarshalEncode(enc, a, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, a := range actions {
			json.MarshalEncode(enc, a, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_CSV:
		w := csv.NewWriter(cCtx.App.Writer)
		for _, a := range actions {
			w.Write([]string{a.AppPath, a.Tool, a.Name, a.Path, strconv.FormatBool(a.Suggest), a.Description}) //nolint:errcheck
		}
		w.Flush()
	case FORMAT_BASIC:
		formatStr := "%-30s %-24s %-s\n"
		printStdout(cCtx, formatStr, "App", "Action", "Name")
		for _, a := range actions {
			printStdout(cCtx, formatStr, a.AppPath, a.Tool, a.Name)
		}
	default:
		if len(actions) == 0 {
			fmt.Fprintln(cCtx.App.ErrWriter, "No actions available") //nolint:errcheck
			return
		}
		formatStr := "%-30s %-24s %-24s %-16s %-8s %-s\n"
		printStdout(cCtx, formatStr, "App", "Action", "Name", "Path", "Suggest", "Description")
		for _, a := range actions {
			printStdout(cCtx, formatStr, a.AppPath, a.Tool, a.Name, a.Path, strconv.FormatBool(a.Suggest), firstLine(a.Description))
		}
	}
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return line
}

func actionShowCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, newBoolFlag("stage", "s", "Use the stage instance of the app instead of prod", false))

	return &cli.Command{
		Name:      "show",
		Usage:     "Show the params of an action",
		Flags:     flags,
		ArgsUsage: "<appPath> [<action>]",
		UsageText: `args: <appPath> [<action>]

` + actionSelectHelp + `

	Examples:
	  Show the params: openrun action show /orders cancel
	  As JSON, with the JSON schema of the args: openrun action show --format json /orders cancel`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() < 1 || cCtx.NArg() > 2 {
				return fmt.Errorf("expected args: <appPath> [<action>]")
			}
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().Get(0))
			values.Add("action", cCtx.Args().Get(1))
			values.Add("stage", strconv.FormatBool(cCtx.Bool("stage")))

			var detail types.ActionDetailResponse
			if err := client.Get("/_openrun/actions/schema", values, &detail); err != nil {
				return err
			}
			format := cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat)
			if format == FORMAT_JSON || format == FORMAT_JSONL || format == FORMAT_JSONL_PRETTY {
				enc := newJSONEncoder(cCtx.App.Writer, format != FORMAT_JSONL)
				return json.MarshalEncode(enc, detail, deterministicJSON)
			}
			printActionDetail(cCtx, &detail, cCtx.Bool("stage"))
			return nil
		},
	}
}

func printActionDetail(cCtx *cli.Context, detail *types.ActionDetailResponse, stage bool) {
	printStdout(cCtx, "Action:      %s (%s)\n", detail.Tool, detail.Name)
	printStdout(cCtx, "App:         %s\n", detail.AppPath)
	if detail.Description != "" {
		printStdout(cCtx, "Description: %s\n", strings.ReplaceAll(strings.TrimSpace(detail.Description), "\n", "\n             "))
	}
	printStdout(cCtx, "Url:         %s\n", detail.Url)
	printStdout(cCtx, "Suggest:     %t\n", detail.Suggest)

	example := []string{"openrun action run"}
	if stage {
		example = append(example, "--stage")
	}
	example = append(example, detail.AppPath, detail.Tool)
	if len(detail.Params) == 0 {
		printStdout(cCtx, "\nThe action has no params\n")
	} else {
		printStdout(cCtx, "\n")
		rows := make([]map[string]any, 0, len(detail.Params))
		for _, p := range detail.Params {
			defaultVal := ""
			if p.Default != nil {
				defaultVal = cellString(p.Default)
			}
			paramType := strings.ToLower(p.Type)
			if p.DisplayType != "" {
				paramType += " (" + strings.ToLower(p.DisplayType) + ")"
			}
			rows = append(rows, map[string]any{"Name": p.Name, "Type": paramType, "Required": p.Required,
				"Default": defaultVal, "Options": strings.Join(p.Options, ","), "Description": firstLine(p.Description)})

			placeholder := "<" + strings.ToLower(p.Type) + ">"
			if strings.EqualFold(p.DisplayType, "file") || strings.EqualFold(p.DisplayType, "fileupload") {
				placeholder = "@<file>"
			}
			arg := p.Name + "=" + placeholder
			if !p.Required || defaultVal != "" {
				arg = "[" + arg + "]"
			}
			example = append(example, arg)
		}
		printTable(cCtx.App.Writer, []string{"Name", "Type", "Required", "Default", "Options", "Description"}, rows)
	}
	printStdout(cCtx, "\nUsage: %s\n", strings.Join(example, " "))
}

func actionInvokeFlags(commonFlags []cli.Flag) []cli.Flag {
	flags := make([]cli.Flag, 0, len(commonFlags)+6)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, newBoolFlag("stage", "s", "Use the stage instance of the app instead of prod", false))
	flags = append(flags, newStringFlag("json", "j", "The args as a JSON object. @file reads the object from a file, - from stdin", ""))
	flags = append(flags, newBoolFlag("quiet", "q", "Do not print the status line", false))
	flags = append(flags, newStringFlag("output", "o", "Save the files of a download or image result: a file name, a directory (needed when the result has several files) or - for stdout", ""))
	return flags
}

func actionRunCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "run",
		Usage:     "Run an action",
		Flags:     actionInvokeFlags(commonFlags),
		ArgsUsage: "<appPath> [<action>] [name=value ...]",
		UsageText: `args: <appPath> [<action>] [name=value ...]

` + actionSelectHelp + `

` + actionArgsHelp + `

The result is written to stdout: a table, lines of text or JSON, as the action reports it
(--format json|jsonl|csv to convert). The output of an action which streams a command is
written as it is produced. For an action which returns files (a download or an image),
the files are listed; --output saves them. The exit code is 0 on success, 2 for param validation errors,
1 for other failures; for a streamed command, the exit code of the command.

	Examples:
	  Run an action: openrun action run /orders cancel id=42 reason=customer
	  Run the only action of an app: openrun action run /report month=2026-08
	  Typed args from a file: openrun action run /orders import --json=@args.json
	  Upload a file: openrun action run /orders import data=@orders.csv
	  Rows as JSON lines: openrun action run --format jsonl /orders list status=open | jq .id
	  Save the file an action returns: openrun action run -o report.pdf /orders report month=2026-08`,
		Action: func(cCtx *cli.Context) error {
			return invokeActionCommand(cCtx, clientConfig, "/_openrun/actions/run", false)
		},
	}
}

func actionValidateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "validate",
		Usage:     "Validate the args for an action, without running it",
		Flags:     actionInvokeFlags(commonFlags),
		ArgsUsage: "<appPath> [<action>] [name=value ...]",
		UsageText: `args: <appPath> [<action>] [name=value ...]

` + actionSelectHelp + `

` + actionArgsHelp + `

The action handler is called with dry_run set. The exit code is 2 when the args have errors.

	Examples:
	  Validate: openrun action validate /orders cancel id=42`,
		Action: func(cCtx *cli.Context) error {
			return invokeActionCommand(cCtx, clientConfig, "/_openrun/actions/run", true)
		},
	}
}

func actionSuggestCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "suggest",
		Usage:     "Get suggested arg values for an action, given the args known so far",
		Flags:     actionInvokeFlags(commonFlags),
		ArgsUsage: "<appPath> [<action>] [name=value ...]",
		UsageText: `args: <appPath> [<action>] [name=value ...]

` + actionSelectHelp + `

` + actionArgsHelp + `

The suggested values are printed as name=value lines, which can be passed to "action run".

	Examples:
	  Suggest values: openrun action suggest /orders cancel id=42`,
		Action: func(cCtx *cli.Context) error {
			return invokeActionCommand(cCtx, clientConfig, "/_openrun/actions/suggest", false)
		},
	}
}

func actionOpenAPICommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("stage", "s", "Use the stage instance of the app instead of prod", false))

	return &cli.Command{
		Name:      "openapi",
		Usage:     "Print the OpenAPI spec of the app's actions REST API (served by the app under /api)",
		Flags:     flags,
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

	Examples:
	  Save the spec: openrun action openapi /orders > orders-openapi.json`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <appPath>")
			}
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().Get(0))
			values.Add("stage", strconv.FormatBool(cCtx.Bool("stage")))

			var spec map[string]any
			if err := client.Get("/_openrun/actions/openapi", values, &spec); err != nil {
				return err
			}
			enc := newJSONEncoder(cCtx.App.Writer, true)
			return json.MarshalEncode(enc, spec, deterministicJSON)
		},
	}
}

// parseActionArgs splits the positional args into the action selector and the
// name=value args. The second positional is the action unless it is a
// name=value pair. name=@path entries are file uploads
func parseActionArgs(cCtx *cli.Context, stdin io.Reader) (*types.ActionRunRequest, map[string]string, error) {
	if cCtx.NArg() < 1 {
		return nil, nil, fmt.Errorf("expected args: <appPath> [<action>] [name=value ...]")
	}
	positional := cCtx.Args().Slice()
	req := &types.ActionRunRequest{AppPath: positional[0], Stage: cCtx.Bool("stage"), Args: map[string]jsontext.Value{}}
	pairs := positional[1:]
	if len(pairs) > 0 && !strings.Contains(pairs[0], "=") {
		req.Action = pairs[0]
		pairs = pairs[1:]
	}

	if doc := cCtx.String("json"); doc != "" {
		var data []byte
		var err error
		switch {
		case doc == "-":
			data, err = io.ReadAll(stdin)
		case strings.HasPrefix(doc, "@"):
			data, err = os.ReadFile(doc[1:])
		default:
			data = []byte(doc)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading --json args: %w", err)
		}
		if err := json.Unmarshal(data, &req.Args); err != nil {
			return nil, nil, fmt.Errorf("--json args have to be a JSON object: %w", err)
		}
		if req.Args == nil {
			// null decodes without an error and clears the map, the name=value
			// args are merged into it below
			return nil, nil, fmt.Errorf("--json args have to be a JSON object, got null")
		}
	}

	files := map[string]string{}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("invalid arg %q: args are passed as name=value", pair)
		}
		if filePath, isFile := strings.CutPrefix(value, "@"); isFile {
			if filePath == "" {
				return nil, nil, fmt.Errorf("invalid arg %q: expected name=@<file>", pair)
			}
			files[name] = filePath
			delete(req.Args, name)
			continue
		}
		// Sent as a JSON string: the server converts it to the type of the
		// param, the way a form field value is converted
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, nil, err
		}
		req.Args[name] = encoded
	}
	return req, files, nil
}

// actionRequestBody builds the request body: the JSON document, or a
// multipart form with the document and the files when there are uploads
func actionRequestBody(req *types.ActionRunRequest, files map[string]string) (io.Reader, string, error) {
	doc, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	if len(files) == 0 {
		return bytes.NewReader(doc), "application/json", nil
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("request", string(doc)); err != nil {
		return nil, "", err
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		file, err := os.Open(files[name])
		if err != nil {
			return nil, "", fmt.Errorf("error opening file for %s: %w", name, err)
		}
		part, err := writer.CreateFormFile(name, filepath.Base(files[name]))
		if err == nil {
			_, err = io.Copy(part, file)
		}
		file.Close() //nolint:errcheck
		if err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return &body, writer.FormDataContentType(), nil
}

// actionResultDoc is the JSON response of the run and suggest action APIs
type actionResultDoc struct {
	Status      string            `json:"status"`
	Report      string            `json:"report"`
	Values      []any             `json:"values"`
	ParamErrors map[string]string `json:"param_errors"`
	Params      map[string]any    `json:"params"` // suggest
	Error       string            `json:"error"`
}

func invokeActionCommand(cCtx *cli.Context, clientConfig *types.ClientConfig, apiPath string, dryRun bool) error {
	req, files, err := parseActionArgs(cCtx, os.Stdin)
	if err != nil {
		return err
	}
	req.DryRun = dryRun
	body, contentType, err := actionRequestBody(req, files)
	if err != nil {
		return err
	}

	// Creating the client changes the working directory to OPENRUN_HOME (the
	// unix socket path length limit): every path the caller gave is resolved
	// before that. The arg files (--json=@file, name=@file) are read above;
	// the --output path is made absolute here
	output := cCtx.String("output")
	outputPath := output
	if output != "" && output != "-" {
		if outputPath, err = filepath.Abs(output); err != nil {
			return err
		}
	}

	client := newHttpClient(clientConfig)
	defer client.CloseIdleConnections()
	resp, err := client.PostRaw(cCtx.Context, apiPath, nil, contentType, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	quiet := cCtx.Bool("quiet")
	status := func(msg string) {
		if msg != "" && !quiet {
			fmt.Fprintln(cCtx.App.ErrWriter, msg) //nolint:errcheck
		}
	}

	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode == http.StatusOK && mediaType == "text/plain" {
		// A streamed command: the output as it is produced, the exit status
		// in a trailer (absent when the stream was cut)
		status(resp.Header.Get(types.ACTION_STATUS_HEADER))
		if _, err := io.Copy(cCtx.App.Writer, resp.Body); err != nil {
			return cli.Exit(fmt.Sprintf("reading the action output: %s", err), actionExitError)
		}
		exitValue := resp.Trailer.Get(types.ACTION_EXIT_TRAILER)
		exitStatus, convErr := strconv.Atoi(exitValue)
		if exitValue == "" || convErr != nil {
			return cli.Exit("the action output ended without an exit status", actionExitError)
		}
		if exitStatus != 0 {
			return cli.Exit(fmt.Sprintf("exit status %d", exitStatus), exitStatus)
		}
		return nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var doc actionResultDoc
	parseErr := json.Unmarshal(data, &doc)

	if resp.StatusCode == http.StatusUnprocessableEntity && parseErr == nil && len(doc.ParamErrors) > 0 {
		status(doc.Status)
		for _, name := range slices.Sorted(maps.Keys(doc.ParamErrors)) {
			fmt.Fprintf(cCtx.App.ErrWriter, "error: param %s: %s\n", name, doc.ParamErrors[name]) //nolint:errcheck
		}
		return cli.Exit("", actionExitParamError)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var reqErr types.RequestError
		if json.Unmarshal(data, &reqErr) == nil && reqErr.Code != 0 {
			return reqErr
		}
		return types.RequestError{Code: resp.StatusCode, Message: cmp.Or(doc.Error, strings.TrimSpace(string(data)))}
	}
	if parseErr != nil {
		return fmt.Errorf("error parsing response: %w", parseErr)
	}

	status(doc.Status)
	format := cCtx.String("format")
	if doc.Params != nil {
		return printSuggestedArgs(cCtx, doc.Params, format)
	}
	if files := actionResultFiles(doc.Report, doc.Values); len(files) > 0 {
		if output != "" {
			return saveActionFiles(cCtx, clientConfig, client, req, files, output, outputPath, quiet)
		}
		if !quiet {
			fmt.Fprintln(cCtx.App.ErrWriter, "Use --output <file|dir> to save the result files") //nolint:errcheck
		}
	}
	return printActionValues(cCtx, doc.Report, doc.Values, format)
}

// actionFile is a file row of a DOWNLOAD or IMAGE result
type actionFile struct {
	name string
	url  string
}

// actionResultFiles returns the files of a download or image result: the
// rows which have a url
func actionResultFiles(report string, values []any) []actionFile {
	if !strings.EqualFold(report, "download") && !strings.EqualFold(report, "image") {
		return nil
	}
	files := []actionFile{}
	for _, value := range values {
		row, ok := value.(map[string]any)
		if !ok {
			continue
		}
		fileURL, _ := row["url"].(string)
		if fileURL == "" {
			continue
		}
		name, _ := row["name"].(string)
		files = append(files, actionFile{name: name, url: fileURL})
	}
	return files
}

// actionFileName returns a safe local file name for a result file: the base
// of its name, or of the url path
func actionFileName(file actionFile, index int) string {
	name := file.name
	if name == "" {
		if parsed, err := url.Parse(file.url); err == nil {
			name = parsed.Path
		}
	}
	name = filepath.Base(filepath.FromSlash(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		name = fmt.Sprintf("download_%d", index+1)
	}
	return name
}

// saveActionFiles downloads the result files. A url within the app is fetched
// through the management API, as the calling user (the CLI has no session
// with the app); any other url is fetched directly, without credentials
// output is the --output value as given (used in messages), outputPath its
// absolute form, resolved before the client changed the working directory
func saveActionFiles(cCtx *cli.Context, clientConfig *types.ClientConfig, client actionFileClient,
	req *types.ActionRunRequest, files []actionFile, output, outputPath string, quiet bool) error {
	toStdout := output == "-"
	if toStdout && len(files) > 1 {
		return fmt.Errorf("the result has %d files, --output has to be a directory", len(files))
	}
	dirMode := false
	if !toStdout {
		info, statErr := os.Stat(outputPath)
		dirMode = len(files) > 1 || strings.HasSuffix(output, "/") || strings.HasSuffix(output, string(filepath.Separator)) ||
			(statErr == nil && info.IsDir())
		if dirMode {
			if err := os.MkdirAll(outputPath, 0755); err != nil {
				return err
			}
		}
	}

	used := map[string]bool{}
	for i, file := range files {
		body, err := openActionFile(cCtx, clientConfig, client, req, file)
		if err != nil {
			return fmt.Errorf("error fetching %s: %w", cmp.Or(file.name, file.url), err)
		}
		if toStdout {
			_, err = io.Copy(cCtx.App.Writer, body)
			body.Close() //nolint:errcheck
			if err != nil {
				return err
			}
			continue
		}

		target, display := outputPath, output
		if dirMode {
			name := actionFileName(file, i)
			for used[name] {
				name = fmt.Sprintf("%d_%s", i+1, name)
			}
			used[name] = true
			target, display = filepath.Join(outputPath, name), filepath.Join(output, name)
		}
		written, err := writeActionFile(target, body)
		body.Close() //nolint:errcheck
		if err != nil {
			return fmt.Errorf("error saving %s: %w", display, err)
		}
		if !quiet {
			fmt.Fprintf(cCtx.App.ErrWriter, "Saved %s (%d bytes)\n", display, written) //nolint:errcheck
		}
	}
	return nil
}

func writeActionFile(target string, body io.Reader) (int64, error) {
	file, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(file, body)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		os.Remove(target) //nolint:errcheck
		return 0, err
	}
	return written, nil
}

// actionFileClient is the management API client call used for file downloads
type actionFileClient interface {
	GetRaw(ctx context.Context, apiPath string, params url.Values) (*http.Response, error)
}

func openActionFile(cCtx *cli.Context, clientConfig *types.ClientConfig, client actionFileClient,
	req *types.ActionRunRequest, file actionFile) (io.ReadCloser, error) {
	var resp *http.Response
	var err error
	if parsed, parseErr := url.Parse(file.url); parseErr == nil && (parsed.IsAbs() || parsed.Host != "") {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("unsupported url %s", file.url)
		}
		var fileReq *http.Request
		if fileReq, err = http.NewRequestWithContext(cCtx.Context, http.MethodGet, file.url, nil); err != nil {
			return nil, err
		}
		httpClient := system.NewPlainHttpClient(clientConfig.Client.SkipCertCheck)
		httpClient.Timeout = 0 // the size of the file is not known
		resp, err = httpClient.Do(fileReq)
	} else {
		values := url.Values{}
		values.Add("appPath", req.AppPath)
		values.Add("action", req.Action)
		values.Add("stage", strconv.FormatBool(req.Stage))
		values.Add("url", file.url)
		resp, err = client.GetRaw(cCtx.Context, "/_openrun/actions/file", values)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close() //nolint:errcheck
		var reqErr types.RequestError
		if json.Unmarshal(data, &reqErr) == nil && reqErr.Message != "" {
			return nil, reqErr
		}
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return resp.Body, nil
}

// printSuggestedArgs prints the suggested values as name=value lines, the
// form the run command takes them in
func printSuggestedArgs(cCtx *cli.Context, params map[string]any, format string) error {
	if format == FORMAT_JSON || format == FORMAT_JSONL || format == FORMAT_JSONL_PRETTY {
		enc := newJSONEncoder(cCtx.App.Writer, format != FORMAT_JSONL)
		return json.MarshalEncode(enc, params, deterministicJSON)
	}
	for _, name := range slices.Sorted(maps.Keys(params)) {
		printStdout(cCtx, "%s=%s\n", name, cellString(params[name]))
	}
	return nil
}

// printActionValues writes the result values: in the given format, or as the
// action reports them (table, text lines, JSON)
func printActionValues(cCtx *cli.Context, report string, values []any, format string) error {
	if len(values) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if row, ok := value.(map[string]any); ok {
			rows = append(rows, row)
		}
	}
	isRows := len(rows) == len(values)

	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		return json.MarshalEncode(enc, values, deterministicJSON)
	case FORMAT_JSONL, FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, format == FORMAT_JSONL_PRETTY)
		for _, value := range values {
			if err := json.MarshalEncode(enc, value, deterministicJSON); err != nil {
				return err
			}
		}
		return nil
	case FORMAT_CSV:
		w := csv.NewWriter(cCtx.App.Writer)
		if isRows {
			keys := rowKeys(rows)
			w.Write(keys) //nolint:errcheck
			for _, row := range rows {
				record := make([]string, 0, len(keys))
				for _, key := range keys {
					record = append(record, cellString(row[key]))
				}
				w.Write(record) //nolint:errcheck
			}
		} else {
			for _, value := range values {
				w.Write([]string{cellString(value)}) //nolint:errcheck
			}
		}
		w.Flush()
		return w.Error()
	}

	switch {
	case !isRows:
		for _, value := range values {
			printStdout(cCtx, "%s\n", cellString(value))
		}
	case strings.EqualFold(report, "json"):
		enc := newJSONEncoder(cCtx.App.Writer, true)
		return json.MarshalEncode(enc, values, deterministicJSON)
	default:
		printTable(cCtx.App.Writer, rowKeys(rows), rows)
	}
	return nil
}

// rowKeys returns the columns of a table result: the keys of the first row
// sorted by name, as the form UI shows them
func rowKeys(rows []map[string]any) []string {
	return slices.Sorted(maps.Keys(rows[0]))
}

// cellString formats a value for a table cell or a name=value line: strings
// as they are, other values as compact JSON
func cellString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	encoded, err := json.Marshal(value, deterministicJSON)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(encoded)
}

// printTable writes rows as a table with the columns sized to their content
func printTable(w io.Writer, keys []string, rows []map[string]any) {
	widths := make([]int, len(keys))
	cells := make([][]string, 0, len(rows))
	for i, key := range keys {
		widths[i] = len(key)
	}
	for _, row := range rows {
		record := make([]string, len(keys))
		for i, key := range keys {
			cell := strings.NewReplacer("\n", " ", "\r", "", "\t", " ").Replace(cellString(row[key]))
			if len(cell) > actionTableCellLimit {
				cell = cell[:actionTableCellLimit-3] + "..."
			}
			record[i] = cell
			widths[i] = max(widths[i], len(cell))
		}
		cells = append(cells, record)
	}

	writeRow := func(record []string) {
		var b strings.Builder
		for i, cell := range record {
			if i == len(record)-1 {
				b.WriteString(cell)
			} else {
				fmt.Fprintf(&b, "%-*s  ", widths[i], cell)
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " ")) //nolint:errcheck
	}
	writeRow(keys)
	for _, record := range cells {
		writeRow(record)
	}
}
