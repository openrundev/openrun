// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// Async action runs on the CLI: "action
// run" of an async action prints the run id (--wait polls for the result,
// --follow tails the output), "action runs" lists them, "action output"
// prints a run's output and "action cancel" stops one

const (
	runPollInterval   = time.Second
	runWaitChunk      = "30s" // the wait of one get_action_run poll
	runOutputPollWait = time.Second
)

// runClient is the client the run reads need
type runClient interface {
	Get(url string, params url.Values, output any) error
}

// actionRunDoc is the get_action_run response
type actionRunDoc struct {
	Run    types.ActionRun `json:"run"`
	Result *struct {
		Status      string            `json:"status"`
		Report      string            `json:"report"`
		Values      []any             `json:"values"`
		ParamErrors map[string]string `json:"param_errors"`
	} `json:"result"`
}

// handleStartedRun handles the 202 response of an async action: prints the
// run id, or with --wait polls the run and renders it like a sync result,
// with --follow tailing the output first
func handleStartedRun(cCtx *cli.Context, clientConfig *types.ClientConfig, started types.ActionRunStarted, status func(string),
	req *types.ActionRunRequest, output, outputPath string) error {
	wait, follow := cCtx.Bool("wait"), cCtx.Bool("follow")
	if !wait && !follow {
		status(fmt.Sprintf("Run started: check it with \"openrun action runs\" or \"openrun action output %s\"", started.RunId))
		fmt.Fprintln(cCtx.App.Writer, started.RunId) //nolint:errcheck
		return nil
	}
	client := newHttpClient(clientConfig)
	defer client.CloseIdleConnections()
	if follow {
		if err := followRunOutput(cCtx, client, started.RunId, true); err != nil {
			return err
		}
	}
	return waitAndPrintRun(cCtx, clientConfig, started.RunId, status, req, output, outputPath)
}

// waitAndPrintRun polls a run until it ends and renders its result. req is
// the run request and output/outputPath the --output option, for the files
// of a download or image result
func waitAndPrintRun(cCtx *cli.Context, clientConfig *types.ClientConfig, runId string, status func(string),
	req *types.ActionRunRequest, output, outputPath string) error {
	client := newHttpClient(clientConfig)
	defer client.CloseIdleConnections()
	var doc actionRunDoc
	for {
		values := url.Values{"runId": {runId}, "wait": {runWaitChunk}}
		if err := client.Get("/_openrun/actions/runs/get", values, &doc); err != nil {
			return err
		}
		if doc.Run.Status != types.ActionRunRunning {
			break
		}
		select {
		case <-cCtx.Done():
			return cli.Exit(fmt.Sprintf("run %s is still running", runId), actionExitError)
		case <-time.After(runPollInterval):
		}
	}
	return printFinishedRun(cCtx, clientConfig, &doc, status, req, output, outputPath)
}

// printFinishedRun renders a finished run: the result values as a sync run
// would print them (the files of a download or image result saved with
// --output), or the stored output of a stream run; the exit code follows
// the run status
func printFinishedRun(cCtx *cli.Context, clientConfig *types.ClientConfig, doc *actionRunDoc, status func(string),
	req *types.ActionRunRequest, output, outputPath string) error {
	run := doc.Run
	if doc.Result != nil && len(doc.Result.ParamErrors) > 0 {
		status(doc.Result.Status)
		for _, name := range sortedKeys(doc.Result.ParamErrors) {
			fmt.Fprintf(cCtx.App.ErrWriter, "error: param %s: %s\n", name, doc.Result.ParamErrors[name]) //nolint:errcheck
		}
		return cli.Exit("", actionExitParamError)
	}
	if run.IsStream {
		if !cCtx.Bool("follow") {
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			if err := followRunOutput(cCtx, client, run.Id, false); err != nil {
				return err
			}
		}
		if run.Status != types.ActionRunSucceeded {
			code := actionExitError
			if run.ExitCode != nil && *run.ExitCode != 0 {
				code = *run.ExitCode
			}
			return cli.Exit(fmt.Sprintf("run %s: %s", run.Status, run.Message), code)
		}
		return nil
	}
	if run.Status != types.ActionRunSucceeded {
		return cli.Exit(fmt.Sprintf("run %s: %s", run.Status, run.Message), actionExitError)
	}
	if doc.Result != nil {
		status(doc.Result.Status)
		if run.ResultTruncated {
			status(fmt.Sprintf("(the stored result was truncated to the size limit, %d rows)", run.ResultRows))
		}
		if files := actionResultFiles(doc.Result.Report, doc.Result.Values); len(files) > 0 && req != nil {
			if output != "" {
				client := newHttpClient(clientConfig)
				defer client.CloseIdleConnections()
				return saveActionFiles(cCtx, clientConfig, client, req, files, output, outputPath, cCtx.Bool("quiet"))
			}
			if !cCtx.Bool("quiet") {
				fmt.Fprintln(cCtx.App.ErrWriter, "Use --output <file|dir> to save the result files") //nolint:errcheck
			}
		}
		return printActionValues(cCtx, doc.Result.Report, doc.Result.Values, cCtx.String("format"))
	}
	return nil
}

// followRunOutput prints a run's stored output; with follow it keeps polling
// while the run is active. Ctrl-C stops following and leaves the run running
func followRunOutput(cCtx *cli.Context, client runClient, runId string, follow bool) error {
	ctx, stop := signal.NotifyContext(cCtx.Context, os.Interrupt)
	defer stop()
	var since int64
	omittedNoted := false
	for {
		var resp types.ActionRunOutputResponse
		if err := client.Get("/_openrun/actions/runs/output", url.Values{"runId": {runId}, "since": {strconv.FormatInt(since, 10)}}, &resp); err != nil {
			return err
		}
		if resp.Since < since {
			fmt.Fprintln(cCtx.App.ErrWriter, "... output restarted from the beginning ...") //nolint:errcheck
		}
		if resp.Run.OutputOmittedBytes > 0 && !omittedNoted && resp.Since == 0 {
			omittedNoted = true
		}
		if resp.Output != "" {
			fmt.Fprint(cCtx.App.Writer, resp.Output) //nolint:errcheck
		}
		since = resp.Run.OutputBytes
		if resp.Run.Status != types.ActionRunRunning || !follow {
			return nil
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(cCtx.App.ErrWriter, "\nstopped following, run %s keeps running; cancel it with \"openrun action cancel %s\"\n", runId, runId) //nolint:errcheck
			return cli.Exit("", actionExitError)
		case <-time.After(runOutputPollWait):
		}
	}
}

func actionRunsCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+4)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, newBoolFlag("stage", "s", "The stage instance of the app instead of prod", false))
	flags = append(flags, newStringFlag("status", "", "Only the runs with this status: running, succeeded, failed, timed_out, canceled or lost", ""))
	flags = append(flags, newIntFlag("limit", "l", "Maximum runs to list", 50))

	return &cli.Command{
		Name:      "runs",
		Usage:     "List the background runs of an app's async actions, newest first",
		Flags:     flags,
		ArgsUsage: "<appPath> [<action>]",
		UsageText: `args: <appPath> [<action>]

` + actionSelectHelp + ` Without an action, the runs of every async action of the app are listed.

	Examples:
	  List the runs of an app: openrun action runs /site
	  Failed runs of one action: openrun action runs --status failed /site rebuild`,
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
			values.Add("status", cCtx.String("status"))
			values.Add("limit", strconv.Itoa(cCtx.Int("limit")))
			var response types.ActionRunsResponse
			if err := client.Get("/_openrun/actions/runs", values, &response); err != nil {
				return err
			}
			return printActionRuns(cCtx, response.Runs, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
		},
	}
}

func printActionRuns(cCtx *cli.Context, runs []types.ActionRun, format string) error {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		return json.MarshalEncode(enc, runs, deterministicJSON)
	case FORMAT_JSONL, FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, format == FORMAT_JSONL_PRETTY)
		for _, run := range runs {
			if err := json.MarshalEncode(enc, run, deterministicJSON); err != nil {
				return err
			}
		}
		return nil
	}
	if len(runs) == 0 {
		fmt.Fprintln(cCtx.App.ErrWriter, "no runs") //nolint:errcheck
		return nil
	}
	w := tabwriter.NewWriter(cCtx.App.Writer, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Run\tAction\tStatus\tStarted\tDuration\tBy\tMessage") //nolint:errcheck
	for _, run := range runs {
		end := time.Now()
		if run.EndedAt != nil {
			end = *run.EndedAt
		}
		duration := end.Sub(run.StartedAt).Round(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", run.Id, run.ActionName, run.Status, //nolint:errcheck
			run.StartedAt.Local().Format("2006-01-02 15:04:05"), duration, run.Actor, firstLine(run.Message))
	}
	return w.Flush()
}

func actionOutputCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("follow", "f", "Keep printing the output while the run is active", false))

	return &cli.Command{
		Name:      "output",
		Usage:     "Print the output of a background action run",
		Flags:     flags,
		ArgsUsage: "<runId>",
		UsageText: `args: <runId>

The stored output is the first and last 10MB of what the command printed (the app's
action.output_head_bytes and action.output_tail_bytes settings), with a marker for
what was left out. For an action which returns values instead of a stream, the values
are printed as JSON.

	Examples:
	  Print the output: openrun action output 3jhhmxbf4wluuppt8ygefuzu1dg
	  Follow a running action: openrun action output --follow 3jhhmxbf4wluuppt8ygefuzu1dg`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <runId>")
			}
			runId := cCtx.Args().First()
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			var doc actionRunDoc
			if err := client.Get("/_openrun/actions/runs/get", url.Values{"runId": {runId}}, &doc); err != nil {
				return err
			}
			if !doc.Run.IsStream && doc.Run.Status != types.ActionRunRunning {
				if doc.Result != nil {
					return printActionValues(cCtx, doc.Result.Report, doc.Result.Values, FORMAT_JSON)
				}
				fmt.Fprintf(cCtx.App.ErrWriter, "run %s %s: %s\n", runId, doc.Run.Status, doc.Run.Message) //nolint:errcheck
				return nil
			}
			return followRunOutput(cCtx, client, runId, cCtx.Bool("follow"))
		},
	}
}

func actionCancelCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "cancel",
		Usage:     "Cancel an active background action run",
		Flags:     commonFlags,
		ArgsUsage: "<runId>",
		UsageText: `args: <runId>

	Examples:
	  openrun action cancel 3jhhmxbf4wluuppt8ygefuzu1dg`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <runId>")
			}
			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			var response types.ActionRunResponse
			if err := client.Post("/_openrun/actions/runs/cancel", url.Values{"runId": {cCtx.Args().First()}}, nil, &response); err != nil {
				return err
			}
			fmt.Fprintf(cCtx.App.Writer, "run %s %s\n", response.Run.Id, response.Run.Status) //nolint:errcheck
			return nil
		},
	}
}

// startedRunOf parses a 202 response of the run action API
func startedRunOf(resp *http.Response, data []byte) (types.ActionRunStarted, bool) {
	var started types.ActionRunStarted
	if resp.StatusCode != http.StatusAccepted || json.Unmarshal(data, &started) != nil || started.RunId == "" {
		return started, false
	}
	return started, true
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && strings.Compare(keys[j], keys[j-1]) < 0; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
