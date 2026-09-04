// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func initJobCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "job",
		Usage: "Run and inspect app jobs (scheduled, manual and before_deploy). Jobs are defined in app.star, apps.ace, --job or app update jobs",
		Subcommands: []*cli.Command{
			jobListCommand(commonFlags, clientConfig),
			jobRunCommand(commonFlags, clientConfig),
			jobRunsCommand(commonFlags, clientConfig),
			jobLogsCommand(commonFlags, clientConfig),
			jobCancelCommand(commonFlags, clientConfig),
		},
	}
}

func jobListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())

	return &cli.Command{
		Name:      "list",
		Usage:     "List the jobs of the apps matching a path glob",
		Flags:     flags,
		ArgsUsage: "[<appPathGlob>]",
		UsageText: `args: [<appPathGlob>]

<appPathGlob> defaults to all. ` + PATH_SPEC_HELP + `

	Examples:
	  List all jobs: openrun job list
	  List the jobs of one app: openrun job list /orders`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one arg: <appPathGlob>")
			}
			client := newHttpClient(clientConfig)
			values := url.Values{}
			values.Add("appPathGlob", cmp.Or(cCtx.Args().First(), "all"))

			var response types.JobListResponse
			if err := client.Get("/_openrun/jobs", values, &response); err != nil {
				return err
			}
			printJobList(cCtx, response.Jobs, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printJobList(cCtx *cli.Context, jobs []types.JobInfo, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, jobs, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, j := range jobs {
			json.MarshalEncode(enc, j, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, j := range jobs {
			json.MarshalEncode(enc, j, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_CSV:
		for _, j := range jobs {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s,%t,%s,%s,%s\n", j.AppPath, j.Stage, j.Spec.Name, j.Origin, jobExecutor(j.Spec), jobTriggerText(j.Spec),
				j.Spec.IsEnabled(), jobNextRun(j), jobLastStatus(j), jobLastRunId(j))
		}
	default:
		formatStr := "%-30s %-6s %-20s %-10s %-8s %-28s %-8s %-20s %-10s %-s\n"
		printStdout(cCtx, formatStr, "App", "Stage", "Job", "Origin", "Type", "Trigger", "Enabled", "NextRun", "LastStatus", "LastRun")
		for _, j := range jobs {
			if len(j.Warnings) > 0 {
				printStdout(cCtx, formatStr, j.AppPath, j.Stage, "-", "-", "-", strings.Join(j.Warnings, "; "), "", "", "", "")
				continue
			}
			printStdout(cCtx, formatStr, j.AppPath, j.Stage, j.Spec.Name, j.Origin, jobExecutor(j.Spec), jobTriggerText(j.Spec),
				strconv.FormatBool(j.Spec.IsEnabled()), jobNextRun(j), jobLastStatus(j), jobLastRunId(j))
		}
	}
}

func jobExecutor(spec types.JobSpec) string {
	if spec.IsRun() {
		return "run"
	}
	return "command"
}

func jobTriggerText(spec types.JobSpec) string {
	if spec.TriggerType() == types.JobTriggerCron {
		text := "cron " + spec.Trigger.Schedule
		if spec.Trigger.Timezone != "" {
			text += " " + spec.Trigger.Timezone
		}
		return text
	}
	return spec.TriggerType()
}

func jobNextRun(j types.JobInfo) string {
	if j.NextRun == nil {
		return "-"
	}
	return *j.NextRun
}

func jobLastStatus(j types.JobInfo) string {
	if j.LastRun == nil {
		return "-"
	}
	return j.LastRun.Status
}

func jobLastRunId(j types.JobInfo) string {
	if j.LastRun == nil {
		return "-"
	}
	return j.LastRun.Id
}

func jobRunCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+5)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("stage", "s", "Run on the stage instance instead of prod", false))
	flags = append(flags, newBoolFlag("wait", "w", "Wait for the run to finish and report its status", false))
	flags = append(flags, newBoolFlag("force", "f", "Run a disabled job, or run alongside an active run of the job", false))
	flags = append(flags, &cli.StringSliceFlag{
		Name:    "arg",
		Aliases: []string{"a"},
		Usage:   "Run argument, name=value, for a param the job declares. Repeat for several",
	})

	return &cli.Command{
		Name:      "run",
		Usage:     "Run a job now",
		Flags:     flags,
		ArgsUsage: "<job> <appPath>",
		UsageText: `args: <job> <appPath>

	Examples:
	  Run a job on prod: openrun job run nightly-report /orders
	  Run on stage and wait: openrun job run --stage --wait migrate /orders
	  Run with arguments: openrun job run --arg region=eu nightly-report /orders`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("expected two args: <job> <appPath>")
			}
			args := map[string]string{}
			for _, arg := range cCtx.StringSlice("arg") {
				key, value, ok := strings.Cut(arg, "=")
				if !ok || key == "" {
					return fmt.Errorf("invalid --arg %q, expected name=value", arg)
				}
				args[key] = value
			}
			client := newHttpClient(clientConfig)
			values := url.Values{}
			values.Add("job", cCtx.Args().Get(0))
			values.Add("appPath", cCtx.Args().Get(1))
			values.Add("stage", strconv.FormatBool(cCtx.Bool("stage")))
			values.Add("wait", strconv.FormatBool(cCtx.Bool("wait")))
			values.Add("force", strconv.FormatBool(cCtx.Bool("force")))

			var response types.JobRunResponse
			if err := client.Post("/_openrun/jobs/run", values, types.JobRunRequest{Args: args}, &response); err != nil {
				return err
			}
			run := response.Run
			if cCtx.Bool("wait") {
				fmt.Printf("Run %s of job %s on %s: %s", run.Id, run.JobName, run.AppPath, run.Status)
				if run.Message != "" {
					fmt.Printf(" (%s)", run.Message)
				}
				fmt.Println()
				if run.Status != types.JobRunSucceeded {
					return fmt.Errorf("job run %s %s", run.Id, run.Status)
				}
				return nil
			}
			fmt.Printf("Started run %s of job %s on %s. Logs: openrun job logs %s\n", run.Id, run.JobName, run.AppPath, run.Id)
			return nil
		},
	}
}

func jobRunsCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+4)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, newStringFlag("job", "j", "Show the runs of one job", ""))
	flags = append(flags, newStringFlag("status", "", "Filter by status: running, succeeded, failed, timed_out, canceled, lost", ""))
	flags = append(flags, newIntFlag("limit", "n", "Maximum number of runs to show", 50))

	return &cli.Command{
		Name:      "runs",
		Usage:     "List the job runs of an app (prod and stage instances), newest first",
		Flags:     flags,
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

	Examples:
	  List runs: openrun job runs /orders
	  Failed runs of one job: openrun job runs --job nightly-report --status failed /orders`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <appPath>")
			}
			client := newHttpClient(clientConfig)
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())
			values.Add("job", cCtx.String("job"))
			values.Add("status", cCtx.String("status"))
			values.Add("limit", strconv.Itoa(cCtx.Int("limit")))

			var response types.JobRunsResponse
			if err := client.Get("/_openrun/jobs/runs", values, &response); err != nil {
				return err
			}
			printJobRuns(cCtx, response.Runs, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

// formatJobTime renders a run timestamp in UTC, like every other job
// timestamp (run records, CL_JOB_SCHEDULED_AT, job list next run)
func formatJobTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func jobRunDuration(run types.JobRun) string {
	if run.EndedAt == nil {
		return "-"
	}
	return run.EndedAt.Sub(run.StartedAt).Round(time.Second).String()
}

func printJobRuns(cCtx *cli.Context, runs []types.JobRun, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, runs, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, r := range runs {
			json.MarshalEncode(enc, r, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, r := range runs {
			json.MarshalEncode(enc, r, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_CSV:
		for _, r := range runs {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", r.Id, r.AppPath, r.JobName, r.Stage(), r.Trigger, r.Status,
				r.StartedAt.UTC().Format(time.RFC3339), jobRunDuration(r), r.Actor, r.Message)
		}
	default:
		formatStr := "%-32s %-20s %-8s %-14s %-10s %-21s %-10s %-12s %-s\n"
		printStdout(cCtx, formatStr, "Run", "Job", "Stage", "Trigger", "Status", "Started (UTC)", "Duration", "Actor", "Message")
		for _, r := range runs {
			printStdout(cCtx, formatStr, r.Id, r.JobName, r.Stage(), r.Trigger, r.Status, formatJobTime(r.StartedAt),
				jobRunDuration(r), r.Actor, strings.ReplaceAll(r.Message, "\n", " "))
		}
	}
}

func jobLogsCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags))
	flags = append(flags, commonFlags...)

	return &cli.Command{
		Name:      "logs",
		Usage:     "Show the output of a job run, while its container exists",
		Flags:     flags,
		ArgsUsage: "<runId>",
		UsageText: `args: <runId>

	Examples:
	  Show run output: openrun job logs run_2abc...`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <runId>")
			}
			client := newHttpClient(clientConfig)
			values := url.Values{}
			values.Add("id", cCtx.Args().First())

			var response types.JobLogsResponse
			if err := client.Get("/_openrun/jobs/logs", values, &response); err != nil {
				return err
			}
			run := response.Run
			fmt.Printf("Run %s job %s app %s status %s\n", run.Id, run.JobName, run.AppPath, run.Status)
			if run.Message != "" && run.ContainerName != "" {
				fmt.Printf("Message: %s\n", run.Message)
			}
			fmt.Println(response.Logs)
			return nil
		},
	}
}

func jobCancelCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags))
	flags = append(flags, commonFlags...)

	return &cli.Command{
		Name:      "cancel",
		Usage:     "Cancel an active job run",
		Flags:     flags,
		ArgsUsage: "<runId>",
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <runId>")
			}
			client := newHttpClient(clientConfig)
			values := url.Values{}
			values.Add("id", cCtx.Args().First())

			var response types.JobRunResponse
			if err := client.Post("/_openrun/jobs/cancel", values, nil, &response); err != nil {
				return err
			}
			fmt.Printf("Cancel requested for run %s of job %s\n", response.Run.Id, response.Run.JobName)
			return nil
		},
	}
}

// parseJobArgs expands --job values: a JSON object, or @file holding a JSON
// object or list of objects. Each entry is validated client side and
// returned in canonical form; "-" is passed through (clears the list)
func parseJobArgs(values []string) ([]string, error) {
	return parseSpecArgs(values, "job", func(doc string) (string, error) {
		spec, err := types.ParseJobSpec(doc)
		if err != nil {
			return "", err
		}
		return spec.String(), nil
	})
}

// parseSpecArgs expands JSON or @file arguments into canonical spec documents
func parseSpecArgs(values []string, kind string, parse func(string) (string, error)) ([]string, error) {
	var ret []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "-" {
			ret = append(ret, value)
			continue
		}
		docs := []string{value}
		if strings.HasPrefix(value, "@") {
			data, err := os.ReadFile(value[1:])
			if err != nil {
				return nil, fmt.Errorf("error reading %s file %s: %w", kind, value[1:], err)
			}
			trimmed := strings.TrimSpace(string(data))
			if strings.HasPrefix(trimmed, "[") {
				var items []jsontext.Value
				if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
					return nil, fmt.Errorf("error parsing %s file %s: %w", kind, value[1:], err)
				}
				docs = docs[:0]
				for _, item := range items {
					docs = append(docs, string(item))
				}
			} else {
				docs = []string{trimmed}
			}
		}
		for _, doc := range docs {
			canonical, err := parse(doc)
			if err != nil {
				return nil, err
			}
			ret = append(ret, canonical)
		}
	}
	return ret, nil
}
