// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func initReplicationCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "replication",
		Usage: "Litestream replication status",
		Subcommands: []*cli.Command{
			replicationStatusCommand(commonFlags, clientConfig),
		},
	}
}

func replicationStatusCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:  "status",
		Usage: "Show litestream replication status for metadata databases and sqlite bindings",
		Flags: flags,
		UsageText: `Examples:
  Show replication status:          openrun replication status
  Show replication status as json:  openrun replication status --format json
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}

			client := newHttpClient(clientConfig)
			// An explicit CLI invocation expects current state, not the
			// server's brief status cache
			values := url.Values{}
			values.Add("refresh", "true")
			var response []types.ReplicationStatusEntry
			if err := client.Get("/_openrun/replication/status", values, &response); err != nil {
				return err
			}

			printReplicationStatus(cCtx, response, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func formatReplicationTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func replicationTarget(entry types.ReplicationStatusEntry) string {
	target := entry.Target
	if entry.Env != "" {
		target += " (" + entry.Env + ")"
	}
	return target
}

func printReplicationStatus(cCtx *cli.Context, entries []types.ReplicationStatusEntry, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(entries) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, entry := range entries {
			enc.Encode(entry) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, entry := range entries {
			enc.Encode(entry) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-10s %-40s %-15s\n"
		printStdout(cCtx, formatStr, "Kind", "Target", "State")
		for _, entry := range entries {
			printStdout(cCtx, formatStr, entry.Kind, replicationTarget(entry), entry.State)
		}
	case FORMAT_TABLE, "":
		formatStr := "%-10s %-40s %-15s %-15s %-20s %-10s %-30s\n"
		printStdout(cCtx, formatStr, "Kind", "Target", "Config", "State", "LastSync", "Files", "Apps")
		for _, entry := range entries {
			files := "-"
			if len(entry.Files) > 0 {
				names := make([]string, 0, len(entry.Files))
				for _, f := range entry.Files {
					names = append(names, f.Path)
				}
				files = strings.Join(names, ",")
			}
			apps := strings.Join(entry.AppPaths, ",")
			printStdout(cCtx, formatStr, entry.Kind, replicationTarget(entry), entry.LitestreamConfig,
				entry.State, formatReplicationTime(entry.LastSync), files, apps)
		}
	case FORMAT_CSV:
		for _, entry := range entries {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s,%d\n", entry.Kind, replicationTarget(entry),
				entry.LitestreamConfig, entry.State, formatReplicationTime(entry.LastSync),
				strings.Join(entry.AppPaths, ";"), entry.ReplicaSize)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}
