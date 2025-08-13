// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func initSyncCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Manage sync operations, scheduled and webhook",
		Subcommands: []*cli.Command{
			syncScheduleCommand(commonFlags, clientConfig),
			syncRunCommand(commonFlags, clientConfig),
			syncListCommand(commonFlags, clientConfig),
			syncDeleteCommand(commonFlags, clientConfig),
		},
	}
}

func syncScheduleCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("branch", "b", "The branch to checkout if using git source", "main"))
	flags = append(flags, newStringFlag("git-auth", "g", "The name of the git_auth entry in server config to use", ""))
	flags = append(flags, newBoolFlag("approve", "a", "Approve the app permissions", false))
	flags = append(flags, newStringFlag("reload", "r", "Which apps to reload: none, updated, matched", ""))
	flags = append(flags, newBoolFlag("promote", "p", "Promote changes from stage to prod", false))
	flags = append(flags, newIntFlag("minutes", "s", "Schedule sync for every N minutes", 0))
	flags = append(flags, newBoolFlag("clobber", "", "Force update app config, overwriting non-declarative changes", false))
	flags = append(flags, newBoolFlag("force-reload", "f", "Force reload even if there are no new commits", false))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "schedule",
		Usage:     "Create scheduled sync job for updating app config",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<filePath>",
		UsageText: `args: <filePath>

<filePath> is the path to the apply file containing the app configuration.

Examples:
  Create scheduled sync, reloading apps with code changes: openrun sync schedule ./app.ace
  Create scheduled sync, reloading only apps with a config change: openrun sync schedule --reload=updated github.com/openrundev/apps/apps.ace
  Create scheduled sync, promoting changes: openrun sync schedule --promote --approve github.com/openrundev/apps/apps.ace
  Create scheduled sync, overwriting changes: openrun sync schedule --promote --clobber github.com/openrundev/apps/apps.ace
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg : <filePath>")
			}

			reloadMode := types.AppReloadOption(cmp.Or(cCtx.String("reload"), string(types.AppReloadOptionMatched)))
			values := url.Values{}

			sourceUrl, err := makeAbsolute(cCtx.Args().Get(0))
			if err != nil {
				return err
			}

			values.Add("path", sourceUrl)
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add("scheduled", "true")

			sync := types.SyncMetadata{
				GitBranch:         cCtx.String("branch"),
				GitAuth:           cCtx.String("git-auth"),
				Promote:           cCtx.Bool("promote"),
				Approve:           cCtx.Bool("approve"),
				Reload:            string(reloadMode),
				Clobber:           cCtx.Bool("clobber"),
				ForceReload:       cCtx.Bool("force-reload"),
				ScheduleFrequency: cCtx.Int("minutes"),
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var syncResponse types.SyncCreateResponse
			err = client.Post("/_openrun/sync", values, sync, &syncResponse)
			if err != nil {
				return err
			}

			if syncResponse.SyncJobStatus.Error != "" {
				return fmt.Errorf("error creating sync job: %s", syncResponse.SyncJobStatus.Error)
			}

			printApplyResponse(cCtx, &syncResponse.SyncJobStatus.ApplyResponse)

			fmt.Printf("\nSync job created with Id: %s\n", syncResponse.Id)
			if syncResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func syncListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "list",
		Usage:     "List the sync jobs",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "",
		UsageText: `
	Examples:
	  List sync jobs: openrun sync list`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 0 {
				return fmt.Errorf("no args expected")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())

			var response types.SyncListResponse
			err := client.Get("/_openrun/sync", values, &response)
			if err != nil {
				return err
			}

			printSyncList(cCtx, response.Entries, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func syncRunCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "run",
		Usage:     "Run specified sync job",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "args: <syncId>",
		UsageText: `
	Examples:
	  Run sync job: openrun sync run cl_sync_44asd232`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one args: <syncId>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("id", cCtx.Args().First())
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var response types.SyncJobStatus
			err := client.Post("/_openrun/sync/run", values, nil, &response)
			if err != nil {
				return err
			}

			if response.Error != "" {
				return fmt.Errorf("error running sync job: %s", response.Error)
			}

			printApplyResponse(cCtx, &response.ApplyResponse)
			if response.ApplyResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func syncDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete specified sync job",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "args: <syncId>",
		UsageText: `
	Examples:
	  Delete sync jobs: openrun sync delete cl_sync_44asd232`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one args: <syncId>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("id", cCtx.Args().First())

			var response types.SyncDeleteResponse
			err := client.Delete("/_openrun/sync", values, &response)
			if err != nil {
				return err
			}

			if response.Id != "" {
				fmt.Fprintf(cCtx.App.Writer, "Sync job with Id %s deleted\n", cCtx.Args().First())
			}

			if response.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func printSyncList(cCtx *cli.Context, sync []*types.SyncEntry, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(sync)
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, s := range sync {
			enc.Encode(s)
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, s := range sync {
			enc.Encode(s)
		}
	case FORMAT_BASIC:
		formatStr := "%-35s %-9s %-12s %-s\n"
		fmt.Fprintf(cCtx.App.Writer, formatStr, "Id", "State", "SyncType", "Path")

		for _, s := range sync {
			fmt.Fprintf(cCtx.App.Writer, formatStr, s.Id, s.Status.State, getSyncType(s), s.Path)
		}
	case FORMAT_TABLE:
		formatStrHead := "%-35s %-9s %-12s %-8s %-8s %-7s %-7s %-10s %-15s %-60s %-s\n"
		formatStrData := "%-35s %-9s %-12s %-8s %-8t %-7t %-7t %-10s %-15s %-60s %-s\n"
		fmt.Fprintf(cCtx.App.Writer, formatStrHead, "Id", "State", "SyncType", "Reload", "Promote", "Approve", "Clobber", "GitAuth", "Branch", "Path", "Error")

		for _, s := range sync {
			fmt.Fprintf(cCtx.App.Writer, formatStrData, s.Id, s.Status.State, getSyncType(s), s.Metadata.Reload, s.Metadata.Promote,
				s.Metadata.Approve, s.Metadata.Clobber, s.Metadata.GitAuth, s.Metadata.GitBranch, s.Path, s.Status.Error)
		}
	case FORMAT_CSV:
		for _, s := range sync {
			fmt.Fprintf(cCtx.App.Writer, "%s,%s,%s,%s,%t,%t,%t,%s,%s,%s,%s,%s\n", s.Id, s.Status.State, getSyncType(s), s.Metadata.Reload, s.Metadata.Promote, s.Metadata.Approve, s.Metadata.Clobber,
				s.Metadata.GitAuth, s.Metadata.GitBranch, s.Path, s.Metadata.WebhookUrl, s.Status.Error)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func getSyncType(sync *types.SyncEntry) string {
	if sync.Metadata.ScheduleFrequency > 0 {
		return fmt.Sprintf("%d (mins)", sync.Metadata.ScheduleFrequency)
	}
	return "Webhook"
}
