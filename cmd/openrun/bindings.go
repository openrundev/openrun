// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	SOURCE_FLAG       = "source"
	GRANT_FLAG        = "grant"
	ADD_GRANT_FLAG    = "add-grant"
	DELETE_GRANT_FLAG = "delete-grant"
	REAPPLY_ALL_FLAG  = "reapply-all"
	REAPPLY_ALL_ARG   = "reapplyAll"
)

func initBindingCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "binding",
		Usage: "Manage binding entries",
		Subcommands: []*cli.Command{
			bindingCreateCommand(commonFlags, clientConfig),
			bindingUpdateCommand(commonFlags, clientConfig),
			bindingDeleteCommand(commonFlags, clientConfig),
			bindingGetCommand(commonFlags, clientConfig),
			bindingListCommand(commonFlags, clientConfig),
			bindingRunCommand(commonFlags, clientConfig),
		},
	}
}

func bindingCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+3)
	flags = append(flags, commonFlags...)
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    CONFIG_FLAG,
			Aliases: []string{"c"},
			Usage:   "Set a config entry. Format is key=value. Can be specified multiple times",
		})
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  GRANT_FLAG,
			Usage: "Grant to add to the binding metadata. Can be specified multiple times",
		})
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create a new binding entry",
		Flags:     flags,
		ArgsUsage: "<source> <binding_path>",
		UsageText: `args: <source> <binding_path>

<source> is the service id or base binding path.
<binding_path> is the unique path of the binding.

Examples:
  Create a binding: openrun binding create --config role=reader postgres/p1 /apps/p1
  Create with grants: openrun binding create --grant "read:*" /apps/p1 /apps/p2
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("expected two args: <source> <binding_path>")
			}
			source := cCtx.Args().Get(0)
			path := cCtx.Args().Get(1)

			config, err := parseConfigEntries(cCtx.StringSlice(CONFIG_FLAG))
			if err != nil {
				return err
			}
			grants := cCtx.StringSlice(GRANT_FLAG)

			binding := types.Binding{
				Path:   path,
				Source: source,
				Metadata: types.BindingMetadata{
					Grants: append([]string(nil), grants...),
					Config: config,
				},
				StagedMetadata: types.BindingMetadata{
					Grants: append([]string(nil), grants...),
					Config: config,
				},
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.Binding
			if err := client.Post("/_openrun/binding", values, &binding, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Binding %s created\n", response.Path)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func bindingUpdateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+3)
	flags = append(flags, commonFlags...)
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  ADD_GRANT_FLAG,
			Usage: "Grant to add to the binding metadata. Can be specified multiple times",
		})
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  DELETE_GRANT_FLAG,
			Usage: "Grant to delete from the binding metadata. Can be specified multiple times",
		})
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote staged grants to active metadata", false))
	flags = append(flags, newBoolFlag(REAPPLY_ALL_FLAG, "", "Reapply all configured grants, including grants already recorded as applied", false))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "update",
		Usage:     "Update an existing binding entry",
		Flags:     flags,
		ArgsUsage: "<path>",
		UsageText: `args: <path>

<path> is the unique path of the binding.

Examples:
  Add a grant: openrun binding update /apps/p2 --add-grant "read:*"
  Delete a grant: openrun binding update /apps/p2 --delete-grant "read:*"
  Promote staged grants: openrun binding update --promote /apps/p2
  Reapply all grants: openrun binding update --reapply-all --promote /apps/p2
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <path>")
			}
			path := cCtx.Args().First()
			addGrants := cCtx.StringSlice(ADD_GRANT_FLAG)
			deleteGrants := cCtx.StringSlice(DELETE_GRANT_FLAG)
			promote := cCtx.Bool(PROMOTE_FLAG)
			reapplyAll := cCtx.Bool(REAPPLY_ALL_FLAG)
			if len(addGrants) == 0 && len(deleteGrants) == 0 && !promote && !reapplyAll {
				return fmt.Errorf("expected at least one --add-grant, --delete-grant, --promote, or --reapply-all")
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(promote))
			values.Add(REAPPLY_ALL_ARG, strconv.FormatBool(reapplyAll))

			updateRequest := types.UpdateBindingRequest{
				Path:         path,
				AddGrants:    addGrants,
				DeleteGrants: deleteGrants,
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.Binding
			if err := client.Put("/_openrun/binding", values, updateRequest, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Binding %s updated\n", response.Path)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func bindingDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete a binding entry",
		Flags:     flags,
		ArgsUsage: "<path>",
		UsageText: `args: <path>

<path> is the unique path of the binding.

Examples:
  Delete binding: openrun binding delete /apps/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <path>")
			}
			path := cCtx.Args().First()

			values := url.Values{}
			values.Add("path", path)
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response map[string]any
			if err := client.Delete("/_openrun/binding", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Binding %s deleted\n", path)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func bindingGetCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:      "get",
		Usage:     "Get a binding entry by path",
		Flags:     flags,
		ArgsUsage: "<path>",
		UsageText: `args: <path>

<path> is the unique path of the binding.

Examples:
  Get binding: openrun binding get /apps/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <path>")
			}
			path := cCtx.Args().First()

			values := url.Values{}
			values.Add("path", path)

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var binding types.Binding
			if err := client.Get("/_openrun/binding", values, &binding); err != nil {
				return err
			}

			printBindingList(cCtx, []types.Binding{binding}, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func bindingListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag(SOURCE_FLAG, "s", "Filter bindings by source", ""))
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:  "list",
		Usage: "List binding entries",
		Flags: flags,
		UsageText: `Examples:
  List all bindings:                openrun binding list
  List bindings for a source:       openrun binding list --source postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}

			values := url.Values{}
			if source := cCtx.String(SOURCE_FLAG); source != "" {
				values.Add("source", source)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response []types.Binding
			if err := client.Get("/_openrun/bindings", values, &response); err != nil {
				return err
			}

			printBindingList(cCtx, response, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func bindingRunCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag(STAGING_FLAG, "s", "Run using the staged binding account", false))

	return &cli.Command{
		Name:      "run-command",
		Usage:     "Run a command through a binding account",
		Flags:     flags,
		ArgsUsage: "<binding_name> <sql>",
		UsageText: `args: <binding_name> <sql>

<binding_name> is the binding path.
<command> is the command to run.

Examples:
  Run a select: openrun binding run-command /apps/p1 "select * from items"
  Run using staged account: openrun binding run-command --staging /apps/p1 "select current_user"
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() < 2 {
				return fmt.Errorf("expected two args: <binding_name> <sql>")
			}
			bindingName := cCtx.Args().Get(0)
			sql := strings.Join(cCtx.Args().Slice()[1:], " ")

			request := types.RunBindingCommandRequest{
				BindingName: bindingName,
				UseStaging:  cCtx.Bool(STAGING_FLAG),
				Command:     sql,
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response map[string]any
			if err := client.Post("/_openrun/binding/run-command", nil, request, &response); err != nil {
				return err
			}

			enc := json.NewEncoder(cCtx.App.Writer)
			enc.SetIndent("", "  ")
			enc.Encode(response) //nolint:errcheck
			return nil
		},
	}
}

func printBindingList(cCtx *cli.Context, bindings []types.Binding, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(bindings) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, b := range bindings {
			enc.Encode(b) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, b := range bindings {
			enc.Encode(b) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-30s %-30s\n"
		printStdout(cCtx, formatStr, "Path", "Source")
		for _, b := range bindings {
			printStdout(cCtx, formatStr, b.Path, b.Source)
		}
	case FORMAT_TABLE, "":
		formatStr := "%-30s %-30s %-25s %-30s %-30s %-s\n"
		printStdout(cCtx, formatStr, "Path", "Source", "UpdateTime", "StagedMetadata", "Metadata", "Account")
		for _, b := range bindings {
			printStdout(cCtx, formatStr, b.Path, b.Source, b.UpdateTime.Format("2006-01-02 15:04:05"),
				formatMap(b.StagedMetadata.Config), formatMap(b.Metadata.Config), formatMap(b.Metadata.Account))
		}
	case FORMAT_CSV:
		for _, b := range bindings {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s,%s\n", b.Id, b.Path, b.Source, b.UpdateTime.Format("2006-01-02 15:04:05"),
				formatMap(b.StagedMetadata.Config), formatMap(b.Metadata.Config), formatMap(b.Metadata.Account))
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func formatMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ";")
}
