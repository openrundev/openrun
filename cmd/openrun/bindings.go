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
	SOURCE_FLAG = "source"
	GRANT_FLAG  = "grant"
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
			Name:    CONFIG_FLAG,
			Aliases: []string{"c"},
			Usage:   "Update a config entry. Format is key=value. Empty value deletes the key. Can be specified multiple times",
		})
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote staged metadata to active metadata", false))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "update",
		Usage:     "Update an existing binding entry",
		Flags:     flags,
		ArgsUsage: "<path>",
		UsageText: `args: <path>

<path> is the unique path of the binding.

Examples:
  Update config key: openrun binding update /apps/p1 --config role=writer
  Delete a config key: openrun binding update /apps/p1 --config role=
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <path>")
			}
			path := cCtx.Args().First()

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)

			fetchValues := url.Values{}
			fetchValues.Add("path", path)
			var binding types.Binding
			if err := client.Get("/_openrun/binding", fetchValues, &binding); err != nil {
				return err
			}
			if binding.StagedMetadata.Config == nil {
				binding.StagedMetadata.Config = map[string]string{}
			}

			for _, entry := range cCtx.StringSlice(CONFIG_FLAG) {
				key, value, ok := strings.Cut(entry, "=")
				if !ok || key == "" {
					return fmt.Errorf("invalid config entry %q, expected key=value", entry)
				}
				if value == "" {
					delete(binding.StagedMetadata.Config, key)
				} else {
					binding.StagedMetadata.Config[key] = value
				}
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(cCtx.Bool(PROMOTE_FLAG)))

			var response types.Binding
			if err := client.Put("/_openrun/binding", values, &binding, &response); err != nil {
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
