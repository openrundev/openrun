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
	SOURCE_FLAG        = "source"
	METADATA_FLAG      = "metadata"
	METADATA_JSON_FLAG = "metadata-json"
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

// parseKVEntries parses key=value entries into a map[string]any. String values are
// stored as-is. To provide non-string values, use the *-json flag instead.
func parseKVEntries(entries []string) (map[string]any, error) {
	out := make(map[string]any, len(entries))
	for _, e := range entries {
		key, value, ok := strings.Cut(e, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid entry %q, expected key=value", e)
		}
		out[key] = value
	}
	return out, nil
}

// mergeJSONIntoMap parses jsonStr (when non-empty) and merges its top-level keys into dst.
// dst is created if nil. Keys from jsonStr take precedence over existing entries.
func mergeJSONIntoMap(dst map[string]any, jsonStr string) (map[string]any, error) {
	if jsonStr == "" {
		return dst, nil
	}
	parsed := map[string]any{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON %q: %w", jsonStr, err)
	}
	if dst == nil {
		dst = make(map[string]any, len(parsed))
	}
	for k, v := range parsed {
		dst[k] = v
	}
	return dst, nil
}

func bindingCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+6)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag(SOURCE_FLAG, "s", "Source for the binding (service id, or base binding path)", ""))
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  METADATA_FLAG,
			Usage: "Set a metadata entry. Format is key=value. Can be specified multiple times",
		})
	flags = append(flags, newStringFlag(METADATA_JSON_FLAG, "", "Metadata as a JSON object. Merged on top of --metadata entries", ""))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create a new binding entry",
		Flags:     flags,
		ArgsUsage: "<path>",
		UsageText: `args: <path>

<path> is the unique path of the binding.

Examples:
  Create a binding: openrun binding create /apps/p1 --source postgres/p1 --metadata role=reader
  Create with JSON metadata: openrun binding create /apps/p1 --source postgres/p1 --metadata-json '{"role":"reader","quota":10}'
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <path>")
			}
			path := cCtx.Args().First()

			metadata, err := parseKVEntries(cCtx.StringSlice(METADATA_FLAG))
			if err != nil {
				return err
			}
			metadata, err = mergeJSONIntoMap(metadata, cCtx.String(METADATA_JSON_FLAG))
			if err != nil {
				return err
			}

			binding := types.Binding{
				Path:   path,
				Source: cCtx.String(SOURCE_FLAG),
				Metadata: types.BindingMetadata{
					Config: metadata,
				},
				StagedMetadata: types.BindingMetadata{
					Config: metadata,
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
	flags := make([]cli.Flag, 0, len(commonFlags)+7)
	flags = append(flags, commonFlags...)
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  METADATA_FLAG,
			Usage: "Update a metadata entry. Format is key=value. Empty value deletes the key. Can be specified multiple times",
		})
	flags = append(flags, newStringFlag(METADATA_JSON_FLAG, "", "Metadata as a JSON object. Merged on top of existing metadata after --metadata edits", ""))
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
  Update metadata key: openrun binding update /apps/p1 --metadata role=writer
  Delete a metadata key: openrun binding update /apps/p1 --metadata role=
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
				binding.StagedMetadata.Config = map[string]any{}
			}

			for _, entry := range cCtx.StringSlice(METADATA_FLAG) {
				key, value, ok := strings.Cut(entry, "=")
				if !ok || key == "" {
					return fmt.Errorf("invalid metadata entry %q, expected key=value", entry)
				}
				if value == "" {
					delete(binding.StagedMetadata.Config, key)
				} else {
					binding.StagedMetadata.Config[key] = value
				}
			}

			var err error
			binding.StagedMetadata.Config, err = mergeJSONIntoMap(binding.StagedMetadata.Config, cCtx.String(METADATA_JSON_FLAG))
			if err != nil {
				return err
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
				formatAnyMap(b.StagedMetadata.Config), formatAnyMap(b.Metadata.Config), formatAnyMap(b.Metadata.Account))
		}
	case FORMAT_CSV:
		for _, b := range bindings {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s\n", b.Path, b.Source, b.UpdateTime.Format("2006-01-02 15:04:05"),
				formatAnyMap(b.StagedMetadata.Config), formatAnyMap(b.Metadata.Config), formatAnyMap(b.Metadata.Account))
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func formatAnyMap(m map[string]any) string {
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
