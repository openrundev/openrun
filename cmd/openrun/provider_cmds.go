// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	SOURCE_URL_FLAG       = "source-url"
	PROVIDER_VERSION_FLAG = "version"
)

func initProviderCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "provider",
		Usage: "Manage out-of-process binding providers",
		Subcommands: []*cli.Command{
			providerInstallCommand(commonFlags, clientConfig),
			providerUninstallCommand(commonFlags, clientConfig),
			providerListCommand(commonFlags, clientConfig),
		},
	}
}

func providerInstallCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag(SOURCE_URL_FLAG, "", "The provider binary source: an http(s) url (supports {version}, {os} and {arch} placeholders) or a server-local file path", ""))
	flags = append(flags, newStringFlag(PROVIDER_VERSION_FLAG, "", "The provider version to install", ""))

	return &cli.Command{
		Name:      "install",
		Usage:     "Install (or update) an out-of-process binding provider",
		Flags:     flags,
		ArgsUsage: "<provider_name>",
		UsageText: `args: <provider_name>

The provider binary is downloaded (or copied), verified, registered in the
metadata database and its service types become available for service create.

Examples:
  openrun provider install mongodb --source-url https://github.com/openrundev/openrun-bindings/releases/download/mongodb%2F{version}/openrun-binding-mongodb-{os}-{arch} --version v0.1.0
  openrun provider install redis --source-url /tmp/openrun-binding-redis
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <provider_name>")
			}
			request := types.ProviderInstallRequest{
				Name:      cCtx.Args().First(),
				SourceURL: cCtx.String(SOURCE_URL_FLAG),
				Version:   cCtx.String(PROVIDER_VERSION_FLAG),
			}
			if request.SourceURL == "" {
				return fmt.Errorf("--%s is required", SOURCE_URL_FLAG)
			}

			client := newHttpClient(clientConfig)
			var response types.BindingProvider
			if err := client.Post("/_openrun/provider", url.Values{}, &request, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Provider %s %s installed, service types: %s\n",
				response.Name, response.Version, strings.Join(response.ServiceTypes, ", "))
			return nil
		},
	}
}

func providerUninstallCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("force", "", "Uninstall even if services of the provider's types exist", false))

	return &cli.Command{
		Name:      "uninstall",
		Usage:     "Uninstall an out-of-process binding provider",
		Flags:     flags,
		ArgsUsage: "<provider_name>",
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <provider_name>")
			}
			name := cCtx.Args().First()

			values := url.Values{}
			values.Add("name", name)
			values.Add("force", strconv.FormatBool(cCtx.Bool("force")))

			client := newHttpClient(clientConfig)
			var response map[string]any
			if err := client.Delete("/_openrun/provider", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Provider %s uninstalled\n", name)
			return nil
		},
	}
}

func providerListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:  "list",
		Usage: "List installed binding providers",
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			client := newHttpClient(clientConfig)
			var response []types.BindingProvider
			if err := client.Get("/_openrun/providers", url.Values{}, &response); err != nil {
				return err
			}

			printProviderList(cCtx, response, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printProviderList(cCtx *cli.Context, providers []types.BindingProvider, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(providers) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, p := range providers {
			enc.Encode(p) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, p := range providers {
			enc.Encode(p) //nolint:errcheck
		}
	case FORMAT_CSV:
		for _, p := range providers {
			printStdout(cCtx, "%s,%s,%s\n", p.Name, p.Version, strings.Join(p.ServiceTypes, " "))
		}
	default:
		formatStr := "%-20s %-15s %-30s %-s\n"
		printStdout(cCtx, formatStr, "Name", "Version", "ServiceTypes", "SourceURL")
		for _, p := range providers {
			printStdout(cCtx, formatStr, p.Name, p.Version, strings.Join(p.ServiceTypes, ", "), p.SourceURL)
		}
	}
}
