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

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	SET_DEFAULT_FLAG = "set-default"
	IS_DEFAULT_FLAG  = "is-default"
	CONFIG_FLAG      = "config"
)

func initServiceCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "service",
		Usage: "Manage service entries",
		Subcommands: []*cli.Command{
			serviceCreateCommand(commonFlags, clientConfig),
			serviceUpdateCommand(commonFlags, clientConfig),
			serviceDeleteCommand(commonFlags, clientConfig),
			serviceListCommand(commonFlags, clientConfig),
		},
	}
}

// parseServiceID parses a service id of the form <service_type>[/<service_name>].
// If name is omitted, it defaults to the service type.
func parseServiceID(id string) (serviceType, name string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid service id %q: expected <service_type>[/<service_name>]", id)
	}
	return parts[0], parts[1], nil
}

func parseConfigEntries(entries []string) (map[string]string, error) {
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		key, value, ok := strings.Cut(e, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid config entry %q, expected key=value", e)
		}
		out[key] = value
	}
	return out, nil
}

func serviceCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+3)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag(IS_DEFAULT_FLAG, "", "Mark this service as the default for its service type", false))
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    CONFIG_FLAG,
			Aliases: []string{"c"},
			Usage:   "Set a config entry. Format is key=value. Can be specified multiple times",
		})
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create a new service entry",
		Flags:     flags,
		ArgsUsage: "<service_id>",
		UsageText: `args: <service_id>

<service_id> is <service_type>/<service_name>. 

Examples:
  Create a postgres service: openrun service create postgres/p1 --is-default --config url=postgres://localhost
  Create a postgres service: openrun service create postgres/p2 --config url=postgres://host:5432/db --config user=admin
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <service_id>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			config, err := parseConfigEntries(cCtx.StringSlice(CONFIG_FLAG))
			if err != nil {
				return err
			}

			service := types.Service{
				Name:        name,
				ServiceType: serviceType,
				IsDefault:   cCtx.Bool(IS_DEFAULT_FLAG),
				Config:      config,
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.Service
			if err := client.Post("/_openrun/service", values, &service, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s created\n", response.ServiceType, response.Name)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func serviceUpdateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+3)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag(SET_DEFAULT_FLAG, "", "Set the is_default flag (true/false)", false))
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    CONFIG_FLAG,
			Aliases: []string{"c"},
			Usage:   "Update a config entry. Format is key=value. Empty value deletes the key. Can be specified multiple times",
		})
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "update",
		Usage:     "Update an existing service binding",
		Flags:     flags,
		ArgsUsage: "<service_id>",
		UsageText: `args: <service_id>

<service_id> is <service_type>/<service_name>. 

Examples:
  Mark service as default: openrun service update postgres/p1 --set-default=true
  Update a config value: openrun service update postgres/p1 --config url=postgres://host:5432/db
  Delete a config key: openrun service update postgres/p1 --config password=
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <service_id>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)

			// Fetch the existing service to merge changes onto
			fetchValues := url.Values{}
			fetchValues.Add("service_type", serviceType)
			fetchValues.Add("name", name)
			var existing []types.Service
			if err := client.Get("/_openrun/services", fetchValues, &existing); err != nil {
				return err
			}
			if len(existing) == 0 {
				return fmt.Errorf("service %s/%s not found", serviceType, name)
			}
			service := existing[0]
			if service.Config == nil {
				service.Config = map[string]string{}
			}

			if cCtx.IsSet(SET_DEFAULT_FLAG) {
				service.IsDefault = cCtx.Bool(SET_DEFAULT_FLAG)
			}

			for _, entry := range cCtx.StringSlice(CONFIG_FLAG) {
				key, value, ok := strings.Cut(entry, "=")
				if !ok || key == "" {
					return fmt.Errorf("invalid config entry %q, expected key=value", entry)
				}
				if value == "" {
					delete(service.Config, key)
				} else {
					service.Config[key] = value
				}
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var response types.Service
			if err := client.Put("/_openrun/service", values, &service, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s updated\n", response.ServiceType, response.Name)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func serviceDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete a service binding",
		Flags:     flags,
		ArgsUsage: "<service_id>",
		UsageText: `args: <service_id>

<service_id> is <service_type>/<service_name>. 

Examples:
  Delete service: openrun service delete postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <service_id>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			values := url.Values{}
			values.Add("service_type", serviceType)
			values.Add("name", name)
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response map[string]any
			if err := client.Delete("/_openrun/service", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s deleted\n", serviceType, name)
			if cCtx.Bool(DRY_RUN_FLAG) {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func serviceListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:      "list",
		Usage:     "List service bindings",
		Flags:     flags,
		ArgsUsage: "[<service_id>]",
		UsageText: `args: [<service_id>]

<service_id> is an optional <service_type>/<service_name> filter. If only the
service type is given, all services of that type are listed. If the service name
is given, only the service with that name is listed.

Examples:
  List all services:                    openrun service list
  List services of type postgres:       openrun service list postgres
  List specific service:                openrun service list postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one arg: [<service_id>]")
			}

			values := url.Values{}
			if cCtx.NArg() == 1 {
				split := strings.Split(cCtx.Args().First(), "/")
				if len(split) > 2 {
					return fmt.Errorf("invalid service id %q, expected <service_type>/<service_name>", cCtx.Args().First())
				}
				serviceType := split[0]
				name := ""
				if len(split) == 2 {
					name = split[1]
				}
				values.Add("service_type", serviceType)
				values.Add("name", name)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response []types.Service
			if err := client.Get("/_openrun/services", values, &response); err != nil {
				return err
			}

			printServiceList(cCtx, response, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printServiceList(cCtx *cli.Context, services []types.Service, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(services) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, s := range services {
			enc.Encode(s) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, s := range services {
			enc.Encode(s) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-20s %-20s %-9s\n"
		printStdout(cCtx, formatStr, "ServiceType", "Name", "IsDefault")
		for _, s := range services {
			printStdout(cCtx, formatStr, s.ServiceType, s.Name, strconv.FormatBool(s.IsDefault))
		}
	case FORMAT_TABLE, "":
		formatStrHead := "%-20s %-20s %-9s %-25s %-s\n"
		formatStrData := "%-20s %-20s %-9t %-25s %-s\n"
		printStdout(cCtx, formatStrHead, "ServiceType", "Name", "IsDefault", "UpdateTime", "Config")
		for _, s := range services {
			printStdout(cCtx, formatStrData, s.ServiceType, s.Name, s.IsDefault, s.UpdateTime.Format("2006-01-02 15:04:05"), formatConfig(s.Config))
		}
	case FORMAT_CSV:
		for _, s := range services {
			printStdout(cCtx, "%s,%s,%t,%s,%s\n", s.ServiceType, s.Name, s.IsDefault, s.UpdateTime.Format("2006-01-02 15:04:05"), formatConfig(s.Config))
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func formatConfig(config map[string]string) string {
	if len(config) == 0 {
		return ""
	}
	parts := make([]string, 0, len(config))
	for k, v := range config {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ";")
}
