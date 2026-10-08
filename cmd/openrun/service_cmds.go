// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	SET_DEFAULT_FLAG = "set-default"
	IS_DEFAULT_FLAG  = "is-default"
	CONFIG_FLAG      = "config"
)

// stagingServiceFlag names the staging service of a service: a string flag,
// unlike the bool --stage of the app and binding commands. --staging is
// accepted as an alias
func stagingServiceFlag(usage string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:    STAGE_FLAG,
		Aliases: []string{STAGING_FLAG},
		Usage:   usage,
	}
}

func initServiceCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "service",
		Usage: "Manage service entries",
		Subcommands: []*cli.Command{
			serviceCreateCommand(commonFlags, clientConfig),
			serviceUpdateCommand(commonFlags, clientConfig),
			serviceDeleteCommand(commonFlags, clientConfig),
			serviceListCommand(commonFlags, clientConfig),
			serviceHealthCommand(commonFlags, clientConfig),
		},
	}
}

func serviceHealthCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "health",
		Usage:     "Check the health of a service: connect with the admin credentials and run a no-op operation",
		Flags:     commonFlags,
		ArgsUsage: "<serviceId>",
		UsageText: `args: <serviceId>

<serviceId> is <serviceType>/<serviceName>.

Examples:
  Check service health: openrun service health postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one argument: <serviceId>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			values := url.Values{}
			values.Add("service_type", serviceType)
			values.Add("name", name)

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			var response map[string]any
			if err := client.Get("/_openrun/service/health", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s is healthy\n", serviceType, name)
			return nil
		},
	}
}

// parseServiceID parses a service id of the form <serviceType>/<serviceName>.
// Both parts are required; "service list" alone accepts a bare type.
func parseServiceID(id string) (serviceType, name string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid service id %q: expected <serviceType>/<serviceName>", id)
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
	flags := make([]cli.Flag, 0, len(commonFlags)+4)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag(IS_DEFAULT_FLAG, "", "Mark this service as the default for its service type", false))
	flags = append(flags, stagingServiceFlag("The name of the staging service for this service, of the same service type"))
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
		ArgsUsage: "<serviceId>",
		UsageText: `args: <serviceId>

<serviceId> is <serviceType>/<serviceName>. 

Examples:
  Create a postgres service: openrun service create postgres/p1 --is-default --config url=postgres://localhost
  Create a postgres service: openrun service create postgres/p2 --config url=postgres://host:5432/db --config user=admin
  Create with a staging service: openrun service create postgres/main --stage stage --config url=postgres://host:5432/db
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one argument: <serviceId>")
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
				Staging:     cCtx.String(STAGE_FLAG),
				Config:      config,
			}

			values := url.Values{}
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			var response types.Service
			if err := client.Post("/_openrun/service", values, &service, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s created\n", response.ServiceType, response.Name)
			if cCtx.Bool(DRY_RUN_FLAG) {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func serviceUpdateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+4)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag(SET_DEFAULT_FLAG, "", "Mark this service as the default for its service type; --set-default=false clears it", false))
	flags = append(flags, stagingServiceFlag("Set the name of the staging service. An empty value (--stage \"\") clears it"))
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    CONFIG_FLAG,
			Aliases: []string{"c"},
			Usage:   "Update a config entry. Format is key=value. Empty value deletes the key. Can be specified multiple times",
		})
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "update",
		Usage:     "Update an existing service entry",
		Flags:     flags,
		ArgsUsage: "<serviceId>",
		UsageText: `args: <serviceId>

<serviceId> is <serviceType>/<serviceName>. 

Examples:
  Mark service as default: openrun service update postgres/p1 --set-default
  Clear the default flag: openrun service update postgres/p1 --set-default=false
  Set the staging service: openrun service update postgres/p1 --stage p1_stage
  Clear the staging service: openrun service update postgres/p1 --stage ""
  Update a config value: openrun service update postgres/p1 --config url=postgres://host:5432/db
  Delete a config key: openrun service update postgres/p1 --config password=
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one argument: <serviceId>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()

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
			if cCtx.IsSet(STAGE_FLAG) {
				service.Staging = cCtx.String(STAGE_FLAG)
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
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
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
		Usage:     "Delete a service entry",
		Flags:     flags,
		ArgsUsage: "<serviceId>",
		UsageText: `args: <serviceId>

<serviceId> is <serviceType>/<serviceName>. 

Examples:
  Delete service: openrun service delete postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one argument: <serviceId>")
			}
			serviceType, name, err := parseServiceID(cCtx.Args().First())
			if err != nil {
				return err
			}

			values := url.Values{}
			values.Add("service_type", serviceType)
			values.Add("name", name)
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			var response map[string]any
			if err := client.Delete("/_openrun/service", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Service %s/%s deleted\n", serviceType, name)
			if cCtx.Bool(DRY_RUN_FLAG) {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func serviceListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())

	return &cli.Command{
		Name:      "list",
		Usage:     "List service entries",
		Flags:     flags,
		ArgsUsage: "[<serviceId>]",
		UsageText: `args: [<serviceId>]

<serviceId> is an optional <serviceType>/<serviceName> filter. If only the
service type is given, all services of that type are listed. If the service name
is given, only the service with that name is listed.

Examples:
  List all services:                    openrun service list
  List services of type postgres:       openrun service list postgres
  List specific service:                openrun service list postgres/p1
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one argument: [<serviceId>]")
			}

			values := url.Values{}
			if cCtx.NArg() == 1 {
				split := strings.Split(cCtx.Args().First(), "/")
				if len(split) > 2 {
					return fmt.Errorf("invalid service id %q, expected <serviceType>/<serviceName>", cCtx.Args().First())
				}
				serviceType := split[0]
				name := ""
				if len(split) == 2 {
					name = split[1]
				}
				values.Add("service_type", serviceType)
				values.Add("name", name)
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
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
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, services, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, s := range services {
			json.MarshalEncode(enc, s, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, s := range services {
			json.MarshalEncode(enc, s, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-20s %-20s %-9s %-20s\n"
		printStdout(cCtx, formatStr, "ServiceType", "Name", "IsDefault", "Staging")
		for _, s := range services {
			printStdout(cCtx, formatStr, s.ServiceType, s.Name, strconv.FormatBool(s.IsDefault), s.Staging)
		}
	case FORMAT_TABLE, "":
		formatStrHead := "%-20s %-20s %-9s %-20s %-25s %-s\n"
		formatStrData := "%-20s %-20s %-9t %-20s %-25s %-s\n"
		printStdout(cCtx, formatStrHead, "ServiceType", "Name", "IsDefault", "Staging", "UpdateTime", "Config")
		for _, s := range services {
			printStdout(cCtx, formatStrData, s.ServiceType, s.Name, s.IsDefault, s.Staging, s.UpdateTime.Format("2006-01-02 15:04:05"), formatMap(s.Config))
		}
	case FORMAT_CSV:
		for _, s := range services {
			printStdout(cCtx, "%s,%s,%s,%t,%s,%s,%s\n", s.Id, s.ServiceType, s.Name, s.IsDefault, s.Staging, s.UpdateTime.Format("2006-01-02 15:04:05"), formatMap(s.Config))
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}
