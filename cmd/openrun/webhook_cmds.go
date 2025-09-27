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

func initWebhookCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "app-webhook",
		Usage: "Manage app level webhooks",
		Subcommands: []*cli.Command{
			webhookListCommand(commonFlags, clientConfig),
			webhookCreateCommand(commonFlags, clientConfig),
			webhookDeleteCommand(commonFlags, clientConfig),
		},
	}
}

func webhookListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:      "list",
		Usage:     "List the webhooks for an app",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

    <app_path> is a required first argument. The optional domain and path are separated by a ":". This is the app for which webhooks are listed.

	Examples:
		openrun app-webhook list example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPath>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())

			var response types.TokenListResponse
			err := client.Get("/_openrun/app_webhook_token", values, &response)
			if err != nil {
				return err
			}

			printWebhookList(cCtx, response.Tokens, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printWebhookList(cCtx *cli.Context, tokens []types.AppToken, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(tokens) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, version := range tokens {
			enc.Encode(version) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, f := range tokens {
			enc.Encode(f) //nolint:errcheck
			printStdout(cCtx, "\n")
		}
	case FORMAT_BASIC:
		fallthrough
	case FORMAT_TABLE:
		formatStrHead := "%-15s %-40s %s\n"
		formatStrData := "%-15s %-40s %s\n"
		printStdout(cCtx, formatStrHead, "Type", "Token", "Url")
		for _, f := range tokens {
			printStdout(cCtx, formatStrData, f.Type, f.Token, f.Url)
		}
	case FORMAT_CSV:
		for _, version := range tokens {
			printStdout(cCtx, "%s,%s,%s\n", version.Type, version.Token, version.Url)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func webhookCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create webhooks for an app",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<webhookType> <appPath>",
		UsageText: `args: <webhookType> appPath>

    <webhookType> is the required first argument. Supported types are: reload, reload_promote and promote.
    <app_path> is the required second argument. The optional domain and path are separated by a ":". This is the app for which webhooks are created.

	Examples:
		openrun app-webhook create reload example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <webhookType> <appPath>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("webhookType", cCtx.Args().Get(0))
			values.Add("appPath", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var response types.TokenCreateResponse
			err := client.Post("/_openrun/app_webhook_token", values, map[string]string{}, &response)
			if err != nil {
				return err
			}

			fmt.Printf("Token: %s\n", response.Token.Token)
			fmt.Printf("Url  : %s\n", response.Token.Url)

			if response.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func webhookDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete webhooks for an app",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<webhookType> <appPath>",
		UsageText: `args: <webhookType> appPath>

    <webhookType> is the required first argument. Supported types are: reload, reload_promote and promote.
    <app_path> is the required second argument. The optional domain and path are separated by a ":". This is the app for which webhooks are deleted.

	Examples:
		openrun app-webhook delete reload example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <webhookType> <appPath>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("webhookType", cCtx.Args().Get(0))
			values.Add("appPath", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var response types.TokenDeleteResponse
			err := client.Delete("/_openrun/app_webhook_token", values, &response)
			if err != nil {
				return err
			}

			fmt.Printf("Token deleted.")

			if response.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}
