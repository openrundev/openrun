// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func initPreviewCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "preview",
		Usage: "Manage OpenRun preview apps",
		Subcommands: []*cli.Command{
			previewCreateCommand(commonFlags, clientConfig),
		},
	}
}

func previewCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("approve", "a", "Approve the app permissions", false))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create a preview version of the app from specified git commit id",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<gitCommitId> <appPath>",
		UsageText: `args: <gitCommitId> <appPath>

<gitCommitId> is the required first argument. This is the commit from which the preview app is to be created.
<app_path> is the required second argument. The optional domain and path are separated by a ":". This is the app for which the preview app is to be created.

	Examples:
	  Preview and approve: openrun preview create --approve 86c24c88ceda21589801895e9f871617a716ad47 /myapp
	  Preview app in dryrun mode: openrun preview create --dry-run 86c24c88ceda21589801895e9f871617a716ad47 example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <gitCommitId> <appPath>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPath", cCtx.Args().Get(1))
			values.Add("commitId", cCtx.Args().Get(0))
			values.Add("approve", strconv.FormatBool(cCtx.Bool("approve")))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var previewResponse types.AppPreviewResponse
			err := client.Post("/_openrun/preview", values, nil, &previewResponse)
			if err != nil {
				return err
			}

			approveResult := previewResponse.ApproveResult
			fmt.Printf("App audit results %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
			printApproveResult(approveResult)

			status := "failed"
			if previewResponse.Success {
				status = "succeeded"
			}
			if approveResult.NeedsApproval {
				if cCtx.Bool("approve") {
					fmt.Printf("App creation %s. Permissions have been approved\n", status)
				} else {
					fmt.Printf("App creation %s, permissions need to be approved, add the --approve option\n", status)
				}
			} else {
				fmt.Printf("App creation %s. No approval required\n", status)
			}

			if previewResponse.HttpUrl != "" {
				fmt.Printf("\n HTTP Url: %s\n", previewResponse.HttpUrl)
			}
			if previewResponse.HttpsUrl != "" {
				fmt.Printf("HTTPS Url: %s\n", previewResponse.HttpsUrl)
			}

			if previewResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			if !previewResponse.Success {
				return fmt.Errorf("preview app creation failed")
			}
			return nil
		},
	}
}
