// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func appUpdateSettingsCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "settings",
		Usage: "Update OpenRun apps settings. Settings changes are NOT staged, they apply immediately to matched staging, prod and preview apps.",
		Subcommands: []*cli.Command{
			appUpdateStageWrite(commonFlags, clientConfig),
			appUpdatePreviewWrite(commonFlags, clientConfig),
		},
	}
}

func appUpdateStageWrite(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "stage-write-access",
		Usage:     "Update write access permission for staging app",
		Flags:     flags,
		ArgsUsage: "<value:true|false> <appPathGlob>",

		UsageText: `args: <value:true|false> <appPathGlob>

The first required argument <value> is a boolean value, true or false.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

Examples:
  Update all apps, across domains: openrun app settings stage-write-access true all
  Update apps in the example.com domain: openrun app settings stage-write-access false "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("expected two arguments: <value> <appPathGlob>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			body := types.CreateUpdateAppRequest()
			boolValue, err := strconv.ParseBool(cCtx.Args().Get(0))
			if err != nil {
				return fmt.Errorf("invalid value %s for stage-write-access, expected true or false", cCtx.Args().Get(0))
			}
			if boolValue {
				body.StageWriteAccess = types.BoolValueTrue
			} else {
				body.StageWriteAccess = types.BoolValueFalse
			}

			var updateResponse types.AppUpdateSettingsResponse
			err = client.Post("/_openrun/app_settings", values, body, &updateResponse)
			if err != nil {
				return err
			}

			for _, updateResult := range updateResponse.UpdateResults {
				printStdout(cCtx, "Updating %s\n", updateResult)
			}
			printStdout(cCtx, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appUpdatePreviewWrite(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "preview-write-access",
		Usage:     "Update write access permission for preview apps",
		Flags:     flags,
		ArgsUsage: "<value:true|false> <appPathGlob>",

		UsageText: `args: <value:true|false> <appPathGlob>

The first required argument <value> is a boolean value, true or false.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

Examples:
  Update all apps, across domains: openrun app settings preview-write-access true all
  Update apps in the example.com domain: openrun app settings preview-write-access false "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("expected two arguments: <value> <appPathGlob>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			body := types.CreateUpdateAppRequest()
			boolValue, err := strconv.ParseBool(cCtx.Args().Get(0))
			if err != nil {
				return fmt.Errorf("invalid value %s for preview-write-access, expected true or false", cCtx.Args().Get(0))
			}
			if boolValue {
				body.PreviewWriteAccess = types.BoolValueTrue
			} else {
				body.PreviewWriteAccess = types.BoolValueFalse
			}

			var updateResponse types.AppUpdateSettingsResponse
			err = client.Post("/_openrun/app_settings", values, body, &updateResponse)
			if err != nil {
				return err
			}

			for _, updateResult := range updateResponse.UpdateResults {
				printStdout(cCtx, "Updating %s\n", updateResult)
			}
			printStdout(cCtx, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appUpdateMetadataCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "update",
		Usage: `Update OpenRun app metadata. Metadata updates are staged and have to be promoted to prod. Use "openrun param" to update app parameter metadata.`,
		Subcommands: []*cli.Command{
			appUpdateAppSpec(commonFlags, clientConfig),
			appUpdateConfig(commonFlags, clientConfig, "container-option", "copt", types.AppMetadataContainerOptions, "<key=value>"),
			appUpdateConfig(commonFlags, clientConfig, "container-arg", "carg", types.AppMetadataContainerArgs, "<key=value>"),
			appUpdateConfig(commonFlags, clientConfig, "container-volumes", "cvol", types.AppMetadataContainerVolumes, "<volume>"),
			appUpdateConfig(commonFlags, clientConfig, "sidecars", "sc", types.AppMetadataSidecars, "<sidecarJson>"),
			appUpdateConfig(commonFlags, clientConfig, "jobs", "jb", types.AppMetadataJobs, "<jobJson>"),
			appUpdateConfig(commonFlags, clientConfig, "app-config", "conf", types.AppMetadataAppConfig, "<key=value>"),
			appUpdateConfig(commonFlags, clientConfig, "auth", "", types.AppMetadataAuthnType, "<authType>"),
			appUpdateConfig(commonFlags, clientConfig, "git-auth", "", types.AppMetadataGitAuthName, "<gitAuth>"),
			appUpdateConfig(commonFlags, clientConfig, "bindings", "bind", types.AppMetadataBindings, "<bindingPath>"),
			appUpdateConfig(commonFlags, clientConfig, "mcp", "", types.AppMetadataMCP, "<true|actions|disable|default|/upstreamPath|json|@file|->"),
		},
	}
}

func appUpdateAppSpec(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote the change from stage to prod", false))

	return &cli.Command{
		Name:      "spec",
		Usage:     "Update app spec for apps",
		Flags:     flags,
		ArgsUsage: "<value:specName|-> <appPathGlob>",

		UsageText: `args: <value:specName|-> <appPathGlob>

The first required argument <value> is a string, a valid app spec name or - (to unset spec).
The last required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

Examples:
  Update all apps, across domains: openrun app update spec - all
  Update apps in the example.com domain: openrun app update spec proxy "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("expected two arguments: <value> <appPathGlob>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(cCtx.Bool(PROMOTE_FLAG)))

			body := types.CreateUpdateAppMetadataRequest()
			body.Spec = types.StringValue(cCtx.Args().Get(0))

			var updateResponse types.AppUpdateMetadataResponse
			if err := client.Post("/_openrun/app_metadata", values, body, &updateResponse); err != nil {
				return err
			}

			for _, updateResult := range updateResponse.StagedUpdateResults {
				printStdout(cCtx, "Updated %s\n", updateResult)
			}

			if len(updateResponse.PromoteResults) > 0 {
				printStdout(cCtx, "Promoted apps: ")
				for i, promoteResult := range updateResponse.PromoteResults {
					if i > 0 {
						printStdout(cCtx, ", ")
					}
					printStdout(cCtx, "%s", promoteResult)
				}
				printStdout(cCtx, "\n")
			}

			printStdout(cCtx, "%d app(s) updated, %d app(s) promoted.\n", len(updateResponse.StagedUpdateResults), len(updateResponse.PromoteResults))

			if updateResponse.DryRun {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

// appUpdateConfig creates a command to update app metadata config
func appUpdateConfig(commonFlags []cli.Flag, clientConfig *types.ClientConfig, arg string, shortFlag string, configType types.AppMetadataConfigType, valName string) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote the change from stage to prod", false))

	// auth, git-auth and mcp take one value; the list types take one or more
	// and replace the whole list
	single := configType == types.AppMetadataAuthnType || configType == types.AppMetadataGitAuthName || configType == types.AppMetadataMCP
	argsUsage := fmt.Sprintf("%s [%s ...] <appPathGlob>", valName, valName)
	argsText := fmt.Sprintf("The initial arguments are the %s values to set.", arg)
	argsError := "expected at least two arguments: " + argsUsage
	if single {
		argsUsage = valName + " <appPathGlob>"
		argsText = fmt.Sprintf("The first argument is the %s value to set.", arg)
		argsError = "expected two arguments: " + argsUsage
	}

	cmd := &cli.Command{
		Name:      arg,
		Usage:     fmt.Sprintf("Update %s metadata for apps", arg),
		Flags:     flags,
		ArgsUsage: argsUsage,

		UsageText: fmt.Sprintf(`args: %s

%s The last argument is <appPathGlob>. `+PATH_SPEC_HELP+`

Examples:
  Update all apps, across domains: openrun app update %s %s all
  Update apps in the example.com domain: openrun app update %s %s "example.com:**"`, argsUsage, argsText, arg, valName, arg, valName),

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() < 2 || (single && cCtx.NArg() != 2) {
				return fmt.Errorf("%s", argsError)
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}

			values.Add("appPathGlob", cCtx.Args().Get(cCtx.NArg()-1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(cCtx.Bool(PROMOTE_FLAG)))

			body := types.CreateUpdateAppMetadataRequest()
			body.ConfigType = configType
			body.ConfigEntries = cCtx.Args().Slice()[:cCtx.NArg()-1]
			if configType == types.AppMetadataContainerVolumes {
				if err := validateNoFlagLikeValues("--cvol", "container volume", body.ConfigEntries); err != nil {
					return err
				}
			}
			if configType == types.AppMetadataSidecars {
				// JSON objects or @file entries; "-" clears all metadata
				// sidecars. The full list replaces the previous one
				entries, err := parseSidecarArgs(body.ConfigEntries)
				if err != nil {
					return err
				}
				body.ConfigEntries = entries
			}
			if configType == types.AppMetadataMCP {
				// @file is expanded here; the server never reads request-named files
				for i, entry := range body.ConfigEntries {
					if entry == "-" {
						continue
					}
					doc, err := types.ParseMCPArg(entry)
					if err != nil {
						return err
					}
					body.ConfigEntries[i] = doc
				}
			}
			if configType == types.AppMetadataJobs {
				// Same as sidecars: the full metadata job list is replaced
				entries, err := parseJobArgs(body.ConfigEntries)
				if err != nil {
					return err
				}
				body.ConfigEntries = entries
			}

			var updateResponse types.AppUpdateMetadataResponse
			if err := client.Post("/_openrun/app_metadata", values, body, &updateResponse); err != nil {
				return err
			}

			for _, updateResult := range updateResponse.StagedUpdateResults {
				printStdout(cCtx, "Updated %s\n", updateResult)
			}

			if len(updateResponse.PromoteResults) > 0 {
				printStdout(cCtx, "Promoted apps: ")
				for i, promoteResult := range updateResponse.PromoteResults {
					if i > 0 {
						printStdout(cCtx, ", ")
					}
					printStdout(cCtx, "%s", promoteResult)
				}
				printStdout(cCtx, "\n")
			}

			printStdout(cCtx, "%d app(s) updated, %d app(s) promoted.\n", len(updateResponse.StagedUpdateResults), len(updateResponse.PromoteResults))

			if updateResponse.DryRun {
				printStdout(cCtx, "%s", DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
	if shortFlag != "" {
		cmd.Aliases = []string{shortFlag}
	}
	return cmd
}
