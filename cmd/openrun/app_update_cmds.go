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

func appUpdateSettingsCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "update-settings",
		Usage: "Update OpenRun apps settings. Settings changes are NOT staged, they apply immediately to matched stage, prod and preview apps.",
		Subcommands: []*cli.Command{
			appUpdateStageWrite(commonFlags, clientConfig),
			appUpdatePreviewWrite(commonFlags, clientConfig),
			appUpdateAuthnType(commonFlags, clientConfig),
			appUpdateGitAuth(commonFlags, clientConfig),
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
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<value:true|false> <appPathGlob>",

		UsageText: `args: <value:true|false> <appPathGlob>

The first required argument <value> is a boolean value, true or false.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

	Examples:
	  Update all apps, across domains: openrun app update-settings stage-write-access true all
	  Update apps in the example.com domain: openrun app update-settings stage-write-access false "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <value> <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
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
				fmt.Printf("Updating %s\n", updateResult)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
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
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<value:true|false> <appPathGlob>",

		UsageText: `args: <value:true|false> <appPathGlob>

The first required argument <value> is a boolean value, true or false.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

	Examples:
	  Update all apps, across domains: openrun app update-settings preview-write-access true all 
	  Update apps in the example.com domain: openrun app update-settings preview-write-access false "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <value> <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
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
				fmt.Printf("Updating %s\n", updateResult)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appUpdateAuthnType(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "auth",
		Usage:     "Update authentication mode for apps",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<value:system|default|none|custom> <appPathGlob>",

		UsageText: `args: <value:default|none> <appPathGlob>

The first required argument <value> is a string, system, default, none or OAuth entry name.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

	Examples:
	  Update all apps, across domains: openrun app update-settings auth default all
	  Update apps in the example.com domain: openrun app update-settings auth none "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <value> <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			body := types.CreateUpdateAppRequest()
			body.AuthnType = types.StringValue(cCtx.Args().Get(0))

			var updateResponse types.AppUpdateSettingsResponse
			if err := client.Post("/_openrun/app_settings", values, body, &updateResponse); err != nil {
				return err
			}

			for _, updateResult := range updateResponse.UpdateResults {
				fmt.Printf("Updating %s\n", updateResult)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appUpdateGitAuth(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "git-auth",
		Usage:     "Update git-auth entry for apps",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<entryName> <appPathGlob>",

		UsageText: `args: <entryName> <appPathGlob> 

The first required argument <entryName> is a string. Specify the git_auth entry key name as configured in the openrun.toml config.
Set to "-" to remove the git_auth entry.
The second required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

	Examples:
	  Update all apps, across domains: openrun app update-settings git-auth mygit all
	  Update apps in the example.com domain: openrun app git-auth gitentrykey "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <entryName> <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			body := types.CreateUpdateAppRequest()
			body.GitAuthName = types.StringValue(cCtx.Args().Get(0))

			var updateResponse types.AppUpdateSettingsResponse
			if err := client.Post("/_openrun/app_settings", values, body, &updateResponse); err != nil {
				return err
			}

			for _, updateResult := range updateResponse.UpdateResults {
				fmt.Printf("Updating %s\n", updateResult)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated.\n", len(updateResponse.UpdateResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appUpdateMetadataCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "update-metadata",
		Usage: `Update OpenRun app metadata. Metadata updates are staged and have to be promoted to prod. Use "openrun param" to update app parameter metadata.`,
		Subcommands: []*cli.Command{
			appUpdateAppSpec(commonFlags, clientConfig),
			appUpdateConfig(commonFlags, clientConfig, "container-option", "copt", types.AppMetadataContainerOptions),
			appUpdateConfig(commonFlags, clientConfig, "container-arg", "carg", types.AppMetadataContainerArgs),
			appUpdateConfig(commonFlags, clientConfig, "container-volumes", "cvol", types.AppMetadataContainerVolumes),
			appUpdateConfig(commonFlags, clientConfig, "app-config", "conf", types.AppMetadataAppConfig),
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
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<value:spec_name|none> <appPathGlob>",

		UsageText: `args: <value:spec_name|none> <appPathGlob>

The first required argument <value> is a string, a valid app spec name or - (to unset spec).
The last required argument is <appPathGlob>. ` + PATH_SPEC_HELP + `

	Examples:
	  Update all apps, across domains: openrun app update-metadata spec - all
	  Update apps in the example.com domain: openrun app update-metadata spec proxy "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <value> <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
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
				fmt.Printf("Updated %s\n", updateResult)
			}

			if len(updateResponse.PromoteResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Promoted apps: ")
				for i, promoteResult := range updateResponse.PromoteResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", promoteResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated, %d app(s) promoted.\n", len(updateResponse.StagedUpdateResults), len(updateResponse.PromoteResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

// appUpdateConfig creates a command to update app metadata config
func appUpdateConfig(commonFlags []cli.Flag, clientConfig *types.ClientConfig, arg string, shortFlag string, configType types.AppMetadataConfigType) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote the change from stage to prod", false))

	return &cli.Command{
		Name:      arg,
		Aliases:   []string{shortFlag},
		Usage:     fmt.Sprintf("Update %s metadata for apps", arg),
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "key=value <appPathGlob>",

		UsageText: fmt.Sprintf(`args: key=value [key=value ...] <appPathGlob>
The initial arguments key=value are strings, the key to set and the value to use delimited by =. The value is optional for
container options. The last argument is <appPathGlob>. `+PATH_SPEC_HELP+`

	Examples:
	  Update all apps, across domains: openrun app update-metadata %s key=value all
	  Update apps in the example.com domain: openrun app update-metadata %s key=value "example.com:**"`, arg, arg),

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() < 2 {
				return fmt.Errorf("requires at least two arguments: key=value [key=value ...] <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}

			values.Add("appPathGlob", cCtx.Args().Get(cCtx.NArg()-1))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(cCtx.Bool(PROMOTE_FLAG)))

			body := types.CreateUpdateAppMetadataRequest()
			body.ConfigType = configType
			body.ConfigEntries = cCtx.Args().Slice()[:cCtx.NArg()-1]

			var updateResponse types.AppUpdateMetadataResponse
			if err := client.Post("/_openrun/app_metadata", values, body, &updateResponse); err != nil {
				return err
			}

			for _, updateResult := range updateResponse.StagedUpdateResults {
				fmt.Printf("Updated %s\n", updateResult)
			}

			if len(updateResponse.PromoteResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Promoted apps: ")
				for i, promoteResult := range updateResponse.PromoteResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", promoteResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			fmt.Fprintf(cCtx.App.Writer, "%d app(s) updated, %d app(s) promoted.\n", len(updateResponse.StagedUpdateResults), len(updateResponse.PromoteResults))

			if updateResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}
