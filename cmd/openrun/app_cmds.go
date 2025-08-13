// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const (
	DRY_RUN_FLAG    = "dry-run"
	DRY_RUN_ARG     = "dryRun"
	DRY_RUN_MESSAGE = "\n" + YELLOW + "*** dry-run mode, changes have NOT been committed. ***" + RESET + "\n"
	PATH_SPEC_HELP  = `The (optional) domain and path are separated by a ":". appPathGlob supports a glob pattern.
In the glob, * matches any number of characters, ** matches any number of characters including /.
all is a shortcut for "*:**", which matches all apps across all domains, including no domain.
To prevent shell expansion for *, placing the path in quotes is recommended.
"all" matches all apps across all domains, same as "*:**".
`
	PROMOTE_FLAG = "promote"
	PROMOTE_ARG  = "promote"
)

func initAppCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "app",
		Usage: "Manage OpenRun apps",
		Subcommands: []*cli.Command{
			appCreateCommand(commonFlags, clientConfig),
			appListCommand(commonFlags, clientConfig),
			appDeleteCommand(commonFlags, clientConfig),
			appApproveCommand(commonFlags, clientConfig),
			appReloadCommand(commonFlags, clientConfig),
			appPromoteCommand(commonFlags, clientConfig),
			appUpdateSettingsCommand(commonFlags, clientConfig),
			appUpdateMetadataCommand(commonFlags, clientConfig),
		},
	}
}

func dryRunFlag() *cli.BoolFlag {
	return newBoolFlag(DRY_RUN_FLAG, "", "Verify command but don't commit any changes", false)
}

func appCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("dev", "d", "Is the application in development mode", false))
	flags = append(flags, newBoolFlag("approve", "a", "Approve the app permissions", false))
	flags = append(flags, newStringFlag("auth", "", "The authentication mode for the app: can be default or none or system or an OAuth account config", "default"))
	flags = append(flags, newStringFlag("branch", "b", "The branch to checkout if using git source", "main"))
	flags = append(flags, newStringFlag("commit", "c", "The commit SHA to checkout if using git source. This takes precedence over branch", ""))
	flags = append(flags, newStringFlag("git-auth", "g", "The name of the git_auth entry in server config to use", ""))
	flags = append(flags, newStringFlag("spec", "", "The spec to use for the app", ""))
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Set a parameter value. Format is paramName=paramValue",
		})
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    "container-option",
			Aliases: []string{"copt"},
			Usage:   "Set a container option. Format is opt[=optValue]",
		})
	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    "container-arg",
			Aliases: []string{"carg"},
			Usage:   "Set an argument for building the container image. Format is argKey=argValue",
		})

	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    "container-volume",
			Aliases: []string{"cvol"},
			Usage:   "Set container volume entries",
		})

	flags = append(flags,
		&cli.StringSliceFlag{
			Name:    "app-config",
			Aliases: []string{"conf"},
			Usage:   "Set an default config option for the app. Format is configKey=configValue, where value has to be encoded in toml formal",
		})

	flags = append(flags,
		&cli.StringSliceFlag{
			Name:  "conf-str",
			Usage: "Set an default config string value for the app. Format is configKey=configValue",
		})

	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "create",
		Usage:     "Create a new app",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<app_source_url> <app_path>",
		UsageText: `args: <app_source_url> <app_path>

<app_source_url> is required first argument. The source url can be a git url or a local disk path on the OpenRun server. If no source is required, use "-" as the
 source url. For local path, the path can be absolute or relative to the OpenRun server home directory OPENRUN_HOME. If using a non public git repo, the git_auth flag must be
 specified, which points to the git key as configured in the OpenRun server config file.

<app_path> is a required second argument. The optional domain and path are separated by a ":". If no domain is specified, the app is created for the default domain.

Examples:
  Create app from github source: openrun app create --approve github.com/openrundev/openrun/examples/memory_usage/ /memory_usage
  Create app from local disk: openrun app create --approve $HOME/openrun_source/openrun/examples/memory_usage/ /memory_usage
  Create app for development (source has to be disk): openrun app create --approve --dev $HOME/openrun_source/openrun/examples/memory_usage/ /memory_usage
  Create app from a git commit: openrun app create --approve --commit 1234567890  github.com/openrundev/openrun/examples/memory_usage/ /memory_usage
  Create app from a git branch: openrun app create --approve --branch main github.com/openrundev/openrun/examples/memory_usage/ /memory_usage
  Create app using git url: openrun app create --approve git@github.com:openrundev/openrun.git/examples/disk_usage /disk_usage
  Create app using git url, with git private key auth: openrun app create --approve --git-auth mykey git@github.com:openrundev/privaterepo.git/examples/disk_usage /disk_usage
  Create app for specified domain, no auth : openrun app create --approve --auth=none github.com/openrundev/openrun/examples/memory_usage/ openrun.example.com:/`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("require two arguments: <app_source_url> <app_path>")
			}

			values := url.Values{}
			values.Add("approve", strconv.FormatBool(cCtx.Bool("approve")))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			params := cCtx.StringSlice("param")
			paramValues := make(map[string]string)
			for _, param := range params {
				key, value, ok := strings.Cut(param, "=")
				if !ok {
					return fmt.Errorf("invalid param format: %s", param)
				}
				paramValues[key] = value
			}

			containerOptions := cCtx.StringSlice("container-option")
			coptMap := make(map[string]string)
			for _, param := range containerOptions {
				key, value, _ := strings.Cut(param, "=")
				coptMap[key] = value // value can be empty string
			}

			containerArgs := cCtx.StringSlice("container-arg")
			cargMap := make(map[string]string)
			for _, param := range containerArgs {
				key, value, ok := strings.Cut(param, "=")
				if !ok {
					return fmt.Errorf("invalid container arg format: %s", param)
				}
				cargMap[key] = value
			}

			containerVolumes := cCtx.StringSlice("container-volume")

			appConfig := cCtx.StringSlice("app-config")
			confMap := make(map[string]string)
			for _, def := range appConfig {
				key, value, ok := strings.Cut(def, "=")
				if !ok {
					return fmt.Errorf("invalid app config format: %s", def)
				}
				confMap[key] = value
			}

			appConfigStr := cCtx.StringSlice("conf-str")
			for _, def := range appConfigStr {
				key, value, ok := strings.Cut(def, "=")
				if !ok {
					return fmt.Errorf("invalid app config format: %s", def)
				}
				confMap[key] = "\"" + value + "\""
			}

			sourceUrl, err := makeAbsolute(cCtx.Args().Get(0))
			if err != nil {
				return err
			}

			body := types.CreateAppRequest{
				Path:             cCtx.Args().Get(1),
				SourceUrl:        sourceUrl,
				IsDev:            cCtx.Bool("dev"),
				AppAuthn:         types.AppAuthnType(cCtx.String("auth")),
				GitBranch:        cCtx.String("branch"),
				GitCommit:        cCtx.String("commit"),
				GitAuthName:      cCtx.String("git-auth"),
				Spec:             types.AppSpec(cCtx.String("spec")),
				ParamValues:      paramValues,
				ContainerOptions: coptMap,
				ContainerArgs:    cargMap,
				ContainerVolumes: containerVolumes,
				AppConfig:        confMap,
			}
			var createResult types.AppCreateResponse
			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			err = client.Post("/_openrun/app", values, body, &createResult)
			if err != nil {
				return err
			}

			printCreateResult(cCtx, createResult)
			if createResult.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func printCreateResult(cCtx *cli.Context, createResult types.AppCreateResponse) {
	fmt.Printf("      App: %s\n", &createResult.AppPathDomain)
	if createResult.HttpUrl != "" {
		fmt.Printf(" HTTP Url: %s\n", createResult.HttpUrl)
	}
	if createResult.HttpsUrl != "" {
		fmt.Printf("HTTPS Url: %s\n", createResult.HttpsUrl)
	}
	approveResult := createResult.ApproveResults[0]
	printApproveResult(approveResult)

	if approveResult.NeedsApproval {
		if cCtx.Bool("approve") {
			fmt.Print("App created. Permissions have been approved\n")
		} else {
			fmt.Print("App created. Permissions need to be approved\n")
		}
	} else {
		fmt.Print("App created. No approval required\n")
	}
}

func appListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("internal", "i", "Include internal apps", false))
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:      "list",
		Usage:     "List apps",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "[<appPathGlob>]",
		UsageText: `args: [<appPathGlob>]

<appPathGlob> defaults to "*:**" (same as "all") for the list command.
` + PATH_SPEC_HELP +
			`
Examples:
  List all apps, across domains: openrun app list
  List apps at the lop level with no domain specified: openrun app list "*"
  List all apps in the domain openrun.example.com: openrun app list "openrun.example.com:**"
  List all apps with no domain specified: openrun app list "**"
  List all apps with no domain, under the /utils folder: openrun app list "/utils/**"
  List all apps with no domain, including staging apps, under the /utils folder: openrun app list --internal "/utils/**"
  List apps at the lop level with no domain specified, with jsonl format: openrun app list --format jsonl "*"`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("only one argument expected: <appPathGlob>")
			}
			values := url.Values{}
			values.Add("internal", fmt.Sprintf("%t", cCtx.Bool("internal")))
			if cCtx.NArg() == 1 {
				values.Add("appPathGlob", cCtx.Args().Get(0))
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var appListResponse types.AppListResponse
			err := client.Get("/_openrun/apps", values, &appListResponse)
			if err != nil {
				return err
			}
			printAppList(cCtx, appListResponse.Apps, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printAppList(cCtx *cli.Context, apps []types.AppResponse, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(apps)
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, app := range apps {
			enc.Encode(app)
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, app := range apps {
			enc.Encode(app)
			fmt.Fprintf(cCtx.App.Writer, "\n")
		}
	case FORMAT_BASIC:
		formatStrHead := "%-30s %-5s %4s %-7s %-s\n"
		formatStrData := "%-30s %-5s %4d %-7s %-s\n"
		fmt.Fprintf(cCtx.App.Writer, formatStrHead, "Name", "Type", "Ver", "Auth", "AppPath")

		for _, app := range apps {
			fmt.Fprintf(cCtx.App.Writer, formatStrData, app.Metadata.Name, appType(app), app.Metadata.VersionMetadata.Version, authType(app),
				app.AppEntry.AppPathDomain())
		}
	case FORMAT_TABLE:
		formatStrHead := "%-30s %-35s %-5s %-7s %-15s %-60s %-40s %-30s %-30s\n"
		formatStrData := "%-30s %-35s %-5s %7d %-15s %-60s %-40s %-30s %-30s\n"
		fmt.Fprintf(cCtx.App.Writer, formatStrHead, "Name", "Id", "Type", "Version", "Auth",
			"AppPath", "SourceUrl", "Spec", "GitInfo")

		for _, app := range apps {
			gitInfo := ""
			if app.Metadata.VersionMetadata.GitBranch != "" || app.Metadata.VersionMetadata.GitCommit != "" {
				gitInfo = fmt.Sprintf("%s:%.20s", app.Metadata.VersionMetadata.GitBranch, app.Metadata.VersionMetadata.GitCommit)
			}
			fmt.Fprintf(cCtx.App.Writer, formatStrData, app.Metadata.Name, app.Id, appType(app), app.Metadata.VersionMetadata.Version, authType(app),
				app.AppEntry.AppPathDomain(), app.SourceUrl, app.Metadata.Spec, gitInfo)
		}
	case FORMAT_CSV:
		for _, app := range apps {
			fmt.Fprintf(cCtx.App.Writer, "\"%s\",%s,%s,%d,%s,%s,\"%s\",\"%s\", %s, %s, \"%s\"\n", app.Metadata.Name, app.Id, appType(app),
				app.Metadata.VersionMetadata.Version, authType(app), app.Metadata.VersionMetadata.GitBranch,
				app.AppEntry.AppPathDomain(), app.SourceUrl, app.Metadata.Spec, app.Metadata.VersionMetadata.GitBranch, app.Metadata.VersionMetadata.GitCommit)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func appType(app types.AppResponse) string {
	if app.IsDev {
		return "DEV"
	} else {
		if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_PROD) {
			if app.StagedChanges {
				return "PROD*"
			} else {
				return "PROD"
			}
		} else if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_PREVIEW) {
			return "VIEW"
		} else if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE) {
			return "STG"
		} else {
			return "----"
		}
	}
}

func authType(app types.AppResponse) string {
	if app.Settings.AuthnType == types.AppAuthnNone {
		return "NONE"
	} else if app.Settings.AuthnType == types.AppAuthnSystem {
		return "SYSTEM"
	} else if app.Settings.AuthnType == types.AppAuthnDefault || app.Settings.AuthnType == "" {
		return "DEFAULT"
	} else {
		return string(app.Settings.AuthnType)
	}
}

func permType(perm types.Permission) string {
	permType := ""
	if perm.IsRead != nil {
		if *perm.IsRead {
			permType = "<READ>"
		} else {
			permType = "<WRITE>"
		}
	}
	return permType
}

func printApproveResult(approveResult types.ApproveResult) {
	fmt.Printf("  Plugins :\n")
	for _, load := range approveResult.NewLoads {
		fmt.Printf("    %s\n", load)
	}
	fmt.Printf("  Permissions:\n")
	for _, perm := range approveResult.NewPermissions {
		secrets := ""
		if len(perm.Secrets) > 0 {
			buf := new(bytes.Buffer)
			for i, entry := range perm.Secrets {
				if i > 0 {
					buf.WriteString(";")
				}
				buf.WriteString(strings.Join(entry, ","))
			}

			secrets = fmt.Sprintf(" secrets=%s", buf.String())
		}
		fmt.Printf("    %s.%s %s %s%s\n", perm.Plugin, perm.Method, perm.Arguments, permType(perm), secrets)
	}
}

func appDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete an app",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<appPathGlob>",

		UsageText: `args: <appPathGlob>

<appPathGlob> is a required argument. ` + PATH_SPEC_HELP + `

Examples:
  Delete all apps, across domains, in dry-run mode: openrun app delete --dry-run all
  Delete apps in the example.com domain: openrun app delete "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(0))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var deleteResult types.AppDeleteResponse
			err := client.Delete("/_openrun/app", values, &deleteResult)
			if err != nil {
				return err
			}

			for _, appInfo := range deleteResult.AppInfo {
				fmt.Fprintf(cCtx.App.Writer, "Deleting %s - %s\n", appInfo.AppPathDomain, appInfo.Id)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) deleted.\n", len(deleteResult.AppInfo))

			if deleteResult.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}

func appApproveCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, newBoolFlag(PROMOTE_FLAG, "p", "Promote the change from stage to prod", false))

	return &cli.Command{
		Name:      "approve",
		Usage:     "Approve app permissions",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<appPathGlob>",

		UsageText: `args: <appPathGlob>

	<appPathGlob> is a required argument. ` + PATH_SPEC_HELP + `

	Examples:
	  Approve all apps, across domains: openrun app approve all
	  Approve apps in the example.com domain: openrun app approve "example.com:**"
		`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().Get(0))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(PROMOTE_ARG, strconv.FormatBool(cCtx.Bool(PROMOTE_FLAG)))

			var approveResponse types.AppApproveResponse
			err := client.Post("/_openrun/approve", values, nil, &approveResponse)
			if err != nil {
				return err
			}

			approvedCount := 0
			for _, approveResult := range approveResponse.StagedUpdateResults {
				if !approveResult.NeedsApproval {
					fmt.Printf("No approval required. %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
				} else {
					approvedCount += 1
					fmt.Printf("App permissions have been approved %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
					printApproveResult(approveResult)
				}
			}

			if len(approveResponse.PromoteResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Promoted apps: ")
				for i, promoteResult := range approveResponse.PromoteResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", promoteResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			fmt.Fprintf(cCtx.App.Writer, "%d app(s) audited, %d app(s) approved, %d app(s) promoted.\n",
				len(approveResponse.StagedUpdateResults), approvedCount, len(approveResponse.PromoteResults))

			if approveResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appReloadCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("approve", "a", "Approve the app permissions", false))
	flags = append(flags, newBoolFlag("promote", "p", "Promote the change from stage to prod", false))
	flags = append(flags, newBoolFlag("force-reload", "f", "Force reload even if there is no new commit", false))
	flags = append(flags, newStringFlag("branch", "b", "The branch to checkout if using git source", ""))
	flags = append(flags, newStringFlag("commit", "c", "The commit SHA to checkout if using git source. This takes precedence over branch", ""))
	flags = append(flags, newStringFlag("git-auth", "g", "The name of the git_auth entry to use", ""))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "reload",
		Usage:     "Reload the app source code",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<appPathGlob>",

		UsageText: `args: <appPathGlob>

<appPathGlob> is a required argument. ` + PATH_SPEC_HELP + `
	Dev apps are reloaded from disk. For prod apps, the stage app is reloaded from git (or from local disk if git is not used).
	If --approve option is specified, the app permissions are audited and approved. If --approve is not specified and the app needs additional
	permissions, the reload will fail. If --promote is specified, the stage app is promoted to prod after reload. If --promote is not specified,
	the stage app is reloaded but not promoted. If --approve and --promote are both specified, the stage app is promoted to prod after approval.

	Examples:
	  Reload all apps, across domains: openrun app reload all
	  Reload apps in the example.com domain: openrun app reload "example.com:**"
	  Reload and promote apps in the example.com domain: openrun app reload --promote "example.com:**"
	  Reload, approve and promote apps in the example.com domain: openrun app reload --approve --promote "example.com:**"
	  Reload all apps from main branch: openrun app reload --branch main all
	  Reload an app from particular commit: openrun app reload --commit 1c119e7c5845e19845dd1d794268b350ced5b71b /myapp1`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().First())
			values.Add("approve", strconv.FormatBool(cCtx.Bool("approve")))
			values.Add("promote", strconv.FormatBool(cCtx.Bool("promote")))
			values.Add("forceReload", strconv.FormatBool(cCtx.Bool("force-reload")))
			values.Add("branch", cCtx.String("branch"))
			values.Add("commit", cCtx.String("commit"))
			values.Add("gitAuth", cCtx.String("git-auth"))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var reloadResponse types.AppReloadResponse
			err := client.Post("/_openrun/reload", values, nil, &reloadResponse)
			if err != nil {
				return err
			}

			if len(reloadResponse.ReloadResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Reloaded apps: ")
				for i, reloadResult := range reloadResponse.ReloadResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", reloadResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			if len(reloadResponse.SkippedResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Skipped apps: ")
				for i, skipResult := range reloadResponse.SkippedResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", skipResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			if len(reloadResponse.ApproveResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Approved apps:\n")
				for _, approveResult := range reloadResponse.ApproveResults {
					if !approveResult.NeedsApproval {
						// Server does not return these for reload to reduce the noise
						fmt.Printf("No approval required. %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
					} else {
						fmt.Printf("App permissions have been approved %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
						printApproveResult(approveResult)
					}
				}
			}

			if len(reloadResponse.PromoteResults) > 0 {
				fmt.Fprintf(cCtx.App.Writer, "Promoted apps: ")
				for i, promoteResult := range reloadResponse.PromoteResults {
					if i > 0 {
						fmt.Fprintf(cCtx.App.Writer, ", ")
					}
					fmt.Fprintf(cCtx.App.Writer, "%s", promoteResult)
				}
				fmt.Fprintln(cCtx.App.Writer)
			}

			fmt.Fprintf(cCtx.App.Writer, "%d app(s) reloaded, %d app(s) skipped, %d app(s) approved, %d app(s) promoted.\n",
				len(reloadResponse.ReloadResults), len(reloadResponse.SkippedResults), len(reloadResponse.ApproveResults), len(reloadResponse.PromoteResults))

			if reloadResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func appPromoteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "promote",
		Usage:     "Promote the app from staging to production",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<appPathGlob>",
		UsageText: `args: <appPathGlob>

<appPathGlob> is a required argument. ` + PATH_SPEC_HELP + `

	Examples:
	  Promote all apps, across domains: openrun app promote all
	  Promote apps in the example.com domain: openrun app promote "example.com:**"`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPathGlob>")
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			values := url.Values{}
			values.Add("appPathGlob", cCtx.Args().First())
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))

			var promoteResponse types.AppPromoteResponse
			err := client.Post("/_openrun/promote", values, nil, &promoteResponse)
			if err != nil {
				return err
			}

			for _, approveResult := range promoteResponse.PromoteResults {
				fmt.Printf("Promoting %s\n", approveResult)
			}
			fmt.Fprintf(cCtx.App.Writer, "%d app(s) promoted.\n", len(promoteResponse.PromoteResults))

			if promoteResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}
			return nil
		},
	}
}
