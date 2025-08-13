// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"fmt"
	"net/url"
	"strconv"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func initApplyCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("branch", "b", "The branch to checkout if using git source", "main"))
	flags = append(flags, newStringFlag("commit", "c", "The commit SHA to checkout if using git source. This takes precedence over branch", ""))
	flags = append(flags, newStringFlag("git-auth", "g", "The name of the git_auth entry in server config to use", ""))
	flags = append(flags, newBoolFlag("approve", "a", "Approve the app permissions", false))
	flags = append(flags, newStringFlag("reload", "r", "Which apps to reload: none, updated, matched", ""))
	flags = append(flags, newBoolFlag("promote", "p", "Promote changes from stage to prod", false))
	flags = append(flags, newBoolFlag("clobber", "", "Force update app config, overwriting non-declarative changes", false))
	flags = append(flags, newBoolFlag("force-reload", "f", "Force reload even if there is no new commit", false))
	flags = append(flags, dryRunFlag())

	return &cli.Command{
		Name:      "apply",
		Usage:     "Apply app configuration declaratively",
		Flags:     flags,
		Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
		ArgsUsage: "<filePath> [<appPathGlob>]",
		UsageText: `args: <filePath> [<appPathGlob>]

<filePath> is the path to the file containing the app configuration.
<appPathGlob> is an optional second argument, which default to "all".
` + PATH_SPEC_HELP +
			`
Examples:
  Apply app config, reloading all apps: openrun apply ./app.ace
  Apply app config for example.com domain apps: openrun apply --reload=updated ./app.ace example.com:**
  Apply app config from git for all apps: openrun apply --promote --approve github.com/openrundev/apps/apps.ace all
  Apply app config from git for all apps, overwriting changes: openrun apply --promote --clobber github.com/openrundev/apps/apps.ace all
`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() == 0 || cCtx.NArg() > 2 {
				return fmt.Errorf("expected one or two arguments: <filePath> [<appPathGlob>]")
			}
			reloadMode := types.AppReloadOption(cmp.Or(cCtx.String("reload"), string(types.AppReloadOptionMatched)))
			appPathGlob := "all"
			if cCtx.NArg() == 2 {
				appPathGlob = cCtx.Args().Get(1)
			}

			sourceUrl, err := makeAbsolute(cCtx.Args().Get(0))
			if err != nil {
				return err
			}

			values := url.Values{}
			values.Add("applyPath", sourceUrl)
			values.Add("appPathGlob", appPathGlob)
			values.Add("approve", strconv.FormatBool(cCtx.Bool("approve")))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add("branch", cCtx.String("branch"))
			values.Add("commit", cCtx.String("commit"))
			values.Add("gitAuth", cCtx.String("git-auth"))
			values.Add("reload", string(reloadMode))
			values.Add("promote", strconv.FormatBool(cCtx.Bool("promote")))
			values.Add("clobber", strconv.FormatBool(cCtx.Bool("clobber")))
			values.Add("forceReload", strconv.FormatBool(cCtx.Bool("force-reload")))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var applyResponse types.AppApplyResponse
			err = client.Post("/_openrun/apply", values, nil, &applyResponse)
			if err != nil {
				return err
			}

			printApplyResponse(cCtx, &applyResponse)
			if applyResponse.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func printApplyResponse(cCtx *cli.Context, applyResponse *types.AppApplyResponse) error {
	if len(applyResponse.CreateResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Created apps:\n")
		for i, createResult := range applyResponse.CreateResults {
			if i > 0 {
				fmt.Fprintf(cCtx.App.Writer, "\n")
			}
			printCreateResult(cCtx, createResult)
		}
	}

	if len(applyResponse.UpdateResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Updated apps: ")
		for i, updateResult := range applyResponse.UpdateResults {
			if i > 0 {
				fmt.Fprintf(cCtx.App.Writer, ", ")
			}
			fmt.Fprintf(cCtx.App.Writer, "%s", updateResult)
		}
		fmt.Fprintln(cCtx.App.Writer)
	}

	if len(applyResponse.ReloadResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Reloaded apps: ")
		for i, reloadResult := range applyResponse.ReloadResults {
			if i > 0 {
				fmt.Fprintf(cCtx.App.Writer, ", ")
			}
			fmt.Fprintf(cCtx.App.Writer, "%s", reloadResult)
		}
		fmt.Fprintln(cCtx.App.Writer)
	}

	if len(applyResponse.SkippedResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Skipped apps: ")
		for i, skipResult := range applyResponse.SkippedResults {
			if i > 0 {
				fmt.Fprintf(cCtx.App.Writer, ", ")
			}
			fmt.Fprintf(cCtx.App.Writer, "%s", skipResult)
		}
		fmt.Fprintln(cCtx.App.Writer)
	}

	if len(applyResponse.ApproveResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Approved apps:\n")
		for _, approveResult := range applyResponse.ApproveResults {
			if !approveResult.NeedsApproval {
				// Server does not return these for reload to reduce the noise
				fmt.Printf("No approval required. %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
			} else {
				fmt.Printf("App permissions have been approved %s - %s\n", approveResult.AppPathDomain, approveResult.Id)
				printApproveResult(approveResult)
			}
		}
	}

	if len(applyResponse.PromoteResults) > 0 {
		fmt.Fprintf(cCtx.App.Writer, "Promoted apps: ")
		for i, promoteResult := range applyResponse.PromoteResults {
			if i > 0 {
				fmt.Fprintf(cCtx.App.Writer, ", ")
			}
			fmt.Fprintf(cCtx.App.Writer, "%s", promoteResult)
		}
		fmt.Fprintln(cCtx.App.Writer)
	}

	fmt.Fprintf(cCtx.App.Writer, "%d app(s) created, %d app(s) updated, %d app(s) reloaded, %d app(s) skipped, %d app(s) approved, %d app(s) promoted.\n",
		len(applyResponse.CreateResults), len(applyResponse.UpdateResults), len(applyResponse.ReloadResults), len(applyResponse.SkippedResults), len(applyResponse.ApproveResults), len(applyResponse.PromoteResults))

	return nil
}
