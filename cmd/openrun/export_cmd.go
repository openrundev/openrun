// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func initExportCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+5)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("service-ref", "s",
		"How binding service references are written: \"default\" uses the target's default service of that type, \"exact\" uses the service name", types.ExportRefDefault))
	flags = append(flags, newStringFlag("git-auth", "g",
		"How git auth references are written: \"default\" omits git_auth (target uses default_git_auth), \"exact\" uses the git_auth entry name", types.ExportRefDefault))
	flags = append(flags, newBoolFlag("exact-commit", "c", "Pin apps to the currently deployed git commit instead of tracking the branch", false))
	flags = append(flags, newBoolFlag("exclude-declarative", "x", "Exclude apps and bindings which are already declaratively managed", false))
	flags = append(flags, newStringFlag("output", "o", "Write the config to this file instead of stdout", ""))

	return &cli.Command{
		Name:      "export",
		Usage:     "Export current app and binding config as a declarative config file",
		Flags:     flags,
		ArgsUsage: "[<appPathGlob>]",
		UsageText: `args: [<appPathGlob>]

<appPathGlob> is an optional argument, defaulting to "all".
` + PATH_SPEC_HELP +
			`
The current prod state of all matched apps is exported, along with all bindings.
Dev apps are exported with dev=True. Stage and preview apps are not exported.
The output can be re-applied with "openrun apply --approve".

Examples:
  Export all apps and bindings: openrun export
  Export to a file: openrun export -o backup.ace
  Export pinning exact commits: openrun export --exact-commit -o backup.ace
  Export only imperatively managed apps: openrun export --exclude-declarative
  Export apps under example.com: openrun export "example.com:**"
`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one argument: [<appPathGlob>]")
			}
			appPathGlob := "all"
			if cCtx.NArg() == 1 {
				appPathGlob = cCtx.Args().Get(0)
			}

			values := url.Values{}
			values.Add("appPathGlob", appPathGlob)
			values.Add("serviceRef", cCtx.String("service-ref"))
			values.Add("gitAuthRef", cCtx.String("git-auth"))
			values.Add("exactCommit", strconv.FormatBool(cCtx.Bool("exact-commit")))
			values.Add("excludeDeclarative", strconv.FormatBool(cCtx.Bool("exclude-declarative")))

			client := newHttpClient(clientConfig)
			var response types.AppExportResponse
			if err := client.Get("/_openrun/export", values, &response); err != nil {
				return err
			}

			return writeConfigOutput(cCtx, response.Config, cCtx.String("output"))
		},
	}
}

func initPrettyPrintCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("output", "o", "Write the formatted config to this file instead of stdout", ""))
	flags = append(flags, newBoolFlag("write", "w", "Write the formatted config back to the input file", false))

	return &cli.Command{
		Name:      "pretty-print",
		Aliases:   []string{"fmt"},
		Usage:     "Pretty print a declarative config file",
		Flags:     flags,
		ArgsUsage: "<filePath>",
		UsageText: `args: <filePath>

<filePath> is the path to the declarative config file to format.

The file is parsed and re-emitted in the canonical format used by "openrun export".
Starlark logic (helper functions, conditionals, config() lookups) is evaluated and
replaced with the resulting literal values.

NOTE: Since starlark logic is evaluated, the output may not be exactly the same as the input.
If there are any functions or conditionals n the output, the output will be as seen after evaluation for the conditional logic.

Examples:
  Print formatted config: openrun pretty-print ./apps.ace
  Format the file in place: openrun pretty-print -w ./apps.ace
`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one argument: <filePath>")
			}
			filePath, err := makeAbsolute(cCtx.Args().Get(0))
			if err != nil {
				return err
			}

			values := url.Values{}
			values.Add("applyPath", filePath)

			client := newHttpClient(clientConfig)
			var response types.AppExportResponse
			if err := client.Get("/_openrun/pretty_print", values, &response); err != nil {
				return err
			}

			output := cCtx.String("output")
			if cCtx.Bool("write") {
				if output != "" {
					return fmt.Errorf("cannot use both --write and --output")
				}
				output = cCtx.Args().Get(0)
			}
			return writeConfigOutput(cCtx, response.Config, output)
		},
	}
}

func writeConfigOutput(cCtx *cli.Context, config, outputFile string) error {
	if outputFile == "" || outputFile == "-" {
		printStdout(cCtx, "%s", config)
		return nil
	}
	return os.WriteFile(outputFile, []byte(config), 0644)
}
