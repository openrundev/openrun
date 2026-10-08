// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"strconv"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func initVersionCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Manage app versions",
		Subcommands: []*cli.Command{
			versionListCommand(commonFlags, clientConfig),
			versionFilesCommand(commonFlags, clientConfig),
			versionSwitchCommand(commonFlags, clientConfig),
			versionRevertCommand(commonFlags, clientConfig),
		},
	}
}

func versionListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, stageFlag("List the versions of the staging instance of the app instead of prod"))

	return &cli.Command{
		Name:      "list",
		Usage:     "List the versions for an app",
		Flags:     flags,
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

<appPath> is a required argument. The optional domain and path are separated by a ":". This is the app for which versions are listed.
With --stage, the versions of the app's staging instance are listed. The staging instance can also be named by its own path.

	Examples:
	  List the prod versions: openrun version list example.com:/myapp
	  List the staging versions: openrun version list --stage example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPath>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())
			values.Add(STAGE_FLAG, strconv.FormatBool(cCtx.Bool(STAGE_FLAG)))

			var response types.AppVersionListResponse
			err := client.Get("/_openrun/version", values, &response)
			if err != nil {
				return err
			}

			printVersionList(cCtx, response.Versions, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printVersionList(cCtx *cli.Context, versions []types.AppVersion, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, versions, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, version := range versions {
			json.MarshalEncode(enc, version, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, version := range versions {
			json.MarshalEncode(enc, version, deterministicJSON) //nolint:errcheck
			printStdout(cCtx, "\n")
		}
	case FORMAT_BASIC:
		formatStrHead := "%6s %8s %8s %-20s\n"
		formatStrData := "%6s %8d %8d %.20s\n"
		printStdout(cCtx, formatStrHead, "Active", "Version", "Previous", "GitCommit")
		for _, version := range versions {
			isLive := ""
			if version.Active {
				isLive = "=====>"
			}
			printStdout(cCtx, formatStrData, isLive, version.Version, version.PreviousVersion, version.Metadata.VersionMetadata.GitCommit)
		}
	case FORMAT_TABLE:
		formatStrHead := "%6s %8s %8s %-30s %-20s %-40s\n"
		formatStrData := "%6s %8d %8d %-30s %.20s %-40s\n"
		printStdout(cCtx, formatStrHead, "Active", "Version", "Previous", "CreateTime", "GitCommit", "GitMessage")
		for _, version := range versions {
			isLive := ""
			if version.Active {
				isLive = "=====>"
			}
			printStdout(cCtx, formatStrData, isLive, version.Version, version.PreviousVersion, version.CreateTime, version.Metadata.VersionMetadata.GitCommit, version.Metadata.VersionMetadata.GitMessage)
		}
	case FORMAT_CSV:
		for _, version := range versions {
			printStdout(cCtx, "%t,%d,%d,\"%s\",%s,\"%s\"\n", version.Active, version.Version, version.PreviousVersion, version.CreateTime, version.Metadata.VersionMetadata.GitCommit, version.Metadata.VersionMetadata.GitMessage)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

func versionFilesCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newFormatFlag())
	flags = append(flags, newStringFlag("version", "v", "The version whose files are listed. Default is the active version", ""))
	flags = append(flags, stageFlag("List the files of the staging instance of the app instead of prod"))

	return &cli.Command{
		Name:      "files",
		Usage:     "List the files in a version of the app",
		Flags:     flags,
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

<appPath> is a required argument. The optional domain and path are separated by a ":". This is the app whose files are listed.
--version selects the version, the active version by default. With --stage, the staging instance of the app is used.

	Examples:
	  Files of the active prod version: openrun version files example.com:/myapp
	  Files of version 3 of the staging instance: openrun version files --stage --version 3 example.com:/myapp`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPath>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())
			values.Add(STAGE_FLAG, strconv.FormatBool(cCtx.Bool(STAGE_FLAG)))
			if version := cCtx.String("version"); version != "" {
				values.Add("version", version)
			}

			var response types.AppVersionFilesResponse
			err := client.Get("/_openrun/version/files", values, &response)
			if err != nil {
				return err
			}

			printFileList(cCtx, response.Files, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printFileList(cCtx *cli.Context, files []types.AppFile, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, files, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, version := range files {
			json.MarshalEncode(enc, version, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, f := range files {
			json.MarshalEncode(enc, f, deterministicJSON) //nolint:errcheck
			printStdout(cCtx, "\n")
		}
	case FORMAT_BASIC:
		fallthrough
	case FORMAT_TABLE:
		formatStrHead := "%7s %-64s %-50s\n"
		formatStrData := "%7d %-64s %-50s\n"
		printStdout(cCtx, formatStrHead, "Size", "Etag", "Path")
		for _, f := range files {
			printStdout(cCtx, formatStrData, f.Size, f.Etag, f.Name)
		}
	case FORMAT_CSV:
		for _, version := range files {
			printStdout(cCtx, "%d,%s,\"%s\"\n", version.Size, version.Etag, version.Name)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}

// instanceLabel names the app instance a command acted on in its output:
// the app path, with " (stage)" when --stage selected the staging instance
func instanceLabel(appPath string, stage bool) string {
	if stage {
		return appPath + " (stage)"
	}
	return appPath
}

func versionSwitchCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, stageFlag("Switch the version of the staging instance of the app instead of prod"))

	return &cli.Command{
		Name:      "switch",
		Usage:     "Switch the version for an app",
		Flags:     flags,
		ArgsUsage: "<version> <appPath>",
		UsageText: `args: <version> <appPath>

<version> is a required first argument. This is the version number to switch to. Use "previous" or "next" to switch to the previous or next version.
<appPath> is a required second argument. The optional domain and path are separated by a ":". This is the app whose version is switched.
With --stage, the staging instance of the app is switched. The staging instance can also be named by its own path.

	Examples:
	  Switch prod to the next version: openrun version switch next example.com:/myapp
	  Switch staging to version 123: openrun version switch --stage 123 /myapp
	  Switch prod to the previous version: openrun version switch previous /test`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 2 {
				return fmt.Errorf("requires two arguments: <version> <appPath>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().Get(1))
			values.Add("version", cCtx.Args().Get(0))
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(STAGE_FLAG, strconv.FormatBool(cCtx.Bool(STAGE_FLAG)))

			var response types.AppVersionSwitchResponse
			err := client.Post("/_openrun/version", values, nil, &response)
			if err != nil {
				return err
			}

			printStdout(cCtx, "Switched %s from version %d to version %d\n", instanceLabel(cCtx.Args().Get(1), cCtx.Bool(STAGE_FLAG)), response.FromVersion, response.ToVersion)

			if response.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}

func versionRevertCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, dryRunFlag())
	flags = append(flags, stageFlag("Revert the version of the staging instance of the app instead of prod"))

	return &cli.Command{
		Name:      "revert",
		Usage:     "Revert the version for an app",
		Flags:     flags,
		ArgsUsage: "<appPath>",
		UsageText: `args: <appPath>

<appPath> is a required argument. The optional domain and path are separated by a ":". This is the app whose version is reverted to the previous one.
With --stage, the staging instance of the app is reverted. The staging instance can also be named by its own path.

	Examples:
	  Revert prod: openrun version revert example.com:/myapp
	  Revert staging: openrun version revert --stage /myapp`,

		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("requires one argument: <appPath>")
			}

			client := newHttpClient(clientConfig)
			defer client.CloseIdleConnections()
			values := url.Values{}
			values.Add("appPath", cCtx.Args().First())
			values.Add("version", "revert") // Use revert as the switch API version
			values.Add(DRY_RUN_ARG, strconv.FormatBool(cCtx.Bool(DRY_RUN_FLAG)))
			values.Add(STAGE_FLAG, strconv.FormatBool(cCtx.Bool(STAGE_FLAG)))

			var response types.AppVersionSwitchResponse
			err := client.Post("/_openrun/version", values, nil, &response)
			if err != nil {
				return err
			}

			printStdout(cCtx, "Reverted %s from version %d to version %d\n", instanceLabel(cCtx.Args().First(), cCtx.Bool(STAGE_FLAG)), response.FromVersion, response.ToVersion)

			if response.DryRun {
				fmt.Print(DRY_RUN_MESSAGE)
			}

			return nil
		},
	}
}
