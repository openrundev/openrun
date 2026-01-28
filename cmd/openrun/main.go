// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const configFileFlagName = "config-file"

func getAllCommands(clientConfig *types.ClientConfig, serverConfig *types.ServerConfig) ([]*cli.Command, error) {
	var allCommands []*cli.Command
	serverCommands, err := getServerCommands(serverConfig, clientConfig)
	if err != nil {
		return nil, err
	}

	clientCommands, err := getClientCommands(clientConfig)
	if err != nil {
		return nil, err
	}

	passwordCommands, err := getPasswordCommands(clientConfig)
	if err != nil {
		return nil, err
	}

	for _, v := range [][]*cli.Command{
		serverCommands,
		clientCommands,
		passwordCommands,
	} {
		allCommands = append(allCommands, v...)
	}
	return allCommands, nil
}

func globalFlags(globalConfig *types.GlobalConfig) ([]cli.Flag, error) {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        configFileFlagName,
			Aliases:     []string{"c"},
			Usage:       "TOML configuration file",
			Destination: &globalConfig.ConfigFile,
			EnvVars:     []string{"CL_CONFIG_FILE"},
		},
		&cli.BoolFlag{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Print version info",
		},
	}, nil
}

// getConfigPath returns the path to the config file and the home directory
// Uses OPENRUN_HOME env if set. Otherwise uses binaries parent path. Setting OPENRUN_HOME is
// the easiest way to configure. Uses some extra heuristics to help avoid having to setup
// OPENRUN_HOME in the env, by using the binaries parent folder as the default.
// On mac, looks for brew install locations also.
func getConfigPath(cCtx *cli.Context) (string, string, bool, error) {
	configFile := cCtx.String(configFileFlagName)
	clHome := os.Getenv(types.OPENRUN_HOME)
	if configFile == "" {
		configFile = os.Getenv("CL_CONFIG_FILE")
		if configFile == "" && clHome != "" {
			configFile = path.Join(clHome, "openrun.toml")
		}
	}
	if clHome != "" {
		// Found OPENRUN_HOME
		return clHome, configFile, true, nil
	}
	if configFile != "" {
		// OPENRUN_HOME not set and config file is set, use config dir path as OPENRUN_HOME
		clHome = filepath.Dir(configFile)
		return clHome, configFile, false, nil
	}

	binFile, err := os.Executable()
	if err != nil {
		return "", "", false, fmt.Errorf("unable to find executable path: %w", err)
	}
	binAbsolute, err := filepath.EvalSymlinks(binFile)
	if err != nil {
		return "", "", false, fmt.Errorf("unable to resolve symlink: %w", err)
	}

	binParent := filepath.Dir(binAbsolute)
	if filepath.Base(binParent) == "bin" {
		// Found bin directory, use its parent
		binParent = filepath.Dir(binParent)
	}
	binParentConfig := path.Join(binParent, "openrun.toml")
	if system.FileExists(binParentConfig) && (strings.Contains(binParent, "openrun") || strings.Contains(binParent, "clhome")) {
		// Config file found in parent directory of the executable, use that as path
		// To avoid clobbering /usr, check if the path contains the string openrun/clhome
		return binParent, binParentConfig, false, nil
	}

	// Running `brew --prefix` would be another option
	if runtime.GOOS == "darwin" { //nolint:staticcheck
		// brew OSX specific checks
		if system.FileExists("/opt/homebrew/etc/openrun.toml") {
			return "/opt/homebrew/var/openrun", "/opt/homebrew/etc/openrun.toml", false, nil
		} else if system.FileExists("/usr/local/etc/openrun.toml") {
			return "/usr/local/var/openrun", "/usr/local/etc/openrun.toml", false, nil
		}
	} else if runtime.GOOS == "linux" {
		// brew linux specific checks
		if system.FileExists("/home/linuxbrew/.linuxbrew/etc/openrun.toml") {
			return "/home/linuxbrew/.linuxbrew/var/openrun", "/home/linuxbrew/.linuxbrew/etc/openrun.toml", false, nil
		} else if system.FileExists("/usr/local/etc/openrun.toml") {
			return "/usr/local/var/openrun", "/usr/local/etc/openrun.toml", false, nil
		} else if system.FileExists("/var/lib/openrun/openrun.toml") {
			// Linux system level installation
			return "/var/lib/openrun", "/var/lib/openrun/openrun.toml", false, nil
		}
	}
	return "", "", false, fmt.Errorf("unable to find OPENRUN_HOME or config file")
}

func parseConfig(cCtx *cli.Context, globalConfig *types.GlobalConfig, clientConfig *types.ClientConfig, serverConfig *types.ServerConfig) error {
	// Find OPENRUN_HOME and config file, update OPENRUN_HOME in env
	clHome, filePath, clHomeEnvSet, err := getConfigPath(cCtx)
	if err != nil {
		return err
	}
	clHome, err = filepath.Abs(clHome)
	if err != nil {
		return fmt.Errorf("unable to resolve OPENRUN_HOME: %w", err)
	}
	os.Setenv(types.OPENRUN_HOME, clHome) //nolint:errcheck

	//fmt.Fprintf(os.Stderr, "Loading config file: %s, clHome %s\n", filePath, clHome)
	buf, err := os.ReadFile(filePath)
	if err != nil {
		if clHomeEnvSet {
			fmt.Fprintf(os.Stderr, "Warning: unable to read config file %s, using default config\n", err)
			return nil
		}
		return err
	}

	if err := system.LoadGlobalConfig(string(buf), globalConfig); err != nil {
		return err
	}
	if err := system.LoadClientConfig(string(buf), clientConfig); err != nil {
		return err
	}
	if err := system.LoadServerConfig(string(buf), serverConfig); err != nil {
		return err
	}

	return nil
}

func main() {
	globalConfig, clientConfig, serverConfig, err := system.GetDefaultConfigs()
	if err != nil {
		log.Fatal(err)
	}
	globalFlags, err := globalFlags(globalConfig)
	if err != nil {
		log.Fatal(err)
	}
	allCommands, err := getAllCommands(clientConfig, serverConfig)
	if err != nil {
		log.Fatal(err)
	}

	app := &cli.App{
		Name:                 "openrun",
		Usage:                "OpenRun client and server https://openrun.dev/",
		EnableBashCompletion: true,
		Suggest:              true,
		Flags:                globalFlags,
		Before: func(ctx *cli.Context) error {
			err := parseConfig(ctx, globalConfig, clientConfig, serverConfig)
			if ctx.Command != nil && ctx.Args().Len() > 0 && ctx.Args().Get(0) == "password" {
				// For password command, ignore error parsing config
				return nil
			}
			if err != nil {
				return fmt.Errorf("error parsing config: %w", err)
			}
			return nil
		},
		ExitErrHandler: func(c *cli.Context, err error) {
			if err != nil {
				fmt.Fprintf(cli.ErrWriter, RED+"error: %s\n"+RESET, err) //nolint:errcheck
				os.Exit(1)
			}
		},
		Commands: allCommands,
		Action: func(ctx *cli.Context) error {
			// Default action when no subcommand is specified
			if ctx.Bool("version") {
				printVersion(ctx)
				os.Exit(0)
				return nil
			}
			return cli.ShowAppHelp(ctx)
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err) //nolint:errcheck
		os.Exit(1)
	}
}

func printStdout(cCtx *cli.Context, format string, a ...any) {
	fmt.Fprintf(cCtx.App.Writer, format, a...) //nolint:errcheck
}
