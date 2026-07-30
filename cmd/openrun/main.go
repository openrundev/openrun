// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
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

func globalFlags(globalConfig *types.GlobalConfig, clientConfig *types.ClientConfig) ([]cli.Flag, error) {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        configFileFlagName,
			Aliases:     []string{"c"},
			Usage:       "TOML configuration file",
			Destination: &globalConfig.ConfigFile,
			EnvVars:     []string{"CL_CONFIG_FILE"},
		},
		&cli.StringFlag{
			Name:        "as",
			Usage:       "Run the command as this user id (like builtin:user1) with RBAC enforcement. Requires RBAC to be enabled; supported over the unix domain socket only",
			Destination: &clientConfig.Client.AsUser,
			EnvVars:     []string{"OPENRUN_AS_USER"},
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
// On mac, looks for brew install locations also. When nothing is found, falls back to
// $HOME/openrun (the install script default), with homeDefaulted set to true.
func getConfigPath(cCtx *cli.Context) (clHomeRet, configFileRet string, clHomeEnvSet, homeDefaulted bool, errRet error) {
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
		return clHome, configFile, true, false, nil
	}
	if configFile != "" {
		// OPENRUN_HOME not set and config file is set, use config dir path as OPENRUN_HOME
		clHome = filepath.Dir(configFile)
		return clHome, configFile, false, false, nil
	}

	binFile, err := os.Executable()
	if err != nil {
		return "", "", false, false, fmt.Errorf("unable to find executable path: %w", err)
	}
	binAbsolute, err := filepath.EvalSymlinks(binFile)
	if err != nil {
		return "", "", false, false, fmt.Errorf("unable to resolve symlink: %w", err)
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
		return binParent, binParentConfig, false, false, nil
	}

	// Running `brew --prefix` would be another option
	if runtime.GOOS == "darwin" { //nolint:staticcheck
		// brew OSX specific checks
		if system.FileExists("/opt/homebrew/etc/openrun.toml") {
			return "/opt/homebrew/var/openrun", "/opt/homebrew/etc/openrun.toml", false, false, nil
		} else if system.FileExists("/usr/local/etc/openrun.toml") {
			return "/usr/local/var/openrun", "/usr/local/etc/openrun.toml", false, false, nil
		}
	} else if runtime.GOOS == "linux" {
		// brew linux specific checks
		if system.FileExists("/home/linuxbrew/.linuxbrew/etc/openrun.toml") {
			return "/home/linuxbrew/.linuxbrew/var/openrun", "/home/linuxbrew/.linuxbrew/etc/openrun.toml", false, false, nil
		} else if system.FileExists("/usr/local/etc/openrun.toml") {
			return "/usr/local/var/openrun", "/usr/local/etc/openrun.toml", false, false, nil
		} else if system.FileExists("/var/lib/openrun/openrun.toml") {
			// Linux system level installation
			return "/var/lib/openrun", "/var/lib/openrun/openrun.toml", false, false, nil
		}
	} else if runtime.GOOS == "windows" {
		// Windows system level installation (machine scoped winget install with
		// the service registered against C:\ProgramData\openrun\openrun.toml).
		// The winget binary is a links shim, so the executable-relative check
		// above cannot discover this home
		if programData := os.Getenv("ProgramData"); programData != "" {
			systemHome := filepath.Join(programData, "openrun")
			systemConfig := filepath.Join(systemHome, "openrun.toml")
			if system.FileExists(systemConfig) {
				return systemHome, systemConfig, false, false, nil
			}
		}
	}

	// Nothing configured or discovered: default to $HOME/openrun, the same
	// location the install scripts use. Package managers like winget cannot
	// run an install script, so this is the normal path for such installs
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", false, false, fmt.Errorf("unable to find OPENRUN_HOME or config file: %w", err)
	}
	defaultHome := filepath.Join(homeDir, "openrun")
	return defaultHome, filepath.Join(defaultHome, "openrun.toml"), false, true, nil
}

func parseConfig(cCtx *cli.Context, globalConfig *types.GlobalConfig, clientConfig *types.ClientConfig, serverConfig *types.ServerConfig) error {
	// Find OPENRUN_HOME and config file, update OPENRUN_HOME in env
	clHome, filePath, clHomeEnvSet, homeDefaulted, err := getConfigPath(cCtx)
	if err != nil {
		return err
	}
	clHome, err = filepath.Abs(clHome)
	if err != nil {
		return fmt.Errorf("unable to resolve OPENRUN_HOME: %w", err)
	}
	os.Setenv(types.OPENRUN_HOME, clHome) //nolint:errcheck

	if homeDefaulted && !system.FileExists(filePath) {
		if system.IsRunningAsService() {
			// The default home resolves to the service account profile (e.g.
			// C:\Windows\System32\config\systemprofile), not the installing
			// user's home, and a bootstrapped admin password would be printed
			// where nobody can see it. Fail fast instead of silently creating
			// a second config under the service profile
			return fmt.Errorf("no config file found (looked for %s): when running as an OS service, set OPENRUN_HOME in the service environment or register the service with --config-file", filePath)
		}
		if cCtx.Args().Get(0) == "server" && cCtx.Args().Get(1) == "start" {
			// First server start with no config setup (e.g. installed through
			// winget, which cannot run the install script): initialize the
			// config with a generated admin password, like the install scripts do
			if err := bootstrapConfigFile(clHome, filePath); err != nil {
				return err
			}
		}
	}

	//fmt.Fprintf(os.Stderr, "Loading config file: %s, clHome %s\n", filePath, clHome)
	buf, err := os.ReadFile(filePath)
	if err != nil {
		if clHomeEnvSet {
			fmt.Fprintf(os.Stderr, "Warning: unable to read config file %s, using default config\n", err)
			return nil
		}
		if homeDefaulted {
			// No install setup found anywhere; run with the default config so
			// commands like help and version work without any setup
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
	if !slices.Contains(validFormats, clientConfig.Client.DefaultFormat) {
		return fmt.Errorf("invalid client.default_format %q in config: valid options are %s",
			clientConfig.Client.DefaultFormat, strings.Join(validFormats, ", "))
	}
	if err := system.LoadServerConfig(string(buf), serverConfig); err != nil {
		return err
	}

	return nil
}

// fatalError prints the error to stderr and exits
func fatalError(err error) {
	fmt.Fprintf(os.Stderr, RED+"error: %s"+RESET+"\n", err) //nolint:errcheck
	system.NotifyServiceFailed(1)
	os.Exit(1)
}

// setUsageErrorHandlers routes flag parsing errors through the app
// ExitErrHandler so they are printed to stderr instead of the urfave/cli
// default of printing usage errors on stdout
func setUsageErrorHandlers(commands []*cli.Command, helpPath string) {
	for _, command := range commands {
		commandPath := helpPath + " " + command.Name
		if command.OnUsageError == nil {
			command.OnUsageError = func(_ *cli.Context, err error, _ bool) error {
				return usageError(command.Flags, commandPath, err)
			}
		}
		setUsageErrorHandlers(command.Subcommands, commandPath)
	}
}

// usageError adds a did-you-mean suggestion for unknown flags and a --help
// hint to flag parsing errors
func usageError(flags []cli.Flag, helpPath string, err error) error {
	if flagName, ok := strings.CutPrefix(err.Error(), "flag provided but not defined: -"); ok && cli.SuggestFlag != nil {
		if suggestion := cli.SuggestFlag(flags, flagName, false); suggestion != "" {
			return fmt.Errorf("%w (did you mean %q?)\nrun '%s --help' for usage", err, suggestion, helpPath)
		}
	}
	return fmt.Errorf("%w\nrun '%s --help' for usage", err, helpPath)
}

func main() {
	// Start the OS service control handler if launched by the Windows
	// service control manager. Must run before any long initialization so
	// the service reports StartPending promptly.
	system.MaybeRunAsService()

	globalConfig, clientConfig, serverConfig, err := system.GetDefaultConfigs()
	if err != nil {
		fatalError(err)
	}
	globalFlags, err := globalFlags(globalConfig, clientConfig)
	if err != nil {
		fatalError(err)
	}
	allCommands, err := getAllCommands(clientConfig, serverConfig)
	if err != nil {
		fatalError(err)
	}
	setUsageErrorHandlers(allCommands, "openrun")

	app := &cli.App{
		Name:                 "openrun",
		Usage:                "OpenRun client and server https://openrun.dev/",
		EnableBashCompletion: true,
		Suggest:              true,
		// Slice flag values are taken verbatim, never split on commas: values
		// legitimately contain commas (binding params like
		// --bind "sqlite;path=/mydata,example=val2", JSON param values). The
		// documented way to pass multiple values is repeating the flag.
		DisableSliceFlagSeparator: true,
		Flags:                     globalFlags,
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
				fatalError(err)
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
			if ctx.Args().Present() {
				// An unknown command should fail instead of showing the help and exiting 0
				arg := ctx.Args().First()
				if cli.SuggestCommand != nil {
					if suggestion := cli.SuggestCommand(ctx.App.Commands, arg); suggestion != "" {
						return fmt.Errorf("unknown command %q. %s\nrun 'openrun --help' for usage", arg, suggestion)
					}
				}
				return fmt.Errorf("unknown command %q\nrun 'openrun --help' for usage", arg)
			}
			return cli.ShowAppHelp(ctx)
		},
	}

	app.OnUsageError = func(_ *cli.Context, err error, _ bool) error {
		return usageError(app.Flags, "openrun", err)
	}

	if err := app.Run(normalizeInterspersedFlags(app, os.Args)); err != nil {
		fatalError(err)
	}
}

func printStdout(cCtx *cli.Context, format string, a ...any) {
	fmt.Fprintf(cCtx.App.Writer, format, a...) //nolint:errcheck
}
