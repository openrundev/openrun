// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/openrundev/openrun/pkg/api"
	"github.com/pkg/profile"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func getServerCommands(serverConfig *types.ServerConfig, clientConfig *types.ClientConfig) ([]*cli.Command, error) {
	flags := []cli.Flag{}
	return []*cli.Command{
		{
			Name:  "server",
			Usage: "Manage the OpenRun server",
			Subcommands: []*cli.Command{
				{
					Name:   "start",
					Usage:  "Start the openrun server",
					Flags:  flags,
					Before: altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
					Action: func(cCtx *cli.Context) error {
						return startServer(cCtx, serverConfig)
					},
				},
				{
					Name:   "stop",
					Usage:  "Stop the openrun server",
					Flags:  flags,
					Before: altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
					Action: func(cCtx *cli.Context) error {
						return stopServer(cCtx, clientConfig)
					},
				},
				{
					Name:   "show-config",
					Usage:  "Show the server dynamic config",
					Flags:  flags,
					Before: altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
					Action: func(cCtx *cli.Context) error {
						return showConfig(cCtx, clientConfig)
					},
				},
				{
					Name:      "update-config",
					Usage:     "Update the server dynamic config",
					Flags:     []cli.Flag{newBoolFlag("force", "f", "Force update even if the config version id is different", false)},
					Before:    altsrc.InitInputSourceWithContext(flags, altsrc.NewTomlSourceFromFlagFunc(configFileFlagName)),
					ArgsUsage: "configFilePath",
					UsageText: `args: configFilePath

	<configFilePath> is the path to the new server config file.`,
					Action: func(cCtx *cli.Context) error {
						return updateConfig(cCtx, clientConfig)
					},
				},
			},
		},
	}, nil
}

func startServer(cCtx *cli.Context, serverConfig *types.ServerConfig) error {
	apiConfig := api.ServerConfig{ServerConfig: serverConfig}
	server, err := api.NewServer(&apiConfig)
	if err != nil {
		fmt.Printf("Error initializing server: %s\n", err)
		os.Exit(1)
	}
	err = server.Start()
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		os.Exit(1)
	}

	if serverConfig.Http.Port >= 0 {
		addr := fmt.Sprintf("http://%s:%d", serverConfig.Http.Host, serverConfig.Http.Port)
		fmt.Fprintf(os.Stderr, "Server listening on %s\n", addr)
	}
	if serverConfig.Https.Port >= 0 {
		addr := fmt.Sprintf("https://%s:%d", serverConfig.Https.Host, serverConfig.Https.Port)
		fmt.Fprintf(os.Stderr, "Server listening on %s\n", addr)
	}

	clHome := os.ExpandEnv("$OPENRUN_HOME")
	switch serverConfig.ProfileMode {
	case "cpu":
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(clHome)).Stop()
	case "memory":
		defer profile.Start(profile.MemProfile, profile.ProfilePath(clHome)).Stop()
	case "allocs":
		defer profile.Start(profile.MemProfileAllocs, profile.ProfilePath(clHome)).Stop()
	case "heap":
		defer profile.Start(profile.MemProfileHeap, profile.ProfilePath(clHome)).Stop()
	case "mutex":
		defer profile.Start(profile.MutexProfile, profile.ProfilePath(clHome)).Stop()
	case "block":
		defer profile.Start(profile.BlockProfile, profile.ProfilePath(clHome)).Stop()
	case "goroutine":
		defer profile.Start(profile.GoroutineProfile, profile.ProfilePath(clHome)).Stop()
	case "clock":
		defer profile.Start(profile.ClockProfile, profile.ProfilePath(clHome)).Stop()
	case "":
		// no profiling
	default:
		fmt.Fprintf(os.Stderr, "Unknown profile mode: %s. Supported modes cpu,memory,allocs,heap,mutex,block,goroutine,clock\n", serverConfig.ProfileMode)
		os.Exit(1)
	}
	if serverConfig.ProfileMode != "" {
		fmt.Fprintf(os.Stderr, "Profiling enabled: %s\n", serverConfig.ProfileMode)
		select {} // block forever, profiling will exit on interrupt
	}

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 30)
	defer cancel()
	_ = server.Stop(ctxTimeout)
	return nil
}

func stopServer(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)

	var response types.AppVersionListResponse
	err := client.Post("/_openrun/stop", nil, nil, &response)
	if err == nil {
		return fmt.Errorf("expected error response when stopping server")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func showConfig(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)

	var response types.ConfigResponse
	err := client.Get("/_openrun/config", nil, &response)
	if err != nil {
		return err
	}
	json, err := json.MarshalIndent(response.DynamicConfig, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", string(json))
	return nil
}

func updateConfig(cCtx *cli.Context, clientConfig *types.ClientConfig) error {
	client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)

	if cCtx.NArg() != 1 {
		return fmt.Errorf("expected one argument: <configFilePath>")
	}
	configFilePath := cCtx.Args().Get(0)
	configFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	var inputConfig types.DynamicConfig
	err = json.Unmarshal(configFile, &inputConfig)
	if err != nil {
		return err
	}

	values := url.Values{}
	values.Add("force", strconv.FormatBool(cCtx.Bool("force")))

	var response types.ConfigResponse
	err = client.Post("/_openrun/config", values, &inputConfig, &response)
	if err != nil {
		return err
	}

	json, err := json.MarshalIndent(response.DynamicConfig, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", string(json))
	return nil
}
