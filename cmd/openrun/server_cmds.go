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
	"syscall"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/openrundev/openrun/pkg/api"
	"github.com/pkg/profile"
	"github.com/urfave/cli/v2"
)

func getServerCommands(serverConfig *types.ServerConfig, clientConfig *types.ClientConfig) ([]*cli.Command, error) {
	flags := []cli.Flag{}
	return []*cli.Command{
		{
			Name:  "server",
			Usage: "Manage the OpenRun server",
			Subcommands: []*cli.Command{
				{
					Name:  "start",
					Usage: "Start the openrun server",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return startServer(cCtx, serverConfig)
					},
				},
				{
					Name:  "stop",
					Usage: "Stop the openrun server",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return stopServer(cCtx, clientConfig)
					},
				},
				{
					Name:  "restart",
					Usage: "Restart the openrun server in-place with zero downtime, reloading the config and picking up a new binary",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return restartServer(cCtx, clientConfig)
					},
				},
				{
					Name:  "show-config",
					Usage: "Show the server dynamic config",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return showConfig(cCtx, clientConfig)
					},
				},
				{
					Name:      "update-config",
					Usage:     "Update the server dynamic config",
					Flags:     []cli.Flag{newBoolFlag("force", "f", "Force update even if the config version id is different", false)},
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
	// Zero downtime in-place restarts are only initialized for the server
	// start command: the upgrader takes over process-wide state (re-exec,
	// listener handoff) which embedded api users must not be subjected to
	serverConfig.EnableInPlaceRestart = true
	apiConfig := api.ServerConfig{ServerConfig: serverConfig}
	server, err := api.NewServer(&apiConfig)
	if err != nil {
		fmt.Printf("Error initializing server: %s\n", err)
		system.NotifyServiceFailed(1)
		os.Exit(1)
	}
	err = server.Start()
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		system.NotifyServiceFailed(1)
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
		system.NotifyServiceFailed(1)
		os.Exit(1)
	}
	if serverConfig.ProfileMode != "" {
		fmt.Fprintf(os.Stderr, "Profiling enabled: %s\n", serverConfig.ProfileMode)
	}

	// Startup has fully succeeded at this point: signal the OS service
	// manager and, if this is an in-place restart child, the previous
	// process (which is waiting on Ready and starts draining as soon as it
	// is called). This must come after every startup step above that can
	// still fail (profile_mode validation and profile.Start, which can
	// os.Exit/log.Fatal on its own) -- signaling any earlier and then
	// failing to start would leave no server running, since the previous
	// process commits to the handoff unconditionally once Ready returns
	if err := server.Ready(); err != nil {
		fmt.Printf("Error signaling readiness: %s\n", err)
		system.NotifyServiceFailed(1)
		os.Exit(1)
	}
	system.NotifyServiceReady()

	waitForShutdownSignal(server)

	system.NotifyServiceStopping()
	defer system.NotifyServiceStopped()

	// Create a deadline to wait for. The drain timeout also bounds how long
	// the old process lingers for websocket connections after an in-place
	// restart handoff. Read from the server's live effective config (not the
	// static serverConfig captured at startup) so a restart.drain_timeout_secs
	// change applied via update-config actually takes effect
	ctxTimeout, cancel := context.WithTimeout(context.Background(), server.DrainTimeout())
	defer cancel()
	_ = server.Stop(ctxTimeout)
	return nil
}

func waitForShutdownSignal(server *api.Server) {
	serverStop := server.StopNotify()
	c := make(chan os.Signal, 1)
	// Accept graceful shutdowns on SIGINT (Ctrl+C) and SIGTERM (kill,
	// service managers): both must stop the apps' child processes (dev mode
	// tailwind watchers) instead of orphaning them
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(c)

	// SIGHUP triggers a zero downtime in-place restart (the unix daemon
	// reload convention; also what systemd ExecReload sends). Never delivered
	// on Windows. Run in a goroutine so shutdown signals stay responsive
	// while the restart is in progress; concurrent requests are serialized
	// by the server
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-c:
			return
		case <-serverStop:
			// Also fires after a successful in-place restart handoff: the
			// new process is serving and this process must drain and exit
			return
		case <-hup:
			go func() {
				if err := server.Restart(); err != nil {
					fmt.Fprintf(os.Stderr, "In-place restart failed: %s\n", err)
				}
			}()
		}
	}
}

func stopServer(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	var response types.AppVersionListResponse
	err := client.Post("/_openrun/stop", nil, nil, &response)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func restartServer(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	// The API blocks until the new process is serving or the restart failed
	// (the old process then keeps running)
	var response map[string]any
	err := client.Post("/_openrun/restart", nil, nil, &response)
	if err != nil {
		return err
	}
	fmt.Printf("Server restarted: %v\n", response["status"])
	return nil
}

func showConfig(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

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
	client := newHttpClient(clientConfig)

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
