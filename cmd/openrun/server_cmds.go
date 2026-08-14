// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

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
					Flags: []cli.Flag{newBoolFlag("wait", "w", "Wait for the server process to exit instead of returning as soon as shutdown starts", false)},
					Action: func(cCtx *cli.Context) error {
						return stopServer(cCtx, clientConfig)
					},
				},
				{
					Name:  "status",
					Usage: "Report ok if the server connection works",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return serverStatus(cCtx, clientConfig)
					},
				},
				{
					Name:  "version",
					Usage: "Report the server version",
					Flags: flags,
					Action: func(cCtx *cli.Context) error {
						return serverVersion(cCtx, clientConfig)
					},
				},
				{
					Name:    "metadata-status",
					Aliases: []string{"metadata_status"},
					Usage:   "Report metadata database connection and maintenance metrics",
					Flags:   flags,
					Action: func(cCtx *cli.Context) error {
						return metadataStatus(cCtx, clientConfig)
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

func stopServer(cCtx *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	var response types.ServerStopResponse
	err := client.Post("/_openrun/stop", nil, nil, &response)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if cCtx.Bool("wait") {
		return waitForServerExit(clientConfig, response.PID)
	}
	return nil
}

// waitForServerExit blocks until the stopped server has fully exited: the
// stop API responds when shutdown starts, and cleanup (final litestream
// sync) runs as the process exits, after the listeners are already closed.
// Over the unix domain socket the server's pid is polled; over http(s) the
// listener port is polled instead, a best effort signal for remote servers
func waitForServerExit(clientConfig *types.ClientConfig, pid int) error {
	serverUri := os.ExpandEnv(clientConfig.ServerUri)
	overTCP := strings.HasPrefix(serverUri, "http://") || strings.HasPrefix(serverUri, "https://")
	var addr string
	if overTCP {
		parsed, err := url.Parse(serverUri)
		if err != nil {
			return fmt.Errorf("error parsing server_uri for --wait: %w", err)
		}
		addr = parsed.Host
		if parsed.Port() == "" {
			if parsed.Scheme == "https" {
				addr += ":443"
			} else {
				addr += ":80"
			}
		}
	}

	running := func() bool {
		if !overTCP && pid > 0 {
			return system.ProcessExists(pid)
		}
		network, target := "tcp", addr
		if !overTCP {
			network, target = "unix", serverUri
		}
		conn, err := net.DialTimeout(network, target, time.Second)
		if err != nil {
			return false
		}
		conn.Close() //nolint:errcheck
		return true
	}

	for deadline := time.Now().Add(120 * time.Second); time.Now().Before(deadline); {
		if !running() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the server to exit")
}

func serverStatus(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	var response types.ServerStatusResponse
	err := client.Get("/_openrun/server_status", nil, &response)
	if err != nil {
		return err
	}
	fmt.Println(response.Status)
	return nil
}

func serverVersion(_ *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	var response types.ServerVersionResponse
	err := client.Get("/_openrun/server_version", nil, &response)
	if err != nil {
		return err
	}
	fmt.Printf("%s (commit %s)\n", response.Version, response.Commit)
	return nil
}

func metadataStatus(cCtx *cli.Context, clientConfig *types.ClientConfig) error {
	client := newHttpClient(clientConfig)

	var response types.MetadataHealthResponse
	if err := client.Get("/_openrun/metadata_health", nil, &response); err != nil {
		return err
	}
	return printMetadataStatus(cCtx, response)
}

func printMetadataStatus(cCtx *cli.Context, response types.MetadataHealthResponse) error {
	output, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(cCtx.App.Writer, string(output)); err != nil {
		return err
	}
	if response.Status != "ok" {
		message := "metadata database is unhealthy"
		if response.PingError != "" {
			message += ": " + response.PingError
		}
		return cli.Exit(message, 1)
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
