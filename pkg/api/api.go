// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"time"

	clserver "github.com/openrundev/openrun/internal/server"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ServerConfig is the configuration for the OpenRun Server
type ServerConfig struct {
	*types.ServerConfig
}

func NewServerConfig() (*ServerConfig, error) {
	embedConfig, err := system.NewServerConfigEmbedded()
	if err != nil {
		return nil, err
	}
	return &ServerConfig{embedConfig}, nil
}

// Server is the instance of the OpenRun Server
type Server struct {
	config *ServerConfig
	server *clserver.Server
}

// NewServer creates a new instance of the OpenRun Server
func NewServer(config *ServerConfig) (*Server, error) {
	server, err := clserver.NewServer(config.ServerConfig)
	if err != nil {
		return nil, err
	}

	return &Server{
		config: config,
		server: server,
	}, nil
}

// Start starts the OpenRun Server
func (s *Server) Start() error {
	return s.server.Start()
}

// Stop stops the OpenRun Server
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Stop(ctx)
}

// Restart performs a zero downtime in-place restart: the current binary is
// re-exec'ed and the listeners are handed off to the new process. Blocks
// until the new process is ready (StopNotify then fires so the caller can
// drain and exit) or the restart has failed, in which case this server
// keeps running and the error is returned
func (s *Server) Restart() error {
	return s.server.RequestRestart()
}

// Ready signals that startup has fully completed. See clserver.Server.Ready
// for why the caller must not call this until every startup step that can
// still fail (e.g. profiling setup) has passed
func (s *Server) Ready() error {
	return s.server.Ready()
}

// DrainTimeout returns the effective shutdown drain timeout: how long Stop
// waits for in-flight requests and hijacked (websocket) connections to
// finish before forcing them closed. See clserver.Server.DrainTimeout
func (s *Server) DrainTimeout() time.Duration {
	return s.server.DrainTimeout()
}

// StopNotify returns a channel that is closed when server shutdown is requested.
func (s *Server) StopNotify() <-chan struct{} {
	serverStop := s.server.StopNotify()
	serviceStop := system.ServiceStopNotify()
	if serviceStop == nil {
		return serverStop
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-serverStop:
		case <-serviceStop:
		}
		close(stop)
	}()
	return stop
}
