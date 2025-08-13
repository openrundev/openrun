// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

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
