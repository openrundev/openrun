// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	"google.golang.org/grpc"
)

// Provider is a running plugin provider process, launched by the OpenRun
// server. Application-level failures are returned as *ProviderError; any
// other error is a transport failure (the process died or broke protocol)
// and the server treats the process and its sessions as dead.
type Provider struct {
	client *goplugin.Client
	rpc    *Client
}

// LaunchConfig configures launching a provider process.
type LaunchConfig struct {
	// ExecPath is the provider executable.
	ExecPath string
	// Logger receives go-plugin lifecycle logs and the provider's forwarded
	// log lines. Nil uses go-plugin's default (stderr).
	Logger hclog.Logger
	// LogLevel is passed to the provider via OPENRUN_PROVIDER_LOG_LEVEL.
	LogLevel string
	// SecureConfig, when set, verifies the executable's checksum before
	// launch.
	SecureConfig *goplugin.SecureConfig
}

// LaunchProvider starts the provider executable and completes the go-plugin
// handshake. The returned Provider must be closed with Kill.
func LaunchProvider(config LaunchConfig) (*Provider, error) {
	cmd := exec.Command(config.ExecPath)
	cmd.Env = append(os.Environ(), "OPENRUN_PROVIDER_LOG_LEVEL="+config.LogLevel)

	clientConfig := &goplugin.ClientConfig{
		HandshakeConfig: Handshake,
		VersionedPlugins: map[int]goplugin.PluginSet{
			ProtocolVersion: {PluginName: &providerPlugin{}},
		},
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           config.Logger,
		SecureConfig:     config.SecureConfig,
		GRPCDialOptions: []grpc.DialOption{
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageSize), grpc.MaxCallSendMsgSize(MaxMessageSize)),
		},
	}

	client := goplugin.NewClient(clientConfig)
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, err
	}
	raw, err := rpcClient.Dispense(PluginName)
	if err != nil {
		client.Kill()
		return nil, err
	}
	return &Provider{client: client, rpc: raw.(*Client)}, nil
}

// Kill terminates the provider process.
func (p *Provider) Kill() {
	p.client.Kill()
}

// Exited reports whether the provider process has exited.
func (p *Provider) Exited() bool {
	return p.client.Exited()
}

// Describe reports the provider's version and module manifests. Valid
// before InitApp; used at registration time to capture the manifests.
func (p *Provider) Describe(ctx context.Context) (*pb.DescribeResponse, error) {
	return p.rpc.pc.Describe(ctx, &pb.DescribeRequest{})
}

// InitApp establishes the app identity for this provider process. Called
// once per process, immediately after launch.
func (p *Provider) InitApp(ctx context.Context, req *pb.InitAppRequest) error {
	resp, err := p.rpc.pc.InitApp(ctx, req)
	if err != nil {
		return err
	}
	return providerErr(resp.GetError(), 1)
}

// InitModule initializes one (module, account) instance in the provider
// process, called lazily before the instance's first Call.
func (p *Provider) InitModule(ctx context.Context, req *pb.InitModuleRequest) error {
	resp, err := p.rpc.pc.InitModule(ctx, req)
	if err != nil {
		return err
	}
	return providerErr(resp.GetError(), 1)
}

// Call invokes a plugin function. An application-level failure is returned
// as *ProviderError together with the (possibly nil) response; a transport
// failure is any other error.
func (p *Provider) Call(ctx context.Context, req *pb.CallRequest) (*pb.CallResponse, error) {
	resp, err := p.rpc.pc.Call(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return resp, providerErr(resp.GetError(), resp.GetErrorCode())
	}
	return resp, nil
}

// CursorNext fetches the next batch of items from a cursor returned by a
// previous Call in the same session.
func (p *Provider) CursorNext(ctx context.Context, req *pb.CursorNextRequest) (*pb.CursorNextResponse, error) {
	resp, err := p.rpc.pc.CursorNext(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return nil, providerErr(resp.GetError(), 1)
	}
	return resp, nil
}

// CursorClose releases a cursor before exhaustion. Closing an unknown
// cursor or session is not an error.
func (p *Provider) CursorClose(ctx context.Context, req *pb.CursorCloseRequest) error {
	resp, err := p.rpc.pc.CursorClose(ctx, req)
	if err != nil {
		return err
	}
	return providerErr(resp.GetError(), 1)
}

// EndSession releases all provider-side state for a session: remaining
// deferred cleanups run and the session is forgotten. Called by the server
// when the request handler finishes.
func (p *Provider) EndSession(ctx context.Context, req *pb.EndSessionRequest) error {
	resp, err := p.rpc.pc.EndSession(ctx, req)
	if err != nil {
		return err
	}
	return providerErr(resp.GetError(), 1)
}

// CheckHealth reports whether the provider process is responsive.
func (p *Provider) CheckHealth(ctx context.Context) error {
	resp, err := p.rpc.pc.CheckHealth(ctx, &pb.CheckHealthRequest{})
	if err != nil {
		return err
	}
	return providerErr(resp.GetError(), 1)
}

// Client is the typed gRPC client for the provider protocol, dispensed by
// go-plugin. Server code uses Provider, which wraps process lifecycle
// around it.
type Client struct {
	pc pb.PluginProviderClient
}
