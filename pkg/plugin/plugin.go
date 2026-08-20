// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"

	goplugin "github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	"google.golang.org/grpc"
)

// ProtocolVersion is the go-plugin protocol version for the v1 Starlark
// plugin provider protocol. Incompatible protocol changes bump this and are
// served side by side through VersionedPlugins during a transition.
const ProtocolVersion = 1

// PluginName is the go-plugin dispense name for the plugin provider plugin.
const PluginName = "starplugin"

// MaxMessageSize is the gRPC send/receive message limit on both sides of the
// provider connection. Larger results must use a Cursor.
const MaxMessageSize = 64 * 1024 * 1024

// Handshake is the go-plugin handshake shared by the server and providers.
// The magic cookie is a sanity check that the launched executable is a
// Starlark plugin provider (not, for example, a binding provider); it is not
// a security measure.
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "OPENRUN_PLUGIN_PROVIDER",
	MagicCookieValue: "8e41c2d7-openrun-starlark-plugin-provider",
}

// ProviderError is an application-level error reported by a provider: the
// plugin function ran and returned a failure. Transport-level failures
// (provider crashed, protocol error) are returned as ordinary gRPC errors
// instead; the server treats those as fatal for the provider process.
type ProviderError struct {
	Message string
	Code    int64 // plugin error code, 1 unless the function set one
}

func (e *ProviderError) Error() string {
	return e.Message
}

func providerErr(msg string, code int64) error {
	if msg == "" {
		return nil
	}
	if code == 0 {
		code = 1
	}
	return &ProviderError{Message: msg, Code: code}
}

// providerPlugin is the go-plugin plugin implementation, used on both sides:
// the provider process serves srv; the server dispenses a *Client.
type providerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	srv pb.PluginProviderServer
}

var _ goplugin.GRPCPlugin = (*providerPlugin)(nil)

func (p *providerPlugin) GRPCServer(broker *goplugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterPluginProviderServer(s, p.srv)
	return nil
}

func (p *providerPlugin) GRPCClient(ctx context.Context, broker *goplugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return &Client{pc: pb.NewPluginProviderClient(conn)}, nil
}
