// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/binding/proto"
	"google.golang.org/grpc"
)

// ProtocolVersion is the go-plugin protocol version for the v1 binding
// provider protocol. Incompatible protocol changes bump this and are served
// side by side through VersionedPlugins during a transition.
const ProtocolVersion = 1

// PluginName is the go-plugin dispense name for the binding provider plugin.
const PluginName = "binding"

// Handshake is the go-plugin handshake shared by the server and providers. The
// magic cookie is a sanity check that the launched executable is a binding
// provider, not a security measure.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "OPENRUN_BINDING_PROVIDER",
	MagicCookieValue: "5c3f7a1e-openrun-binding-provider",
}

// ProviderError is an application-level error reported by a provider: the
// provider ran and returned a failure. Transport-level failures (provider
// crashed, protocol error) are returned as ordinary gRPC errors instead, and
// may be retried by the server after respawning the provider.
type ProviderError struct {
	Message string
}

func (e *ProviderError) Error() string {
	return e.Message
}

func providerErr(msg string) error {
	if msg == "" {
		return nil
	}
	return &ProviderError{Message: msg}
}

// providerPlugin is the go-plugin plugin implementation, used on both sides:
// the provider process serves srv; the server dispenses a *Client.
type providerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	srv pb.BindingProviderServer
}

var _ plugin.GRPCPlugin = (*providerPlugin)(nil)

func (p *providerPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterBindingProviderServer(s, p.srv)
	return nil
}

func (p *providerPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return &Client{pc: pb.NewBindingProviderClient(conn)}, nil
}
