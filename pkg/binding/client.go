// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/binding/proto"
	"google.golang.org/grpc"
)

// Provider is a running provider process, launched by the OpenRun server.
// Methods mirror the ServiceBinding interface using SDK types; the server
// converts to its internal types. Application-level failures are returned as
// *ProviderError; any other error is a transport failure (the process died or
// broke protocol) and the caller may respawn the provider and retry.
type Provider struct {
	client *plugin.Client
	rpc    *Client
}

// LaunchConfig configures launching a provider process.
type LaunchConfig struct {
	// ExecPath is the provider executable.
	ExecPath string
	// Logger receives go-plugin lifecycle logs and the provider's forwarded log
	// lines. Nil uses go-plugin's default (stderr).
	Logger hclog.Logger
	// LogLevel is passed to the provider via OPENRUN_PROVIDER_LOG_LEVEL.
	LogLevel string
	// SecureConfig, when set, verifies the executable's checksum before launch.
	SecureConfig *plugin.SecureConfig
}

// LaunchProvider starts the provider executable and completes the go-plugin
// handshake. The returned Provider must be closed with Kill.
func LaunchProvider(config LaunchConfig) (*Provider, error) {
	cmd := exec.Command(config.ExecPath)
	cmd.Env = append(os.Environ(), "OPENRUN_PROVIDER_LOG_LEVEL="+config.LogLevel)

	clientConfig := &plugin.ClientConfig{
		HandshakeConfig: Handshake,
		VersionedPlugins: map[int]plugin.PluginSet{
			ProtocolVersion: {PluginName: &providerPlugin{}},
		},
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           config.Logger,
		SecureConfig:     config.SecureConfig,
		GRPCDialOptions: []grpc.DialOption{
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageSize), grpc.MaxCallSendMsgSize(MaxMessageSize)),
		},
	}

	client := plugin.NewClient(clientConfig)
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

func (p *Provider) Describe(ctx context.Context) (string, []ServiceTypeInfo, error) {
	return p.rpc.Describe(ctx)
}

func (p *Provider) GetAccountEnv(ctx context.Context, serviceType string) ([]string, []string, error) {
	return p.rpc.GetAccountEnv(ctx, serviceType)
}

func (p *Provider) InitializeService(ctx context.Context, serviceType string, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	return p.rpc.InitializeService(ctx, serviceType, serviceConfig, runtime)
}

func (p *Provider) CloseService(ctx context.Context) error {
	return p.rpc.CloseService(ctx)
}

func (p *Provider) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata BindingMetadata,
	derivedFromMetadata *BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	return p.rpc.GenerateAccount(ctx, bindingId, bindingPath, bindingMetadata, derivedFromMetadata, isStaging)
}

func (p *Provider) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	return p.rpc.DeleteArtifact(ctx, artifact)
}

func (p *Provider) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	return p.rpc.ApplyGrants(ctx, account, bindingMetadata, derivedFromMetadata, reapplyAll)
}

func (p *Provider) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata BindingMetadata, revokes, regrants []BindingGrant) error {
	return p.rpc.RevokeGrants(ctx, account, derivedFromMetadata, revokes, regrants)
}

func (p *Provider) RunCommand(ctx context.Context, bindingMetadata BindingMetadata, command string) (map[string]any, error) {
	return p.rpc.RunCommand(ctx, bindingMetadata, command)
}

// Client is the typed gRPC client for the provider protocol, dispensed by
// go-plugin. Server code uses Provider, which wraps process lifecycle around it.
type Client struct {
	pc pb.BindingProviderClient
}

func (c *Client) Describe(ctx context.Context) (string, []ServiceTypeInfo, error) {
	resp, err := c.pc.Describe(ctx, &pb.DescribeRequest{})
	if err != nil {
		return "", nil, err
	}
	infos := make([]ServiceTypeInfo, 0, len(resp.GetServiceTypes()))
	for _, t := range resp.GetServiceTypes() {
		grantTypes := make([]GrantType, 0, len(t.GetSupportedGrantTypes()))
		for _, gt := range t.GetSupportedGrantTypes() {
			grantTypes = append(grantTypes, GrantType(gt))
		}
		infos = append(infos, ServiceTypeInfo{
			ServiceType:         t.GetServiceType(),
			SupportedGrantTypes: grantTypes,
			RequiredConfigKeys:  t.GetRequiredConfigKeys(),
			OptionalConfigKeys:  t.GetOptionalConfigKeys(),
		})
	}
	return resp.GetProviderVersion(), infos, nil
}

func (c *Client) GetAccountEnv(ctx context.Context, serviceType string) ([]string, []string, error) {
	resp, err := c.pc.GetAccountEnv(ctx, &pb.GetAccountEnvRequest{ServiceType: serviceType})
	if err != nil {
		return nil, nil, err
	}
	if resp.GetError() != "" {
		return nil, nil, providerErr(resp.GetError())
	}
	return resp.GetParams(), resp.GetOptionalParams(), nil
}

func (c *Client) InitializeService(ctx context.Context, serviceType string, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	resp, err := c.pc.InitializeService(ctx, &pb.InitializeServiceRequest{
		ServiceType:              serviceType,
		ServiceConfig:            serviceConfig,
		LocalhostBindingHostname: runtime.LocalhostBindingHostname,
	})
	if err != nil {
		return err
	}
	return providerErr(resp.GetError())
}

func (c *Client) CloseService(ctx context.Context) error {
	resp, err := c.pc.CloseService(ctx, &pb.CloseServiceRequest{})
	if err != nil {
		return err
	}
	return providerErr(resp.GetError())
}

func (c *Client) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata BindingMetadata,
	derivedFromMetadata *BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	req := &pb.GenerateAccountRequest{
		BindingId:       bindingId,
		BindingPath:     bindingPath,
		BindingMetadata: metadataToProto(bindingMetadata),
		IsStaging:       isStaging,
	}
	if derivedFromMetadata != nil {
		req.DerivedFromMetadata = metadataToProto(*derivedFromMetadata)
	}
	resp, err := c.pc.GenerateAccount(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	// Artifacts are returned even on failure so the caller can roll them back.
	return resp.GetAccount(), artifactsFromProto(resp.GetCreatedArtifacts()), providerErr(resp.GetError())
}

func (c *Client) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	resp, err := c.pc.DeleteArtifact(ctx, &pb.DeleteArtifactRequest{
		Artifact: &pb.Artifact{Type: string(artifact.Type), Name: artifact.Name},
	})
	if err != nil {
		return err
	}
	return providerErr(resp.GetError())
}

func (c *Client) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	resp, err := c.pc.ApplyGrants(ctx, &pb.ApplyGrantsRequest{
		Account:             account,
		BindingMetadata:     metadataToProto(bindingMetadata),
		DerivedFromMetadata: metadataToProto(derivedFromMetadata),
		ReapplyAll:          reapplyAll,
	})
	if err != nil {
		return GrantApplyResult{}, err
	}
	if resp.GetError() != "" {
		return GrantApplyResult{}, providerErr(resp.GetError())
	}
	return GrantApplyResult{
		GrantsApplied:  grantsFromProto(resp.GetGrantsApplied()),
		Granted:        grantsFromProto(resp.GetGranted()),
		PendingRevokes: grantsFromProto(resp.GetPendingRevokes()),
	}, nil
}

func (c *Client) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata BindingMetadata, revokes, regrants []BindingGrant) error {
	resp, err := c.pc.RevokeGrants(ctx, &pb.RevokeGrantsRequest{
		Account:             account,
		DerivedFromMetadata: metadataToProto(derivedFromMetadata),
		Revokes:             grantsToProto(revokes),
		Regrants:            grantsToProto(regrants),
	})
	if err != nil {
		return err
	}
	return providerErr(resp.GetError())
}

func (c *Client) RunCommand(ctx context.Context, bindingMetadata BindingMetadata, command string) (map[string]any, error) {
	resp, err := c.pc.RunCommand(ctx, &pb.RunCommandRequest{
		BindingMetadata: metadataToProto(bindingMetadata),
		Command:         command,
	})
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return nil, providerErr(resp.GetError())
	}
	var result map[string]any
	if resp.GetResult() != nil {
		result = resp.GetResult().AsMap()
	}
	return result, nil
}
