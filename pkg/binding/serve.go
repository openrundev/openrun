// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/binding/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// ServeConfig configures a binding provider process.
type ServeConfig struct {
	// Bindings maps each service type served by this provider to its builder.
	Bindings map[string]Builder

	// TypeInfo optionally describes each service type's grant types and config
	// schema, keyed by service type, reported to the server via Describe.
	TypeInfo map[string]ServiceTypeInfo

	// ProviderVersion is the provider's release version, reported via Describe.
	ProviderVersion string
}

// Serve runs the provider plugin. It is called from a provider executable's
// main function and blocks until the server side closes the plugin. The
// OPENRUN_PROVIDER_LOG_LEVEL environment variable (set by the server from its
// own log level) controls provider log verbosity.
func Serve(config *ServeConfig) {
	srv := &providerServer{
		config: config,
		logger: newServeLogger(os.Getenv("OPENRUN_PROVIDER_LOG_LEVEL")),
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		VersionedPlugins: map[int]plugin.PluginSet{
			ProtocolVersion: {PluginName: &providerPlugin{srv: srv}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// providerServer implements the provider-side gRPC service, hosting exactly
// one ServiceBinding instance: the server launches one provider process per
// binding instance, so no instance handles appear in the protocol.
type providerServer struct {
	pb.UnimplementedBindingProviderServer

	config *ServeConfig
	logger *Logger

	mu       sync.Mutex
	instance ServiceBinding
}

func (s *providerServer) Describe(ctx context.Context, req *pb.DescribeRequest) (*pb.DescribeResponse, error) {
	types := make([]*pb.ServiceTypeInfo, 0, len(s.config.Bindings))
	for _, serviceType := range slices.Sorted(maps.Keys(s.config.Bindings)) {
		// ServiceType comes from the Bindings map key; TypeInfo entries do not
		// need to repeat it.
		info := &pb.ServiceTypeInfo{ServiceType: serviceType}
		if typeInfo, ok := s.config.TypeInfo[serviceType]; ok {
			for _, gt := range typeInfo.SupportedGrantTypes {
				info.SupportedGrantTypes = append(info.SupportedGrantTypes, string(gt))
			}
			info.RequiredConfigKeys = typeInfo.RequiredConfigKeys
			info.OptionalConfigKeys = typeInfo.OptionalConfigKeys
		}
		types = append(types, info)
	}
	return &pb.DescribeResponse{
		ProviderVersion: s.config.ProviderVersion,
		ServiceTypes:    types,
	}, nil
}

func (s *providerServer) GetAccountEnv(ctx context.Context, req *pb.GetAccountEnvRequest) (*pb.GetAccountEnvResponse, error) {
	builder, ok := s.config.Bindings[req.GetServiceType()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "provider does not serve service type %q", req.GetServiceType())
	}
	// Static info: always answered from a fresh, uninitialized instance, so
	// the call works before InitializeService.
	params, optionalParams, err := builder().GetAccountEnv(ctx)
	if err != nil {
		return &pb.GetAccountEnvResponse{Error: err.Error()}, nil
	}
	return &pb.GetAccountEnvResponse{Params: params, OptionalParams: optionalParams}, nil
}

func (s *providerServer) InitializeService(ctx context.Context, req *pb.InitializeServiceRequest) (*pb.InitializeServiceResponse, error) {
	builder, ok := s.config.Bindings[req.GetServiceType()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "provider does not serve service type %q", req.GetServiceType())
	}

	s.mu.Lock()
	if s.instance != nil {
		s.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "service already initialized in this provider process")
	}
	instance := builder()
	s.instance = instance
	s.mu.Unlock()

	err := instance.InitializeService(ctx, s.logger, req.GetServiceConfig(), ServiceBindingRuntime{
		LocalhostBindingHostname: req.GetLocalhostBindingHostname(),
	})
	if err != nil {
		s.mu.Lock()
		s.instance = nil
		s.mu.Unlock()
		return &pb.InitializeServiceResponse{Error: err.Error()}, nil
	}
	return &pb.InitializeServiceResponse{}, nil
}

// getInstance returns the initialized instance, or a gRPC error if
// InitializeService has not succeeded (a protocol violation by the caller).
func (s *providerServer) getInstance() (ServiceBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.instance == nil {
		return nil, status.Error(codes.FailedPrecondition, "service not initialized")
	}
	return s.instance, nil
}

func (s *providerServer) CloseService(ctx context.Context, req *pb.CloseServiceRequest) (*pb.CloseServiceResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}
	if err := instance.CloseService(ctx); err != nil {
		return &pb.CloseServiceResponse{Error: err.Error()}, nil
	}
	return &pb.CloseServiceResponse{}, nil
}

func (s *providerServer) GenerateAccount(ctx context.Context, req *pb.GenerateAccountRequest) (*pb.GenerateAccountResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}

	var derivedFrom *BindingMetadata
	if req.DerivedFromMetadata != nil {
		m := metadataFromProto(req.GetDerivedFromMetadata())
		derivedFrom = &m
	}

	account, artifacts, err := instance.GenerateAccount(ctx, req.GetBindingId(), req.GetBindingPath(),
		metadataFromProto(req.GetBindingMetadata()), derivedFrom, req.GetIsStaging())
	resp := &pb.GenerateAccountResponse{
		Account:          account,
		CreatedArtifacts: artifactsToProto(artifacts),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *providerServer) DeleteArtifact(ctx context.Context, req *pb.DeleteArtifactRequest) (*pb.DeleteArtifactResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}
	artifact := Artifact{Type: ArtifactType(req.GetArtifact().GetType()), Name: req.GetArtifact().GetName()}
	if err := instance.DeleteArtifact(ctx, artifact); err != nil {
		return &pb.DeleteArtifactResponse{Error: err.Error()}, nil
	}
	return &pb.DeleteArtifactResponse{}, nil
}

func (s *providerServer) ApplyGrants(ctx context.Context, req *pb.ApplyGrantsRequest) (*pb.ApplyGrantsResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}
	result, err := instance.ApplyGrants(ctx, req.GetAccount(),
		metadataFromProto(req.GetBindingMetadata()), metadataFromProto(req.GetDerivedFromMetadata()), req.GetReapplyAll())
	if err != nil {
		return &pb.ApplyGrantsResponse{Error: err.Error()}, nil
	}
	return &pb.ApplyGrantsResponse{
		GrantsApplied:  grantsToProto(result.GrantsApplied),
		Granted:        grantsToProto(result.Granted),
		PendingRevokes: grantsToProto(result.PendingRevokes),
	}, nil
}

func (s *providerServer) RevokeGrants(ctx context.Context, req *pb.RevokeGrantsRequest) (*pb.RevokeGrantsResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}
	err = instance.RevokeGrants(ctx, req.GetAccount(), metadataFromProto(req.GetDerivedFromMetadata()),
		grantsFromProto(req.GetRevokes()), grantsFromProto(req.GetRegrants()))
	if err != nil {
		return &pb.RevokeGrantsResponse{Error: err.Error()}, nil
	}
	return &pb.RevokeGrantsResponse{}, nil
}

func (s *providerServer) RunCommand(ctx context.Context, req *pb.RunCommandRequest) (*pb.RunCommandResponse, error) {
	instance, err := s.getInstance()
	if err != nil {
		return nil, err
	}
	result, err := instance.RunCommand(ctx, metadataFromProto(req.GetBindingMetadata()), req.GetCommand())
	if err != nil {
		return &pb.RunCommandResponse{Error: err.Error()}, nil
	}
	// structpb only accepts []any/map[string]any values; bindings return typed
	// values like []string or []map[string]any. Round-trip through JSON to
	// normalize — the result is JSON on the caller's side in any case.
	normalized, err := normalizeJSONMap(result)
	if err != nil {
		return &pb.RunCommandResponse{Error: fmt.Sprintf("provider returned non-serializable command result: %s", err)}, nil
	}
	resultStruct, err := structpb.NewStruct(normalized)
	if err != nil {
		return &pb.RunCommandResponse{Error: fmt.Sprintf("provider returned non-serializable command result: %s", err)}, nil
	}
	return &pb.RunCommandResponse{Result: resultStruct}, nil
}

// normalizeJSONMap converts a command result into plain JSON types
// (map[string]any, []any, float64, string, bool, nil) via a JSON round trip.
func normalizeJSONMap(m map[string]any) (map[string]any, error) {
	if m == nil {
		return nil, nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var normalized map[string]any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}
