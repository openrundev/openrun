// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	pb "github.com/openrundev/openrun/pkg/binding/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// fakeBinding is a controllable ServiceBinding used to verify the gRPC
// round trip preserves the interface contract.
type fakeBinding struct {
	initConfig map[string]string
	runtime    ServiceBindingRuntime
	closed     bool
}

func (f *fakeBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "user"}, []string{"extra"}, nil
}

func (f *fakeBinding) InitializeService(ctx context.Context, logger *Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	if serviceConfig["fail_init"] != "" {
		return errors.New(serviceConfig["fail_init"])
	}
	f.initConfig = serviceConfig
	f.runtime = runtime
	return nil
}

func (f *fakeBinding) CloseService(ctx context.Context) error {
	f.closed = true
	return nil
}

func (f *fakeBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata BindingMetadata,
	derivedFromMetadata *BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	artifacts := []Artifact{{Type: ArtifactUser, Name: "u_" + bindingId}}
	if bindingMetadata.Config["partial_failure"] != "" {
		// The partial-failure contract: artifacts are returned WITH the error.
		return nil, artifacts, errors.New("simulated partial failure")
	}
	account := map[string]string{"user": "u_" + bindingId, "staging": fmt.Sprintf("%t", isStaging)}
	if derivedFromMetadata != nil {
		account["derived"] = "true"
	}
	return account, artifacts, nil
}

func (f *fakeBinding) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	return nil
}

func (f *fakeBinding) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	grants, err := ParseGrants(bindingMetadata.Grants, []GrantType{GrantTypeRead, GrantTypeFull})
	if err != nil {
		return GrantApplyResult{}, err
	}
	revokes, _ := DiffGrants(bindingMetadata.GrantsApplied, grants)
	return GrantApplyResult{
		GrantsApplied:  grants,
		Granted:        grants,
		PendingRevokes: revokes,
	}, nil
}

func (f *fakeBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata BindingMetadata, revokes, regrants []BindingGrant) error {
	return nil
}

func (f *fakeBinding) RunCommand(ctx context.Context, bindingMetadata BindingMetadata, command string) (map[string]any, error) {
	if command == "fail" {
		return nil, errors.New("command failed")
	}
	if command == "typed" {
		// Typed values as returned by the sql-based bindings; the serve side
		// must JSON-normalize these before the structpb conversion.
		return map[string]any{
			"columns":       []string{"id", "note"},
			"rows":          []map[string]any{{"id": int64(1), "note": "n1"}},
			"rows_affected": int64(2),
		}, nil
	}
	return map[string]any{"echo": command, "count": float64(2)}, nil
}

// newTestClient wires a Client to a providerServer over an in-memory gRPC
// connection: the same proto mapping code paths as a real provider process,
// minus the process handshake (covered by the server-side e2e test).
func newTestClient(t *testing.T, config *ServeConfig) *Client {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	pb.RegisterBindingProviderServer(srv, &providerServer{config: config, logger: NewLogger("WARN")})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return &Client{pc: pb.NewBindingProviderClient(conn)}
}

func testServeConfig() *ServeConfig {
	return &ServeConfig{
		ProviderVersion: "v0.0.1-test",
		Bindings: map[string]Builder{
			"fake": func() ServiceBinding { return &fakeBinding{} },
		},
		TypeInfo: map[string]ServiceTypeInfo{
			"fake": {
				ServiceType:         "fake",
				SupportedGrantTypes: []GrantType{GrantTypeRead, GrantTypeFull},
				RequiredConfigKeys:  []string{"url"},
			},
		},
	}
}

func TestRoundTripDescribe(t *testing.T) {
	client := newTestClient(t, testServeConfig())
	version, infos, err := client.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "v0.0.1-test" {
		t.Fatalf("version = %q", version)
	}
	if len(infos) != 1 || infos[0].ServiceType != "fake" {
		t.Fatalf("infos = %+v", infos)
	}
	if !reflect.DeepEqual(infos[0].SupportedGrantTypes, []GrantType{GrantTypeRead, GrantTypeFull}) {
		t.Fatalf("grant types = %+v", infos[0].SupportedGrantTypes)
	}
}

func TestRoundTripGetAccountEnv(t *testing.T) {
	client := newTestClient(t, testServeConfig())
	ctx := context.Background()

	// Static info: callable before InitializeService.
	params, optional, err := client.GetAccountEnv(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(params, []string{"url", "url_direct", "user"}) || !reflect.DeepEqual(optional, []string{"extra"}) {
		t.Fatalf("params = %v optional = %v", params, optional)
	}

	// Unknown service type is a transport-level error.
	var providerError *ProviderError
	if _, _, err := client.GetAccountEnv(ctx, "unknown"); err == nil || errors.As(err, &providerError) {
		t.Fatalf("expected transport error for unknown type, got %v", err)
	}
}

func TestRoundTripInitialize(t *testing.T) {
	client := newTestClient(t, testServeConfig())
	ctx := context.Background()

	// Unknown service type is a transport-level error, not a ProviderError.
	err := client.InitializeService(ctx, "unknown", nil, ServiceBindingRuntime{})
	var providerError *ProviderError
	if err == nil || errors.As(err, &providerError) {
		t.Fatalf("expected transport error for unknown type, got %v", err)
	}

	// Application-level init failure is a ProviderError.
	err = client.InitializeService(ctx, "fake", map[string]string{"fail_init": "bad config"}, ServiceBindingRuntime{})
	if !errors.As(err, &providerError) || providerError.Message != "bad config" {
		t.Fatalf("expected ProviderError(bad config), got %v", err)
	}

	// A failed init leaves the instance uninitialized; a successful init works.
	if err := client.InitializeService(ctx, "fake", map[string]string{"url": "fake://x"},
		ServiceBindingRuntime{LocalhostBindingHostname: "host.docker.internal"}); err != nil {
		t.Fatal(err)
	}

	// Double initialize is a protocol violation: transport-level error.
	err = client.InitializeService(ctx, "fake", map[string]string{"url": "fake://x"}, ServiceBindingRuntime{})
	if err == nil || errors.As(err, &providerError) {
		t.Fatalf("expected transport error for double init, got %v", err)
	}
}

func TestRoundTripGenerateAccount(t *testing.T) {
	client := newTestClient(t, testServeConfig())
	ctx := context.Background()
	if err := client.InitializeService(ctx, "fake", map[string]string{"url": "fake://x"}, ServiceBindingRuntime{}); err != nil {
		t.Fatal(err)
	}

	derived := &BindingMetadata{Grants: []string{"read:*"}}
	account, artifacts, err := client.GenerateAccount(ctx, "bnd_1", "/p", BindingMetadata{}, derived, true)
	if err != nil {
		t.Fatal(err)
	}
	if account["user"] != "u_bnd_1" || account["staging"] != "true" || account["derived"] != "true" {
		t.Fatalf("account = %v", account)
	}
	if len(artifacts) != 1 || artifacts[0] != (Artifact{Type: ArtifactUser, Name: "u_bnd_1"}) {
		t.Fatalf("artifacts = %v", artifacts)
	}

	// Partial failure: artifacts must arrive alongside the ProviderError.
	_, artifacts, err = client.GenerateAccount(ctx, "bnd_2", "/p",
		BindingMetadata{Config: map[string]string{"partial_failure": "y"}}, nil, false)
	var providerError *ProviderError
	if !errors.As(err, &providerError) {
		t.Fatalf("expected ProviderError, got %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Name != "u_bnd_2" {
		t.Fatalf("partial failure artifacts = %v", artifacts)
	}
}

func TestRoundTripRunCommand(t *testing.T) {
	client := newTestClient(t, testServeConfig())
	ctx := context.Background()

	// Method call before initialize is a protocol violation.
	_, err := client.RunCommand(ctx, BindingMetadata{}, "x")
	var providerError *ProviderError
	if err == nil || errors.As(err, &providerError) {
		t.Fatalf("expected transport error before init, got %v", err)
	}

	if err := client.InitializeService(ctx, "fake", map[string]string{"url": "fake://x"}, ServiceBindingRuntime{}); err != nil {
		t.Fatal(err)
	}
	result, err := client.RunCommand(ctx, BindingMetadata{}, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if result["echo"] != "hello" || result["count"] != float64(2) {
		t.Fatalf("result = %v", result)
	}

	_, err = client.RunCommand(ctx, BindingMetadata{}, "fail")
	if !errors.As(err, &providerError) || providerError.Message != "command failed" {
		t.Fatalf("expected ProviderError(command failed), got %v", err)
	}

	// Typed slices ([]string, []map[string]any) and int64 values must survive
	// the round trip via JSON normalization.
	result, err = client.RunCommand(ctx, BindingMetadata{}, "typed")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"columns":       []any{"id", "note"},
		"rows":          []any{map[string]any{"id": float64(1), "note": "n1"}},
		"rows_affected": float64(2),
	}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("typed result = %#v, want %#v", result, want)
	}
}
