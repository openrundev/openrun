// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// newMCPTestServer builds a server with a real metadata DB, RBAC enabled
// with alice (developer grant) and bob (no grants), and one applied app at
// /apps/mcp-test. Returns the server and a connected MCP client session
// factory: connectMCP(principal, groups, scopes) dials an in-memory MCP
// session whose server-side context carries that identity, the way the
// bearer middleware attaches it for HTTP requests
func newMCPTestServer(t *testing.T) (*Server, func(t *testing.T, principal string, groups []string, scopes []string) *mcp.ClientSession) {
	t.Helper()
	server, db, ctx := newApplyTestServer(t)
	t.Cleanup(func() { db.Close() })
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	server.staticConfig.BuiltinAuth = map[string]types.BuiltinAuthEntry{
		"alice": {Password: "unused", Groups: []string{"dev"}},
		"bob":   {Password: "unused"},
	}
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	t.Cleanup(func() {
		server.stopAuditWriter()
		_ = server.auditDB.Close()
	})

	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Enabled: true,
		Grants: []types.RBACGrant{
			{Description: "alice dev", Users: []string{"builtin:alice"}, Roles: []string{"openrun-developer"},
				Targets: []string{"/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/mcp-test")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply app: %v", err)
	}
	server.apps.ResetAllAppCache()

	connect := func(t *testing.T, principal string, groups []string, scopes []string) *mcp.ClientSession {
		t.Helper()
		serverCtx := server.apiTokenRequestContext(context.Background(), principal, groups, scopes, InvokerMCP, nil)
		serverTransport, clientTransport := mcp.NewInMemoryTransports()
		serverSession, err := server.getMCPServer().Connect(serverCtx, serverTransport, nil)
		if err != nil {
			t.Fatalf("mcp server connect: %v", err)
		}
		t.Cleanup(func() { _ = serverSession.Close() })
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
		clientSession, err := client.Connect(context.Background(), clientTransport, nil)
		if err != nil {
			t.Fatalf("mcp client connect: %v", err)
		}
		t.Cleanup(func() { _ = clientSession.Close() })
		return clientSession
	}
	return server, connect
}

func callToolText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		return "<nil result>"
	}
	var parts []string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func TestMCPToolListExcludesDefaultDisabledOps(t *testing.T) {
	_, connect := newMCPTestServer(t)
	session := connect(t, "builtin:alice", []string{"dev"}, nil)

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"list_apps", "get_app", "create_app", "delete_apps", "promote_apps",
		"list_services", "list_bindings", "list_sync", "list_secrets", "config_get", "server_version"} {
		if !slices.Contains(names, want) {
			t.Fatalf("tool %s missing from tools list %v", want, names)
		}
	}
	// The MCP default-disabled operations must not appear as tools
	for _, dontWant := range []string{"stop_server", "restart_server", "secret_reveal", "config_update",
		"provider_install", "user_add"} {
		if slices.Contains(names, dontWant) {
			t.Fatalf("default-disabled op %s must not be an MCP tool", dontWant)
		}
	}

	// Annotations: read-only ops carry ReadOnlyHint, destructive ops the
	// destructive hint
	for _, tool := range tools.Tools {
		if tool.Name == "list_apps" && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Fatal("list_apps must carry ReadOnlyHint")
		}
		if tool.Name == "delete_apps" && (tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint) {
			t.Fatal("delete_apps must carry DestructiveHint")
		}
	}
}

func TestMCPRBACEnforcedPerIdentity(t *testing.T) {
	_, connect := newMCPTestServer(t)

	// alice holds openrun-developer on /apps/**: list_apps returns the app
	aliceSession := connect(t, "builtin:alice", []string{"dev"}, nil)
	result, err := aliceSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "list_apps", Arguments: map[string]any{"path_glob": "/apps/**"}})
	if err != nil {
		t.Fatalf("alice list_apps: %v", err)
	}
	if result.IsError {
		t.Fatalf("alice list_apps returned tool error: %s", callToolText(t, result))
	}
	if !strings.Contains(callToolText(t, result), "/apps/mcp-test") {
		t.Fatalf("alice must see /apps/mcp-test, got: %s", callToolText(t, result))
	}

	// bob has no grants: the app list is filtered empty
	bobSession := connect(t, "builtin:bob", nil, nil)
	result, err = bobSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "list_apps", Arguments: map[string]any{"path_glob": "/apps/**"}})
	if err != nil {
		t.Fatalf("bob list_apps: %v", err)
	}
	if strings.Contains(callToolText(t, result), "/apps/mcp-test") {
		t.Fatalf("bob must not see /apps/mcp-test, got: %s", callToolText(t, result))
	}

	// bob cannot delete: RBAC error surfaces as a tool error
	result, err = bobSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "delete_apps", Arguments: map[string]any{"path_glob": "/apps/mcp-test"}})
	if err != nil {
		t.Fatalf("bob delete_apps transport error: %v", err)
	}
	if !result.IsError {
		t.Fatal("bob delete_apps must fail RBAC")
	}
}

func TestMCPScopeCeiling(t *testing.T) {
	_, connect := newMCPTestServer(t)

	// alice with a read-only scoped credential: reads work, writes are
	// denied by the scope ceiling even though RBAC would allow them
	session := connect(t, "builtin:alice", []string{"dev"}, []string{"*:read"})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "list_apps", Arguments: map[string]any{"path_glob": "/apps/**"}})
	if err != nil || result.IsError {
		t.Fatalf("scoped list_apps must work: %v %s", err, callToolText(t, result))
	}
	if !strings.Contains(callToolText(t, result), "/apps/mcp-test") {
		t.Fatalf("scoped alice must still see the app, got: %s", callToolText(t, result))
	}

	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "delete_apps", Arguments: map[string]any{"path_glob": "/apps/mcp-test"}})
	if err != nil {
		t.Fatalf("scoped delete_apps transport error: %v", err)
	}
	if !result.IsError {
		t.Fatal("*:read scoped credential must not be able to delete apps")
	}
}

func TestMCPInvokerOpPolicy(t *testing.T) {
	server, connect := newMCPTestServer(t)

	// Build the MCP server first (tool registered), then disable the op:
	// invocation-time policy must refuse the call regardless of the cached
	// tool list the client holds
	server.getMCPServer()
	server.staticConfig.Api.MCP.Disable = []string{"list_apps"}
	session := connect(t, "builtin:alice", []string{"dev"}, nil)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "list_apps", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !result.IsError || !strings.Contains(callToolText(t, result), "disabled") {
		t.Fatalf("disabled op must fail with a disabled error, got: %s", callToolText(t, result))
	}
	server.staticConfig.Api.MCP.Disable = nil
}

// TestMCPCatalogParity enforces that every registry operation is either an
// MCP tool or an explicitly documented exclusion, so api.mcp enable works
// for every default-disabled op and the surface cannot silently drift
func TestMCPCatalogParity(t *testing.T) {
	server, _ := newMCPTestServer(t)

	// Enable every default-disabled op so its tool registers
	for op, entry := range apiRegistry {
		if entry.MCPDisabled {
			server.staticConfig.Api.MCP.Enable = append(server.staticConfig.Api.MCP.Enable, string(op))
		}
	}
	srv := server.buildMCPServer()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := srv.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer serverSession.Close() //nolint:errcheck
	client := mcp.NewClient(&mcp.Implementation{Name: "parity", Version: "0"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close() //nolint:errcheck

	tools := map[string]bool{}
	for tool, err := range clientSession.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatalf("tools iteration: %v", err)
		}
		tools[tool.Name] = true
	}

	for op, entry := range apiRegistry {
		excluded := entry.MCPExcluded != ""
		if excluded && tools[string(op)] {
			t.Fatalf("op %s is marked MCPExcluded (%s) but has a tool registered", op, entry.MCPExcluded)
		}
		if !excluded && !tools[string(op)] {
			t.Fatalf("registry op %s has no MCP tool and no MCPExcluded reason", op)
		}
		if !excluded && entry.Description == "" {
			t.Fatalf("registry op %s has an MCP tool but no Description", op)
		}
	}
}

// TestMCPToolSchemasSnapshot pins every tool's generated input schema to a
// golden file, so a renamed field or jsonschema tag shows up in review
// instead of shipping invisibly. Regenerate with OPENRUN_UPDATE_SCHEMAS=1
func TestMCPToolSchemasSnapshot(t *testing.T) {
	server, _ := newMCPTestServer(t)
	for op, entry := range apiRegistry {
		if entry.MCPDisabled {
			server.staticConfig.Api.MCP.Enable = append(server.staticConfig.Api.MCP.Enable, string(op))
		}
	}
	srv := server.buildMCPServer()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := srv.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer serverSession.Close() //nolint:errcheck
	client := mcp.NewClient(&mcp.Implementation{Name: "schemas", Version: "0"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close() //nolint:errcheck

	schemas := map[string]any{}
	for tool, err := range clientSession.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatalf("tools iteration: %v", err)
		}
		schemas[tool.Name] = tool.InputSchema
	}
	got, err := json.Marshal(schemas, jsontext.WithIndent("  "), json.Deterministic(true))
	if err != nil {
		t.Fatalf("marshal schemas: %v", err)
	}

	goldenPath := filepath.Join("testdata", "mcp_tool_schemas.json")
	if os.Getenv("OPENRUN_UPDATE_SCHEMAS") != "" {
		if err := os.WriteFile(goldenPath, got, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with OPENRUN_UPDATE_SCHEMAS=1 to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("MCP tool input schemas changed. Review the diff and regenerate with"+
			" OPENRUN_UPDATE_SCHEMAS=1 go test ./internal/server/ -run TestMCPToolSchemasSnapshot\ngot:\n%s", string(got))
	}
}

// TestMCPBindingResponsesRedactAccount is the regression test for binding
// account credential leaks: binding_create/binding_update responses must
// redact account material (revealing needs binding:reveal via
// binding_show_account), matching the REST handlers
func TestMCPBindingResponsesRedactAccount(t *testing.T) {
	server, connect := newMCPTestServer(t)

	previousBuilder, hadPrevious := bindings.GetServiceBinding("applytest")
	bindings.SetServiceBinding("applytest", func() bindings.ServiceBinding {
		return &applyTestServiceBinding{}
	})
	t.Cleanup(func() {
		if hadPrevious {
			bindings.SetServiceBinding("applytest", previousBuilder)
		} else {
			bindings.SetServiceBinding("applytest", nil)
		}
	})

	trustedCtx := system.WithTrustedOperation(context.Background())
	service := &types.Service{Name: "redactsvc", ServiceType: "applytest", Config: map[string]string{}}
	if err := server.CreateService(trustedCtx, service, false); err != nil {
		t.Fatalf("create service: %v", err)
	}

	// admin holds every permission, so any leak would be visible in the response
	session := connect(t, "admin", nil, nil)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "binding_create", Arguments: map[string]any{
			"path": "/apps/redact-test/db", "source": "applytest/redactsvc"}})
	if err != nil {
		t.Fatalf("binding_create: %v", err)
	}
	text := callToolText(t, result)
	if result.IsError {
		t.Fatalf("binding_create failed: %s", text)
	}
	// The applytest builder puts role and schema keys into the account map;
	// artifacts legitimately carry {"type":"role"} entries, so assert on the
	// account map itself
	if strings.Contains(text, `"account"`) || strings.Contains(text, `"schema"`) {
		t.Fatalf("binding_create response leaks account credentials: %s", text)
	}

	// Grants need a derived binding; create one off the base and update it
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "binding_create", Arguments: map[string]any{
			"path": "/apps/redact-test/db2", "source": "/apps/redact-test/db",
			"grants": []string{"read:t1"}}})
	if err != nil || result.IsError {
		t.Fatalf("derived binding_create: %v %s", err, callToolText(t, result))
	}
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "binding_update", Arguments: map[string]any{
			"path": "/apps/redact-test/db2", "add_grants": []string{"read:t2"}}})
	if err != nil {
		t.Fatalf("binding_update: %v", err)
	}
	text = callToolText(t, result)
	if result.IsError {
		t.Fatalf("binding_update failed: %s", text)
	}
	if strings.Contains(text, `"account"`) || strings.Contains(text, `"schema"`) {
		t.Fatalf("binding_update response leaks account credentials: %s", text)
	}

	// binding_show_account is MCP default-disabled, so the reveal tool is
	// absent from this session entirely - revealing stays an explicit,
	// separately-enabled operation
	_, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "binding_show_account", Arguments: map[string]any{"name": "/apps/redact-test/db"}})
	if err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("binding_show_account must be absent by default, got %v", err)
	}
}
