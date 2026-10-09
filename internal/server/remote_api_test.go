// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// Integration tests for the remote CLI path: a real TCP handler served over
// TLS, driven through system.HttpClient (the exact client the CLI uses),
// authenticated with API keys minted for builtin auth users, with RBAC
// deciding what each user can do.

// newRemoteApiTestServer builds the server with builtin users alice
// (openrun-developer on /apps/**), carol (openrun-user on /apps/**: app:read
// without app:read_detail) and bob (no grants), one applied app at
// /apps/remote-test, and a TLS httptest server running the real TCP router.
// mintKey creates a PAT the way the UDS CLI would (trusted context)
func newRemoteApiTestServer(t *testing.T) (*Server, *httptest.Server, func(t *testing.T, req *types.ApiKeyCreateRequest) string) {
	t.Helper()
	server, db, ctx := newApplyTestServer(t)
	t.Cleanup(func() { db.Close() })
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	// system.NewHttpClient chdirs to OPENRUN_HOME (UDS path length); restore
	// the working directory so later tests are not left in a deleted temp dir
	origWd, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("getwd: %v", wdErr)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	server.staticConfig.BuiltinAuth = map[string]types.BuiltinAuthEntry{
		"alice": {Password: "unused", Groups: []string{"dev"}},
		"bob":   {Password: "unused"},
		"carol": {Password: "unused"},
	}
	server.staticConfig.Api.Rest = types.ApiSurfaceConfig{Enable: true, Auth: []string{"admin"}}
	server.staticConfig.Api.MCP = types.ApiSurfaceConfig{Enable: true, Auth: []string{"admin"}}
	server.staticConfig.System.DefaultDomain = "127.0.0.1"
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	t.Cleanup(func() {
		server.stopAuditWriter()
		_ = server.auditDB.Close()
		_ = server.auditDBOwner.Close()
	})
	server.csrfMiddleware = http.NewCrossOriginProtection()
	server.authHandler = NewAdminBasicAuth(server.Logger, server.staticConfig)
	server.builtinAuth = NewBuiltinAuth(server.Logger, server.Config)
	server.oAuthManager = &OAuthManager{Logger: server.Logger, config: server.staticConfig}
	server.samlManager = &SAMLManager{Logger: server.Logger, config: server.staticConfig}
	formLogin, err := NewFormLoginManager(server.Logger, server.Config, nil, nil,
		server.authHandler, server.builtinAuth, false)
	if err != nil {
		t.Fatalf("form login: %v", err)
	}
	server.formLogin = formLogin

	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Grants: []types.RBACGrant{
			{Description: "alice dev", Users: []string{"builtin:alice"}, Roles: []string{"openrun-developer"},
				Targets: []string{"/apps/**"}},
			{Description: "carol user", Users: []string{"builtin:carol"}, Roles: []string{"openrun-user"},
				Targets: []string{"/apps/**"}},
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/remote-test")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all", ApplyOptions{Reload: types.AppReloadOptionNone}, nil); err != nil {
		t.Fatalf("apply app: %v", err)
	}
	server.apps.ResetAllAppCache()

	handler := NewTCPHandler(server.Logger, server.staticConfig, server)
	ts := httptest.NewTLSServer(handler.router)
	t.Cleanup(ts.Close)

	mintKey := func(t *testing.T, req *types.ApiKeyCreateRequest) string {
		t.Helper()
		resp, err := server.CreateApiKey(system.WithTrustedOperation(context.Background()), req)
		if err != nil {
			t.Fatalf("mint key for %q: %v", req.User, err)
		}
		return resp.Key
	}
	return server, ts, mintKey
}

// remoteClient builds the CLI's HTTP client against the test server
func remoteClient(ts *httptest.Server, apiKey string) *system.HttpClient {
	return system.NewHttpClient(ts.URL, apiKey, true)
}

func TestRemoteApiAuthRequired(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	// No token: 401
	var response types.AppListResponse
	err := remoteClient(ts, "").Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected unauthorized without token, got %v", err)
	}

	// Garbage token: 401
	err = remoteClient(ts, "orun_pat_dead_beef").Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected unauthorized with bad token, got %v", err)
	}

	// Valid token for alice: authenticated, RBAC-filtered list includes the app
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	if err := remoteClient(ts, aliceKey).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &response); err != nil {
		t.Fatalf("alice list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "alice apps", 1, len(response.Apps))

	// bob authenticates fine but sees nothing (no grants)
	bobKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:bob"})
	var bobResponse types.AppListResponse
	if err := remoteClient(ts, bobKey).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &bobResponse); err != nil {
		t.Fatalf("bob list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "bob apps", 0, len(bobResponse.Apps))
}

func TestRemoteApiExpiredKey(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	shortKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice", ExpiresIn: "1ms"})
	time.Sleep(10 * time.Millisecond)
	var response types.AppListResponse
	err := remoteClient(ts, shortKey).Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expired key must be unauthorized, got %v", err)
	}
}

func TestRemoteApiRequiresRBAC(t *testing.T) {
	// RBAC has no dynamic disable; the remote surfaces are excluded up
	// front when the static security.unsafe_disable_rbac flag is set (the
	// same validation runs at startup and on dynamic config updates)
	config := &types.ServerConfig{}
	config.Api.Rest = types.ApiSurfaceConfig{Enable: true, Auth: []string{"admin"}}
	config.Api.MCP.Auth = []string{"admin"}
	config.Api.ExternalUrl = "https://example.com"
	config.Https.Port = 25223
	config.Security.UnsafeDisableRBAC = true
	err := validateApiSurfaceConfig(config)
	if err == nil || !strings.Contains(err.Error(), "requires RBAC enforcement") {
		t.Fatalf("an enabled surface with unsafe_disable_rbac must be rejected, got %v", err)
	}
	config.Security.UnsafeDisableRBAC = false
	if err := validateApiSurfaceConfig(config); err != nil {
		t.Fatalf("api config with RBAC enforcement must validate, got %v", err)
	}
	// Every surface needs at least one login mechanism, enabled or not
	config.Api.MCP.Auth = nil
	err = validateApiSurfaceConfig(config)
	if err == nil || !strings.Contains(err.Error(), "api.mcp auth: at least one login mechanism") {
		t.Fatalf("an empty auth list must be rejected, got %v", err)
	}
}

func TestRemoteApiInvokerOpPolicy(t *testing.T) {
	server, ts, mintKey := newRemoteApiTestServer(t)

	server.staticConfig.Api.Rest.DisableApis = []string{"list_apps"}
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	var response types.AppListResponse
	err := remoteClient(ts, aliceKey).Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled op must be refused for rest invoker, got %v", err)
	}
	server.staticConfig.Api.Rest.DisableApis = nil
}

// Commander covers successful key management. Keep the permission denials
// that its remote CLI cases do not exercise.
func TestRemoteApiKeyManagementDenied(t *testing.T) {
	server, ts, mintKey := newRemoteApiTestServer(t)
	bob, err := server.CreateApiKey(system.WithTrustedOperation(t.Context()),
		&types.ApiKeyCreateRequest{User: "builtin:bob"})
	testutil.AssertNoError(t, err)
	alice := remoteClient(ts, mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"}))

	var list types.ApiKeyListResponse
	err = remoteClient(ts, bob.Key).Get("/_openrun/apikey", nil, &list)
	testutil.AssertEqualsInt(t, "list requires apikey:manage:self", http.StatusForbidden, requestErrorCode(t, err))

	var deleted types.ApiKeyDeleteResponse
	err = alice.Delete("/_openrun/apikey", url.Values{"id": {bob.Id}}, &deleted)
	testutil.AssertEqualsInt(t, "deleting another user's key requires admin", http.StatusForbidden, requestErrorCode(t, err))
}

func TestRemoteApiKeyAttenuation(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	// A read-only, rest-bound, expiring key for alice
	parentKey := mintKey(t, &types.ApiKeyCreateRequest{
		User: "builtin:alice", Scopes: []string{"*:read", "apikey:manage:self"},
		Resources: []string{"rest"}, ExpiresIn: "1h"})

	var created types.ApiKeyCreateResponse
	client := remoteClient(ts, parentKey)

	// Unscoped child: denied (parent is scoped)
	if err := client.Post("/_openrun/apikey", nil, &types.ApiKeyCreateRequest{}, &created); err == nil {
		t.Fatal("scoped parent must not mint an unscoped key")
	}

	// Broader scope: denied
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"*"}}, &created); err == nil {
		t.Fatal("child scope * must exceed the parent's *:read")
	}

	// Literal-only permission not held by the parent: denied
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"secret:reveal"}}, &created); err == nil {
		t.Fatal("child must not gain secret:reveal from a parent without it")
	}

	// Broader resource: denied
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"app:read"}, Resources: []string{"mcp"}}, &created); err == nil {
		t.Fatal("child resource mcp must exceed the rest-bound parent")
	}

	// Outliving the parent: an explicit never is denied; a longer TTL is
	// clamped to the parent's expiry
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"app:read"}, ExpiresIn: "never"}, &created); err == nil {
		t.Fatal("child must not outlive the parent (never)")
	}
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"app:read"}, ExpiresIn: "48h"}, &created); err != nil {
		t.Fatalf("longer ttl child must be clamped, not rejected: %v", err)
	}
	if created.ExpiresAt == nil || time.Until(*created.ExpiresAt) > time.Hour+time.Minute {
		t.Fatalf("child expiry must be clamped to the parent's 1h, got %v", created.ExpiresAt)
	}

	// A properly attenuated child works: narrower scope, same resource,
	// shorter expiry
	if err := client.Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Scopes: []string{"app:read"}, ExpiresIn: "30m"}, &created); err != nil {
		t.Fatalf("attenuated child must be allowed: %v", err)
	}

	// UDS (no credential) minting stays unrestricted
	unscoped := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice", ExpiresIn: "never"})
	if unscoped == "" {
		t.Fatal("trusted caller must mint freely")
	}
}
