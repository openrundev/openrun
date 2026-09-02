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
// (openrun-developer on /apps/**) and bob (no grants), one applied app at
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
		},
	}); err != nil {
		t.Fatalf("rbac config update: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/remote-test")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
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

func TestRemoteApiRBACWrites(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	// bob cannot delete
	bobKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:bob"})
	var deleteResponse types.AppDeleteResponse
	err := remoteClient(ts, bobKey).Delete("/_openrun/app",
		url.Values{"appPathGlob": {"/apps/remote-test"}, "dryRun": {"true"}}, &deleteResponse)
	if err == nil {
		t.Fatal("bob delete must fail RBAC")
	}

	// alice (openrun-developer includes app:manage -> app:delete) can, dry run
	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	if err := remoteClient(ts, aliceKey).Delete("/_openrun/app",
		url.Values{"appPathGlob": {"/apps/remote-test"}, "dryRun": {"true"}}, &deleteResponse); err != nil {
		t.Fatalf("alice dry-run delete: %v", err)
	}
}

func TestRemoteApiScopeCeiling(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	// Read-only scoped key for alice: reads work, writes are denied by the
	// scope ceiling even though alice's grants allow them
	scopedKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice", Scopes: []string{"*:read"}})
	var listResponse types.AppListResponse
	if err := remoteClient(ts, scopedKey).Get("/_openrun/apps",
		url.Values{"appPathGlob": {"/apps/**"}}, &listResponse); err != nil {
		t.Fatalf("scoped list apps: %v", err)
	}
	testutil.AssertEqualsInt(t, "scoped apps", 1, len(listResponse.Apps))

	var deleteResponse types.AppDeleteResponse
	err := remoteClient(ts, scopedKey).Delete("/_openrun/app",
		url.Values{"appPathGlob": {"/apps/remote-test"}, "dryRun": {"true"}}, &deleteResponse)
	if err == nil {
		t.Fatal("*:read scoped key must not delete")
	}
}

func TestRemoteApiResourceBinding(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	// A key bound to the mcp surface is rejected at the REST surface
	mcpKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice", Resources: []string{"mcp"}})
	var response types.AppListResponse
	err := remoteClient(ts, mcpKey).Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("mcp-bound key must be unauthorized at the rest surface, got %v", err)
	}
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

func TestRemoteApiKeyManagement(t *testing.T) {
	_, ts, mintKey := newRemoteApiTestServer(t)

	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	bobKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:bob"})
	adminKey := mintKey(t, &types.ApiKeyCreateRequest{User: "admin"})

	// alice (openrun-developer carries apikey:manage:self) creates her own
	// key over the remote CLI path
	var createResponse types.ApiKeyCreateResponse
	if err := remoteClient(ts, aliceKey).Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{Description: "alice laptop"}, &createResponse); err != nil {
		t.Fatalf("alice create own key: %v", err)
	}
	testutil.AssertEqualsString(t, "key user", "builtin:alice", createResponse.User)
	if !strings.HasPrefix(createResponse.Key, "orun_pat_") {
		t.Fatalf("key format: %q", createResponse.Key)
	}
	if createResponse.ExpiresAt == nil {
		t.Fatal("default key must carry the 90d expiry")
	}

	// alice cannot create a key for bob (admin only)
	err := remoteClient(ts, aliceKey).Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{User: "builtin:bob"}, &createResponse)
	if err == nil {
		t.Fatal("alice creating a key for bob must require admin")
	}

	// admin can, and the audit trail records it as create_apikey_other
	if err := remoteClient(ts, adminKey).Post("/_openrun/apikey", nil,
		&types.ApiKeyCreateRequest{User: "builtin:bob", Description: "for bob"}, &createResponse); err != nil {
		t.Fatalf("admin create key for bob: %v", err)
	}
	testutil.AssertEqualsString(t, "key user", "builtin:bob", createResponse.User)

	// bob has no apikey:manage:self grant: he cannot list keys
	var listResponse types.ApiKeyListResponse
	if err := remoteClient(ts, bobKey).Get("/_openrun/apikey", nil, &listResponse); err == nil {
		t.Fatal("bob without apikey:manage:self must not list keys")
	}

	// alice lists only her own keys
	if err := remoteClient(ts, aliceKey).Get("/_openrun/apikey", nil, &listResponse); err != nil {
		t.Fatalf("alice list keys: %v", err)
	}
	for _, key := range listResponse.Keys {
		testutil.AssertEqualsString(t, "listed key user", "builtin:alice", key.User)
	}
	if len(listResponse.Keys) != 2 {
		t.Fatalf("alice keys: want 2 got %d", len(listResponse.Keys))
	}

	// --all requires admin
	if err := remoteClient(ts, aliceKey).Get("/_openrun/apikey",
		url.Values{"all": {"true"}}, &listResponse); err == nil {
		t.Fatal("alice list --all must require admin")
	}
	if err := remoteClient(ts, adminKey).Get("/_openrun/apikey",
		url.Values{"all": {"true"}}, &listResponse); err != nil {
		t.Fatalf("admin list --all: %v", err)
	}
	if len(listResponse.Keys) < 4 {
		t.Fatalf("admin list --all: want >=4 keys got %d", len(listResponse.Keys))
	}

	// alice deletes her own created key; deleting bob's needs admin
	var deleteResponse types.ApiKeyDeleteResponse
	var aliceOwnedId, bobOwnedId string
	for _, key := range listResponse.Keys {
		if key.User == "builtin:alice" && key.Description == "alice laptop" {
			aliceOwnedId = key.Id
		}
		if key.User == "builtin:bob" && key.Description == "for bob" {
			bobOwnedId = key.Id
		}
	}
	if err := remoteClient(ts, aliceKey).Delete("/_openrun/apikey",
		url.Values{"id": {aliceOwnedId}}, &deleteResponse); err != nil {
		t.Fatalf("alice delete own key: %v", err)
	}
	if err := remoteClient(ts, aliceKey).Delete("/_openrun/apikey",
		url.Values{"id": {bobOwnedId}}, &deleteResponse); err == nil {
		t.Fatal("alice deleting bob's key must require admin")
	}
	if err := remoteClient(ts, adminKey).Delete("/_openrun/apikey",
		url.Values{"id": {bobOwnedId}}, &deleteResponse); err != nil {
		t.Fatalf("admin delete bob's key: %v", err)
	}
}

func TestRemoteApiPlaintextRefused(t *testing.T) {
	server, _, mintKey := newRemoteApiTestServer(t)

	// A plaintext listener with the same router: the remote surface does not
	// exist there (404), even with a valid credential
	handler := NewTCPHandler(server.Logger, server.staticConfig, server)
	plainTs := httptest.NewServer(handler.router)
	defer plainTs.Close()

	aliceKey := mintKey(t, &types.ApiKeyCreateRequest{User: "builtin:alice"})
	var response types.AppListResponse
	err := system.NewHttpClient(plainTs.URL, aliceKey, true).Get("/_openrun/apps", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("plaintext remote api must 404, got %v", err)
	}

	// The health endpoint stays served over plaintext for LB probes
	healthResp, err := http.Get(plainTs.URL + "/_openrun/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer healthResp.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "health status", http.StatusOK, healthResp.StatusCode)
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
