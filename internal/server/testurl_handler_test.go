// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestResolveAppAuth(t *testing.T) {
	tests := []struct {
		name        string
		auth        types.AppAuthnType
		defaultAuth string
		wantCore    string
	}{
		{"none", "none", "none", "none"},
		{"system", "system", "none", "system"},
		{"rbac prefix stripped", "rbac:none", "none", "none"},
		{"default resolves", "default", "none", "none"},
		{"empty resolves", "", "none", "none"},
		{"default resolves rbac", "default", "rbac:none", "none"},
		{"rbac default resolves plain", "rbac:default", "none", "none"},
		{"modifier kept", "none+forward_abc", "none", "none+forward_abc"},
		{"default with modifier resolves", "default+forward_abc", "system", "system"},
		{"no default falls back to system", "default", "", "system"},
		{"oauth passthrough", "github", "none", "github"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &types.ServerConfig{}
			config.Security.AppDefaultAuthType = tt.defaultAuth
			core := resolveAppAuth(tt.auth, config)
			testutil.AssertEqualsString(t, "core auth", tt.wantCore, core)
		})
	}
}

func TestParseTestUrlDirectives(t *testing.T) {
	// No directive segments
	parsed, err := parseTestUrlDirectives("/abc", "/abc/page")
	testutil.AssertNoError(t, err)
	if parsed != nil {
		t.Fatalf("want nil result, got %+v", parsed)
	}

	// Single perm directive with a page path
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:read,app:write/page")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.perms, []string{"app:read", "app:write"}) {
		t.Fatalf("perms: got %v", parsed.perms)
	}
	testutil.AssertEqualsString(t, "extended prefix", "/abc/_cl_perm=app:read,app:write", parsed.extendedPrefix)
	testutil.AssertEqualsString(t, "stripped", "/abc/page", parsed.strippedPath)

	// Multiple perm directives merge with dedupe
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:read/_cl_perm=binding:create,app:read/deep/page")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.perms, []string{"app:read", "binding:create"}) {
		t.Fatalf("merged perms: got %v", parsed.perms)
	}
	testutil.AssertEqualsString(t, "extended prefix", "/abc/_cl_perm=app:read/_cl_perm=binding:create,app:read", parsed.extendedPrefix)
	testutil.AssertEqualsString(t, "stripped", "/abc/deep/page", parsed.strippedPath)

	// Role directive, alone and mixed with perm
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_role=viewer,editor/page")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.roles, []string{"viewer", "editor"}) {
		t.Fatalf("roles: got %v", parsed.roles)
	}
	if parsed.perms != nil {
		t.Fatalf("perms should be nil, got %v", parsed.perms)
	}
	testutil.AssertEqualsString(t, "extended prefix", "/abc/_cl_role=viewer,editor", parsed.extendedPrefix)

	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_role=viewer/_cl_perm=app:read/_cl_role=editor,viewer/page")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.roles, []string{"viewer", "editor"}) {
		t.Fatalf("merged roles: got %v", parsed.roles)
	}
	if !slices.Equal(parsed.perms, []string{"app:read"}) {
		t.Fatalf("perms: got %v", parsed.perms)
	}
	testutil.AssertEqualsString(t, "stripped", "/abc/page", parsed.strippedPath)

	// Directives-only URL strips to the bare app path
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:read")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped", "/abc", parsed.strippedPath)
	testutil.AssertEqualsString(t, "extended prefix", "/abc/_cl_perm=app:read", parsed.extendedPrefix)

	// Root app
	parsed, err = parseTestUrlDirectives("/", "/_cl_perm=app:read/page")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped", "/page", parsed.strippedPath)
	testutil.AssertEqualsString(t, "extended prefix", "/_cl_perm=app:read", parsed.extendedPrefix)

	// Root app, directives only
	parsed, err = parseTestUrlDirectives("/", "/_cl_perm=app:read")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped", "/", parsed.strippedPath)

	// Directives after the first non-directive segment are left alone
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:read/page/_cl_perm=extra")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.perms, []string{"app:read"}) {
		t.Fatalf("perms: got %v", parsed.perms)
	}
	testutil.AssertEqualsString(t, "stripped", "/abc/page/_cl_perm=extra", parsed.strippedPath)

	// A _cl_ suffix inside a segment (stage/preview style) is not a directive
	parsed, err = parseTestUrlDirectives("/abc", "/abc/page_cl_perm=x")
	testutil.AssertNoError(t, err)
	if parsed != nil {
		t.Fatalf("want nil result for suffixed segment, got %+v", parsed)
	}

	// Unknown directive key fails closed
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_user=someone/page")
	testutil.AssertErrorContains(t, err, "unknown _cl_ directive key \"user\"")

	// _cl_ segment without = fails closed
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_stage")
	testutil.AssertErrorContains(t, err, "unknown _cl_ directive")

	// Empty value
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=")
	testutil.AssertErrorContains(t, err, "cannot be empty")
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_role=")
	testutil.AssertErrorContains(t, err, "_cl_role directive value cannot be empty")

	// Empty entry in list
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:read,")
	testutil.AssertErrorContains(t, err, "empty entry")

	// Unsupported characters (space arrives decoded from %20)
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app: read")
	testutil.AssertErrorContains(t, err, "unsupported character")
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_role=some role")
	testutil.AssertErrorContains(t, err, "unsupported character")

	// Percent (a literal %25 in the URL decodes to %)
	_, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app%read")
	testutil.AssertErrorContains(t, err, "unsupported character")

	// Glob perms are allowed
	parsed, err = parseTestUrlDirectives("/abc", "/abc/_cl_perm=app:*/page")
	testutil.AssertNoError(t, err)
	if !slices.Equal(parsed.perms, []string{"app:*"}) {
		t.Fatalf("glob perms: got %v", parsed.perms)
	}
}

// newTestUrlTestServer builds a minimal server with the testurl flag and RBAC
// config set as specified
func newTestUrlTestServer(t *testing.T, enableTestUrl, rbacEnabled bool) *Handler {
	t.Helper()
	return newTestUrlTestServerConfig(t, enableTestUrl, &types.RBACConfig{Enabled: rbacEnabled})
}

func newTestUrlTestServerConfig(t *testing.T, enableTestUrl bool, rbacConfig *types.RBACConfig) *Handler {
	t.Helper()
	logger := testutil.TestLogger()
	config := &types.ServerConfig{}
	config.Security.UnsafeEnableTestUrlRbac = enableTestUrl
	config.Security.AppDefaultAuthType = "none"

	rbacManager, err := rbac.NewRBACHandler(logger, rbacConfig, config)
	testutil.AssertNoError(t, err)

	server := &Server{
		Logger:       logger,
		staticConfig: config,
		rbacManager:  rbacManager,
	}
	return &Handler{Logger: logger, server: server}
}

func devAppInfo(auth types.AppAuthnType, isDev bool) types.AppInfo {
	return types.AppInfo{
		AppPathDomain: types.AppPathDomain{Domain: "example.com", Path: "/abc"},
		Id:            "app_dev_test",
		IsDev:         isDev,
		Auth:          auth,
	}
}

func TestApplyTestUrlDirectives(t *testing.T) {
	directiveURL := "http://example.com/abc/_cl_perm=app:read,binding:create/page"

	// Feature enabled, dev app with none auth: directives parsed and stripped
	h := newTestUrlTestServer(t, true, false)
	req := httptest.NewRequest("GET", directiveURL, nil)
	newReq, err := h.applyTestUrlDirectives(devAppInfo("none", true), req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/abc/page", newReq.URL.Path)
	dirs := rbac.GetUrlDirectives(newReq.Context())
	if dirs == nil {
		t.Fatal("directives not set in context")
	}
	if !slices.Equal(dirs.Perms, []string{"app:read", "binding:create"}) {
		t.Fatalf("perms: got %v", dirs.Perms)
	}
	testutil.AssertEqualsString(t, "extended prefix", "/abc/_cl_perm=app:read,binding:create", dirs.ExtendedPrefix)

	// Malformed directive is a 400 level error
	req = httptest.NewRequest("GET", "http://example.com/abc/_cl_bogus/page", nil)
	_, err = h.applyTestUrlDirectives(devAppInfo("none", true), req)
	testutil.AssertErrorContains(t, err, "unknown _cl_ directive")

	// passthrough asserts the request is returned unchanged, no error
	passthrough := func(t *testing.T, h *Handler, appInfo types.AppInfo, url string) {
		t.Helper()
		req := httptest.NewRequest("GET", url, nil)
		newReq, err := h.applyTestUrlDirectives(appInfo, req)
		testutil.AssertNoError(t, err)
		if newReq != req {
			t.Fatal("request should be unchanged")
		}
		if rbac.GetUrlDirectives(newReq.Context()) != nil {
			t.Fatal("directives should not be set in context")
		}
	}

	// Flag disabled: byte identical passthrough, even for a dev none auth app
	passthrough(t, newTestUrlTestServer(t, false, false), devAppInfo("none", true), directiveURL)

	// Prod app: passthrough
	passthrough(t, h, devAppInfo("none", false), directiveURL)

	// system auth (admin user): passthrough, nothing changes for system auth
	passthrough(t, h, devAppInfo("system", true), directiveURL)

	// oauth style auth: passthrough
	passthrough(t, h, devAppInfo("github", true), directiveURL)

	// RBAC config enabled: RBAC applies to every app, real enforcement is
	// active and simulation is off, passthrough (with or without the legacy
	// rbac: auth prefix, which has no effect)
	passthrough(t, newTestUrlTestServer(t, true, true), devAppInfo("none", true), directiveURL)
	passthrough(t, newTestUrlTestServer(t, true, true), devAppInfo("rbac:none", true), directiveURL)

	// rbac:none app with RBAC config disabled: RBAC inactive, directives honored
	req = httptest.NewRequest("GET", directiveURL, nil)
	newReq, err = h.applyTestUrlDirectives(devAppInfo("rbac:none", true), req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/abc/page", newReq.URL.Path)

	// No directive segments: fast passthrough
	passthrough(t, h, devAppInfo("none", true), "http://example.com/abc/page")

	// default auth resolving to none is honored
	req = httptest.NewRequest("GET", directiveURL, nil)
	newReq, err = h.applyTestUrlDirectives(devAppInfo("default", true), req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/abc/page", newReq.URL.Path)

	// Root app
	req = httptest.NewRequest("GET", "http://example.com/_cl_perm=app:read", nil)
	rootApp := devAppInfo("none", true)
	rootApp.Path = "/"
	newReq, err = h.applyTestUrlDirectives(rootApp, req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/", newReq.URL.Path)
	testutil.AssertEqualsString(t, "extended prefix", "/_cl_perm=app:read",
		rbac.GetUrlDirectives(newReq.Context()).ExtendedPrefix)

	// Escaped path after the directives is preserved consistently
	req = httptest.NewRequest("GET", "http://example.com/abc/_cl_perm=app:read/pa%20ge", nil)
	newReq, err = h.applyTestUrlDirectives(devAppInfo("none", true), req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/abc/pa ge", newReq.URL.Path)
	testutil.AssertEqualsString(t, "escaped path", "/abc/pa%20ge", newReq.URL.EscapedPath())
}

func TestApplyTestUrlDirectivesRoles(t *testing.T) {
	// Roles resolve against the configured roles even with RBAC disabled
	rbacConfig := &types.RBACConfig{
		Enabled: false,
		Roles: map[string][]types.RBACPermission{
			"viewer": {"app:read", "custom:report_view"},
			"editor": {"role:viewer", "app:update"},
		},
	}
	h := newTestUrlTestServerConfig(t, true, rbacConfig)

	req := httptest.NewRequest("GET", "http://example.com/abc/_cl_role=editor/page", nil)
	newReq, err := h.applyTestUrlDirectives(devAppInfo("none", true), req)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "stripped path", "/abc/page", newReq.URL.Path)
	dirs := rbac.GetUrlDirectives(newReq.Context())
	if dirs == nil || !dirs.HasPerms() {
		t.Fatal("directives with perms expected")
	}
	// The role's builtin perms match, including hierarchy (editor -> viewer)
	if !dirs.MatchesPerm(types.PermissionRead) || !dirs.MatchesPerm(types.PermissionUpdate) {
		t.Error("role perms should match")
	}
	if dirs.MatchesPerm(types.PermissionDelete) {
		t.Error("app:delete should not match")
	}
	// The app visible perms list carries the custom perms the role confers
	if !slices.Contains(dirs.Perms, "report_view") {
		t.Errorf("derived custom perms expected, got %v", dirs.Perms)
	}

	// Unknown role fails closed with a 400 level error
	req = httptest.NewRequest("GET", "http://example.com/abc/_cl_role=bogus/page", nil)
	_, err = h.applyTestUrlDirectives(devAppInfo("none", true), req)
	testutil.AssertErrorContains(t, err, "unknown role \"bogus\"")
}
