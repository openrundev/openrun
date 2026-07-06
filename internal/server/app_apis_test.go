// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appcore "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	saml2 "github.com/russellhaering/gosaml2"
)

func newAuthRedirectTestServer(defaultDomain string, fallbackUnknownDomains bool) *Server {
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		System: types.SystemConfig{
			DefaultDomain:          defaultDomain,
			FallbackUnknownDomains: fallbackUnknownDomains,
		},
	}
	return &Server{
		Logger:      logger,
		config:      config,
		authHandler: NewAdminBasicAuth(logger, config),
		oAuthManager: &OAuthManager{
			Logger:          logger,
			config:          config,
			providerConfigs: map[string]*types.AuthConfig{},
		},
		samlManager: &SAMLManager{
			Logger:    logger,
			config:    config,
			providers: map[string]*saml2.SAMLServiceProvider{},
		},
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
	}
}

func newAuthRedirectTestApp(authType types.AppAuthnType) *appcore.App {
	return &appcore.App{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		AppEntry: &types.AppEntry{
			Path: "/myapp",
			Metadata: types.AppMetadata{
				AuthnType: authType,
			},
		},
	}
}

func TestMainAppPathDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		self          types.AppPathDomain
		mainApp       types.AppId
		linkedAppPath string
		want          types.AppPathDomain
	}{
		{
			name: "prod app returns self",
			self: types.AppPathDomain{Path: "/app"},
			want: types.AppPathDomain{Path: "/app"},
		},
		{
			name:          "stage path mode resolves to main",
			self:          types.AppPathDomain{Path: "/app" + types.STAGE_SUFFIX},
			mainApp:       types.AppId("app_prd_1"),
			linkedAppPath: "/app",
			want:          types.AppPathDomain{Path: "/app"},
		},
		{
			name:          "stage domain mode resolves to main domain",
			self:          types.AppPathDomain{Domain: "stage.app.example.com", Path: "/"},
			mainApp:       types.AppId("app_prd_1"),
			linkedAppPath: "app.example.com:/",
			want:          types.AppPathDomain{Domain: "app.example.com", Path: "/"},
		},
		{
			name:          "preview resolves to base",
			self:          types.AppPathDomain{Path: "/app" + types.PREVIEW_SUFFIX + "_abc"},
			mainApp:       types.AppId("app_pre_1"),
			linkedAppPath: "/app",
			want:          types.AppPathDomain{Path: "/app"},
		},
		{
			name:    "legacy fallback trims stage suffix when linked path missing",
			self:    types.AppPathDomain{Path: "/app" + types.STAGE_SUFFIX},
			mainApp: types.AppId("app_stg_1"),
			want:    types.AppPathDomain{Path: "/app"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mainAppPathDomain(tc.self, tc.mainApp, tc.linkedAppPath)
			if got != tc.want {
				t.Fatalf("mainAppPathDomain = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestStageAppPathDomain(t *testing.T) {
	t.Parallel()

	server := &Server{
		config: &types.ServerConfig{
			System: types.SystemConfig{
				DefaultDomain: "apps.example.com",
			},
		},
	}

	tests := []struct {
		name    string
		prod    types.AppPathDomain
		stageAt string
		want    types.AppPathDomain
	}{
		{
			name: "default mode is domain",
			prod: types.AppPathDomain{Domain: "app.apps.example.com", Path: "/tools/app"},
			want: types.AppPathDomain{Domain: "stage.app.apps.example.com", Path: "/tools/app"},
		},
		{
			name:    "path mode",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/"},
			stageAt: "path",
			want:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/_cl_stage"},
		},
		{
			name:    "domain mode subdomain",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/"},
			stageAt: "domain",
			want:    types.AppPathDomain{Domain: "stage.app.apps.example.com", Path: "/"},
		},
		{
			name:    "domain mode default domain",
			prod:    types.AppPathDomain{Path: "/"},
			stageAt: "domain",
			want:    types.AppPathDomain{Domain: "stage.apps.example.com", Path: "/"},
		},
		{
			name:    "auto is treated as explicit domain",
			prod:    types.AppPathDomain{Path: "/tools/app"},
			stageAt: "auto",
			want:    types.AppPathDomain{Domain: "auto", Path: "/tools/app"},
		},
		{
			name:    "explicit domain",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/tools/app"},
			stageAt: "stage.example.net",
			want:    types.AppPathDomain{Domain: "stage.example.net", Path: "/tools/app"},
		},
		{
			name:    "explicit relative domain",
			prod:    types.AppPathDomain{Path: "/"},
			stageAt: "stage.",
			want:    types.AppPathDomain{Domain: "stage.apps.example.com", Path: "/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := server.stageAppPathDomain(tc.prod, tc.stageAt)
			if err != nil {
				t.Fatalf("stageAppPathDomain returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("stageAppPathDomain = %s, want %s", got, tc.want)
			}
		})
	}
}

func newAppAPIMetadataTestServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
	ctx := context.Background()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
		System: types.SystemConfig{
			DefaultDomain:      "localhost",
			DefaultStageDomain: "stage",
			StageAt:            "domain",
		},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	secretManager, err := system.NewSecretManager(ctx, map[string]types.SecretConfig{"env": types.SecretConfig{}}, "env", config)
	if err != nil {
		t.Fatalf("new secret manager: %v", err)
	}
	server := &Server{
		Logger:         logger,
		config:         config,
		db:             db,
		notifyClose:    make(chan types.AppPathDomain),
		secretsManager: secretManager,
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
	}
	server.apps = NewAppStore(logger, server)
	return server, db, ctx
}

func TestStaticDiskSpecServesFromDiskWithoutPersistingSourceFiles(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()

	sourceDir := t.TempDir()
	indexPath := filepath.Join(sourceDir, "index.html")
	if err := os.WriteFile(indexPath, []byte("version one"), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "other.txt"), []byte("other file"), 0o600); err != nil {
		t.Fatalf("write other: %v", err)
	}

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	_, err = server.CreateAppTx(ctx, tx, "/diskstatic", true, false, &types.CreateAppRequest{
		SourceUrl: sourceDir,
		Spec:      types.StaticDiskSpec,
		ParamValues: map[string]string{
			"index": "index.html",
		},
		StageAt: "path",
	}, nil, server.newBindingAccountManager(false))
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("create static disk app: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	prod, err := db.GetAppEntry(ctx, types.AppPathDomain{Path: "/diskstatic"})
	if err != nil {
		t.Fatalf("get prod app: %v", err)
	}
	stage, err := db.GetAppEntry(ctx, types.AppPathDomain{Path: "/diskstatic" + types.STAGE_SUFFIX})
	if err != nil {
		t.Fatalf("get stage app: %v", err)
	}

	tx, err = db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin query transaction: %v", err)
	}
	for _, entry := range []*types.AppEntry{prod, stage} {
		var fileCount int
		err = tx.QueryRowContext(ctx, `select count(*) from app_files where appid = ?`, entry.Id).Scan(&fileCount)
		if err != nil {
			t.Fatalf("query app files for %s: %v", entry.Id, err)
		}
		if fileCount != 0 {
			t.Fatalf("app_files count for %s = %d, want 0", entry.Id, fileCount)
		}

		var versionCount int
		err = tx.QueryRowContext(ctx, `select count(*) from app_versions where appid = ?`, entry.Id).Scan(&versionCount)
		if err != nil {
			t.Fatalf("query app versions for %s: %v", entry.Id, err)
		}
		if versionCount == 0 {
			t.Fatalf("app_versions count for %s = 0, want metadata version", entry.Id)
		}
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback query transaction: %v", err)
	}

	application, err := server.setupApp(ctx, prod, types.Transaction{})
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}
	if err := application.Initialize(ctx, types.DryRunFalse); err != nil {
		t.Fatalf("initialize app: %v", err)
	}
	defer application.Close() //nolint:errcheck

	req := httptest.NewRequest(http.MethodGet, "/diskstatic", nil)
	rec := httptest.NewRecorder()
	application.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "version one" {
		t.Fatalf("body = %q, want disk content", got)
	}

	if err := os.WriteFile(indexPath, []byte("version two"), 0o600); err != nil {
		t.Fatalf("rewrite index: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/diskstatic", nil)
	rec = httptest.NewRecorder()
	application.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status after rewrite = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "version two" {
		t.Fatalf("body after rewrite = %q, want updated disk content", got)
	}
}

func TestCreateAppRejectsStageDomainRouteOverlap(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	existing := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_PROD + "stagechild",
		Domain:    "stage.example.com",
		Path:      "/foo/bar",
		SourceUrl: t.TempDir(),
	}
	if err := db.CreateApp(ctx, tx, existing); err != nil {
		t.Fatalf("create existing app: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit existing app: %v", err)
	}

	_, err = server.CreateAppTx(ctx, types.Transaction{}, "example.com:/foo", false, false, &types.CreateAppRequest{
		SourceUrl: t.TempDir(),
	}, nil, server.newBindingAccountManager(false))
	if err == nil {
		t.Fatal("expected stage route overlap error")
	}
	if !strings.Contains(err.Error(), "stage app overlaps with existing app at stage.example.com:/foo/bar") {
		t.Fatalf("error = %q, want stage overlap", err.Error())
	}
	if _, err := db.GetAppEntry(ctx, types.AppPathDomain{Domain: "example.com", Path: "/foo"}); !errors.Is(err, metadata.ErrAppNotFound) {
		t.Fatalf("prod app lookup error = %v, want ErrAppNotFound", err)
	}
}

func TestGetStageAppFallsBackToLegacyStageSuffix(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	prod := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_PROD + "legacy",
		Path:      "/legacy",
		SourceUrl: t.TempDir(),
	}
	stage := &types.AppEntry{
		Id:            types.ID_PREFIX_APP_STAGE + "legacy",
		Path:          "/legacy" + types.STAGE_SUFFIX,
		MainApp:       prod.Id,
		LinkedAppPath: prod.AppPathDomain().String(),
		SourceUrl:     prod.SourceUrl,
	}
	if err := db.CreateApp(ctx, tx, prod); err != nil {
		t.Fatalf("create prod app: %v", err)
	}
	if err := db.CreateApp(ctx, tx, stage); err != nil {
		t.Fatalf("create stage app: %v", err)
	}
	got, err := server.getStageApp(ctx, tx, prod)
	if err != nil {
		t.Fatalf("getStageApp returned error: %v", err)
	}
	if got.Id != stage.Id {
		t.Fatalf("stage app id = %q, want %q", got.Id, stage.Id)
	}
}

func TestValidateAppAuthnTypeChecksForwardModifier(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	server.config.Forward = map[string]types.ForwardConfig{
		"authz": {AuthUrl: "http://auth.example.com/check"},
	}
	server.oAuthManager.providerConfigs["github"] = &types.AuthConfig{}

	if err := server.validateAppAuthnType("github+forward_authz"); err != nil {
		t.Fatalf("validate auth with forward modifier: %v", err)
	}
	if err := server.validateAppAuthnType("rbac:github+forward_authz"); err != nil {
		t.Fatalf("validate rbac auth with forward modifier: %v", err)
	}
	if err := server.validateAppAuthnType("github+forward_missing"); err == nil {
		t.Fatal("expected missing forward config error")
	}
	if err := server.validateAppAuthnType("github+bad_authz"); err == nil {
		t.Fatal("expected invalid auth modifier error")
	}
}

func TestUpdateAppMetadataConfigValidatesForwardModifier(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	server.config.Forward = map[string]types.ForwardConfig{
		"authz": {AuthUrl: "http://auth.example.com/check"},
	}
	server.oAuthManager.providerConfigs["github"] = &types.AuthConfig{}
	appEntry := &types.AppEntry{}

	err := server.updateAppMetadataConfig(context.Background(), types.Transaction{}, appEntry, types.AppMetadataAuthnType, []string{"github+forward_missing"}, false, nil)
	if err == nil {
		t.Fatal("expected missing forward config error")
	}

	err = server.updateAppMetadataConfig(context.Background(), types.Transaction{}, appEntry, types.AppMetadataAuthnType, []string{"github+forward_authz"}, false, nil)
	if err != nil {
		t.Fatalf("update auth metadata: %v", err)
	}
	if appEntry.Metadata.AuthnType != "github+forward_authz" {
		t.Fatalf("auth = %q, want %q", appEntry.Metadata.AuthnType, "github+forward_authz")
	}
}

func TestUpdateAppMetadataConfigBindingPerms(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	appEntry := &types.AppEntry{}

	err := server.updateAppMetadataConfig(context.Background(), types.Transaction{}, appEntry, types.AppMetadataBindingPerms, []string{"postgres/custom", "mysql"}, false, nil)
	if err != nil {
		t.Fatalf("update binding perms metadata: %v", err)
	}

	want := []string{"postgres/custom", "mysql"}
	if strings.Join(appEntry.Metadata.BindingSourcePerms, ",") != strings.Join(want, ",") {
		t.Fatalf("binding source perms = %v, want %v", appEntry.Metadata.BindingSourcePerms, want)
	}
}

func TestGetAppsDoesNotResolveBindingServices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	defer db.Close()

	server := &Server{
		Logger: logger,
		config: config,
		db:     db,
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
	}

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	binding := &types.Binding{
		Id:          types.ID_PREFIX_BINDING + "stale",
		Path:        "/stale",
		Source:      "postgres/deleted",
		ServiceType: "postgres",
		ServiceName: "deleted",
	}
	if err := db.CreateBinding(ctx, tx, binding); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	prod := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_PROD + "stale",
		Path:      "/bound",
		SourceUrl: t.TempDir(),
		Metadata: types.AppMetadata{
			Name:     "Bound",
			Bindings: []string{binding.Path},
			VersionMetadata: types.VersionMetadata{
				Version: 1,
			},
		},
	}
	stage := &types.AppEntry{
		Id:        types.ID_PREFIX_APP_STAGE + "stale",
		Path:      "/bound" + types.STAGE_SUFFIX,
		MainApp:   prod.Id,
		SourceUrl: prod.SourceUrl,
		Metadata: types.AppMetadata{
			Name:     "Bound stage",
			Bindings: []string{binding.Path},
			VersionMetadata: types.VersionMetadata{
				Version: 1,
			},
		},
	}
	prod.LinkedAppPath = stage.AppPathDomain().String()
	stage.LinkedAppPath = prod.AppPathDomain().String()
	if err := db.CreateApp(ctx, tx, prod); err != nil {
		t.Fatalf("create prod app: %v", err)
	}
	if err := db.CreateApp(ctx, tx, stage); err != nil {
		t.Fatalf("create stage app: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	apps, err := server.GetApps(ctx, "", false)
	if err != nil {
		t.Fatalf("get apps: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("apps length = %d, want 1", len(apps))
	}
	if apps[0].Path != prod.Path {
		t.Fatalf("app path = %q, want %q", apps[0].Path, prod.Path)
	}
	if got := strings.Join(apps[0].Metadata.Bindings, ","); got != binding.Path {
		t.Fatalf("app bindings = %q, want %q", got, binding.Path)
	}
}

func TestAuthorizeListStripsForwardModifier(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	server.config.Security.AppDefaultAuthType = "github+forward_authz"
	server.config.Forward = map[string]types.ForwardConfig{
		"authz": {AuthUrl: "http://auth.example.com/check"},
	}

	tests := map[string]types.AppAuthnType{
		"explicit auth modifier": "github+forward_authz",
		"default auth modifier":  types.AppAuthnDefault,
	}

	for name, authType := range tests {
		t.Run(name, func(t *testing.T) {
			appInfo := &types.AppInfo{
				AppPathDomain: types.AppPathDomain{Path: "/myapp"},
				Auth:          authType,
			}
			authorized, err := server.AuthorizeList(context.Background(), "github:user-123", appInfo, nil)
			if err != nil {
				t.Fatalf("authorize list: %v", err)
			}
			if !authorized {
				t.Fatal("expected list authorization")
			}
		})
	}
}

func TestResolvesDefaultAuthWithForwardModifier(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	server.config.Security.AppDefaultAuthType = "github+forward_authz"
	server.config.Forward = map[string]types.ForwardConfig{
		"authz": {AuthUrl: "http://auth.example.com/check"},
	}

	// github is intentionally left unregistered, so dispatch reaches the
	// "unsupported provider" branch whose message reveals which provider name the
	// auth resolution produced. When an app uses default auth and the configured
	// default carries a +forward_ modifier, the modifier (and any rbac: prefix)
	// must be resolved away, leaving "github" - not "github+forward_authz", which
	// is the regression this guards against.
	tests := map[string]types.AppAuthnType{
		"default keyword": types.AppAuthnDefault,
		"empty auth":      "",
		"rbac default":    types.AppAuthnType(rbac.RBAC_AUTH_PREFIX + string(types.AppAuthnDefault)),
	}

	for name, authType := range tests {
		t.Run(name, func(t *testing.T) {
			app := newAuthRedirectTestApp(authType)
			req := httptest.NewRequest(http.MethodGet, "http://example.com/myapp", nil)
			rec := httptest.NewRecorder()

			server.authenticateAndServeApp(rec, req, app)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status: want %d got %d (body %q)", http.StatusInternalServerError, rec.Code, rec.Body.String())
			}
			if got, want := strings.TrimSpace(rec.Body.String()), "Unsupported authentication provider: github"; got != want {
				t.Fatalf("resolved provider: want %q got %q", want, got)
			}
		})
	}
}

func TestAuthenticateAndServeAppRedirectsFallbackOAuthToCanonicalHost(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	app := newAuthRedirectTestApp("github")

	req := httptest.NewRequest(http.MethodGet, "http://unknown.test:8080/myapp?x=1", nil)
	rec := httptest.NewRecorder()

	server.authenticateAndServeApp(rec, req, app)

	if rec.Code != http.StatusFound {
		t.Fatalf("status: want %d got %d", http.StatusFound, rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "http://example.com:8080/myapp?x=1" {
		t.Fatalf("location: got %q", got)
	}
}

func TestAuthenticateAndServeAppRedirectsFallbackSAMLToCanonicalHostForHTMX(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	app := newAuthRedirectTestApp("saml_okta")

	req := httptest.NewRequest(http.MethodGet, "https://unknown.test/myapp?x=1", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	server.authenticateAndServeApp(rec, req, app)

	if got := rec.Header().Get("HX-Redirect"); got != "https://example.com/myapp?x=1" {
		t.Fatalf("HX-Redirect: got %q", got)
	}
}

func TestCanonicalAuthRedirectURLTreatsLocalhostAliasesAsEquivalent(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("localhost", true)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:25222/myapp", nil)

	if redirectURL, redirectNeeded := server.canonicalAuthRedirectURL(req, types.AppPathDomain{Path: "/myapp"}); redirectNeeded {
		t.Fatalf("unexpected redirect to %q", redirectURL)
	}
}

func TestMatchAppRejectsUnknownHostWhenFallbackDisabled(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	apps := []types.AppInfo{{AppPathDomain: types.AppPathDomain{Path: "/myapp"}}}
	server.apps = &AppStore{
		Logger:     server.Logger,
		server:     server,
		allApps:    apps,
		domainApps: buildDomainApps(apps, "example.com"),
		allDomains: map[string]bool{
			"example.com": true,
		},
	}

	if _, err := server.MatchApp("unknown.test", "/myapp"); err == nil {
		t.Fatal("MatchApp should reject unknown hosts when fallback_unknown_domains is disabled")
	}
}

func TestMatchAppRootDoesNotShadowInternalApps(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", false)
	apps := []types.AppInfo{
		{AppPathDomain: types.AppPathDomain{Path: "/"}},
		{AppPathDomain: types.AppPathDomain{Path: "/" + types.STAGE_SUFFIX}},
		{AppPathDomain: types.AppPathDomain{Path: "/" + types.PREVIEW_SUFFIX + "_abc123"}},
	}
	server.apps = &AppStore{
		Logger:     server.Logger,
		server:     server,
		allApps:    apps,
		domainApps: buildDomainApps(apps, "example.com"),
		allDomains: map[string]bool{
			"example.com": true,
		},
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "stage", path: "/" + types.STAGE_SUFFIX, want: "/" + types.STAGE_SUFFIX},
		{name: "preview", path: "/" + types.PREVIEW_SUFFIX + "_abc123", want: "/" + types.PREVIEW_SUFFIX + "_abc123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			appInfo, err := server.MatchApp("example.com", tc.path)
			if err != nil {
				t.Fatalf("MatchApp returned error: %v", err)
			}
			if appInfo.Path != tc.want {
				t.Fatalf("matched path = %q, want %q", appInfo.Path, tc.want)
			}
		})
	}
}

func TestIsOpenRunCookieName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cookie string
		want   bool
	}{
		{name: "oauth session", cookie: "github_openrun_session", want: true},
		{name: "saml session", cookie: "saml_okta_openrun_saml_session", want: true},
		{name: "gothic session", cookie: "_gothic_session", want: true},
		{name: "app cookie", cookie: "sessionid", want: false},
		{name: "contains openrun but different suffix", cookie: "openrun_theme", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isOpenRunCookieName(tt.cookie); got != tt.want {
				t.Fatalf("isOpenRunCookieName(%q): want %v got %v", tt.cookie, tt.want, got)
			}
		})
	}
}

func TestStripOpenRunCookies(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header.Add("Cookie", strings.Join([]string{
		"app_session=keep1",
		"github_openrun_session=drop1",
		"theme=keep2",
		"_gothic_session=drop2",
		"saml_okta_openrun_saml_session=drop3",
	}, "; "))

	stripOpenRunCookies(req)

	got := req.Header.Values("Cookie")
	if len(got) != 1 {
		t.Fatalf("cookie header count: want 1 got %d", len(got))
	}
	if got[0] != "app_session=keep1; theme=keep2" {
		t.Fatalf("cookie header: got %q", got[0])
	}
}

func TestStripOpenRunCookiesRemovesHeaderWhenOnlyOpenRunCookiesRemain(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header.Add("Cookie", "github_openrun_session=drop1; _gothic_session=drop2")

	stripOpenRunCookies(req)

	if got := req.Header.Get("Cookie"); got != "" {
		t.Fatalf("cookie header: want empty got %q", got)
	}
}

func TestStripOpenRunCookieHeaderFastPath(t *testing.T) {
	t.Parallel()

	const cookieHeader = "app_session=keep1; theme=keep2"
	got, changed := stripOpenRunCookieHeader(cookieHeader)
	if changed {
		t.Fatal("expected fast path to leave header unchanged")
	}
	if got != cookieHeader {
		t.Fatalf("cookie header: want %q got %q", cookieHeader, got)
	}
}

func TestStripOpenRunCookieHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		want    string
		changed bool
	}{
		{
			name:    "removes oauth and saml cookies",
			header:  "app_session=keep1; github_openrun_session=drop1; theme=keep2; saml_okta_openrun_saml_session=drop2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "removes gothic cookie",
			header:  "app_session=keep1; _gothic_session=drop1; theme=keep2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles extra whitespace",
			header:  "  app_session=keep1  ;\tgithub_openrun_session=drop1\t;  theme=keep2 ",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles duplicate separators",
			header:  "app_session=keep1;; github_openrun_session=drop1; ; theme=keep2;",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "handles cookie without equals",
			header:  "app_session=keep1; github_openrun_session; theme=keep2",
			want:    "app_session=keep1; theme=keep2",
			changed: true,
		},
		{
			name:    "keeps non openrun cookie containing openrun substring",
			header:  "app_session=keep1; openrun_theme=keep2",
			want:    "app_session=keep1; openrun_theme=keep2",
			changed: false,
		},
		{
			name:    "removes all cookies when only openrun remain",
			header:  "_gothic_session=drop1; github_openrun_session=drop2",
			want:    "",
			changed: true,
		},
		{
			name:    "empty header",
			header:  "",
			want:    "",
			changed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, changed := stripOpenRunCookieHeader(tt.header)
			if changed != tt.changed {
				t.Fatalf("changed: want %v got %v", tt.changed, changed)
			}
			if got != tt.want {
				t.Fatalf("cookie header: want %q got %q", tt.want, got)
			}
		})
	}
}

func TestStripOpenRunCookiesMultipleHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header["Cookie"] = []string{
		"app_session=keep1; github_openrun_session=drop1",
		"theme=keep2",
		"_gothic_session=drop2",
	}

	stripOpenRunCookies(req)

	got := req.Header["Cookie"]
	if len(got) != 2 {
		t.Fatalf("cookie header count: want 2 got %d", len(got))
	}
	if got[0] != "app_session=keep1" {
		t.Fatalf("cookie header 0: got %q", got[0])
	}
	if got[1] != "theme=keep2" {
		t.Fatalf("cookie header 1: got %q", got[1])
	}
}

func TestStripOpenRunCookiesLeavesHeadersUntouchedWhenNoMatch(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/myapp", nil)
	req.Header["Cookie"] = []string{
		"app_session=keep1; theme=keep2",
		"locale=en-US",
	}

	before := append([]string(nil), req.Header["Cookie"]...)
	stripOpenRunCookies(req)
	after := req.Header["Cookie"]

	if len(after) != len(before) {
		t.Fatalf("cookie header count: want %d got %d", len(before), len(after))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatalf("cookie header %d: want %q got %q", i, before[i], after[i])
		}
	}
}

func BenchmarkStripOpenRunCookieHeaderNoMatch(b *testing.B) {
	const cookieHeader = "app_session=keep1; theme=keep2; locale=en-US"
	for i := 0; i < b.N; i++ {
		stripOpenRunCookieHeader(cookieHeader)
	}
}

func BenchmarkStripOpenRunCookieHeaderWithOpenRunCookies(b *testing.B) {
	const cookieHeader = "app_session=keep1; github_openrun_session=drop1; theme=keep2; _gothic_session=drop2; saml_okta_openrun_saml_session=drop3"
	for i := 0; i < b.N; i++ {
		stripOpenRunCookieHeader(cookieHeader)
	}
}

func TestMatchAppFallsBackToDefaultDomainWhenEnabled(t *testing.T) {
	t.Parallel()

	server := newAuthRedirectTestServer("example.com", true)
	apps := []types.AppInfo{{AppPathDomain: types.AppPathDomain{Path: "/myapp"}}}
	server.apps = &AppStore{
		Logger:     server.Logger,
		server:     server,
		allApps:    apps,
		domainApps: buildDomainApps(apps, "example.com"),
		allDomains: map[string]bool{
			"example.com": true,
		},
	}

	appInfo, err := server.MatchApp("unknown.test", "/myapp")
	if err != nil {
		t.Fatalf("MatchApp returned error: %v", err)
	}
	if appInfo.Path != "/myapp" {
		t.Fatalf("matched path: got %q", appInfo.Path)
	}
}
