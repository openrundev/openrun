// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestConfigReadRedactsCredentials(t *testing.T) {
	server, db, trusted := newSyncRBACTestServer(t)
	defer db.Close()
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Roles:  map[string][]types.RBACPermission{"reader": {types.PermissionConfigRead}},
		Grants: []types.RBACGrant{{Users: []string{"reader"}, Roles: []string{"reader"}}},
	}); err != nil {
		t.Fatal(err)
	}
	server.dynamicConfig = &types.DynamicConfig{
		Entries: map[string]map[string]map[string]any{
			"auth": {"oidc": {"client_secret": "private-client-secret", "client_id": "public-client"}},
		},
		Settings: map[string]map[string]any{"system": {"builder_auth_token": "private-builder-token"}},
	}
	ctx := system.WithApiScopes(rbacEnforcedCtx(trusted, "reader"), []string{"config:read"})
	response, err := server.GetConfigResponse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := response.DynamicConfig.Entries["auth"]["oidc"]["client_secret"]; got != RedactedValue {
		t.Errorf("client secret exposed: %v", got)
	}
	if got := response.DynamicConfig.Settings["system"]["builder_auth_token"]; got != RedactedValue {
		t.Errorf("builder token exposed: %v", got)
	}
	if got := response.DynamicConfig.Entries["auth"]["oidc"]["client_id"]; got != "public-client" {
		t.Errorf("non-sensitive field changed: %v", got)
	}
	response, err = server.GetConfigResponse(trusted)
	if err != nil || response.DynamicConfig.Entries["auth"]["oidc"]["client_secret"] != "private-client-secret" {
		t.Fatalf("trusted config export must retain the original credential: %v", err)
	}
}

func TestRBACRemotePublishLockout(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	remoteCtx := server.apiTokenRequestContext(ctx, "config-editor", nil, []string{"config:update"}, InvokerRest, nil)
	if err := server.validateRBACCandidate(remoteCtx, rbac.DefaultConfig(), false); err == nil || !strings.Contains(err.Error(), "remove your own") {
		t.Fatalf("remote publisher must get lockout protection: %v", err)
	}
	if err := server.validateRBACCandidate(remoteCtx, rbac.DefaultConfig(), true); err != nil {
		t.Fatalf("force must allow deliberate lockout: %v", err)
	}
}

func TestRejectedConfigPersistencePreservesRBAC(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	previous := &types.DynamicConfig{VersionId: "stale", RBAC: *rbac.DefaultConfig()}
	server.dynamicConfig = previous
	if err := server.rbacManager.UpdateRBACConfig(&previous.RBAC); err != nil {
		t.Fatal(err)
	}
	candidate := &types.DynamicConfig{VersionId: "stale", RBAC: types.RBACConfig{
		Grants: []types.RBACGrant{{Users: []string{"candidate-admin"}, Roles: []string{"openrun-admin"}}},
	}}
	// There is no stored config row with this version, so the database CAS
	// rejects the update after the candidate has passed local validation.
	if _, err := server.UpdateDynamicConfig(ctx, candidate, false); err == nil || !strings.Contains(err.Error(), "no config entry found") {
		t.Fatalf("expected persistence rejection: %v", err)
	}
	if err := server.enforceGlobalPerm(rbacEnforcedCtx(ctx, "candidate-admin"), types.PermissionConfigUpdate, ""); err == nil {
		t.Fatal("rejected candidate admin grant remained live")
	}
	if got := server.GetDynamicConfig().VersionId; got != "stale" {
		t.Fatalf("live config version changed: %s", got)
	}
}

func TestSyncBackgroundPreservesCredentialCeiling(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	applyPath := filepath.Join(t.TempDir(), "sync.ace")
	// An empty initial apply requires no app permission. Adding an app later
	// must not turn a sync:create-only credential into the admin identity's
	// unrestricted durable authority.
	if err := os.WriteFile(applyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	creatorCtx := system.WithApiScopes(rbacEnforcedCtx(ctx, types.ADMIN_USER), []string{"sync:create"})
	response, err := server.CreateSyncEntry(creatorCtx, applyPath, true, false, &types.SyncMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	entry := getSyncEntryForTest(t, db, ctx, response.Id)
	writeSyncApplyFile(t, applyPath, "/apps/denied")
	jobCtx := server.attachSyncRBAC(newBackgroundOperationContext(entry.UserID), entry)
	status, _, err := server.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, nil)
	if err != nil || !strings.Contains(status.Error, string(types.PermissionApply)) {
		t.Fatalf("background sync escaped credential ceiling: status %+v, %v", status, err)
	}
	if _, err := db.GetAppEntry(ctx, types.AppPathDomain{Path: "/apps/denied"}); err == nil {
		t.Fatal("denied background sync created an app")
	}
}

func TestManualJobPreservesRBAC(t *testing.T) {
	server, db, trusted := newSyncRBACTestServer(t)
	defer db.Close()
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatal(err)
	}
	defer func() {
		server.stopAuditWriter()
		_ = server.auditDB.Close()
	}()
	initOpenRunPlugin(server)
	source := t.TempDir()
	code := `load("openrun.in", "openrun")
def inspect(dry_run, args):
    return ",".join(openrun.get_permissions("/apps/jobs").value)
def slow(dry_run, args):
    for i in range(1000000000):
        pass
app = ace.app("job authorization", jobs=[ace.job("inspect", run=inspect), ace.job("slow", run=slow)],
    permissions=[ace.permission("openrun.in", "get_permissions", [], permit=["inspect"])])
`
	if err := os.WriteFile(filepath.Join(source, "app.star"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.CreateApp(trusted, "/apps/jobs", true, false, &types.CreateAppRequest{SourceUrl: source}); err != nil {
		t.Fatal(err)
	}
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Roles:  map[string][]types.RBACPermission{"runner": {types.PermissionUpdate, "custom:inspect"}},
		Grants: []types.RBACGrant{{Users: []string{"runner"}, Roles: []string{"runner"}, Targets: []string{"/apps/jobs"}}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, wait := range []bool{true, false} {
		for _, user := range []string{"runner", types.ADMIN_USER} {
			ctx, cancel := context.WithCancel(system.WithApiScopes(rbacEnforcedCtx(trusted, user), []string{"app:update"}))
			// An app invoking another app's job must not supply its grant target.
			if !wait {
				ctx = context.WithValue(ctx, types.APP_PATH_DOMAIN, types.AppPathDomain{Path: "/caller"})
			}
			response, err := server.RunJob(ctx, "/apps/jobs", "inspect", false, wait, false, nil)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			run := &response.Run
			deadline := time.Now().Add(3 * time.Second)
			for run.Status == types.JobRunRunning && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
				run, err = db.GetJobRun(trusted, run.Id)
				if err != nil {
					t.Fatal(err)
				}
			}
			if run.Status != types.JobRunSucceeded || run.Message != "app:update" {
				t.Fatalf("job escaped caller permissions: %+v", run)
			}
		}
	}
	// The same function used by the scheduler must run as the app owner,
	// with live grants instead of trusted server authority.
	entry, err := db.GetAppEntry(trusted, types.AppPathDomain{Path: "/apps/jobs"})
	if err != nil {
		t.Fatal(err)
	}
	entry.UserID = "runner"
	cronCtx, err := server.cronJobContext(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.enforceGlobalPerm(cronCtx, types.PermissionConfigUpdate, ""); err == nil {
		t.Fatal("cron owner must not acquire config:update")
	}
	if err := server.enforceAppPermEntry(cronCtx, types.PermissionUpdate, entry); err != nil {
		t.Fatalf("cron owner should keep app:update: %v", err)
	}
	server.startCronRun(trusted, entry, types.JobSpec{Name: "inspect", Run: "inspect"}, time.Now().UTC())
	deadline := time.Now().Add(3 * time.Second)
	cronFinished := false
	for time.Now().Before(deadline) {
		runs, err := db.ListJobRuns(trusted, []types.AppId{entry.Id}, "inspect", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, run := range runs {
			if run.Trigger != types.JobTriggerCron || run.Status == types.JobRunRunning {
				continue
			}
			if run.Status != types.JobRunSucceeded {
				t.Fatalf("cron lost app-scoped plugin permit: %+v", run)
			}
			cronFinished = true
		}
		if cronFinished {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cronFinished {
		t.Fatal("cron did not finish")
	}
	// Deleted builtin users must lose even direct principal grants when
	// the next scheduled job context is created.
	server.staticConfig.BuiltinAuth = map[string]types.BuiltinAuthEntry{"runner": {Groups: []string{"runners"}}}
	entry.UserID = "builtin:runner"
	cronCtx, err = server.cronJobContext(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if got := system.GetContextGroups(cronCtx); len(got) != 1 || got[0] != "runners" {
		t.Fatalf("cron must resolve current builtin groups: %v", got)
	}
	delete(server.staticConfig.BuiltinAuth, "runner")
	cronCtx, err = server.cronJobContext(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if got := system.GetContextUserId(cronCtx); got != "" {
		t.Fatalf("deleted builtin owner retained identity %q", got)
	}

	// Detaching an asynchronous job from its HTTP request must retain the
	// upstream job registry's shutdown cancellation and cleanup tracking.
	response, err := server.RunJob(rbacEnforcedCtx(trusted, "runner"), "/apps/jobs", "slow", false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.jobRuns.stop()
	waited := make(chan struct{})
	go func() { server.jobRuns.wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("job retained authorization but ignored server shutdown")
	}
	run, err := db.GetJobRun(trusted, response.Run.Id)
	if err != nil || run.Status != types.JobRunCanceled {
		t.Fatalf("shutdown must cancel the job: %+v, %v", run, err)
	}
}

func TestRemoteConfigRoundTripPreservesCredentials(t *testing.T) {
	server, db, trusted := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	previous := &types.DynamicConfig{VersionId: "initial", RBAC: *rbac.DefaultConfig(),
		Entries:  map[string]map[string]map[string]any{"git_auth": {"gh": {"password": "secret-password", "user_id": "git"}}},
		Settings: map[string]map[string]any{"system": {"builder_auth_token": "secret-token"}},
	}
	if err := db.InitConfig(trusted, types.ADMIN_USER, previous); err != nil {
		t.Fatal(err)
	}
	if err := server.updateDynamicConfigCache(trusted, previous); err != nil {
		t.Fatal(err)
	}
	remote := rbacEnforcedCtx(trusted, types.ADMIN_USER)
	response, err := server.GetConfigResponse(remote)
	if err != nil {
		t.Fatal(err)
	}
	response.DynamicConfig.Entries["git_auth"]["gh"]["user_id"] = "edited"
	updated, err := server.UpdateDynamicConfig(remote, &response.DynamicConfig, false)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Entries["git_auth"]["gh"]["password"] != "secret-password" || stored.Settings["system"]["builder_auth_token"] != "secret-token" || stored.Entries["git_auth"]["gh"]["user_id"] != "edited" {
		t.Fatalf("round trip corrupted stored config: %+v", stored)
	}
	if updated.Entries["git_auth"]["gh"]["password"] != RedactedValue || updated.Settings["system"]["builder_auth_token"] != RedactedValue {
		t.Fatal("remote update response exposed restored credentials")
	}
	if response.DynamicConfig.VersionId != "initial" || response.DynamicConfig.Entries["git_auth"]["gh"]["password"] != RedactedValue {
		t.Fatal("update mutated caller's redacted document")
	}
	response.DynamicConfig.VersionId = updated.VersionId
	response.DynamicConfig.Entries["git_auth"]["gh"]["password"] = "replacement-password"
	updated, err = server.UpdateDynamicConfig(remote, &response.DynamicConfig, false)
	if err != nil || updated.Entries["git_auth"]["gh"]["password"] != RedactedValue {
		t.Fatalf("explicit secret replacement failed: %v", err)
	}
	stored, err = db.GetConfig()
	if err != nil || stored.Entries["git_auth"]["gh"]["password"] != "replacement-password" {
		t.Fatalf("replacement was not stored: %v", err)
	}
	response.DynamicConfig.VersionId = updated.VersionId
	response.DynamicConfig.Entries["git_auth"]["new"] = map[string]any{"password": RedactedValue}
	if _, err := server.UpdateDynamicConfig(remote, &response.DynamicConfig, false); err == nil || !strings.Contains(err.Error(), "no stored value") {
		t.Fatalf("unresolvable placeholder should be rejected: %v", err)
	}
	// A derived export failure cannot reject or roll back a database commit.
	exportPath := filepath.Join(os.Getenv("OPENRUN_HOME"), "config", "dynamic_config.json")
	if err := os.Remove(exportPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(exportPath, 0700); err != nil {
		t.Fatal(err)
	}
	candidate, err := copyDynamicConfig(updated)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Entries["git_auth"]["gh"]["user_id"] = "committed"
	committed, err := server.UpdateDynamicConfig(remote, candidate, false)
	if err != nil {
		t.Fatalf("export failure incorrectly rejected committed update: %v", err)
	}
	stored, err = db.GetConfig()
	if err != nil || stored.VersionId != committed.VersionId || server.GetDynamicConfig().VersionId != committed.VersionId || stored.Entries["git_auth"]["gh"]["user_id"] != "committed" {
		t.Fatalf("database and live state diverged after export failure: %+v, %v", stored, err)
	}
}

func TestRejectedConfigDoesNotReapplyPreviousSecrets(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	secretsManager, err := system.NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", server.staticConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := secretsManager.BindDBStores(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := secretsManager.CreateSecret(ctx, &types.CreateSecretRequest{Name: "rbac_review_secret", Value: "original-password"}, "admin", false); err != nil {
		t.Fatal(err)
	}
	server.secretsManager.Store(secretsManager)
	previous := &types.DynamicConfig{VersionId: "unpersisted", RBAC: *rbac.DefaultConfig(),
		Entries: map[string]map[string]map[string]any{"git_auth": {"gh": {"password": `{{secret_from "db" "rbac_review_secret"}}`}}},
	}
	if err := server.updateDynamicConfigCache(ctx, previous); err != nil {
		t.Fatal(err)
	}
	originalRuntime, originalSecrets := server.Config(), server.secretsMgr()
	exportPath := filepath.Join(os.Getenv("OPENRUN_HOME"), "config", "dynamic_config.json")
	if err := os.WriteFile(exportPath, []byte("untouched export"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secretsManager.DeleteSecret(ctx, "db", "rbac_review_secret"); err != nil {
		t.Fatal(err)
	}
	server.oAuthManager = NewOAuthManager(server.Logger, server.staticConfig, db)
	if _, err := server.prepareDynamicConfig(ctx, previous, true); err == nil {
		t.Fatal("test requires the previous secret template to be unresolvable")
	}
	for _, failure := range []string{"database", "template", "oauth"} {
		candidate := &types.DynamicConfig{VersionId: previous.VersionId, RBAC: types.RBACConfig{
			Grants: []types.RBACGrant{{Users: []string{"candidate-admin"}, Roles: []string{"openrun-admin"}}},
		}}
		wantError := "no config entry found"
		switch failure {
		case "template":
			candidate.Entries = map[string]map[string]map[string]any{"git_auth": {"gh": {"password": `{{secret_from "missing-provider" "candidate"}}`}}}
			wantError = "missing-provider"
		case "oauth":
			candidate.Entries = map[string]map[string]map[string]any{"auth": {"github": {"key": "candidate-key", "secret": "candidate-secret"}}}
			wantError = "callback_url"
		}
		_, err := server.UpdateDynamicConfig(ctx, candidate, false)
		if err == nil || !strings.Contains(err.Error(), wantError) || strings.Contains(err.Error(), "restoring previous") || strings.Contains(err.Error(), "rbac_review_secret") {
			t.Fatalf("rejection must describe only the candidate failure: %v", err)
		}
		if server.Config() != originalRuntime || server.secretsMgr() != originalSecrets || server.dynamicConfig != previous {
			t.Fatal("rejection changed active state")
		}
		if err := server.enforceGlobalPerm(rbacEnforcedCtx(ctx, "candidate-admin"), types.PermissionConfigUpdate, ""); err == nil {
			t.Fatal("rejected candidate grant became live")
		}
		data, err := os.ReadFile(exportPath)
		if err != nil || string(data) != "untouched export" {
			t.Fatalf("rejection rewrote export: %q, %v", data, err)
		}
	}
}

func TestCronOwnerIdentityResolution(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatal(err)
	}
	entry := &types.AppEntry{Id: "app_cron_review", Path: "/cron-review", UserID: "github:owner"}
	cronCtx, err := server.cronJobContext(ctx, entry)
	if err != nil || system.GetContextUserId(cronCtx) != entry.UserID {
		t.Fatalf("principal without identity row lost authority: %v", err)
	}
	if _, phantom := server.staleGroupsAudited.Load(""); phantom {
		t.Fatal("missing identity produced a stale federated snapshot audit")
	}
	if err := server.enforceAppPermEntry(cronCtx, types.PermissionUpdate, entry); err != nil {
		t.Fatalf("owner without identity row lost owner permissions: %v", err)
	}
	// Make only identity lookups fail, leaving run claiming/recording usable.
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // Cleanup only; the successful path commits below.
	if _, err := tx.ExecContext(ctx, "DROP TABLE identities"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if cronCtx, err := server.cronJobContext(ctx, entry); err == nil || cronCtx != nil {
		t.Fatalf("lookup failure returned an executable context: %v", err)
	}
	server.startCronRun(ctx, entry, types.JobSpec{Name: "inspect"}, time.Now().UTC())
	runs, err := db.ListJobRuns(ctx, []types.AppId{entry.Id}, "inspect", "", 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("expected claimed failed run: %+v, %v", runs, err)
	}
	if runs[0].Status != types.JobRunFailed || !strings.Contains(runs[0].Message, "error resolving scheduled job owner") {
		t.Fatalf("infrastructure failure must stop before loading/executing job: %+v", runs[0])
	}
}

func TestPreviewAccessUsesMainAppOwner(t *testing.T) {
	server, db, _ := newSyncRBACTestServer(t)
	defer db.Close()
	preview := newAuthRedirectTestApp(types.AppAuthnNone)
	preview.Path = "/main--preview"
	preview.MainApp = "app_main"
	preview.LinkedAppPath = "/main"
	// A CORS preflight gives the real app handler a minimal successful response.
	preview.AppConfig.Security.DisableCSRFProtection = true
	preview.AppConfig.CORS.AllowOrigin = "*"
	for _, tc := range []struct {
		name  string
		owner string
		grant types.RBACPermission
		want  int
	}{
		{"preview creator", "main-owner", types.PermissionPreview, http.StatusForbidden},
		{"main owner", types.ANONYMOUS_USER, types.PermissionPreview, http.StatusNoContent},
		{"explicit access", "main-owner", types.PermissionAccess, http.StatusNoContent},
		{"orphaned preview with explicit access", "", types.PermissionAccess, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preview.UserID = tc.owner // persisted ownership, inherited at creation or migration
			server.apps.idToInfo = map[types.AppId]types.AppInfo{}
			if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
				Roles:  map[string][]types.RBACPermission{"previewer": {tc.grant}},
				Grants: []types.RBACGrant{{Users: []string{types.ANONYMOUS_USER}, Roles: []string{"previewer"}, Targets: []string{"/main"}}},
			}); err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			server.authenticateAndServeApp(recorder, httptest.NewRequest(http.MethodOptions, "http://localhost/main--preview", nil), preview)
			if recorder.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestConfigPlaceholderConsistency(t *testing.T) {
	server, db, trusted := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	previous := &types.DynamicConfig{VersionId: "initial", RBAC: *rbac.DefaultConfig(),
		Entries:  map[string]map[string]map[string]any{"git_auth": {"gh": {"password": "stored-secret", "user_id": "git"}}},
		Settings: map[string]map[string]any{"system": {"builder_auth_token": "stored-token", "list_apps_title": "original"}},
	}
	if err := db.InitConfig(trusted, types.ADMIN_USER, previous); err != nil {
		t.Fatal(err)
	}
	if err := server.updateDynamicConfigCache(trusted, previous); err != nil {
		t.Fatal(err)
	}
	remote := rbacEnforcedCtx(trusted, types.ADMIN_USER)
	values := map[string]any{"password": RedactedValue, "user_id": RedactedValue}
	entryResponse, err := server.SetConfigEntry(remote, "git_auth", "gh", values, "")
	if err != nil {
		t.Fatal(err)
	}
	if values["password"] != RedactedValue || entryResponse.Entries["git_auth"]["gh"]["password"] != RedactedValue {
		t.Fatal("entry update exposed stored secret in caller map or response")
	}
	for _, key := range []string{"builder_auth_token", "list_apps_title"} {
		response, err := server.SetConfigValue(remote, "system", key, RedactedValue, "")
		if err != nil {
			t.Fatal(err)
		}
		if response.Settings["system"]["builder_auth_token"] != RedactedValue {
			t.Fatal("setting response exposed stored token")
		}
	}
	stored, err := db.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Entries["git_auth"]["gh"]["password"] != "stored-secret" || stored.Settings["system"]["builder_auth_token"] != "stored-token" {
		t.Fatal("placeholder did not preserve credentials")
	}
	if stored.Entries["git_auth"]["gh"]["user_id"] != RedactedValue || stored.Settings["system"]["list_apps_title"] != RedactedValue {
		t.Fatal("nonsecret placeholder literal was unexpectedly substituted")
	}
	if _, err := server.SetConfigEntry(remote, "git_auth", "new", values, ""); err == nil {
		t.Fatal("new entry accepted placeholder with no secret to keep")
	}
	trustedResponse, err := server.UpdateDynamicConfig(trusted, stored, false)
	if err != nil || trustedResponse.Entries["git_auth"]["gh"]["password"] != "stored-secret" {
		t.Fatalf("trusted response must retain credentials: %v", err)
	}
}

func TestPreviewManagementUsesMainOwner(t *testing.T) {
	server, db, trusted := newSyncRBACTestServer(t)
	defer db.Close()
	preview := &types.AppEntry{Id: "app_pre_review", MainApp: "app_prd_main", Path: "/main--preview", LinkedAppPath: "/main", UserID: "main-owner"}
	info := types.AppInfo{Id: preview.Id, MainApp: preview.MainApp, AppPathDomain: preview.AppPathDomain(), LinkedAppPath: preview.LinkedAppPath, UserID: preview.UserID}
	server.apps.idToInfo = map[types.AppId]types.AppInfo{} // listing needs no owner lookup
	for _, granted := range []bool{true, false} {
		config := &types.RBACConfig{}
		if granted {
			config.Roles = map[string][]types.RBACPermission{"previewer": {types.PermissionPreview}}
			config.Grants = []types.RBACGrant{{Users: []string{"creator"}, Roles: []string{"previewer"}, Targets: []string{"/main"}}}
		}
		if err := server.rbacManager.UpdateRBACConfig(config); err != nil {
			t.Fatal(err)
		}
		ctx := rbacEnforcedCtx(trusted, "creator")
		if err := server.enforceAppPermEntry(ctx, types.PermissionDelete, preview); err == nil {
			t.Fatal("preview creator acquired delete through ownership")
		}
		if err := server.enforceAppPermInfos(ctx, types.PermissionUpdate, []types.AppInfo{info}); err == nil {
			t.Fatal("preview creator acquired update through glob ownership")
		}
		if allowed, err := server.AuthorizeList(ctx, "creator", &info, nil); err != nil || allowed {
			t.Fatalf("preview creator acquired read through ownership: %v", err)
		}
		if err := server.enforceAppPermEntry(rbacEnforcedCtx(trusted, "main-owner"), types.PermissionDelete, preview); err != nil {
			t.Fatalf("main owner lost preview management: %v", err)
		}
	}
}

func TestStageAccessDoesNotLookupMainOwner(t *testing.T) {
	server, db, _ := newSyncRBACTestServer(t)
	defer db.Close()
	stage := newAuthRedirectTestApp(types.AppAuthnNone)
	stage.Id = "app_stg_review"
	stage.MainApp = "app_prd_main"
	stage.UserID = types.ANONYMOUS_USER
	stage.AppConfig.Security.DisableCSRFProtection = true
	stage.AppConfig.CORS.AllowOrigin = "*"
	// A nil store would panic if serving the stage attempted a lookup.
	apps := server.apps
	server.apps = nil
	defer func() { server.apps = apps }()
	recorder := httptest.NewRecorder()
	server.authenticateAndServeApp(recorder, httptest.NewRequest(http.MethodOptions, "http://localhost/myapp", nil), stage)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("stage owner access failed: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestInvalidSAMLConfigDoesNotCommit(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	server.samlManager = NewSAMLManager(server.Logger, server.staticConfig, nil, db)
	previous := &types.DynamicConfig{VersionId: "initial", RBAC: *rbac.DefaultConfig()}
	if err := db.InitConfig(ctx, types.ADMIN_USER, previous); err != nil {
		t.Fatal(err)
	}
	if err := server.updateDynamicConfigCache(ctx, previous); err != nil {
		t.Fatal(err)
	}
	original := server.Config()
	for _, callback := range []string{"", "https://localhost"} {
		server.staticConfig.Security.CallbackUrl = callback
		candidate := &types.DynamicConfig{VersionId: previous.VersionId, RBAC: *rbac.DefaultConfig(),
			Entries: map[string]map[string]map[string]any{"saml": {"invalid": {"metadata_url": ":invalid"}}},
		}
		if _, err := server.UpdateDynamicConfig(ctx, candidate, false); err == nil {
			t.Fatal("invalid SAML config committed")
		}
		stored, err := db.GetConfig()
		if err != nil || stored.VersionId != previous.VersionId || server.Config() != original {
			t.Fatalf("rejected SAML config changed state: %v", err)
		}
		if server.samlManager.getProviderConfig("saml_invalid") != nil {
			t.Fatal("rejected SAML provider became live")
		}
	}
}

func TestBrowserLoginRefreshesCronGroups(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatal(err)
	}
	if err := server.rbacManager.UpdateRBACConfig(&types.RBACConfig{
		Roles:  map[string][]types.RBACPermission{"reader": {types.PermissionConfigRead}},
		Grants: []types.RBACGrant{{Users: []string{"group:readers"}, Roles: []string{"reader"}}},
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewOAuthManager(server.Logger, server.staticConfig, db)
	manager.providerConfigs = map[string]*types.AuthConfig{"github": {}}
	originalComplete := gothic.CompleteUserAuth
	defer func() { gothic.CompleteUserAuth = originalComplete }()
	loginGroups := []any{"readers"}
	gothic.CompleteUserAuth = func(http.ResponseWriter, *http.Request) (goth.User, error) {
		return goth.User{UserID: "subject-1", Email: "owner@example.com", RawData: map[string]any{"groups": loginGroups}}, nil
	}
	login := func() {
		t.Helper()
		if err := db.StoreKV(ctx, "login-state", map[string]any{
			AUTH_KEY: false, PROVIDER_NAME_KEY: "github", REDIRECT_URL: "https://apps.example.com/",
		}, nil); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/auth/github/callback?state="+base64.URLEncoding.EncodeToString([]byte("login-state")), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("provider", "github")
		req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, route))
		recorder := httptest.NewRecorder()
		manager.authCallback(recorder, req)
		if recorder.Code != http.StatusFound {
			t.Fatalf("callback failed: %d %s", recorder.Code, recorder.Body.String())
		}
		if err := db.DeleteKV(ctx, "login-state"); err != nil {
			t.Fatal(err)
		}
	}
	login()
	identity, err := db.GetIdentityByPrincipal(ctx, "github:owner@example.com")
	if err != nil || identity.GroupsObservedAt == nil || identity.StableSubject != "subject-1" {
		t.Fatalf("browser login did not persist identity: %+v, %v", identity, err)
	}
	entry := &types.AppEntry{Path: "/job-app", UserID: identity.PrincipalName}
	cronCtx, err := server.cronJobContext(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.enforceGlobalPerm(cronCtx, types.PermissionConfigRead, ""); err != nil {
		t.Fatalf("cron lost browser IdP groups: %v", err)
	}
	loginGroups = []any{}
	login()
	refreshed, err := db.GetIdentityByPrincipal(ctx, identity.PrincipalName)
	if err != nil || refreshed.Id != identity.Id || len(refreshed.Groups) != 0 {
		t.Fatalf("login failed to replace group snapshot: %+v, %v", refreshed, err)
	}
	cronCtx, err = server.cronJobContext(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.enforceGlobalPerm(cronCtx, types.PermissionConfigRead, ""); err == nil {
		t.Fatal("removed IdP group retained authority")
	}
	// SAML uses the same writer after validating the assertion and request id.
	if err := observeFederatedIdentity(ctx, db, "saml_company", "employee", "employee", []string{"readers"}); err != nil {
		t.Fatal(err)
	}
	entry.UserID = "saml_company:employee"
	cronCtx, err = server.cronJobContext(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.enforceGlobalPerm(cronCtx, types.PermissionConfigRead, ""); err != nil {
		t.Fatalf("cron lost SAML groups: %v", err)
	}
	// Refreshing group observations must not re-enable a disabled identity.
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "UPDATE identities SET disabled_at = CURRENT_TIMESTAMP WHERE principal_name = ?", entry.UserID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := observeFederatedIdentity(ctx, db, "saml_company", "employee", "employee", []string{"readers"}); err != nil {
		t.Fatal(err)
	}
	cronCtx, err = server.cronJobContext(ctx, entry)
	if err != nil || system.GetContextUserId(cronCtx) != "" {
		t.Fatalf("login re-enabled disabled cron owner: %v", err)
	}
}

func TestConfigNotifyAppliesRBACWithUnavailableProviders(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	server.staticConfig.Security.CallbackUrl = "https://localhost"
	server.oAuthManager = NewOAuthManager(server.Logger, server.staticConfig, db)
	server.samlManager = NewSAMLManager(server.Logger, server.staticConfig, nil, db)
	server.dynamicConfig = &types.DynamicConfig{VersionId: "old", RBAC: types.RBACConfig{
		Grants: []types.RBACGrant{{Users: []string{"old-admin"}, Roles: []string{"openrun-admin"}}},
	}}
	if err := server.rbacManager.UpdateRBACConfig(&server.dynamicConfig.RBAC); err != nil {
		t.Fatal(err)
	}
	committed := &types.DynamicConfig{VersionId: "committed-on-other-node", RBAC: *rbac.DefaultConfig(), Entries: map[string]map[string]map[string]any{
		"auth": {"oidc": {"key": "client", "secret": "credential", "discovery_url": ":unavailable"}},
		"saml": {"company": {"metadata_url": ":unavailable"}},
	}}
	if err := db.InitConfig(ctx, types.ADMIN_USER, committed); err != nil {
		t.Fatal(err)
	}
	server.configNotifyHandler(types.ConfigUpdatePayload{ServerId: "other-node"})
	if server.GetDynamicConfig().VersionId != committed.VersionId {
		t.Fatal("provider failure left stale config")
	}
	if err := server.enforceGlobalPerm(rbacEnforcedCtx(ctx, "old-admin"), types.PermissionConfigUpdate, ""); err == nil {
		t.Fatal("provider failure left revoked admin live")
	}
	if server.oAuthManager.ValidateProviderName("oidc") || server.samlManager.ValidateSAMLProvider("saml_company") {
		t.Fatal("unavailable providers must be disabled")
	}
	candidate, err := copyDynamicConfig(committed)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Entries["auth"]["oidc"]["key"] = "changed-client"
	if _, err := server.UpdateDynamicConfig(ctx, candidate, false); err == nil {
		t.Fatal("originating update accepted unreachable IdP")
	}
}

func TestCronDisabledRBACSchedulerAttribution(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	server.staticConfig.Security.UnsafeDisableRBAC = true
	manager, err := rbac.NewRBACHandler(server.Logger, rbac.DefaultConfig(), server.staticConfig)
	if err != nil {
		t.Fatal(err)
	}
	server.rbacManager = manager
	jobCtx, err := server.cronJobContext(ctx, &types.AppEntry{})
	if err != nil || system.GetContextUserId(jobCtx) != jobSchedulerActor || system.IsAppRBACEnabled(jobCtx) {
		t.Fatalf("scheduler attribution changed: %v", err)
	}
}

func TestNestedConfigRedactionRoundTrip(t *testing.T) {
	server, db, ctx := newSyncRBACTestServer(t)
	defer db.Close()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	server.staticConfig.Api.MCP.Auth = []string{"admin"}
	server.staticConfig.Api.Rest.Auth = []string{"admin"}
	initial := &types.DynamicConfig{VersionId: "initial", RBAC: *rbac.DefaultConfig(), Entries: map[string]map[string]map[string]any{
		"builder_agent": {"codex_review": {"env": map[string]any{"API_TOKEN": "private-token", "DISPLAY": "public"}}},
	}}
	if err := db.InitConfig(ctx, types.ADMIN_USER, initial); err != nil {
		t.Fatal(err)
	}
	if err := server.updateDynamicConfigCache(ctx, initial); err != nil {
		t.Fatal(err)
	}
	remote := rbacEnforcedCtx(ctx, types.ADMIN_USER)
	response, err := server.GetConfigResponse(remote)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := server.GetConfigEntries(remote, []string{"builder_agent"})
	if err != nil {
		t.Fatal(err)
	}
	if entries["builder_agent"][0].Values["env"].(map[string]any)["API_TOKEN"] != RedactedValue {
		t.Fatal("console entry read leaked nested token")
	}
	env := response.DynamicConfig.Entries["builder_agent"]["codex_review"]["env"].(map[string]any)
	if env["API_TOKEN"] != RedactedValue {
		t.Fatal("nested token leaked")
	}
	env["DISPLAY"] = "edited"
	updated, err := server.UpdateDynamicConfig(remote, &response.DynamicConfig, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Entries["builder_agent"]["codex_review"]["env"].(map[string]any)["API_TOKEN"] != RedactedValue {
		t.Fatal("nested token leaked in update response")
	}
	stored, err := db.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	storedEnv := stored.Entries["builder_agent"]["codex_review"]["env"].(map[string]any)
	if storedEnv["API_TOKEN"] != "private-token" || storedEnv["DISPLAY"] != "edited" {
		t.Fatal("nested round trip corrupted config")
	}
	entry := map[string]any{"env": map[string]string{"API_TOKEN": RedactedValue, "DISPLAY": RedactedValue}}
	if _, err := server.SetConfigEntry(remote, "builder_agent", "codex_review", entry, ""); err != nil {
		t.Fatal(err)
	}
	if entry["env"].(map[string]string)["API_TOKEN"] != RedactedValue {
		t.Fatal("restore mutated caller's nested map")
	}
	if _, err := server.SetConfigEntry(remote, "builder_agent", "codex_new", entry, ""); err == nil {
		t.Fatal("nested placeholder without a stored value was accepted")
	}
}

func TestJobAuthorizationSnapshotIsolation(t *testing.T) {
	groups, scopes := []string{"workers"}, []string{"app:update"}
	expiry := time.Now().Add(time.Hour)
	cred := &types.Credential{Scopes: scopes, Resources: []string{"rest"}, ExpiresAt: &expiry}
	caller := system.WithApiCredential(system.WithApiScopes(&managementAPIContext{
		Context: context.Background(), userId: "worker", groups: groups, rbacEnabled: true,
	}, scopes), cred)
	caller = system.WithApiInvoker(caller, InvokerMCP)
	shared := &ContextShared{Operation: "run_job"}
	caller = context.WithValue(caller, types.SHARED, shared)
	caller = context.WithValue(caller, types.APP_AUTH, types.AppAuthnNone)
	caller = context.WithValue(caller, types.CUSTOM_PERMS, []string{"caller-only"})
	caller = context.WithValue(caller, types.TESTURL_DIRECTIVES, rbac.NewUrlDirectives([]string{"admin"}, "/caller"))
	caller = context.WithValue(caller, types.SYNC_ID, "sync-test")
	sa := rbac.NewSyncAuthorizer(&types.RBACSnapshot{})
	caller = rbac.WithSyncAuthorizer(caller, sa)
	parent, cancel := context.WithCancel(context.Background())
	worker := newJobAuthorizationContext(parent, caller)
	groups[0], scopes[0], cred.Resources[0] = "changed", "*", "mcp"
	expiry = time.Now().Add(24 * time.Hour)
	for _, key := range []types.ContextKey{types.SHARED, types.CUSTOM_PERMS, types.APP_AUTH, types.TESTURL_DIRECTIVES} {
		if worker.Value(key) != nil {
			t.Fatalf("worker inherited request key %s", key)
		}
	}
	if system.GetContextUserId(worker) != "worker" || system.GetContextGroups(worker)[0] != "workers" || !system.IsAppRBACEnabled(worker) {
		t.Fatal("worker lost authorization snapshot")
	}
	if system.GetContextApiInvoker(worker) != InvokerMCP {
		t.Fatal("worker lost API surface policy")
	}
	gotScopes, present := system.GetContextApiScopes(worker)
	if !present || len(gotScopes) != 1 || gotScopes[0] != "app:update" {
		t.Fatal("credential scope snapshot mutated")
	}
	if system.GetContextValue(worker, types.SYNC_ID) != "sync-test" || rbac.GetSyncAuthorizer(worker) != sa {
		t.Fatal("worker lost sync authorization")
	}
	workerCred := system.GetContextApiCredential(worker)
	if workerCred.Resources[0] != "rest" || !workerCred.ExpiresAt.Before(expiry) {
		t.Fatal("worker lost credential attenuation")
	}
	cancel()
	if worker.Err() != context.Canceled {
		t.Fatal("worker ignored job cancellation")
	}
	unattributed := newJobAuthorizationContext(context.Background(), context.Background())
	if system.AppRBACMarkerPresent(unattributed) || system.IsTrustedOperation(unattributed) {
		t.Fatal("snapshot elevated unattributed caller")
	}
}

// newSecretRevealJobServer returns a server with a stored secret and an app
// at /jobs/audit whose reveal job reads it back through the admin plugin
func newSecretRevealJobServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
	server, db, trusted := newSyncRBACTestServer(t)
	t.Setenv("OPENRUN_HOME", t.TempDir())
	if err := server.initAuditDB("sqlite:" + filepath.Join(t.TempDir(), "audit.db")); err != nil {
		t.Fatal(err)
	}
	manager, err := system.NewSecretManager(trusted, map[string]types.SecretConfig{"db": {}}, "db", server.staticConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BindDBStores(trusted, db); err != nil {
		t.Fatal(err)
	}
	server.secretsManager.Store(manager)
	if _, err := manager.CreateSecret(trusted, &types.CreateSecretRequest{Name: "job_secret", Value: "private-value"}, "admin", false); err != nil {
		t.Fatal(err)
	}
	initAdminPlugin(server)
	source := t.TempDir()
	code := `load("openrun_admin.in", "openrun_admin")
def reveal(dry_run, args):
    openrun_admin.get_secret("job_secret", reveal=True)
    return "revealed"
app = ace.app("audit isolation", jobs=[ace.job("reveal", run=reveal)],
    permissions=[ace.permission("openrun_admin.in", "get_secret", [])])
`
	if err := os.WriteFile(filepath.Join(source, "app.star"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.CreateApp(trusted, "/jobs/audit", true, false, &types.CreateAppRequest{SourceUrl: source}); err != nil {
		t.Fatal(err)
	}
	return server, db, trusted
}

func TestJobKeepsApiSurfacePolicy(t *testing.T) {
	server, db, trusted := newSecretRevealJobServer(t)
	defer db.Close()
	scopes := []string{"app:update", "secret:reveal"}
	// secret_reveal is disabled on MCP by default: a job started from MCP
	// must not reach it, while the same job started from REST may
	for _, tc := range []struct{ invoker, message string }{
		{InvokerMCP, "disabled for the mcp API surface"},
		{InvokerRest, "revealed"},
	} {
		ctx := server.apiTokenRequestContext(trusted, types.ADMIN_USER, nil, scopes, tc.invoker, nil)
		response, err := server.RunJob(ctx, "/jobs/audit", "reveal", false, true, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(response.Run.Message, tc.message) {
			t.Fatalf("%s job run: %+v, want message containing %q", tc.invoker, response.Run, tc.message)
		}
	}
}

func TestAsyncSecretRevealDoesNotMutateRequestAudit(t *testing.T) {
	server, db, trusted := newSecretRevealJobServer(t)
	defer db.Close()
	shared := &ContextShared{Operation: "run_job", Target: "/jobs/audit"}
	ctx := context.WithValue(rbacEnforcedCtx(trusted, types.ADMIN_USER), types.SHARED, shared)
	ctx = system.WithApiScopes(ctx, []string{"app:update", "secret:reveal"})
	response, err := server.RunJob(ctx, "/jobs/audit", "reveal", false, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		// This is the request finalizer's read, concurrent with the worker.
		if shared.Operation != "run_job" || shared.Target != "/jobs/audit" {
			t.Fatal("job relabeled triggering request's audit event")
		}
		run, err := db.GetJobRun(trusted, response.Run.Id)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status != types.JobRunRunning {
			if run.Status != types.JobRunSucceeded || run.Message != "revealed" {
				t.Fatalf("secret reveal job failed: %+v", run)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("secret reveal job did not finish")
}
