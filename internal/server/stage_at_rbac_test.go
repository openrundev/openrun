// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// A custom stage_at domain is a location the caller picks, the caller needs
// app:create there: a grant on one domain must not allow placing the stage
// app on another domain
func TestStageAtCustomDomainNeedsCreatePerm(t *testing.T) {
	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close() //nolint:errcheck
	server.staticConfig.System.StageAt = "path"

	rbacConfig := &types.RBACConfig{
		Roles: map[string][]types.RBACPermission{"creator": {types.PermissionCreate}},
		Grants: []types.RBACGrant{
			{Users: []string{"builtin:mallory"}, Roles: []string{"creator"}, Targets: []string{"teama.localhost:**", "teamstage.localhost:**"}},
		},
	}
	mgr, err := rbac.NewRBACHandler(server.Logger, rbacConfig, server.staticConfig)
	if err != nil {
		t.Fatal(err)
	}
	server.rbacManager = mgr

	sourceDir := writeStageTestAppSource(t)
	createStageTestApp(t, ctx, server, db, sourceDir, "/payroll", "")
	before, err := server.MatchApp("localhost", "/payroll/login")
	if err != nil {
		t.Fatal(err)
	}

	low := system.WithDiskSourceAccess(&managementAPIContext{Context: ctx, userId: "builtin:mallory", groups: []string{}, rbacEnabled: true}, true)
	create := func(appPath, stageAt string) error {
		t.Helper()
		tx, err := db.BeginTransaction(low)
		if err != nil {
			t.Fatal(err)
		}
		req := &types.CreateAppRequest{SourceUrl: sourceDir, StageAt: stageAt, AppAuthn: "none"}
		if _, err := server.CreateAppTx(low, tx, appPath, DeployOptions{}, req, nil, server.newBindingAccountManager(false), nil); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		server.apps.ResetAllAppCache()
		return nil
	}

	// Stage domain outside the caller's grant
	for _, stageAt := range []string{"localhost", "other.localhost"} {
		err := create("teama.localhost:/payroll", stageAt)
		if err == nil || !strings.Contains(err.Error(), string(types.PermissionCreate)) {
			t.Fatalf("stage_at %s: expected an app:create denial, got %v", stageAt, err)
		}
	}
	after, err := server.MatchApp("localhost", "/payroll/login")
	if err != nil {
		t.Fatal(err)
	}
	if after.Id != before.Id {
		t.Fatalf("existing app route was taken over by %s", after.Id)
	}

	// A stage domain inside the grant, and the derived modes, are allowed
	if err := create("teama.localhost:/ok1", "teamstage.localhost"); err != nil {
		t.Fatalf("stage_at inside the grant: %v", err)
	}
	if err := create("teama.localhost:/ok2", "path"); err != nil {
		t.Fatalf("stage_at path: %v", err)
	}
}

// The apply pre-pass prepares app creates before Apply marks the operation:
// a custom stage_at domain needs app:apply there, as in the apply itself
func TestStageAtCustomDomainApplyPrepass(t *testing.T) {
	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close() //nolint:errcheck
	server.staticConfig.System.StageAt = "path"

	mgr, err := rbac.NewRBACHandler(server.Logger, &types.RBACConfig{
		Roles: map[string][]types.RBACPermission{"applier": {types.PermissionApply}},
		Grants: []types.RBACGrant{
			{Users: []string{"builtin:deployer"}, Roles: []string{"applier"}, Targets: []string{"teama.localhost:**", "teamstage.localhost:**"}},
		},
	}, server.staticConfig)
	if err != nil {
		t.Fatal(err)
	}
	server.rbacManager = mgr

	caller := &managementAPIContext{Context: ctx, userId: "builtin:deployer", groups: []string{}, rbacEnabled: true}
	req := &types.CreateAppRequest{StageAt: "teamstage.localhost"}
	newEntry := func() *types.AppEntry {
		return &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "stagetest"), Path: "/svc", Domain: "teama.localhost"}
	}

	if _, err := server.prepareStageAppEntry(caller, newEntry(), req); err == nil ||
		!strings.Contains(err.Error(), string(types.PermissionCreate)) {
		t.Fatalf("expected an app:create denial outside apply, got %v", err)
	}
	prepass := context.WithValue(caller, types.APPLY_PREPARE, "true")
	if _, err := server.prepareStageAppEntry(prepass, newEntry(), req); err != nil {
		t.Fatalf("apply pre-pass with app:apply on both domains: %v", err)
	}
	req.StageAt = "other.localhost"
	if _, err := server.prepareStageAppEntry(prepass, newEntry(), req); err == nil ||
		!strings.Contains(err.Error(), string(types.PermissionApply)) {
		t.Fatalf("expected an app:apply denial for a domain outside the grant, got %v", err)
	}
}

// Apps without a domain are served on the default domain: an app on the
// explicit default domain cannot overlap one without a domain, or the reverse
func TestCheckAppValidDefaultDomainNamespace(t *testing.T) {
	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close() //nolint:errcheck
	server.staticConfig.System.StageAt = "path"
	defaultDomain := server.Config().System.DefaultDomain
	if defaultDomain == "" {
		t.Skip("no default domain in the test config")
	}

	sourceDir := writeStageTestAppSource(t)
	createStageTestApp(t, ctx, server, db, sourceDir, "/nodomain", "")
	createStageTestApp(t, ctx, server, db, sourceDir, defaultDomain+":/withdomain", "")

	tests := []struct {
		domain, path string
		overlap      bool
	}{
		{defaultDomain, "/nodomain", true},
		{defaultDomain, "/nodomain/sub", true},
		{"", "/withdomain", true},
		{"", "/other", false},
		{defaultDomain, "/other", false},
		{"other.example.com", "/nodomain", false},
	}
	for _, test := range tests {
		matched, err := server.CheckAppValid(test.domain, test.path)
		if err != nil {
			t.Fatal(err)
		}
		if (matched != "") != test.overlap {
			t.Errorf("CheckAppValid(%q, %q) = %q, want overlap %t", test.domain, test.path, matched, test.overlap)
		}
	}
}

// The folder part of a git source url must stay inside the checkout, also
// when the repository has a symlink at that name
func TestCheckFolderInCheckout(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(repo, "app"), outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(repo, "app"), filepath.Join(repo, "inner")); err != nil {
		t.Fatal(err)
	}
	if err := checkFolderInCheckout(repo, filepath.Join(repo, "app")); err != nil {
		t.Fatalf("folder inside the checkout: %v", err)
	}
	if err := checkFolderInCheckout(repo, filepath.Join(repo, "inner")); err != nil {
		t.Fatalf("symlink which stays inside the checkout: %v", err)
	}
	if err := checkFolderInCheckout(repo, filepath.Join(repo, "link")); err == nil {
		t.Fatal("expected a folder which is a symlink out of the checkout to be refused")
	}
	if err := checkFolderInCheckout(repo, filepath.Join(repo, "link", "sub")); err == nil {
		t.Fatal("expected a folder below a symlink out of the checkout to be refused")
	}
}
