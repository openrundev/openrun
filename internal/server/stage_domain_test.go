// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// TestStageDomainSuffix covers the "domain_suffix" derivation: the stage label
// goes after the first label of a subdomain, apex domains (the default
// domain, registrable domains, public suffixes, bare hosts) get it prepended
func TestStageDomainSuffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		defaultDomain string
		domain        string
		want          string
	}{
		// Default domain and its subdomains
		{"example.com", "example.com", "stage.example.com"},
		{"example.com", "EXAMPLE.com", "stage.EXAMPLE.com"},
		{"example.com", "app.example.com", "app.stage.example.com"},
		{"example.com", "x.y.example.com", "x.stage.y.example.com"},
		{"example.com", "stage.example.com", "stage.stage.example.com"},
		{"example.com", "App.Example.COM", "App.stage.Example.COM"},
		// Label boundary: not a subdomain of the default domain, registrable
		{"example.com", "notexample.com", "stage.notexample.com"},

		// Other domains, the public suffix list decides
		{"example.com", "other.org", "stage.other.org"},
		{"example.com", "app.other.org", "app.stage.other.org"},
		{"example.com", "x.y.other.org", "x.stage.y.other.org"},
		{"example.com", "other.co.uk", "stage.other.co.uk"},
		{"example.com", "app.other.co.uk", "app.stage.other.co.uk"},
		{"example.com", "co.uk", "stage.co.uk"}, // public suffix itself
		{"example.com", "my_app.other.org", "my_app.stage.other.org"},

		// The list is case sensitive and in punycode, the lookup is not
		{"example.com", "other.CO.UK", "stage.other.CO.UK"},
		{"example.com", "app.other.CO.UK", "app.stage.other.CO.UK"},
		{"example.com", "me.GITHUB.IO", "stage.me.GITHUB.IO"},
		{"example.com", "食狮.公司.cn", "stage.食狮.公司.cn"},
		{"example.com", "x.食狮.公司.cn", "x.stage.食狮.公司.cn"},
		{"example.com", "xn--85x722f.xn--55qx5d.cn", "stage.xn--85x722f.xn--55qx5d.cn"},
		// Unicode normalization: fullwidth com.cn, decomposed accent in a listed suffix
		{"example.com", "foo.ｃｏｍ.cn", "stage.foo.ｃｏｍ.cn"},
		{"example.com", "x.foo.ｃｏｍ.cn", "x.stage.foo.ｃｏｍ.cn"},
		{"example.com", "foo.aéroport.ci", "stage.foo.aéroport.ci"},
		{"example.com", "x.foo.aéroport.ci", "x.stage.foo.aéroport.ci"},

		// Characters a resolver maps to a label separator: the first "." is not
		// the end of the first label, so nothing is inserted
		{"example.com", "app。other.org", "stage.app。other.org"},
		{"example.com", "app.sub。other.org", "stage.app.sub。other.org"},
		{"example.com", "app．other.org", "stage.app．other.org"},
		{"example.com", "app。example.com", "stage.app。example.com"},
		{"example.com", "x。y.example.com", "stage.x。y.example.com"},
		{"example.com", "a⒈b.other.org", "stage.a⒈b.other.org"}, // "⒈" maps to "1."
		// The default domain comparison is ASCII only: no unicode case folding
		{"Σ.example.com", "σ.example.com", "σ.stage.example.com"},
		{"Σ.example.com", "app.σ.example.com", "app.stage.σ.example.com"},
		{"σ.example.com", "app.σ.example.com", "app.stage.σ.example.com"},
		{"σ.example.com", "σ.example.com", "stage.σ.example.com"},

		// Private section of the list
		{"example.com", "me.github.io", "stage.me.github.io"},
		{"example.com", "x.me.github.io", "x.stage.me.github.io"},
		// Wildcard (*.ck) and exception (!www.ck) rules
		{"example.com", "foo.ck", "stage.foo.ck"},
		{"example.com", "a.foo.ck", "stage.a.foo.ck"},
		{"example.com", "x.a.foo.ck", "x.stage.a.foo.ck"},
		{"example.com", "www.ck", "stage.www.ck"},
		{"example.com", "x.www.ck", "x.stage.www.ck"},

		// Default domain below a registrable domain
		{"apps.example.com", "example.com", "stage.example.com"},
		{"apps.example.com", "apps.example.com", "stage.apps.example.com"},
		{"apps.example.com", "tool.apps.example.com", "tool.stage.apps.example.com"},
		{"apps.example.com", "other.example.com", "other.stage.example.com"},

		// Names the list does not know: the default domain check comes first
		{"corp.internal", "app.corp.internal", "app.stage.corp.internal"},
		{"localhost", "localhost", "stage.localhost"},
		{"localhost", "app.localhost", "app.stage.localhost"},
		{"localhost", "app.test", "stage.app.test"},
		{"localhost", "app.corp.test", "app.stage.corp.test"},
		{"me.github.io", "x.me.github.io", "x.stage.me.github.io"},

		// Bare hosts, IP addresses and malformed names are prefixed, as in domain mode
		{"example.com", "myhost", "stage.myhost"},
		{"localhost", "127.0.0.1", "stage.127.0.0.1"},
		{"localhost", "::1", "stage.::1"},
		{"example.com", ".example.com", "stage..example.com"},
		{"example.com", "x..example.com", "stage.x..example.com"},
		{"example.com", "app.example.com.", "stage.app.example.com."},
		{"example.com", "a..other.org", "stage.a..other.org"},
		// Hyphens are not validated, the list decides
		{"example.com", "-bad-.other.org", "-bad-.stage.other.org"},
		{"example.com", "ab--cd.other.org", "ab--cd.stage.other.org"},
		{"example.com", "ab--cd.example.com", "ab--cd.stage.example.com"},
		// Names the mapping rejects are prefixed, also below the default domain
		{"example.com", "xn--zz.other.org", "stage.xn--zz.other.org"},
		{"example.com", "xn--zz.example.com", "stage.xn--zz.example.com"},
		{"example.com", "x。xn--zz.example.com", "stage.x。xn--zz.example.com"},
		{"example.com", "x。ab--cd.example.com", "stage.x。ab--cd.example.com"},

		// No default domain
		{"", "app.example.com", "app.stage.example.com"},
		{"", "example.com", "stage.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.defaultDomain+"/"+tc.domain, func(t *testing.T) {
			t.Parallel()
			if got := stageDomainSuffix(tc.domain, tc.defaultDomain, "stage"); got != tc.want {
				t.Errorf("stageDomainSuffix(%q, default %q) = %q, want %q", tc.domain, tc.defaultDomain, got, tc.want)
			}
		})
	}
}

// TestStageDomainSuffixLabel covers the stage label normalization, and that
// the apex branch matches what the domain mode derives
func TestStageDomainSuffixLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		label    string
		wantSub  string // for app.example.com
		wantApex string // for example.com
	}{
		{"stage", "app.stage.example.com", "stage.example.com"},
		{"", "app.stage.example.com", "stage.example.com"},
		{"  ", "app.stage.example.com", "stage.example.com"},
		{".", "app.stage.example.com", "stage.example.com"},
		{"stage.", "app.stage.example.com", "stage.example.com"},
		{" stg ", "app.stg.example.com", "stg.example.com"},
		{"stage.eu", "app.stage.eu.example.com", "stage.eu.example.com"},
		{"stage.stage", "app.stage.stage.example.com", "stage.stage.example.com"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.label), func(t *testing.T) {
			t.Parallel()
			if got := stageDomainSuffix("app.example.com", "example.com", tc.label); got != tc.wantSub {
				t.Errorf("subdomain: got %q, want %q", got, tc.wantSub)
			}
			got := stageDomainSuffix("example.com", "example.com", tc.label)
			if got != tc.wantApex {
				t.Errorf("apex: got %q, want %q", got, tc.wantApex)
			}
			if tc.label != "." {
				// Other than the degenerate "." label (kept as is in domain mode),
				// an apex domain stages at the same place in both modes
				if prefix := stageDomain("example.com", tc.label); prefix != got {
					t.Errorf("apex %q differs from domain mode %q", got, prefix)
				}
			}
		})
	}
}

// TestStageDomainSuffixDistinct checks that distinct prod domains never derive
// the same stage domain under one configuration, including against the stage
// domains the domain mode derives (a fleet with both shapes), and with
// repeated label stage labels
func TestStageDomainSuffixDistinct(t *testing.T) {
	t.Parallel()

	domains := []string{
		"example.com", "app.example.com", "stage.example.com", "stage.stage.example.com",
		"app.stage.example.com", "stage.app.example.com", "x.y.example.com", "x.stage.y.example.com",
		"stage.x.y.example.com", "eu.example.com", "stage.eu.example.com", "eu.stage.example.com",
		"other.org", "stage.other.org", "app.other.org", "stage.app.other.org", "app.stage.other.org",
	}
	for _, label := range []string{"stage", "stage.eu", "stage.stage"} {
		derived := map[string]string{} // stage domain -> prod domain
		for _, domain := range domains {
			for _, stage := range []string{stageDomainSuffix(domain, "example.com", label), stageDomain(domain, label)} {
				if prev, ok := derived[stage]; ok && prev != domain {
					t.Errorf("label %q: %s and %s both stage at %s", label, prev, domain, stage)
				}
				derived[stage] = domain
			}
		}
	}
}

func TestStageAppPathDomainSuffixMode(t *testing.T) {
	t.Parallel()

	newServer := func(system types.SystemConfig) *Server {
		return &Server{staticConfig: &types.ServerConfig{System: system}}
	}
	server := newServer(types.SystemConfig{DefaultDomain: "apps.example.com"})

	tests := []struct {
		name    string
		prod    types.AppPathDomain
		stageAt string
		want    types.AppPathDomain
	}{
		{
			name: "fallback default is domain_suffix",
			prod: types.AppPathDomain{Domain: "app.apps.example.com", Path: "/tools/app"},
			want: types.AppPathDomain{Domain: "app.stage.apps.example.com", Path: "/tools/app"},
		},
		{
			name:    "explicit mode, subdomain of default domain",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/"},
			stageAt: "domain_suffix",
			want:    types.AppPathDomain{Domain: "app.stage.apps.example.com", Path: "/"},
		},
		{
			name:    "mode name is case insensitive",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/"},
			stageAt: " Domain_Suffix ",
			want:    types.AppPathDomain{Domain: "app.stage.apps.example.com", Path: "/"},
		},
		{
			name:    "app without domain uses the default domain, prepended",
			prod:    types.AppPathDomain{Path: "/tools/app"},
			stageAt: "domain_suffix",
			want:    types.AppPathDomain{Domain: "stage.apps.example.com", Path: "/tools/app"},
		},
		{
			name:    "subdomain outside the default domain",
			prod:    types.AppPathDomain{Domain: "app.other.org", Path: "/"},
			stageAt: "domain_suffix",
			want:    types.AppPathDomain{Domain: "app.stage.other.org", Path: "/"},
		},
		{
			name:    "registrable domain outside the default domain",
			prod:    types.AppPathDomain{Domain: "other.org", Path: "/"},
			stageAt: "domain_suffix",
			want:    types.AppPathDomain{Domain: "stage.other.org", Path: "/"},
		},
		{
			name:    "domain mode keeps the prefix shape",
			prod:    types.AppPathDomain{Domain: "app.apps.example.com", Path: "/"},
			stageAt: "domain",
			want:    types.AppPathDomain{Domain: "stage.app.apps.example.com", Path: "/"},
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

	t.Run("custom stage label", func(t *testing.T) {
		t.Parallel()
		server := newServer(types.SystemConfig{DefaultDomain: "example.com", DefaultStageDomain: "stg"})
		got, err := server.stageAppPathDomain(types.AppPathDomain{Domain: "app.example.com", Path: "/"}, "")
		if err != nil || got.Domain != "app.stg.example.com" {
			t.Fatalf("got %s (%v), want app.stg.example.com:/", got, err)
		}
	})

	t.Run("derived domain with a colon is rejected", func(t *testing.T) {
		t.Parallel()
		// domain:path would not parse back from the stored link to the stage app
		prod := types.AppPathDomain{Domain: "app.example.com", Path: "/reports"}
		for _, system := range []types.SystemConfig{
			{DefaultDomain: "example.com", DefaultStageDomain: "stage:8080"},
			{DefaultDomain: "example.com:8080"},
		} {
			server := newServer(system)
			for _, mode := range []string{"domain_suffix", "domain"} {
				for _, app := range []types.AppPathDomain{prod, {Path: "/reports"}} {
					got, err := server.stageAppPathDomain(app, mode)
					if !strings.Contains(got.Domain, ":") && err == nil {
						continue // this combination derives a usable domain
					}
					if err == nil || !strings.Contains(err.Error(), "cannot contain ':'") {
						t.Errorf("%+v mode %s app %s: got %s, %v; want the colon error", system, mode, app, got, err)
					}
				}
			}
			// path staging does not derive a domain
			if _, err := server.stageAppPathDomain(prod, "path"); err != nil {
				t.Errorf("path mode: %v", err)
			}
		}
		server := newServer(types.SystemConfig{DefaultDomain: "example.com", DefaultStageDomain: "stage:8080"})
		if _, err := server.stageAppPathDomain(prod, ""); err == nil {
			t.Error("stage label with a colon was accepted")
		}
	})

	t.Run("no app domain and no default domain", func(t *testing.T) {
		t.Parallel()
		server := newServer(types.SystemConfig{})
		for _, mode := range []string{"", "domain_suffix", "domain"} {
			if _, err := server.stageAppPathDomain(types.AppPathDomain{Path: "/app"}, mode); err == nil ||
				!strings.Contains(err.Error(), "default_domain are empty") {
				t.Errorf("mode %q: error = %v, want the empty domain error", mode, err)
			}
		}
		// An app domain is enough
		got, err := server.stageAppPathDomain(types.AppPathDomain{Domain: "app.example.com", Path: "/"}, "")
		if err != nil || got.Domain != "app.stage.example.com" {
			t.Fatalf("got %s (%v), want app.stage.example.com:/", got, err)
		}
	})
}

// TestStageAtPrecedence: the per app value wins over the dynamic system
// setting, which wins over the static one, which wins over the fallback
func TestStageAtPrecedence(t *testing.T) {
	t.Parallel()

	logger := types.NewLogger(&types.LogConfig{Level: "ERROR"})
	prod := types.AppPathDomain{Domain: "app.example.com", Path: "/"}
	const (
		suffixShape = "app.stage.example.com:/"
		prefixShape = "stage.app.example.com:/"
		pathShape   = "app.example.com:/_cl_stage"
	)
	check := func(t *testing.T, server *Server, stageAt, want string) {
		t.Helper()
		got, err := server.stageAppPathDomain(prod, stageAt)
		if err != nil {
			t.Fatalf("stageAppPathDomain(%q): %v", stageAt, err)
		}
		if got.String() != want {
			t.Errorf("stageAppPathDomain(%q) = %s, want %s", stageAt, got, want)
		}
	}

	static := &types.ServerConfig{}
	static.System.DefaultDomain = "example.com"
	server := &Server{Logger: logger, staticConfig: static}

	// Nothing set: built in fallback
	check(t, server, "", suffixShape)

	// Static setting
	static.System.StageAt = "domain"
	check(t, server, "", prefixShape)

	// Dynamic setting over static, through the config merge
	merged, err := mergeDynamicConfig(logger, static, &types.DynamicConfig{
		Settings: map[string]map[string]any{"system": {"stage_at": "path"}},
	}, nil)
	if err != nil {
		t.Fatalf("merge dynamic config: %v", err)
	}
	if merged.System.StageAt != "path" {
		t.Fatalf("merged stage_at = %q, want path", merged.System.StageAt)
	}
	server.effectiveConfig.Store(merged)
	check(t, server, "", pathShape)

	// Per app value over both
	check(t, server, "domain_suffix", suffixShape)
	check(t, server, "domain", prefixShape)
	check(t, server, "staging.example.net", "staging.example.net:/")

	// domain_suffix as the dynamic setting
	merged, err = mergeDynamicConfig(logger, static, &types.DynamicConfig{
		Settings: map[string]map[string]any{"system": {"stage_at": "domain_suffix"}},
	}, nil)
	if err != nil {
		t.Fatalf("merge dynamic config: %v", err)
	}
	server.effectiveConfig.Store(merged)
	check(t, server, "", suffixShape)
}

// writeStageTestAppSource creates a minimal static app source dir
func writeStageTestAppSource(t *testing.T) string {
	t.Helper()
	sourceDir := t.TempDir()
	appStar := `app = ace.app("stage test app", static_only=True, index="index.html")`
	if err := os.WriteFile(filepath.Join(sourceDir, "app.star"), []byte(appStar), 0o600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "index.html"), []byte("v1"), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	return sourceDir
}

func createStageTestApp(t *testing.T, ctx context.Context, server *Server, db *metadata.Metadata, sourceDir, path, stageAt string) {
	t.Helper()
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	req := &types.CreateAppRequest{SourceUrl: sourceDir, StageAt: stageAt}
	if _, err := server.CreateAppTx(ctx, tx, path, DeployOptions{Approve: true}, req, nil, server.newBindingAccountManager(false), nil); err != nil {
		_ = tx.Rollback()
		t.Fatalf("create %s: %v", path, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	server.apps.ResetAllAppCache()
}

// stageTestLocation returns the stored stage app location of a prod app, and
// its stage_at as export derives it
func stageTestLocation(t *testing.T, ctx context.Context, server *Server, prodPath string) (string, string, []string) {
	t.Helper()
	pathDomain, err := parseAppPath(prodPath)
	if err != nil {
		t.Fatalf("parse %s: %v", prodPath, err)
	}
	prod, err := server.db.GetAppEntry(ctx, pathDomain)
	if err != nil {
		t.Fatalf("get prod app %s: %v", prodPath, err)
	}
	stage, err := server.getStageApp(ctx, types.Transaction{}, prod)
	if err != nil {
		t.Fatalf("get stage app of %s: %v", prodPath, err)
	}
	if prod.LinkedAppPath != stage.AppPathDomain().String() {
		t.Errorf("%s linked app path %q does not match the stage app %s", prodPath, prod.LinkedAppPath, stage.AppPathDomain())
	}
	builder := newExportBuilder(types.ExportOptions{})
	stageAt := server.deriveStageAt(ctx, types.Transaction{}, prod, builder)
	return stage.AppPathDomain().String(), stageAt, builder.warnings
}

// TestStageDefaultChangeKeepsExistingApps is the upgrade case: apps created
// under the old default keep their stored stage location once the default is
// domain_suffix, only new apps get the new shape, and export emits the mode
// which reproduces each location
func TestStageDefaultChangeKeepsExistingApps(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t) // stage_at = "domain", default domain localhost
	defer db.Close()
	sourceDir := writeStageTestAppSource(t)

	createStageTestApp(t, ctx, server, db, sourceDir, "old.localhost:/", "")
	createStageTestApp(t, ctx, server, db, sourceDir, "/oldpath", "")
	createStageTestApp(t, ctx, server, db, sourceDir, "/pathstaged", "path")
	createStageTestApp(t, ctx, server, db, sourceDir, "custom.localhost:/", "stg.example.net")

	existing := []struct {
		prod, wantStage, wantStageAt string
	}{
		{"old.localhost:/", "stage.old.localhost:/", "domain"},
		{"/oldpath", "stage.localhost:/oldpath", ""}, // apex, same in both modes: matches the new default too
		{"/pathstaged", "/pathstaged_cl_stage", "path"},
		{"custom.localhost:/", "stg.example.net:/", "stg.example.net"},
	}
	for _, app := range existing {
		if stage, _, _ := stageTestLocation(t, ctx, server, app.prod); stage != app.wantStage {
			t.Fatalf("before the default change: %s staged at %s, want %s", app.prod, stage, app.wantStage)
		}
	}

	// The upgrade: no explicit stage_at, the built in default applies
	server.staticConfig.System.StageAt = ""
	server.apps.ResetAllAppCache()

	for _, app := range existing {
		stage, stageAt, warnings := stageTestLocation(t, ctx, server, app.prod)
		if stage != app.wantStage {
			t.Errorf("%s stage app moved to %s, want %s", app.prod, stage, app.wantStage)
		}
		if stageAt != app.wantStageAt {
			t.Errorf("%s exports stage_at %q, want %q", app.prod, stageAt, app.wantStageAt)
		}
		if len(warnings) != 0 {
			t.Errorf("%s export warnings: %v", app.prod, warnings)
		}
	}

	// A new app gets the new shape and exports without a stage_at
	createStageTestApp(t, ctx, server, db, sourceDir, "new.localhost:/", "")
	stage, stageAt, _ := stageTestLocation(t, ctx, server, "new.localhost:/")
	if stage != "new.stage.localhost:/" || stageAt != "" {
		t.Errorf("new app staged at %s with stage_at %q, want new.stage.localhost:/ and no stage_at", stage, stageAt)
	}
	// The pinned mode still gives the old shape
	createStageTestApp(t, ctx, server, db, sourceDir, "pinned.localhost:/", "domain")
	stage, stageAt, _ = stageTestLocation(t, ctx, server, "pinned.localhost:/")
	if stage != "stage.pinned.localhost:/" || stageAt != "domain" {
		t.Errorf("pinned app staged at %s with stage_at %q, want stage.pinned.localhost:/ and domain", stage, stageAt)
	}

	// Requests are routed to both shapes
	for host, wantId := range map[string]string{
		"stage.old.localhost": types.ID_PREFIX_APP_STAGE,
		"new.stage.localhost": types.ID_PREFIX_APP_STAGE,
		"new.localhost":       types.ID_PREFIX_APP_PROD,
	} {
		info, err := server.MatchApp(host, "/")
		if err != nil {
			t.Errorf("match %s: %v", host, err)
		} else if !strings.HasPrefix(string(info.Id), wantId) {
			t.Errorf("match %s: app id %s, want prefix %s", host, info.Id, wantId)
		}
	}
	// and the derived stage domain is one a certificate can be issued for
	for _, host := range []string{"new.stage.localhost", "stage.old.localhost"} {
		if allowed, err := server.certDomainAllowed(host); err != nil || !allowed {
			t.Errorf("certDomainAllowed(%s) = %v, %v, want true", host, allowed, err)
		}
	}
	if allowed, err := server.certDomainAllowed("other.stage.localhost"); err != nil || allowed {
		t.Errorf("certDomainAllowed(other.stage.localhost) = %v, %v, want false", allowed, err)
	}
}

// TestStageAtExport covers stage_at derivation on a server whose default is
// not domain_suffix, and a stage domain spelled like a mode name
func TestStageAtExport(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()
	server.staticConfig.System.StageAt = "path"
	sourceDir := writeStageTestAppSource(t)

	createStageTestApp(t, ctx, server, db, sourceDir, "sfx.localhost:/", "domain_suffix")
	createStageTestApp(t, ctx, server, db, sourceDir, "/apex", "domain_suffix")
	createStageTestApp(t, ctx, server, db, sourceDir, "pfx.localhost:/", "domain")
	createStageTestApp(t, ctx, server, db, sourceDir, "/dflt", "")

	for _, tc := range []struct {
		prod, wantStage, wantStageAt string
	}{
		{"sfx.localhost:/", "sfx.stage.localhost:/", "domain_suffix"},
		// Both domain modes derive stage.localhost, "domain" is what older servers understand
		{"/apex", "stage.localhost:/apex", "domain"},
		{"pfx.localhost:/", "stage.pfx.localhost:/", "domain"},
		{"/dflt", "/dflt_cl_stage", ""},
	} {
		stage, stageAt, warnings := stageTestLocation(t, ctx, server, tc.prod)
		if stage != tc.wantStage || stageAt != tc.wantStageAt {
			t.Errorf("%s: staged at %s with stage_at %q, want %s and %q", tc.prod, stage, stageAt, tc.wantStage, tc.wantStageAt)
		}
		if len(warnings) != 0 {
			t.Errorf("%s export warnings: %v", tc.prod, warnings)
		}
	}

	// A stage app on a domain literally named like a mode (possible before the
	// name was reserved) cannot be exported as a custom stage domain
	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	prod := &types.AppEntry{
		Id:            types.ID_PREFIX_APP_PROD + "literal",
		Path:          "/literal",
		LinkedAppPath: "domain_suffix:/literal",
		SourceUrl:     sourceDir,
	}
	stage := &types.AppEntry{
		Id:            types.ID_PREFIX_APP_STAGE + "literal",
		Domain:        "domain_suffix",
		Path:          "/literal",
		MainApp:       prod.Id,
		LinkedAppPath: "/literal",
		SourceUrl:     sourceDir,
	}
	for _, entry := range []*types.AppEntry{prod, stage} {
		if err := db.CreateApp(ctx, tx, entry); err != nil {
			t.Fatalf("create %s: %v", entry.Id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	stagePath, stageAt, warnings := stageTestLocation(t, ctx, server, "/literal")
	if stagePath != "domain_suffix:/literal" {
		t.Fatalf("literal stage app at %s", stagePath)
	}
	if stageAt != "" {
		t.Errorf("literal mode named stage domain exported as stage_at %q, want it omitted", stageAt)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "stage_at mode name") {
		t.Errorf("warnings = %v, want one mode name warning", warnings)
	}
}

// TestStageSuffixCreateRejections: the derived domain_suffix location goes
// through the same create time checks as any stage location
func TestStageSuffixCreateRejections(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()
	server.staticConfig.System.StageAt = "domain_suffix"
	server.staticConfig.Security.AuthCallbackDomain = "login.stage.localhost"
	server.formLogin = &FormLoginManager{getConfig: server.Config}
	sourceDir := writeStageTestAppSource(t)

	// A prod app already sits where the stage app would go
	createStageTestApp(t, ctx, server, db, sourceDir, "taken.stage.localhost:/sub", "path")

	create := func(path string) error {
		t.Helper()
		tx, err := db.BeginTransaction(ctx)
		if err != nil {
			t.Fatalf("begin transaction: %v", err)
		}
		if _, err := server.CreateAppTx(ctx, tx, path, DeployOptions{Approve: true},
			&types.CreateAppRequest{SourceUrl: sourceDir}, nil, server.newBindingAccountManager(false), nil); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		server.apps.ResetAllAppCache()
		return nil
	}
	assertNoApp := func(domain, path string) {
		t.Helper()
		if _, err := db.GetAppEntry(ctx, types.AppPathDomain{Domain: domain, Path: path}); !errors.Is(err, metadata.ErrAppNotFound) {
			t.Errorf("app %s:%s lookup error = %v, want ErrAppNotFound", domain, path, err)
		}
	}

	err := create("taken.localhost:/")
	if err == nil || !strings.Contains(err.Error(), "stage app overlaps with existing app at taken.stage.localhost:/sub") {
		t.Fatalf("overlap: error = %v, want the stage overlap error", err)
	}
	assertNoApp("taken.localhost", "/")
	assertNoApp("taken.stage.localhost", "/")

	// The derived stage domain is the reserved auth callback domain
	err = create("login.localhost:/")
	if err == nil || !strings.Contains(err.Error(), `stage apps cannot be created on the auth callback domain "login.stage.localhost"`) {
		t.Fatalf("auth domain: error = %v, want the auth callback domain error", err)
	}
	assertNoApp("login.localhost", "/")
	assertNoApp("login.stage.localhost", "/")

	// An unrelated app is fine
	if err := create("fine.localhost:/"); err != nil {
		t.Fatalf("create fine.localhost: %v", err)
	}
	if stage, _, _ := stageTestLocation(t, ctx, server, "fine.localhost:/"); stage != "fine.stage.localhost:/" {
		t.Errorf("fine.localhost staged at %s", stage)
	}
}

// TestStageDefaultDomainChange: changing default_domain after creation does
// not rewrite stored stage links. Entries stored without a domain are served
// on the current default domain, a domain mode stage app has an explicit
// domain and stays where it was created (same as the domain mode)
func TestStageDefaultDomainChange(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t) // default domain localhost
	defer db.Close()
	server.staticConfig.System.StageAt = "domain_suffix"
	server.staticConfig.Http.Port = 8080
	sourceDir := writeStageTestAppSource(t)

	createStageTestApp(t, ctx, server, db, sourceDir, "/pathstaged", "path")
	createStageTestApp(t, ctx, server, db, sourceDir, "/suffixstaged", "")

	urls := func(prodPath string) (string, string, string) {
		t.Helper()
		prod, err := db.GetAppEntry(ctx, types.AppPathDomain{Path: prodPath})
		if err != nil {
			t.Fatalf("get %s: %v", prodPath, err)
		}
		stage, err := server.getStageApp(ctx, types.Transaction{}, prod)
		if err != nil {
			t.Fatalf("get stage of %s: %v", prodPath, err)
		}
		return prod.LinkedAppPath, server.getAppHttpUrl(prod), server.getAppHttpUrl(stage)
	}
	assertUrls := func(prodPath, wantLink, wantProd, wantStage string) {
		t.Helper()
		link, prodUrl, stageUrl := urls(prodPath)
		if link != wantLink || prodUrl != wantProd || stageUrl != wantStage {
			t.Errorf("%s: link %q prod %q stage %q, want %q %q %q", prodPath, link, prodUrl, stageUrl, wantLink, wantProd, wantStage)
		}
	}

	assertUrls("/pathstaged", "/pathstaged_cl_stage", "http://localhost:8080/pathstaged", "http://localhost:8080/pathstaged_cl_stage")
	assertUrls("/suffixstaged", "stage.localhost:/suffixstaged", "http://localhost:8080/suffixstaged", "http://stage.localhost:8080/suffixstaged")

	server.staticConfig.System.DefaultDomain = "apps.example.com"
	server.apps.ResetAllAppCache()

	// Stored links are unchanged; domainless entries follow the new default
	assertUrls("/pathstaged", "/pathstaged_cl_stage", "http://apps.example.com:8080/pathstaged", "http://apps.example.com:8080/pathstaged_cl_stage")
	assertUrls("/suffixstaged", "stage.localhost:/suffixstaged", "http://apps.example.com:8080/suffixstaged", "http://stage.localhost:8080/suffixstaged")

	// New apps derive from the new default domain
	createStageTestApp(t, ctx, server, db, sourceDir, "/afterchange", "")
	createStageTestApp(t, ctx, server, db, sourceDir, "sub.apps.example.com:/", "")
	if stage, _, _ := stageTestLocation(t, ctx, server, "/afterchange"); stage != "stage.apps.example.com:/afterchange" {
		t.Errorf("/afterchange staged at %s", stage)
	}
	if stage, _, _ := stageTestLocation(t, ctx, server, "sub.apps.example.com:/"); stage != "sub.stage.apps.example.com:/" {
		t.Errorf("sub.apps.example.com staged at %s", stage)
	}
}

// TestStageSuffixMixedCaseDomain pins an existing limitation rather than
// implying support: derivation keeps the case of the prod domain, and domains
// are matched exactly at request time, so a mixed case domain (in any stage
// mode) is not reachable by the lower case host clients send
func TestStageSuffixMixedCaseDomain(t *testing.T) {
	t.Parallel()

	server, db, ctx := newAppAPIMetadataTestServer(t)
	defer db.Close()
	server.staticConfig.System.StageAt = "domain_suffix"
	sourceDir := writeStageTestAppSource(t)

	createStageTestApp(t, ctx, server, db, sourceDir, "Mixed.Localhost:/", "")
	if stage, _, _ := stageTestLocation(t, ctx, server, "Mixed.Localhost:/"); stage != "Mixed.stage.Localhost:/" {
		t.Fatalf("mixed case app staged at %s, want Mixed.stage.Localhost:/", stage)
	}
	if _, err := server.MatchApp("Mixed.stage.Localhost", "/"); err != nil {
		t.Errorf("exact case host did not match: %v", err)
	}
	for _, host := range []string{"mixed.stage.localhost", "mixed.localhost"} {
		if info, err := server.MatchApp(host, "/"); err == nil {
			t.Errorf("lower case host %s matched %s; mixed case domains are now matched case insensitively, update the docs", host, info.Id)
		}
	}
}

// TestStageAtExportReimport: an export applied on a fresh server with the
// same settings recreates every stage app at its original location, and
// re-applying with a different stage_at does not move an existing stage app
func TestStageAtExportReimport(t *testing.T) {
	source, sourceDb, ctx := newApplyTestServer(t) // no stage_at: built in default, default domain localhost
	defer sourceDb.Close()
	appSourceDir := writeExportTestAppSource(t)

	apps := []struct {
		path, stageAt, wantStage string
	}{
		{"sfx.localhost:/", "", "sfx.stage.localhost:/"},
		{"/plain", "", "stage.localhost:/plain"},
		{"deep.sub.localhost:/x", "", "deep.stage.sub.localhost:/x"},
		{"app.example.com:/", "", "app.stage.example.com:/"},
		{"example.com:/apex", "", "stage.example.com:/apex"},
		{"pfx.localhost:/", "domain", "stage.pfx.localhost:/"},
		{"/pathstaged", "path", "/pathstaged_cl_stage"},
		{"custom.localhost:/", "stg.example.net", "stg.example.net:/"},
	}
	var applyData strings.Builder
	for _, app := range apps {
		stageAt := ""
		if app.stageAt != "" {
			stageAt = fmt.Sprintf(", stage_at=%q", app.stageAt)
		}
		fmt.Fprintf(&applyData, "app(%q, %q%s)\n", app.path, appSourceDir, stageAt)
	}
	applyPath := filepath.Join(t.TempDir(), "stage.ace")
	if err := os.WriteFile(applyPath, []byte(applyData.String()), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
	apply := func(server *Server, path string) {
		t.Helper()
		if _, _, err := server.Apply(ctx, types.Transaction{}, path, "all", ApplyOptions{Reload: types.AppReloadOptionNone}, nil); err != nil {
			t.Fatalf("apply %s: %v", path, err)
		}
		server.apps.ResetAllAppCache()
	}
	assertLocations := func(server *Server, label string) {
		t.Helper()
		for _, app := range apps {
			if stage, _, _ := stageTestLocation(t, ctx, server, app.path); stage != app.wantStage {
				t.Errorf("%s: %s staged at %s, want %s", label, app.path, stage, app.wantStage)
			}
		}
	}

	apply(source, applyPath)
	assertLocations(source, "source server")

	exported, err := source.Export(ctx, "all", types.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.Contains(exported, "WARNING") {
		t.Errorf("export has warnings:\n%s", exported)
	}
	// Only the locations which differ from the server default carry a stage_at
	for _, want := range []string{`stage_at="domain"`, `stage_at="path"`, `stage_at="stg.example.net"`} {
		if strings.Count(exported, want) != 1 {
			t.Errorf("export has %d of %s, want 1:\n%s", strings.Count(exported, want), want, exported)
		}
	}
	if strings.Contains(exported, "domain_suffix") {
		t.Errorf("export names the default mode:\n%s", exported)
	}

	// Fresh server, same settings
	target, targetDb, _ := newApplyTestServer(t)
	defer targetDb.Close()
	exportPath := filepath.Join(t.TempDir(), "export.ace")
	if err := os.WriteFile(exportPath, []byte(exported), 0600); err != nil {
		t.Fatalf("write export: %v", err)
	}
	apply(target, exportPath)
	assertLocations(target, "re-import")

	// Re-apply over the existing apps with every stage_at changed: stage_at is
	// a create time property, nothing moves
	var changed strings.Builder
	for _, app := range apps {
		stageAt := "path"
		if app.stageAt == "path" {
			stageAt = "domain_suffix"
		}
		fmt.Fprintf(&changed, "app(%q, %q, stage_at=%q)\n", app.path, appSourceDir, stageAt)
	}
	changedPath := filepath.Join(t.TempDir(), "changed.ace")
	if err := os.WriteFile(changedPath, []byte(changed.String()), 0600); err != nil {
		t.Fatalf("write changed apply file: %v", err)
	}
	apply(source, changedPath)
	assertLocations(source, "after re-apply with a changed stage_at")
}
