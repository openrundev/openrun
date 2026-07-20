// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func TestMarkerBlockUpsertAndRemove(t *testing.T) {
	manual := "# manual header\napp(\"Hand Made\", \"/manual\", \"/src/manual\")\n"

	content, err := upsertMarkerBlock(manual, "/teams/pto", "app(\"PTO\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, manual) {
		t.Fatalf("manual content modified:\n%s", content)
	}
	if !strings.Contains(content, builderMarkerBegin+"/teams/pto\napp(\"PTO\"") {
		t.Fatalf("block not inserted:\n%s", content)
	}

	// republish replaces the block in place, not appends
	updated, err := upsertMarkerBlock(content, "/teams/pto", "app(\"PTO v2\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(updated, builderMarkerBegin+"/teams/pto") != 1 {
		t.Fatalf("expected one block after republish:\n%s", updated)
	}
	if !strings.Contains(updated, "PTO v2") || strings.Contains(updated, "\"PTO\",") {
		t.Fatalf("stanza not replaced:\n%s", updated)
	}

	// a second app gets its own block; removing the first keeps the second
	twoApps, err := upsertMarkerBlock(updated, "/tools/crm", "app(\"CRM\", \"/tools/crm\", \"repo/apps/crm\")")
	if err != nil {
		t.Fatal(err)
	}
	removed, found, err := removeMarkerBlock(twoApps, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("block for /teams/pto not found")
	}
	if strings.Contains(removed, "/teams/pto") || !strings.Contains(removed, "/tools/crm") {
		t.Fatalf("wrong block removed:\n%s", removed)
	}
	if !strings.HasPrefix(removed, manual) {
		t.Fatalf("manual content modified on remove:\n%s", removed)
	}

	// removing an absent block reports not found, no error
	_, found, err = removeMarkerBlock(removed, "/absent")
	if err != nil || found {
		t.Fatalf("expected not found without error, got found=%v err=%v", found, err)
	}
}

func TestMarkerBlockBrokenMarkers(t *testing.T) {
	// begin without end must error, not guess
	broken := builderMarkerBegin + "/teams/pto\napp(...)\n# no end marker\n"
	if _, err := upsertMarkerBlock(broken, "/teams/pto", "app(2)"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
	if _, _, err := removeMarkerBlock(broken, "/teams/pto"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
}

func TestMarkerBlockPathPrefixNoCollision(t *testing.T) {
	// /teams/pto must not match /teams/pto2's markers
	content, err := upsertMarkerBlock("", "/teams/pto2", "app(\"Other\", \"/teams/pto2\", \"repo/apps/pto2\")")
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := removeMarkerBlock(content, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("/teams/pto matched /teams/pto2's block")
	}
}

func TestBuilderSourceZip(t *testing.T) {
	workspace := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("app.star", "app = 1")
	writeFile("static/style.css", "body {}")
	writeFile(".git/config", "excluded")
	writeFile("node_modules/pkg/index.js", "excluded")
	writeFile(".opencode/state", "excluded")

	var buf bytes.Buffer
	if err := writeBuilderSourceZip(workspace, &buf); err != nil {
		t.Fatal(err)
	}
	zipContent := buf.Bytes()
	reader, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, f := range reader.File {
		got[f.Name] = true
	}
	for _, want := range []string{"app.star", "static/style.css"} {
		if !got[want] {
			t.Errorf("zip is missing %s, has %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("zip has unexpected entries (vcs/agent dirs must be excluded): %v", got)
	}

	content, err := reader.Open("app.star")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(content)
	content.Close() //nolint:errcheck
	if string(data) != "app = 1" {
		t.Errorf("app.star content %q", data)
	}
}

// TestBuilderSourceName verifies the published source directory name is
// unique per full publish target: base-name collisions (/teams/a vs
// /other/a) or the same path on two domains must map to different dirs
func TestBuilderSourceName(t *testing.T) {
	tests := []struct{ domain, path, want string }{
		{"", "/app", "app"},
		{"", "/teams/a", "teams_a"},
		{"", "/other/a", "other_a"},
		{"example.com", "/teams/app", "example.com_teams_app"},
		{"other.example.com", "/teams/app", "other.example.com_teams_app"},
		{"Example.com", "/Teams/MyApp", "example.com_teams_myapp"},
	}
	seen := map[string]string{}
	for _, tt := range tests {
		target := types.AppPathDomain{Domain: tt.domain, Path: tt.path}
		got := builderSourceName(target)
		if got != tt.want {
			t.Errorf("builderSourceName(%s): got %q, want %q", target.String(), got, tt.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("source name %q collides: %s and %s", got, prev, target.String())
		}
		seen[got] = target.String()
	}
}

func TestBuilderZipName(t *testing.T) {
	cases := map[string]string{
		"my app":        "my-app-source.zip",
		"Pets/Tracker!": "Pets-Tracker-source.zip",
		"   ":           "builder-app-source.zip",
		"a.b_c-d":       "a.b_c-d-source.zip",
	}
	for in, want := range cases {
		if got := builderZipName(in); got != want {
			t.Errorf("builderZipName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateProfilePublish(t *testing.T) {
	valid := [][2]string{
		{"", ""},
		{"subdomain", "apps.example.com"},
		{"subdomain", "."},
		{"subdomain", "apps."},
		{"path", "/teams"},
		{"glob", "/teams/*"},
		{"glob", "example.com:/**"},
	}
	for _, pair := range valid {
		if err := validateProfilePublish(pair[0], pair[1]); err != nil {
			t.Errorf("mode %q target %q: unexpected error %v", pair[0], pair[1], err)
		}
	}
	invalid := [][2]string{
		{"", "/teams"},            // target without a mode
		{"subdomain", ""},         // missing target
		{"subdomain", "a.com:/x"}, // domain only
		{"path", "teams"},         // must start with /
		{"path", "/teams/*"},      // glob syntax in path mode
		{"glob", ""},              // missing target
		{"glob", "/teams/[x"},     // bad glob
		{"somewhere", "/teams"},   // unknown mode
	}
	for _, pair := range invalid {
		if err := validateProfilePublish(pair[0], pair[1]); err == nil {
			t.Errorf("mode %q target %q: expected an error", pair[0], pair[1])
		}
	}
}

func TestBuilderCheckProfileTarget(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"

	check := func(mode, target, path string) error {
		profile := &types.BuilderProfileConfig{Agent: "opencode", PublishMode: mode, PublishTarget: target}
		appPathDomain, err := parseAppPath(path)
		if err != nil {
			t.Fatalf("parse %q: %v", path, err)
		}
		return s.builderCheckProfileTarget("prof", profile, appPathDomain)
	}

	// No mode: anywhere
	if err := check("", "", "/anywhere"); err != nil {
		t.Errorf("empty mode: %v", err)
	}

	// Subdomain: label under the target domain, path must be /
	if err := check("subdomain", "apps.example.com", "my-app.apps.example.com:/"); err != nil {
		t.Errorf("subdomain ok case: %v", err)
	}
	// trailing dot appends the default domain; "." alone is the default domain
	if err := check("subdomain", "apps.", "my-app.apps.example.com:/"); err != nil {
		t.Errorf("subdomain trailing dot: %v", err)
	}
	if err := check("subdomain", ".", "my-app.example.com:/"); err != nil {
		t.Errorf("subdomain of default domain: %v", err)
	}
	for _, bad := range []string{"/plain-path", "apps.example.com:/", "my-app.other.com:/",
		"my-app.apps.example.com:/sub"} {
		if err := check("subdomain", "apps.example.com", bad); err == nil {
			t.Errorf("subdomain: expected rejection of %q", bad)
		}
	}

	// Path prefix: no domain, path under the prefix
	if err := check("path", "/teams", "/teams/my-app"); err != nil {
		t.Errorf("path ok case: %v", err)
	}
	for _, bad := range []string{"/teamsother/x", "/other/my-app", "d.com:/teams/x"} {
		if err := check("path", "/teams", bad); err == nil {
			t.Errorf("path: expected rejection of %q", bad)
		}
	}

	// Glob: full match required
	if err := check("glob", "/teams/*", "/teams/my-app"); err != nil {
		t.Errorf("glob ok case: %v", err)
	}
	if err := check("glob", "/teams/*", "/other/my-app"); err == nil {
		t.Error("glob: expected rejection outside the glob")
	}
}

func TestBuilderSubdomainLabelValidation(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"
	profile := &types.BuilderProfileConfig{Agent: "opencode", PublishMode: "subdomain", PublishTarget: "."}
	for _, bad := range []string{"some/path", "UPPER", "-lead", "trail-", "a_b", "dot..dot"} {
		appPathDomain := types.AppPathDomain{Domain: bad + ".example.com", Path: "/"}
		if err := s.builderCheckProfileTarget("prof", profile, appPathDomain); err == nil {
			t.Errorf("expected rejection of subdomain label %q", bad)
		}
	}
	for _, good := range []string{"my-app", "a", "team.my-app"} {
		appPathDomain := types.AppPathDomain{Domain: good + ".example.com", Path: "/"}
		if err := s.builderCheckProfileTarget("prof", profile, appPathDomain); err != nil {
			t.Errorf("subdomain label %q: %v", good, err)
		}
	}
}

func TestBuilderResolvePath(t *testing.T) {
	s := &Server{staticConfig: &types.ServerConfig{}}
	s.staticConfig.System.DefaultDomain = "example.com"

	resolved, pathDomain, err := s.builderResolvePath("my-app.:/")
	if err != nil || resolved != "my-app.example.com:/" || pathDomain.Domain != "my-app.example.com" {
		t.Errorf("relative domain not resolved: %q %+v %v", resolved, pathDomain, err)
	}
	resolved, _, err = s.builderResolvePath("my-app.other.com:/")
	if err != nil || resolved != "my-app.other.com:/" {
		t.Errorf("absolute domain changed: %q %v", resolved, err)
	}
	resolved, _, err = s.builderResolvePath("/plain/path")
	if err != nil || resolved != "/plain/path" {
		t.Errorf("plain path changed: %q %v", resolved, err)
	}
}

// TestBuilderFirstPublishConflicts: a FIRST publish is rejected when an app
// already exists at the target or the local source folder does; a republish
// to the session's own path skips both checks. Relative (trailing ".")
// domains are preserved in the returned path but resolved for the checks
func TestBuilderFirstPublishConflicts(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	server.staticConfig.System.DefaultDomain = "example.com"

	// Create an app at /apps/taken (trusted, no RBAC)
	applyPath := filepath.Join(t.TempDir(), "app.ace")
	writeSyncApplyFile(t, applyPath, "/apps/taken")
	if _, _, err := server.Apply(system.WithTrustedOperation(ctx), types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()

	session := &types.BuilderSession{Id: "bld_ses_x", Profile: ""}

	// First publish onto an existing app: rejected
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/taken", session); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected app-exists conflict, got %v", err)
	}
	// Republish to the session's own path: allowed
	session.PublishPath = "/apps/taken"
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/taken", session); err != nil {
		t.Fatalf("republish to own path rejected: %v", err)
	}
	session.PublishPath = ""

	// Local source folder conflict (publish root is $OPENRUN_HOME/app_src)
	home := t.TempDir()
	t.Setenv("OPENRUN_HOME", home)
	folder := filepath.Join(home, appSrcDir, builderSourceName(types.AppPathDomain{Path: "/apps/foldertaken"}))
	if err := os.MkdirAll(folder, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.builderCheckPublishPath(ctx, "/apps/foldertaken", session); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected folder conflict, got %v", err)
	}

	// A relative-domain target is preserved in the returned path (portable
	// apps.star declaration) while checks run against the resolved path
	publishPath, appPathDomain, err := server.builderCheckPublishPath(ctx, "my-app.:/", session)
	if err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if publishPath != "my-app.:/" || appPathDomain.Domain != "my-app." {
		t.Fatalf("relative domain not preserved: %q %+v", publishPath, appPathDomain)
	}
}

func TestValidateProfileServices(t *testing.T) {
	for _, valid := range [][]string{nil, {}, {"defaults"}, {"postgres"}, {"postgres/main", "redis"}} {
		if err := validateProfileServices(valid); err != nil {
			t.Errorf("services %v: unexpected error %v", valid, err)
		}
	}
	for _, invalid := range [][]string{{"defaults", "postgres"}, {""}, {"a b"}, {"a/b/c"}} {
		if err := validateProfileServices(invalid); err == nil {
			t.Errorf("services %v: expected an error", invalid)
		}
	}
}
