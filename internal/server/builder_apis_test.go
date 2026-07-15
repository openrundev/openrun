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
