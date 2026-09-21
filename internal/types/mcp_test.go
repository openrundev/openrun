// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertEq(t *testing.T, msg, want, got string) {
	t.Helper()
	if want != got {
		t.Fatalf("%s: want %q got %q", msg, want, got)
	}
}

func TestParseMCPConfig(t *testing.T) {
	config, err := ParseMCPConfig(`{}`)
	if err != nil {
		t.Fatalf("empty doc: %v", err)
	}
	assertEq(t, "default path", "/", config.Path)
	assertEq(t, "upstream", "/", config.UpstreamPath())

	config, err = ParseMCPConfig(`{"path":"/","container_path":"mcp/","scopes":["a","b"],"default_scope":"a","tools":{"t":"b"},"allowed_origins":["HTTPS://App.Example.com:8443"]}`)
	if err != nil {
		t.Fatalf("full doc: %v", err)
	}
	assertEq(t, "container path normalized", "/mcp", config.ContainerPath)
	assertEq(t, "upstream", "/mcp", config.UpstreamPath())
	assertEq(t, "origin normalized", "https://app.example.com:8443", config.AllowedOrigins[0])

	for name, doc := range map[string]string{
		"container path with region": `{"path":"/mcp","container_path":"/x"}`,
		"unnormalized path":          `{"path":"/a/../b"}`,
		"default scope undeclared":   `{"default_scope":"a"}`,
		"tool scope undeclared":      `{"scopes":["a"],"tools":{"t":"b"}}`,
		"duplicate scope":            `{"scopes":["a","a"]}`,
		"scope with space":           `{"scopes":["a b"]}`,
		"origin with path":           `{"allowed_origins":["https://a.example.com/x"]}`,
		"origin without scheme":      `{"allowed_origins":["a.example.com"]}`,
		"not json":                   `nope`,
	} {
		if _, err := ParseMCPConfig(doc); err == nil {
			t.Errorf("%s: must fail", name)
		}
	}
}

func TestParseMCPArg(t *testing.T) {
	doc, err := ParseMCPArg("")
	if err != nil || doc != `{"path":"/"}` {
		t.Fatalf("bare: %q %v", doc, err)
	}
	doc, err = ParseMCPArg("true")
	if err != nil || doc != `{"path":"/"}` {
		t.Fatalf("true: %q %v", doc, err)
	}
	doc, err = ParseMCPArg("false")
	if err != nil || doc != "" {
		t.Fatalf("false: %q %v", doc, err)
	}
	doc, err = ParseMCPArg("/mcp")
	if err != nil || doc != `{"path":"/","container_path":"/mcp"}` {
		t.Fatalf("path: %q %v", doc, err)
	}
	doc, err = ParseMCPArg(`{"path":"/mcp","scopes":["r"]}`)
	if err != nil || !strings.Contains(doc, `"path":"/mcp"`) {
		t.Fatalf("json: %q %v", doc, err)
	}
	file := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(file, []byte(`{"path":"/api/mcp"}`), 0600); err != nil {
		t.Fatal(err)
	}
	doc, err = ParseMCPArg("@" + file)
	if err != nil || doc != `{"path":"/api/mcp"}` {
		t.Fatalf("file: %q %v", doc, err)
	}
	for _, bad := range []string{"mcp", "http://x", "@/nonexistent/file", `{"path":"/x","container_path":"/y"}`} {
		if _, err := ParseMCPArg(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
	// The server-side form never reads files
	if _, err := ParseMCPValue("@" + file); err == nil || !strings.Contains(err.Error(), "expanded by the CLI") {
		t.Fatalf("ParseMCPValue must refuse @file, got %v", err)
	}
}
