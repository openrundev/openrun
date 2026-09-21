// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestMCPProbeHealthy(t *testing.T) {
	jsonrpc := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Method not found"}}`)
	for name, tc := range map[string]struct {
		status int
		body   []byte
		want   bool
	}{
		"legacy server ok":            {http.StatusOK, []byte(`{"jsonrpc":"2.0","result":{}}`), true},
		"modern server unsupported":   {http.StatusBadRequest, jsonrpc, true},
		"modern server method absent": {http.StatusNotFound, jsonrpc, true},
		"wrong path plain 404":        {http.StatusNotFound, []byte("404 page not found"), false},
		"get-only endpoint":           {http.StatusMethodNotAllowed, jsonrpc, false},
		"server error":                {http.StatusInternalServerError, jsonrpc, false},
		"html 400":                    {http.StatusBadRequest, []byte("<html>bad</html>"), false},
	} {
		testutil.AssertEqualsBool(t, name, tc.want, mcpProbeHealthy(tc.status, tc.body))
	}
}

func TestMCPHealthProbeRequest(t *testing.T) {
	var got *http.Request
	var deleted string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = r.Header.Get("Mcp-Session-Id")
			w.WriteHeader(http.StatusOK)
			return
		}
		got = r.Clone(r.Context())
		// A stateful legacy server opens a session for the initialize
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
	}))
	defer upstream.Close()
	healthy, status, err := mcpHealthProbe(upstream.Client(), upstream.URL+"/mcp")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	testutil.AssertEqualsBool(t, "healthy", true, healthy)
	testutil.AssertEqualsString(t, "status", "200", status)
	testutil.AssertEqualsString(t, "method", http.MethodPost, got.Method)
	testutil.AssertEqualsString(t, "path", "/mcp", got.URL.Path)
	testutil.AssertEqualsString(t, "protocol header", "2025-06-18", got.Header.Get("MCP-Protocol-Version"))
	testutil.AssertEqualsString(t, "probe session closed", "sess-1", deleted)
}

func TestMCPVerifyVersion(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
	}))
	defer upstream.Close()
	handler := &ContainerHandler{scheme: "http", stripAppPath: true}
	handler.containerConfig.DeployHealthAttempts = 2
	handler.containerConfig.HealthTimeoutSecs = 2
	if handler.mcpVerifyVersion() != nil {
		t.Fatal("non-mcp apps have no version check")
	}
	handler.mcpHealthPath = "/mcp"
	host := strings.TrimPrefix(upstream.URL, "http://")
	if err := handler.mcpVerifyVersion()(context.Background(), host); err != nil {
		t.Fatalf("healthy endpoint: %v", err)
	}
	handler.mcpHealthPath = "/wrong"
	err := handler.mcpVerifyVersion()(context.Background(), host)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("wrong path must fail after retries, got %v", err)
	}
	if calls < 3 {
		t.Fatalf("expected retries, got %d calls", calls)
	}
}
