// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// TestMCPConfirmationOverHTTP characterizes the destructive-confirmation
// flow on the real streamable-HTTP transport in stateless mode. The claim
// under test: the confirmation does NOT hold the POST open - phase 1
// (preview + input_required) completes immediately, the elicitation wait
// happens client-side, and the retry is an independent POST. It also checks
// that a client abandoning mid-confirmation leaves no server-side state
func TestMCPConfirmationOverHTTP(t *testing.T) {
	server, ts, mintKey := newRemoteApiTestServer(t)

	applyCtx := system.WithTrustedOperation(context.Background())
	appExists := func(path string) bool {
		apps, err := server.GetApps(applyCtx, path, false)
		if err != nil {
			t.Fatalf("get apps: %v", err)
		}
		return len(apps) > 0
	}

	// Wrap the TCP router to record the wall-clock duration of every MCP POST
	var mu sync.Mutex
	var postDurations []time.Duration
	handler := NewTCPHandler(server.Logger, server.staticConfig, server)
	timed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler.router.ServeHTTP(w, r)
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/mcp") {
			mu.Lock()
			postDurations = append(postDurations, time.Since(start))
			mu.Unlock()
		}
	})
	timedTs := httptest.NewTLSServer(timed)
	defer timedTs.Close()
	_ = ts

	// Explicit scopes: an mcp-only key with no scopes defaults to the
	// read-only ceiling, and this test exercises a destructive tool
	adminKey := mintKey(t, &types.ApiKeyCreateRequest{User: "admin", Resources: []string{"mcp"}, Scopes: []string{"*"}})
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	httpClient.Transport = &bearerRoundTripper{inner: httpClient.Transport, token: adminKey}

	const elicitDelay = 1500 * time.Millisecond
	newSession := func(action string, delay time.Duration) *mcp.ClientSession {
		client := mcp.NewClient(&mcp.Implementation{Name: "http-elicit", Version: "0"}, &mcp.ClientOptions{
			ElicitationHandler: func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				time.Sleep(delay) // the human thinking
				return &mcp.ElicitResult{Action: action}, nil
			},
		})
		session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
			Endpoint:   timedTs.URL + "/_openrun/mcp",
			HTTPClient: httpClient,
		}, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}

	// Apply an app to delete
	applyPath := t.TempDir() + "/app.ace"
	writeSyncApplyFile(t, applyPath, "/apps/http-confirm")
	if _, _, err := server.Apply(applyCtx, types.Transaction{}, applyPath, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()

	// Accepted delete with a slow human: total time includes the delay, but
	// NO single POST is held anywhere near that long
	session := newSession("accept", elicitDelay)
	start := time.Now()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "delete_apps", Arguments: map[string]any{"path_glob": "/apps/http-confirm"}})
	total := time.Since(start)
	if err != nil || result.IsError {
		t.Fatalf("confirmed delete: %v %s", err, callToolText(t, result))
	}
	if appExists("/apps/http-confirm") {
		t.Fatal("accepted delete must remove the app")
	}
	if total < elicitDelay {
		t.Fatalf("total call time %v must include the elicitation delay", total)
	}

	mu.Lock()
	durations := append([]time.Duration(nil), postDurations...)
	mu.Unlock()
	if len(durations) < 2 {
		t.Fatalf("expected at least 2 MCP POSTs (phase 1 + retry), got %d", len(durations))
	}
	for i, d := range durations {
		if d > elicitDelay/2 {
			t.Fatalf("POST %d held for %v: the confirmation must not hold a connection open", i, d)
		}
	}

	// Client abandons mid-confirmation: the elicitation handler errors, the
	// call fails client-side, and the server is untouched and fully usable
	applyPath2 := t.TempDir() + "/app.ace"
	writeSyncApplyFile(t, applyPath2, "/apps/http-abandon")
	if _, _, err := server.Apply(applyCtx, types.Transaction{}, applyPath2, "all",
		false, false, false, types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	server.apps.ResetAllAppCache()

	abandonClient := mcp.NewClient(&mcp.Implementation{Name: "abandon", Version: "0"}, &mcp.ClientOptions{
		ElicitationHandler: func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return nil, context.Canceled // user closed the prompt / client gave up
		},
	})
	abandonSession, err := abandonClient.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   timedTs.URL + "/_openrun/mcp",
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer abandonSession.Close() //nolint:errcheck
	if _, err := abandonSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "delete_apps", Arguments: map[string]any{"path_glob": "/apps/http-abandon"}}); err == nil {
		t.Fatal("abandoned confirmation should surface as an error")
	}
	if !appExists("/apps/http-abandon") {
		t.Fatal("abandoned confirmation must not delete the app")
	}
	// The same session keeps working afterwards - nothing server-side leaked
	if result, err := abandonSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "list_apps", Arguments: map[string]any{"path_glob": "all"}}); err != nil || result.IsError {
		t.Fatalf("session unusable after abandoned confirmation: %v", err)
	}
}

type bearerRoundTripper struct {
	inner http.RoundTripper
	token string
}

func (b *bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.inner.RoundTrip(r)
}
