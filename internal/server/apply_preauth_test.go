// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// A caller without apply rights on any app must be refused before the apply
// file is fetched: the fetch sends the server's git credentials to the url
func TestApplyRefusedBeforeGitFetch(t *testing.T) {
	server, db, _ := newSyncRBACTestServer(t)
	defer db.Close() //nolint:errcheck

	var requests atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer remote.Close()

	server.staticConfig.GitAuth = map[string]types.GitAuthEntry{
		"corp": {UserID: "svc-bot", Password: "test-password"},
	}
	server.staticConfig.Security.DefaultGitAuth = "corp"
	applyUrl := remote.URL + "/org/repo/apps.star"

	nobody := rbacEnforcedCtx(t.Context(), "builtin:nobody")
	if _, _, err := server.Apply(nobody, types.Transaction{}, applyUrl, "/nomatch", ApplyOptions{}, nil); err == nil {
		t.Fatal("expected apply to be denied")
	}
	if _, err := server.ApplyDelete(nobody, applyUrl, "/nomatch", false, GitRef{}); err == nil {
		t.Fatal("expected apply delete to be denied")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("%d requests reached the git remote for a caller without apply rights", got)
	}

	// A caller with app:apply on some path passes the early check, the
	// fetch is attempted (and fails against this test remote)
	creator := rbacEnforcedCtx(t.Context(), "creator")
	if _, _, err := server.Apply(creator, types.Transaction{}, applyUrl, "/nomatch", ApplyOptions{}, nil); err == nil {
		t.Fatal("expected the fetch to fail")
	}
	if requests.Load() == 0 {
		t.Fatal("expected the fetch to be attempted for a caller with apply rights")
	}
	// app:apply does not include app:delete
	before := requests.Load()
	if _, err := server.ApplyDelete(creator, applyUrl, "/nomatch", false, GitRef{}); err == nil {
		t.Fatal("expected apply delete to be denied without app:delete")
	}
	if requests.Load() != before {
		t.Fatal("apply delete fetched the url for a caller without app:delete")
	}
}
