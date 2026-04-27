// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestKVSessionStoreKeepsPayloadOutOfCookie(t *testing.T) {
	t.Parallel()

	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	groups := make([]string, 500)
	for i := range groups {
		groups[i] = fmt.Sprintf("engineering-platform-group-%03d-with-a-long-name", i)
	}

	req := httptest.NewRequest("GET", "/app", nil)
	w := httptest.NewRecorder()
	session, err := store.Get(req, "github_openrun_session")
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	session.Values[PROVIDER_NAME_KEY] = "github"
	session.Values[USER_KEY] = "user@example.com"
	session.Values[GROUPS_KEY] = groups
	testutil.AssertNoError(t, session.Save(req, w))

	cookies := w.Result().Cookies()
	testutil.AssertEqualsInt(t, "cookie count", 1, len(cookies))
	if len(cookies[0].Value) > 256 {
		t.Fatalf("expected opaque session cookie to stay small, got %d bytes", len(cookies[0].Value))
	}
	if strings.Contains(cookies[0].String(), "engineering-platform-group") {
		t.Fatal("session cookie unexpectedly contains group data")
	}

	req2 := httptest.NewRequest("GET", "/app", nil)
	req2.AddCookie(cookies[0])
	session2, err := store.Get(req2, "github_openrun_session")
	testutil.AssertNoError(t, err)
	gotGroups, ok := anyToStringSlice(session2.Values[GROUPS_KEY])
	if !ok {
		t.Fatal("expected groups to round-trip from KV session store")
	}
	testutil.AssertEqualsInt(t, "group count", len(groups), len(gotGroups))
}

func TestKVSessionStoreDeleteRemovesServerSideSession(t *testing.T) {
	t.Parallel()

	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.Options.Secure = false

	req := httptest.NewRequest("GET", "/app", nil)
	w := httptest.NewRecorder()
	session, err := store.Get(req, "github_openrun_session")
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	testutil.AssertNoError(t, session.Save(req, w))

	_, err = db.FetchKVBlob(req.Context(), store.kvKey(session))
	testutil.AssertNoError(t, err)

	session.Options.MaxAge = -1
	w = httptest.NewRecorder()
	testutil.AssertNoError(t, session.Save(req, w))

	_, err = db.FetchKVBlob(req.Context(), store.kvKey(session))
	if err == nil {
		t.Fatal("expected deleted session to be removed from KV store")
	}
}

func TestKVSessionStoreSaveRefreshesExpiry(t *testing.T) {
	t.Parallel()

	db := NewInmemoryKVStore()
	store := NewKVSessionStore(db,
		[]byte("test-session-key-32bytes-long!!!"),
		[]byte("test-session-block-32bytes-key!!"),
	)
	store.MaxAge(3600)

	req := httptest.NewRequest("GET", "/app", nil)
	w := httptest.NewRecorder()
	session, err := store.Get(req, "github_openrun_session")
	testutil.AssertNoError(t, err)
	session.Values[AUTH_KEY] = true
	testutil.AssertNoError(t, session.Save(req, w))

	key := store.kvKey(session)
	expiredAt := time.Now().Add(-time.Hour)
	db.deleteAt[key] = &expiredAt

	session.Values[USER_KEY] = "user@example.com"
	testutil.AssertNoError(t, session.Save(req, httptest.NewRecorder()))

	refreshed := db.deleteAt[key]
	if refreshed == nil || !refreshed.After(time.Now()) {
		t.Fatalf("expected save to refresh session expiry, got %v", refreshed)
	}
}
