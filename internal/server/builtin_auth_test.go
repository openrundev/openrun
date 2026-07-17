// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func testBuiltinAuth(t *testing.T, users map[string]types.BuiltinAuthEntry) *BuiltinAuth {
	t.Helper()
	config := &types.ServerConfig{BuiltinAuth: users}
	logger := testutil.TestLogger()
	return NewBuiltinAuth(logger, func() *types.ServerConfig { return config })
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func TestBuiltinAuthAuthenticate(t *testing.T) {
	auth := testBuiltinAuth(t, map[string]types.BuiltinAuthEntry{
		"alice": {Password: hashPassword(t, "pw1"), Groups: []string{"dev", "qa"}},
		"bob":   {Password: hashPassword(t, "pw2")},
	})

	userId, groups, ok := auth.authenticate(basicAuthHeader("alice", "pw1"))
	testutil.AssertEqualsBool(t, "ok", true, ok)
	testutil.AssertEqualsString(t, "userId", "builtin:alice", userId)
	testutil.AssertEqualsInt(t, "groups", 2, len(groups))
	testutil.AssertEqualsString(t, "group", "dev", groups[0])

	// Groups default to an empty list when not configured
	userId, groups, ok = auth.authenticate(basicAuthHeader("bob", "pw2"))
	testutil.AssertEqualsBool(t, "ok", true, ok)
	testutil.AssertEqualsString(t, "userId", "builtin:bob", userId)
	testutil.AssertEqualsInt(t, "groups", 0, len(groups))

	_, _, ok = auth.authenticate(basicAuthHeader("alice", "wrong"))
	testutil.AssertEqualsBool(t, "wrong password", false, ok)

	_, _, ok = auth.authenticate(basicAuthHeader("unknown", "pw1"))
	testutil.AssertEqualsBool(t, "unknown user", false, ok)

	_, _, ok = auth.authenticate("")
	testutil.AssertEqualsBool(t, "empty header", false, ok)

	_, _, ok = auth.authenticate("Basic not-base64!!!")
	testutil.AssertEqualsBool(t, "bad header", false, ok)
}

func TestBuiltinAuthCacheReset(t *testing.T) {
	users := map[string]types.BuiltinAuthEntry{
		"alice": {Password: hashPassword(t, "pw1")},
	}
	auth := testBuiltinAuth(t, users)

	header := basicAuthHeader("alice", "pw1")
	_, _, ok := auth.authenticate(header)
	testutil.AssertEqualsBool(t, "ok", true, ok)

	// A password change comes with a cache reset (applyDynamicConfig); the
	// old password header must stop working
	users["alice"] = types.BuiltinAuthEntry{Password: hashPassword(t, "pw2")}
	auth.ResetCache()
	_, _, ok = auth.authenticate(header)
	testutil.AssertEqualsBool(t, "old password after reset", false, ok)

	_, _, ok = auth.authenticate(basicAuthHeader("alice", "pw2"))
	testutil.AssertEqualsBool(t, "new password", true, ok)
}

func TestValidateUsername(t *testing.T) {
	for _, valid := range []string{"alice", "alice@example.com", "a_b-c.d", "user1"} {
		if err := validateUsername(valid); err != nil {
			t.Errorf("expected %q to be valid: %s", valid, err)
		}
	}
	for _, invalid := range []string{"", "a:b", "a b", "a\tb", "a\nb"} {
		if err := validateUsername(invalid); err == nil {
			t.Errorf("expected %q to be invalid", invalid)
		}
	}
}
