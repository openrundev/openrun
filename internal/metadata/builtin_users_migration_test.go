// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"encoding/json/v2"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func TestMigrateDefaultBuiltinUsers(t *testing.T) {
	// The fixed hashes match the documented passwords
	for name, entry := range DefaultBuiltinUsers {
		if err := bcrypt.CompareHashAndPassword([]byte(entry.Password), []byte(name)); err != nil {
			t.Fatalf("default user %s: password must equal the user name: %v", name, err)
		}
	}

	users := func(t *testing.T, doc []byte) map[string]any {
		t.Helper()
		var parsed struct {
			RBAC    map[string]any            `json:"rbac"`
			Entries map[string]map[string]any `json:"entries"`
		}
		if err := json.Unmarshal(doc, &parsed); err != nil {
			t.Fatalf("parse: %v %s", err, doc)
		}
		if len(parsed.RBAC["grants"].([]any)) == 0 {
			t.Fatalf("rbac config must be present: %s", doc)
		}
		return parsed.Entries["builtin_auth"]
	}

	// Fresh install: a version id, default RBAC and both users in the
	// CreateUpdateUser shape
	initial := InitialDynamicConfig(nil)
	if initial.VersionId == "" || len(initial.RBAC.Grants) == 0 {
		t.Fatalf("initial config must carry a version id and the default RBAC config: %+v", initial)
	}
	for _, name := range []string{"test1", "test2"} {
		entry := initial.Entries["builtin_auth"][name]
		if entry == nil || entry["password"] != DefaultBuiltinUsers[name].Password || len(entry["groups"].([]string)) != 0 {
			t.Fatalf("initial config must carry user %s with the fixed hash and no groups: %v", name, entry)
		}
	}

	// A store with no entries at all gets both users
	// A static [builtin_auth.test1] in openrun.toml keeps its password and
	// groups: the default is not seeded over it (a dynamic entry would
	// shadow it), only test2 is
	static := map[string]types.BuiltinAuthEntry{"test1": {Password: "operator-hash", Groups: []string{"ops"}}}
	if entries := DefaultBuiltinEntries(static)["builtin_auth"]; entries["test1"] != nil || entries["test2"] == nil {
		t.Fatalf("static test1 must be skipped and test2 seeded: %v", entries)
	}
	out, changed, err := migrateDefaultBuiltinUsers([]byte(`{"rbac":{"grants":[{"users":["*"],"roles":["openrun-user"]}]}}`), static)
	if err != nil || !changed {
		t.Fatalf("static skip: %v changed=%v", err, changed)
	}
	if got := users(t, out); got["test1"] != nil || got["test2"] == nil {
		t.Fatalf("migration must skip the static test1 and add test2: %s", out)
	}

	out, changed, err = migrateDefaultBuiltinUsers(
		[]byte(`{"version_id":"ver_0","rbac":{"grants":[{"users":["*"],"roles":["openrun-user"]}]}}`), nil)
	if err != nil || !changed {
		t.Fatalf("bare store: %v changed=%v", err, changed)
	}
	bare := users(t, out)
	for _, name := range []string{"test1", "test2"} {
		entry, _ := bare[name].(map[string]any)
		if entry == nil || entry["password"] != DefaultBuiltinUsers[name].Password || len(entry["groups"].([]any)) != 0 {
			t.Fatalf("migrated config must carry user %s with the fixed hash and no groups: %s", name, out)
		}
	}

	// Idempotent: running again over the result changes nothing
	if again, changed, err := migrateDefaultBuiltinUsers(out, nil); err != nil || changed || string(again) != string(out) {
		t.Fatalf("second run must be a no-op: %v changed=%v", err, changed)
	}

	// Existing store: other entries and an existing test1 are kept verbatim,
	// only the missing user is added
	existing := `{"version_id":"ver_1","rbac":{"grants":[{"users":["*"],"roles":["openrun-user"]}]},` +
		`"entries":{"git_auth":{"gh":{"user_id":"x"}},"builtin_auth":{"test1":{"password":"custom","groups":["ops"]}}},` +
		`"settings":{"system":{"default_domain":"example.com"}}}`
	out, changed, err = migrateDefaultBuiltinUsers([]byte(existing), nil)
	if err != nil || !changed {
		t.Fatalf("existing: %v changed=%v", err, changed)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["version_id"] != "ver_1" || parsed["settings"].(map[string]any)["system"].(map[string]any)["default_domain"] != "example.com" {
		t.Fatalf("unrelated fields must survive: %s", out)
	}
	got := users(t, out)
	if got["test1"].(map[string]any)["password"] != "custom" {
		t.Fatalf("an existing test1 entry must be kept: %s", out)
	}
	if got["test2"].(map[string]any)["password"] != DefaultBuiltinUsers["test2"].Password {
		t.Fatalf("test2 must be added: %s", out)
	}
	if parsed["entries"].(map[string]any)["git_auth"] == nil {
		t.Fatalf("other entry sections must survive: %s", out)
	}
}
