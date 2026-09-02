// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestMigrateRBACDefaultConfig(t *testing.T) {
	// RBAC was dynamically enabled: config kept verbatim, only the legacy
	// enabled field dropped - no grant appended
	enabled := `{"version_id":"v1","rbac":{"enabled":true,"groups":{"g1":["u1"]},"roles":{},"grants":[` +
		`{"description":"custom","users":["u1"],"roles":["openrun-admin"],"targets":["all"]}]}}`
	out, changed, err := migrateRBACDefaultConfig([]byte(enabled))
	if err != nil || !changed {
		t.Fatalf("enabled migration: changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(out), "enabled") || strings.Contains(string(out), "openrun-user") {
		t.Fatalf("enabled config must keep grants verbatim without the enabled field: %s", out)
	}
	if !strings.Contains(string(out), `"custom"`) {
		t.Fatalf("existing grant must be preserved: %s", out)
	}

	// RBAC was disabled: the default all-principals grant is appended
	disabled := `{"version_id":"v1","rbac":{"enabled":false,"groups":{},"roles":{},"grants":[]}}`
	out, changed, err = migrateRBACDefaultConfig([]byte(disabled))
	if err != nil || !changed {
		t.Fatalf("disabled migration: changed=%v err=%v", changed, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	grants := doc["rbac"].(map[string]any)["grants"].([]any)
	if len(grants) != 1 {
		t.Fatalf("expected the default grant, got %v", grants)
	}
	grant := grants[0].(map[string]any)
	users := grant["users"].([]any)
	roles := grant["roles"].([]any)
	if len(users) != 1 || users[0] != "*" || len(roles) != 1 || roles[0] != "openrun-user" {
		t.Fatalf("unexpected default grant: %v", grant)
	}

	// Idempotent: migrating the migrated output changes nothing
	out2, changed, err := migrateRBACDefaultConfig(out)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatalf("second migration must be a no-op, got %s", out2)
	}

	// No rbac section at all (config never touched): default grant appended
	empty := `{"version_id":"v1"}`
	out, changed, err = migrateRBACDefaultConfig([]byte(empty))
	if err != nil || !changed {
		t.Fatalf("empty migration: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(string(out), "openrun-user") {
		t.Fatalf("default grant must be appended for a config without rbac: %s", out)
	}

	// Unparseable config errors (the caller logs and continues)
	if _, _, err := migrateRBACDefaultConfig([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid json")
	}
}
