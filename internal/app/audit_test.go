// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestNeedsApprovalChecksPermissionPermit(t *testing.T) {
	t.Parallel()

	result := &types.ApproveResult{
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
		ApprovedPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
	}
	if needsApproval(result) {
		t.Fatal("did not expect approval when permit list is unchanged")
	}

	result.ApprovedPermissions[0].Permit = []string{"net:write"}
	if !needsApproval(result) {
		t.Fatal("expected approval when permit list changes")
	}
}

func TestServerConfigCoverageChecksPermissionPermit(t *testing.T) {
	t.Parallel()

	result := &types.ApproveResult{
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", Permit: []string{"net:read"}},
		},
	}
	serverPerms := []types.Permission{{Plugin: "http.in", Method: "get"}}
	if !needsApprovalWithServerConfig(result, serverPerms) {
		t.Fatal("expected approval when app permission permit is not covered by server config")
	}

	serverPerms[0].Permit = []string{"net:read"}
	if needsApprovalWithServerConfig(result, serverPerms) {
		t.Fatal("did not expect approval when permit list is covered by server config")
	}
}

func TestSecretsCovered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requested [][]string
		allowed   [][]string
		covered   bool
	}{
		{"no request", nil, nil, true},
		{"no allowed", [][]string{{"my_secret"}}, nil, false},
		{"exact", [][]string{{"my_secret"}}, [][]string{{"my_secret"}}, true},
		{"other secret", [][]string{{"my_secret"}}, [][]string{{"other"}}, false},
		{"allowed regex covers literal", [][]string{{"db_pass"}}, [][]string{{"regex:^db_.*"}}, true},
		{"allowed wildcard covers requested regex", [][]string{{"regex:.*"}}, [][]string{{"regex:.*"}}, true},
		{"literal does not cover requested regex", [][]string{{"regex:.*"}}, [][]string{{"my_secret"}}, false},
		{"narrower regex does not cover wildcard", [][]string{{"regex:.*"}}, [][]string{{"regex:^db_.*"}}, false},
		{"every request needs cover", [][]string{{"a"}, {"b"}}, [][]string{{"a"}}, false},
		{"allowed prefix covers longer request", [][]string{{"db", "pass"}}, [][]string{{"db"}}, true},
		{"multi entry mismatch", [][]string{{"db", "pass"}}, [][]string{{"db", "user"}}, false},
		// a longer allowed pattern names a different (joined) secret
		{"longer allowed does not cover its prefix", [][]string{{"PROD"}}, [][]string{{"PROD", "PUBLIC_KEY"}}, false},
		{"empty request never covered", [][]string{{}}, [][]string{{"PROD"}}, false},
		// a requested regex is compared as a pattern, not matched as text
		{"regex text not matched by a narrower regex", [][]string{{"regex:HOSTSECRET|OTHER"}}, [][]string{{"regex:HOSTSECRET"}}, false},
		{"regex text not matched by a regex matching its spelling", [][]string{{"regex:^db_.*"}}, [][]string{{"regex:re.*"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := secretsCovered(tc.requested, tc.allowed); got != tc.covered {
				t.Fatalf("secretsCovered(%v, %v) = %v, want %v", tc.requested, tc.allowed, got, tc.covered)
			}
		})
	}
}

func TestUngrantedSecretsMirrorsRuntimeAllowlist(t *testing.T) {
	t.Parallel()

	declared := []types.Permission{
		{Plugin: "proxy.in", Method: "config", Arguments: []string{"<CONTAINER_URL>"}},
		{Plugin: "container.in", Method: "config", Arguments: []string{"AUTO"}, Secrets: [][]string{{"regex:.*"}}},
	}
	serverNoSecrets := []types.Permission{{Plugin: "container.in", Method: "config", Arguments: []string{"regex:.*"}, Secrets: [][]string{}}}

	// Neither approved nor allowed by the server config: the secrets are ungranted
	got := ungrantedSecrets(declared, nil, serverNoSecrets)
	if len(got) != 1 || got[0].Plugin != "container.in" {
		t.Fatalf("ungranted = %+v, want the container.in config permission", got)
	}

	// The server config allowing all secrets for the method grants them
	serverAll := []types.Permission{{Plugin: "container.in", Method: "config", Arguments: []string{"regex:.*"}, Secrets: [][]string{{"regex:.*"}}}}
	if got := ungrantedSecrets(declared, nil, serverAll); len(got) != 0 {
		t.Fatalf("ungranted = %+v, want none with server config allowing all secrets", got)
	}

	// Approved on the app grants them, the server config adding nothing
	if got := ungrantedSecrets(declared, declared, serverNoSecrets); len(got) != 0 {
		t.Fatalf("ungranted = %+v, want none when approved", got)
	}

	// The union of approved and server config is what counts, as at runtime
	approvedPart := []types.Permission{{Plugin: "container.in", Method: "config", Arguments: []string{"AUTO"}, Secrets: [][]string{{"a"}}}}
	serverPart := []types.Permission{{Plugin: "container.in", Method: "config", Secrets: [][]string{{"b"}}}}
	twoSecrets := []types.Permission{{Plugin: "container.in", Method: "config", Secrets: [][]string{{"a"}, {"b"}}}}
	if got := ungrantedSecrets(twoSecrets, approvedPart, serverPart); len(got) != 0 {
		t.Fatalf("ungranted = %+v, want none when approved and server config together cover the request", got)
	}
	if got := ungrantedSecrets(twoSecrets, approvedPart, nil); len(got) != 1 {
		t.Fatalf("ungranted = %+v, want the permission when only part of the request is covered", got)
	}

	// A permission declaring no secrets is never reported
	if got := ungrantedSecrets(declared[:1], nil, nil); len(got) != 0 {
		t.Fatalf("ungranted = %+v, want none for permissions without secrets", got)
	}
}

func TestSetApprovalStateKeepsServerCoverageAndReportsSecrets(t *testing.T) {
	t.Parallel()

	a := &App{serverConfig: &types.ServerConfig{Permissions: types.PermissionsConfig{Allow: []types.Permission{
		{Plugin: "proxy.in", Method: "config", Arguments: []string{"<CONTAINER_URL>"}},
		{Plugin: "container.in", Method: "config", Arguments: []string{"regex:.*"}, Secrets: [][]string{}},
	}}}}
	declared := []types.Permission{
		{Plugin: "proxy.in", Method: "config", Arguments: []string{"<CONTAINER_URL>"}},
		{Plugin: "container.in", Method: "config", Arguments: []string{"AUTO"}, Secrets: [][]string{{"regex:.*"}}},
	}

	// Not approved on the app: the server config covers the calls, so the app
	// deploys without approval (unchanged behavior), the change is reported
	// and the secrets are flagged as ungranted
	results := &types.ApproveResult{NewLoads: []string{"proxy.in", "container.in"}, NewPermissions: declared}
	a.setApprovalState(results)
	if results.NeedsApproval {
		t.Fatal("server config covered permissions must not need approval")
	}
	if !results.Changed {
		t.Fatal("declared permissions differ from the approved ones, expected Changed")
	}
	if len(results.UngrantedSecrets) != 1 || results.UngrantedSecrets[0].Method != "config" {
		t.Fatalf("UngrantedSecrets = %+v, want the container.in config permission", results.UngrantedSecrets)
	}

	// Approved: nothing changed, nothing ungranted
	results = &types.ApproveResult{NewLoads: []string{"proxy.in", "container.in"}, ApprovedLoads: []string{"proxy.in", "container.in"},
		NewPermissions: declared, ApprovedPermissions: declared}
	a.setApprovalState(results)
	if results.NeedsApproval || results.Changed || len(results.UngrantedSecrets) != 0 {
		t.Fatalf("approved app: NeedsApproval=%v Changed=%v Ungranted=%+v, want all clear", results.NeedsApproval, results.Changed, results.UngrantedSecrets)
	}

	// A permission the server config does not cover still needs approval
	results = &types.ApproveResult{NewPermissions: []types.Permission{{Plugin: "http.in", Method: "get", Arguments: []string{"https://example.com"}}}}
	a.setApprovalState(results)
	if !results.NeedsApproval || !results.Changed {
		t.Fatal("uncovered permission must need approval")
	}
}

func TestMainAppPathUsesLinkedPath(t *testing.T) {
	t.Parallel()

	stage := &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_STAGE + "abc"), Path: "/secretapp", Domain: "stage.localhost",
		MainApp: types.AppId(types.ID_PREFIX_APP_PROD + "abc"), LinkedAppPath: "/secretapp"}}
	if got := stage.mainAppPath(); got != "/secretapp" {
		t.Fatalf("stage mainAppPath() = %q, want the linked prod path", got)
	}
	legacy := &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_STAGE + "abc"), Path: "/secretapp" + types.STAGE_SUFFIX,
		MainApp: types.AppId(types.ID_PREFIX_APP_PROD + "abc")}}
	if got := legacy.mainAppPath(); got != "/secretapp" {
		t.Fatalf("legacy stage mainAppPath() = %q, want the suffix trimmed", got)
	}
	prod := &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "abc"), Path: "/secretapp", Domain: "example.com"}}
	if got := prod.mainAppPath(); got != "example.com:/secretapp" {
		t.Fatalf("prod mainAppPath() = %q, want its own path", got)
	}
}

// TestPatternCoversRegexDeclaration verifies that a regex pattern in the
// server config covers an app's own regex: declaration only when it
// authorizes everything the declaration does, not when it happens to match
// the declaration's text (regex:get|head matches the text "regex:get|post")
func TestPatternCoversRegexDeclaration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, declared string
		want              bool
	}{
		{"get", "get", true},
		{"regex:get|head", "get", true},
		{"regex:get|head", "post", false},
		{"regex:get|head", "regex:get|post", false},
		{"regex:get|head", "regex:get|head", true},
		{"regex:.*", "regex:get|post", true},
		{"regex:^get$", "regex:get", false},
		{"get", "regex:get", false},
		{"regex:^https://example\\.com", "regex:^https://evil\\.com|https://example\\.com", false},
		{"regex:example", "regex:evil|example", false},
		{"regex:^(get|head)?$", "regex:post", false},
		{"regex:^$", "regex:.*", false},
		{"regex:\\bget", "regex:get", false},
		{"regex:(?m)^", "regex:get", false},
		{"regex:(get)?", "regex:post", true},
		{"regex:[\\s\\S]*", "regex:^https://", true},
		{"regex:(", "regex:get", false},
	}
	for _, c := range cases {
		if got := patternCovers(c.pattern, c.declared); got != c.want {
			t.Errorf("patternCovers(%q, %q) = %v, want %v", c.pattern, c.declared, got, c.want)
		}
	}

	result := &types.ApproveResult{
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "regex:get|post", Secrets: [][]string{{"TOKEN"}}},
		},
	}
	serverPerms := []types.Permission{{Plugin: "http.in", Method: "regex:get|head", Secrets: [][]string{{"TOKEN"}}}}
	if !needsApprovalWithServerConfig(result, serverPerms) {
		t.Fatal("expected approval: server regex:get|head does not cover the app's regex:get|post")
	}
	if got := ungrantedSecrets(result.NewPermissions, nil, serverPerms); len(got) != 1 {
		t.Fatalf("expected the secret on regex:get|post to stay ungranted, got %v", got)
	}
	serverPerms[0].Method = "regex:.*"
	if needsApprovalWithServerConfig(result, serverPerms) {
		t.Fatal("did not expect approval: server regex:.* covers every method")
	}
	if got := ungrantedSecrets(result.NewPermissions, nil, serverPerms); len(got) != 0 {
		t.Fatalf("expected the secret to be granted by regex:.*, got %v", got)
	}
}

func TestNeedsApprovalLoadOrderAndPermissionOrder(t *testing.T) {
	t.Parallel()

	isRead, isWrite := true, false
	result := &types.ApproveResult{
		NewLoads:      []string{"store.in", "http.in"},
		ApprovedLoads: []string{"http.in", "store.in"},
		NewPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", IsRead: &isRead},
			{Plugin: "http.in", Method: "get", Arguments: []string{"https://a"}, IsRead: &isWrite},
		},
		ApprovedPermissions: []types.Permission{
			{Plugin: "http.in", Method: "get", IsRead: &isRead},
			{Plugin: "http.in", Method: "get", Arguments: []string{"https://a"}, IsRead: &isWrite},
		},
	}
	if needsApproval(result) {
		t.Fatal("did not expect approval when only the load order changes")
	}

	// Permission order is enforced: the first matching entry decides, so
	// moving the URL-specific write rule ahead of the broad read rule changes
	// what a call to https://a is allowed to do
	result.NewPermissions[0], result.NewPermissions[1] = result.NewPermissions[1], result.NewPermissions[0]
	if !needsApproval(result) {
		t.Fatal("expected approval when the permission order changes")
	}
}
