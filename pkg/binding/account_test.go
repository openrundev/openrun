// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/pkg/binding/bindingtest"
)

func TestAccountName(t *testing.T) {
	// Default: bnd_ prefix stripped
	name, err := AccountName("cl_p_", "cl_s_", "bnd_2b7ho4wrbgf3rtqxcfhrwmjfpqm", false, NameOptions{})
	if err != nil || name != "cl_p_2b7ho4wrbgf3rtqxcfhrwmjfpqm" {
		t.Fatalf("name = %q err = %v", name, err)
	}

	// Staging prefix
	name, _ = AccountName("cl_p_", "cl_s_", "bnd_abc", true, NameOptions{})
	if name != "cl_s_abc" {
		t.Fatalf("staging name = %q", name)
	}

	// Uppercase (Oracle-style)
	name, _ = AccountName("CP_", "CS_", "bnd_abc", false, NameOptions{Uppercase: true})
	if name != "CP_ABC" {
		t.Fatalf("uppercase name = %q", name)
	}

	// KeepIDPrefix keeps bnd_
	name, _ = AccountName("cl_usr_prd_", "cl_usr_stg_", "bnd_abc", false, NameOptions{KeepIDPrefix: true})
	if name != "cl_usr_prd_bnd_abc" {
		t.Fatalf("keep-prefix name = %q", name)
	}

	// MaxLen enforcement
	if _, err := AccountName("CP_", "CS_", "bnd_"+strings.Repeat("x", 30), false, NameOptions{MaxLen: 30, Uppercase: true}); err == nil {
		t.Fatal("expected identifier limit error")
	}
}

func TestAccountURLs(t *testing.T) {
	adminURL := "sqlserver://sa:adminpw@localhost:1433?database=appdb"

	accountURL, directURL, err := AccountURLs(adminURL, "lgn", "pw1", "")
	if err != nil {
		t.Fatal(err)
	}
	bindingtest.AssertURL(t, accountURL, "sqlserver", "localhost:1433", "lgn", "pw1", "", map[string]string{"database": "appdb"})
	if accountURL != directURL {
		t.Fatalf("no binding hostname: url %q != direct %q", accountURL, directURL)
	}

	// binding hostname applies to url only; url_direct keeps the service host
	accountURL, directURL, err = AccountURLs("oracle://system:o@localhost:1521/XEPDB1", "CP_A", "pw", "host.docker.internal")
	if err != nil {
		t.Fatal(err)
	}
	bindingtest.AssertURL(t, accountURL, "oracle", "host.docker.internal:1521", "CP_A", "pw", "/XEPDB1", map[string]string{})
	bindingtest.AssertURL(t, directURL, "oracle", "localhost:1521", "CP_A", "pw", "/XEPDB1", map[string]string{})

	// "disable" leaves the host unchanged
	accountURL, _, err = AccountURLs(adminURL, "lgn", "pw", "disable")
	if err != nil {
		t.Fatal(err)
	}
	bindingtest.AssertURL(t, accountURL, "sqlserver", "localhost:1433", "lgn", "pw", "", map[string]string{"database": "appdb"})
}

func TestApplyGrantsIncremental(t *testing.T) {
	meta := BindingMetadata{
		Grants:        []string{"read:t1", "full:t2"},
		GrantsApplied: []BindingGrant{{GrantType: GrantTypeRead, GrantTarget: "t1"}, {GrantType: GrantTypeRead, GrantTarget: "old"}},
	}
	supported := []GrantType{GrantTypeRead, GrantTypeFull}

	var applied []BindingGrant
	result, err := ApplyGrantsIncremental(meta, supported, false, func(grants []BindingGrant) ([]BindingGrant, error) {
		applied = grants
		return grants, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only the new grant is executed
	if len(applied) != 1 || applied[0] != (BindingGrant{GrantType: GrantTypeFull, GrantTarget: "t2"}) {
		t.Fatalf("applied = %v", applied)
	}
	// read:old is pending revoke, still listed in GrantsApplied
	if len(result.PendingRevokes) != 1 || result.PendingRevokes[0].GrantTarget != "old" {
		t.Fatalf("pending revokes = %v", result.PendingRevokes)
	}
	if len(result.GrantsApplied) != 3 {
		t.Fatalf("grants applied = %v", result.GrantsApplied)
	}
	if len(result.Granted) != 1 || result.Granted[0].GrantTarget != "t2" {
		t.Fatalf("granted = %v", result.Granted)
	}

	// reapplyAll: all desired grants are executed; entries that could not be
	// re-executed are dropped from GrantsApplied (pending revokes stay)
	result, err = ApplyGrantsIncremental(meta, supported, true, func(grants []BindingGrant) ([]BindingGrant, error) {
		if len(grants) != 2 {
			t.Fatalf("reapplyAll grants = %v", grants)
		}
		return grants[:1], nil // second grant skipped (e.g. table missing)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.GrantsApplied) != 2 { // processed (1) + pending revoke (1)
		t.Fatalf("reapplyAll grants applied = %v", result.GrantsApplied)
	}
}

func TestApplyGrantsRebuild(t *testing.T) {
	meta := BindingMetadata{
		Grants:        []string{"read:new"},
		GrantsApplied: []BindingGrant{{GrantType: GrantTypeRead, GrantTarget: "old"}},
	}
	var rebuilt []BindingGrant
	result, err := ApplyGrantsRebuild(meta, []GrantType{GrantTypeRead, GrantTypeFull}, func(grantsApplied []BindingGrant) error {
		rebuilt = grantsApplied
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild receives the union: revokes are deferred
	if len(rebuilt) != 2 {
		t.Fatalf("rebuilt = %v", rebuilt)
	}
	if len(result.PendingRevokes) != 1 || result.PendingRevokes[0].GrantTarget != "old" {
		t.Fatalf("pending revokes = %v", result.PendingRevokes)
	}
	if len(result.Granted) != 1 || result.Granted[0].GrantTarget != "new" {
		t.Fatalf("granted = %v", result.Granted)
	}
}

func TestRevokeThenRegrant(t *testing.T) {
	var ops []string
	perms := func(op string, grants []BindingGrant) error {
		ops = append(ops, op)
		return nil
	}

	// No revokes: no calls at all
	if err := RevokeThenRegrant(nil, []BindingGrant{{GrantType: GrantTypeRead, GrantTarget: "t"}}, perms); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("ops = %v", ops)
	}

	// Revoke then regrant, in order
	revokes := []BindingGrant{{GrantType: GrantTypeRead, GrantTarget: "t"}}
	if err := RevokeThenRegrant(revokes, revokes, perms); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[0] != "revoke" || ops[1] != "grant" {
		t.Fatalf("ops = %v", ops)
	}
}
