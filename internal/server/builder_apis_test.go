// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

func TestMarkerBlockUpsertAndRemove(t *testing.T) {
	manual := "# manual header\napp(\"Hand Made\", \"/manual\", \"/src/manual\")\n"

	content, err := upsertMarkerBlock(manual, "/teams/pto", "app(\"PTO\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, manual) {
		t.Fatalf("manual content modified:\n%s", content)
	}
	if !strings.Contains(content, builderMarkerBegin+"/teams/pto\napp(\"PTO\"") {
		t.Fatalf("block not inserted:\n%s", content)
	}

	// republish replaces the block in place, not appends
	updated, err := upsertMarkerBlock(content, "/teams/pto", "app(\"PTO v2\", \"/teams/pto\", \"repo/apps/pto\")")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(updated, builderMarkerBegin+"/teams/pto") != 1 {
		t.Fatalf("expected one block after republish:\n%s", updated)
	}
	if !strings.Contains(updated, "PTO v2") || strings.Contains(updated, "\"PTO\",") {
		t.Fatalf("stanza not replaced:\n%s", updated)
	}

	// a second app gets its own block; removing the first keeps the second
	twoApps, err := upsertMarkerBlock(updated, "/tools/crm", "app(\"CRM\", \"/tools/crm\", \"repo/apps/crm\")")
	if err != nil {
		t.Fatal(err)
	}
	removed, found, err := removeMarkerBlock(twoApps, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("block for /teams/pto not found")
	}
	if strings.Contains(removed, "/teams/pto") || !strings.Contains(removed, "/tools/crm") {
		t.Fatalf("wrong block removed:\n%s", removed)
	}
	if !strings.HasPrefix(removed, manual) {
		t.Fatalf("manual content modified on remove:\n%s", removed)
	}

	// removing an absent block reports not found, no error
	_, found, err = removeMarkerBlock(removed, "/absent")
	if err != nil || found {
		t.Fatalf("expected not found without error, got found=%v err=%v", found, err)
	}
}

func TestMarkerBlockBrokenMarkers(t *testing.T) {
	// begin without end must error, not guess
	broken := builderMarkerBegin + "/teams/pto\napp(...)\n# no end marker\n"
	if _, err := upsertMarkerBlock(broken, "/teams/pto", "app(2)"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
	if _, _, err := removeMarkerBlock(broken, "/teams/pto"); err == nil {
		t.Fatal("expected error for begin marker without end")
	}
}

func TestMarkerBlockPathPrefixNoCollision(t *testing.T) {
	// /teams/pto must not match /teams/pto2's markers
	content, err := upsertMarkerBlock("", "/teams/pto2", "app(\"Other\", \"/teams/pto2\", \"repo/apps/pto2\")")
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := removeMarkerBlock(content, "/teams/pto")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("/teams/pto matched /teams/pto2's block")
	}
}
