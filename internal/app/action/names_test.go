// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestSlugName(t *testing.T) {
	for input, want := range map[string]string{
		"Cancel Order":    "cancel_order",
		"  Deploy!! now ": "deploy_now",
		"orders cancel":   "orders_cancel",
		"v2-API":          "v2_api",
		"":                "",
		"***":             "",
	} {
		testutil.AssertEqualsString(t, "slug of "+input, want, slugName(input))
	}
}

func TestToolNames(t *testing.T) {
	root := &Action{name: "Cancel Order", actionPath: "/"}
	nested := &Action{name: "Nested", actionPath: "/orders/cancel"}
	collide := &Action{name: "Other", actionPath: "/orders_cancel"}
	sameAsRoot := &Action{name: "X", actionPath: "/cancel_order"}
	unnamedRoot := &Action{name: "!!", actionPath: "/"}

	names := ToolNames([]*Action{root, nested, collide, sameAsRoot})
	// The root action is named from its action name, never "root"
	testutil.AssertEqualsString(t, "root", "cancel_order", names[root])
	testutil.AssertEqualsString(t, "nested", "orders_cancel", names[nested])
	testutil.AssertEqualsString(t, "collision suffix", "orders_cancel_2", names[collide])
	testutil.AssertEqualsString(t, "collision with root", "cancel_order_2", names[sameAsRoot])

	names = ToolNames([]*Action{unnamedRoot})
	testutil.AssertEqualsString(t, "root fallback", "root", names[unnamedRoot])
}

func TestFindAction(t *testing.T) {
	root := &Action{name: "Deploy", actionPath: "/"}
	logs := &Action{name: "Logs", actionPath: "/logs"}
	actions := []*Action{root, logs}

	for selector, want := range map[string]*Action{"deploy": root, "/": root, "logs": logs, "/logs": logs, "/logs/": logs} {
		got, err := FindAction(actions, selector)
		if err != nil || got != want {
			t.Fatalf("selector %q: got %v, %v", selector, got, err)
		}
	}

	_, err := FindAction(actions, "missing")
	testutil.AssertErrorContains(t, err, `action "missing" not found`)
	_, err = FindAction(actions, "")
	testutil.AssertErrorContains(t, err, "app has 2 actions, specify the action to use")

	// A single action app needs no selector
	got, err := FindAction([]*Action{logs}, "")
	if err != nil || got != logs {
		t.Fatalf("single action: got %v, %v", got, err)
	}
}

func TestAuditOp(t *testing.T) {
	testutil.AssertEqualsString(t, "ui run", "execute", AuditOp(SourceUI, OpRun))
	testutil.AssertEqualsString(t, "api validate", "api_validate", AuditOp(SourceAPI, OpValidate))
	testutil.AssertEqualsString(t, "mgmt suggest", "mgmt_suggest", AuditOp(SourceMgmt, OpSuggest))
	testutil.AssertEqualsString(t, "mcp run", "mcp_execute", AuditOp(SourceMCP, OpRun))
}

func TestMarkdownTable(t *testing.T) {
	rows := []map[string]any{
		{"name": "a|b", "count": 1},
		{"name": "line1\nline2", "count": nil},
		{"name": strings.Repeat("x", mcpCellLimit+10)},
	}
	table := markdownTable(rows, 2)
	lines := strings.Split(strings.TrimSpace(table), "\n")
	testutil.AssertEqualsString(t, "header", "| count | name |", lines[0])
	testutil.AssertEqualsString(t, "separator", "| --- | --- |", lines[1])
	testutil.AssertEqualsString(t, "pipe escaped", `| 1 | a\|b |`, lines[2])
	testutil.AssertEqualsString(t, "newline flattened, nil empty", "|  | line1 line2 |", lines[3])
	testutil.AssertEqualsString(t, "row limit", "... 1 more rows", lines[4])
}

func TestWriteLimitedLines(t *testing.T) {
	lines := []string{"aaaa", "bbbb", "cccc", "dddd"}
	render := func(limit int, values []string) string {
		var b strings.Builder
		produced := 0
		writeLimitedLines(&b, len(values), func(i int) string { produced++; return values[i] }, limit)
		if produced > 3 && limit < 15 {
			t.Fatalf("limit %d: %d lines rendered, the rest must not be produced", limit, produced)
		}
		return b.String()
	}
	testutil.AssertEqualsString(t, "all fit", "aaaa\nbbbb\ncccc\ndddd\n", render(100, lines))
	testutil.AssertEqualsString(t, "exact fit", "aaaa\nbbbb\n", render(10, lines[:2]))
	testutil.AssertEqualsString(t, "two fit", "aaaa\nbbbb\n... 2 more values, the text is limited to 12 bytes\n", render(12, lines))
	// A first line over the limit is cut, not dropped
	out := render(6, []string{"0123456789", "next"})
	testutil.AssertStringContains(t, out, "012345\n... (cut, 6 of 10 bytes shown)")
	testutil.AssertStringContains(t, out, "... 1 more values")
	testutil.AssertEqualsString(t, "no lines", "", render(10, nil))
}

func TestCapText(t *testing.T) {
	testutil.AssertEqualsString(t, "short", "abc", capText("abc", 10))
	// The cut is on a character boundary
	capped := capText("aé€z", 4) // a=1 byte, é=2, €=3
	testutil.AssertStringContains(t, capped, "aé\n... (cut, 3 of 7 bytes shown)")
}
