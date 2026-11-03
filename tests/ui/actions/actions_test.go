// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

// Package actions drives the Starlark action pages (the <app>/<action>
// form) in a headless Chromium against a real server built from the
// working tree: the actions kitchen sink app (tests/actions_tests) covers
// multiple actions with the sidebar switcher, every param input type, list
// and suggest dropdowns, Validate and Suggest, every report type and the
// handler error path; two small fixtures under testdata cover the single
// action layout with a suggest-filled dropdown and an async run.
package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/openrundev/openrun/tests/ui/testenv"
)

const httpPort = 25926

var (
	env     *testenv.Env
	browser *rod.Browser
	skipMsg string
)

func TestMain(m *testing.M) {
	code, err := setupAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "actions test setup failed:", err)
		code = 1
	}
	os.Exit(code)
}

func setupAndRun(m *testing.M) (int, error) {
	binPath := os.Getenv("OPENRUN_TEST_BROWSER")
	if binPath == "" {
		var found bool
		binPath, found = launcher.LookPath()
		if !found {
			skipMsg = "no Chromium-based browser found, set OPENRUN_TEST_BROWSER"
			return m.Run(), nil
		}
	}

	var err error
	env, err = testenv.Start(httpPort, testenv.Options{
		// The kitchen sink's Process File action numbers the upload with
		// nl through exec.in, which the anonymous page user may call only
		// with the anon system plugin flag; RBAC is off so that user can
		// run the permit-gated Restricted action too
		SecurityExtra: `allowed_exec_commands = ["sh", "nl", "cat"]
unsafe_allow_system_plugins_anon = true
unsafe_disable_rbac = true`,
		ExtraConfig: `[permissions]
disallow = []
`,
	})
	if err != nil {
		return 1, err
	}
	defer env.Stop()

	u, err := launcher.New().Bin(binPath).Headless(true).Launch()
	if err != nil {
		return 1, fmt.Errorf("launching browser: %w", err)
	}
	browser = rod.New().ControlURL(u)
	if err := browser.Connect(); err != nil {
		return 1, fmt.Errorf("connecting to browser: %w", err)
	}
	defer browser.Close() //nolint:errcheck

	return m.Run(), nil
}

/* ---------- fixtures ---------- */

// kitchensinkSource is the actions kitchen sink app (tests/actions_tests)
func kitchensinkSource() string {
	return filepath.Join(testenv.RepoRoot(), "tests", "actions_tests")
}

// fixtureSource returns the disk path of a fixture app under testdata
func fixtureSource(name string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "testdata", name)
}

// appURL is the server url of an app path
func appURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", env.Port, path)
}

// createApp creates an app from a fixture, deleted when the test ends
func createApp(t *testing.T, source, path string) {
	t.Helper()
	if out, err := env.CLI("app", "create", "--approve", source, path); err != nil {
		t.Fatalf("creating app %s: %v\n%s", path, err, out)
	}
	t.Cleanup(func() { _, _ = env.CLI("app", "delete", path) })
}

/* ---------- page helpers ---------- */

// page wraps a rod page with test helpers
type page struct {
	*rod.Page
	t *testing.T
}

// open navigates a fresh incognito page to the url and waits for load
func open(t *testing.T, url string) *page {
	t.Helper()
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	b, err := browser.Incognito()
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	pg := &page{Page: p, t: t}
	pg.navigate(url)
	return pg
}

func (p *page) navigate(url string) {
	p.t.Helper()
	if err := p.Timeout(30 * time.Second).Navigate(url); err != nil {
		p.t.Fatalf("navigate %s: %v", url, err)
	}
	p.waitLoaded()
}

// waitLoaded polls document.readyState, avoiding the WaitLoad event race
// (the load event can fire before the wait subscribes)
func (p *page) waitLoaded() {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if state, err := p.Eval(`() => document.readyState`); err == nil && state.Value.String() == "complete" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.t.Fatalf("page did not finish loading: %s", p.url())
}

func (p *page) url() string {
	info, err := p.Info()
	if err != nil {
		p.t.Fatal(err)
	}
	return info.URL
}

// el waits for the selector (htmx swaps land asynchronously)
func (p *page) el(sel string) *rod.Element {
	p.t.Helper()
	el, err := p.Timeout(15 * time.Second).Element(sel)
	if err != nil {
		p.t.Fatalf("element %q: %v", sel, err)
	}
	return el.CancelTimeout()
}

// elR waits for an element matching the selector whose text matches the
// regexp
func (p *page) elR(sel, textRe string) *rod.Element {
	p.t.Helper()
	el, err := p.Timeout(15*time.Second).ElementR(sel, textRe)
	if err != nil {
		p.t.Fatalf("element %q with text %q: %v", sel, textRe, err)
	}
	return el.CancelTimeout()
}

// hasEl reports whether the selector matches an element right now
func (p *page) hasEl(sel string) bool {
	p.t.Helper()
	return p.MustHas(sel)
}

// waitText polls until the selector's combined rendered text contains
// substr
func (p *page) waitText(sel, substr string) {
	p.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		els, err := p.Elements(sel)
		if err == nil {
			var sb strings.Builder
			for _, el := range els {
				txt, _ := el.Text()
				sb.WriteString(txt)
				sb.WriteString(" ")
			}
			last = sb.String()
			if strings.Contains(last, substr) {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatalf("timed out waiting for %q in %q, last content: %.300q", substr, sel, last)
}

// text returns the rendered text of an element, trimmed
func (p *page) text(sel string) string {
	p.t.Helper()
	return strings.TrimSpace(p.el(sel).MustText())
}

// value returns the current value of a form control
func (p *page) value(sel string) string {
	p.t.Helper()
	return p.el(sel).MustProperty("value").String()
}

// setValue replaces the text of an input or textarea
func (p *page) setValue(sel, v string) {
	p.t.Helper()
	p.el(sel).MustSelectAllText().MustInput(v)
}

// attr returns an attribute of an element ("" when absent)
func (p *page) attr(sel, name string) string {
	p.t.Helper()
	if a := p.el(sel).MustAttribute(name); a != nil {
		return *a
	}
	return ""
}

// pickOption opens a searchable-select dropdown through its toggle button
// and clicks the option with the value
func (p *page) pickOption(name, value string) {
	p.t.Helper()
	p.el(fmt.Sprintf("#param_%s_div searchable-select button[aria-label='Show all options']", name)).MustClick()
	p.el(fmt.Sprintf("#param_%s_listbox:not([hidden])", name))
	p.el(fmt.Sprintf("#param_%s_listbox li[data-value='%s']", name, value)).MustClick()
	p.el(fmt.Sprintf("#param_%s_listbox[hidden]", name))
}

// optionValues returns the data-value of every option of a dropdown
func (p *page) optionValues(name string) string {
	p.t.Helper()
	return p.MustEval(`(name) => Array.from(document.querySelectorAll("#param_" + name + "_listbox li[role=option]")).map((o) => o.dataset.value).join(",")`, name).String()
}

// formButton clicks the Run/Start, Validate or Suggest button of the form
func (p *page) formButton(label string) {
	p.t.Helper()
	p.elR("#action_form button", "^"+label+"$").MustClick()
}

// navLink returns the sidebar switcher link of an action by name
func (p *page) navLink(name string) *rod.Element {
	p.t.Helper()
	return p.elR("#action-nav a", "^"+name+"$")
}

// paramError returns the text of a param's error output
func (p *page) paramError(name string) string {
	p.t.Helper()
	return p.text("#param_" + name + "_error")
}

// markParam tags the current fragment of a param so a wait can tell the
// swapped-in one apart (a repeated Suggest renders the same markup)
func (p *page) markParam(name string) {
	p.t.Helper()
	p.MustEval(`(name) => { document.querySelector("#param_" + name + "_div > div").dataset.old = "1"; }`, name)
}

func requireEqual(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %q, want %q", what, got, want)
	}
}

/* ---------- tests ---------- */

// TestMultiActionNav covers the multi-action app layout: the title and
// description of the current action, the sidebar switcher with every
// action, and the entered param values carried over to the next action
// through the link query string (actions.js appends them at click time;
// hidden params do not render on the target)
func TestMultiActionNav(t *testing.T) {
	const path = "/kitchen-nav"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/")

	requireEqual(t, "title", p.text("h1.page-title"), "Deploy")
	if desc := p.text("main p"); !strings.Contains(desc, "Deploy an app") {
		t.Fatalf("action description missing, got %q", desc)
	}
	names := []string{}
	for _, l := range p.MustElements("#action-nav a") {
		names = append(names, strings.TrimSpace(l.MustText()))
	}
	requireEqual(t, "nav links", strings.Join(names, " "),
		"Deploy Logs Inspect Release Notes Process File Logo Image Restricted Fail")
	requireEqual(t, "active link", p.text("#action-nav a[aria-current=page]"), "Deploy")

	// Deploy shows its own params; the ones hidden for it do not render
	for _, name := range []string{"app_name", "env", "region", "replicas", "notify", "api_token"} {
		p.el("#param_" + name)
	}
	for _, name := range []string{"notes", "upload", "audit_tag"} {
		if p.hasEl("#param_" + name) {
			t.Fatalf("hidden param %s rendered on Deploy", name)
		}
	}

	// Switching actions keeps the entered values: app_name typed here
	// prefills Logs (its link gets ?app_name=... at click time)
	p.setValue("#param_app_name", "navtest-api")
	p.setValue("#param_replicas", "7")
	p.navLink("Logs").MustClick()
	p.waitText("h1.page-title", "Logs")
	p.waitLoaded()
	if u := p.url(); !strings.Contains(u, "app_name=navtest-api") || !strings.Contains(u, "replicas=7") {
		t.Fatalf("nav link did not carry the form values, url %s", u)
	}
	requireEqual(t, "app_name on Logs", p.value("#param_app_name"), "navtest-api")
	requireEqual(t, "active link", p.text("#action-nav a[aria-current=page]"), "Logs")
	if p.hasEl("#param_replicas") {
		t.Fatal("replicas is hidden on Logs but rendered")
	}
	// ... and back: the hidden replicas value passes through the Logs
	// page query string to Deploy
	p.navLink("Deploy").MustClick()
	p.waitText("h1.page-title", "Deploy")
	p.waitLoaded()
	requireEqual(t, "replicas back on Deploy", p.value("#param_replicas"), "7")
	requireEqual(t, "app_name back on Deploy", p.value("#param_app_name"), "navtest-api")
}

// TestSingleActionLayout: a single action app has no sidebar switcher,
// just the form
func TestSingleActionLayout(t *testing.T) {
	const path = "/kitchen-single"
	createApp(t, fixtureSource("suggestapp"), path)
	p := open(t, appURL(path)+"/")
	requireEqual(t, "title", p.text("h1.page-title"), "Pick Org")
	if p.hasEl("#action-nav") {
		t.Fatal("single action app renders the action switcher nav")
	}
	p.el("#action_form #param_org")
	p.formButton("Run")
	p.waitText("#ActionMessage", "org is")
}

// TestParamInputs covers the form control rendered for each param type
// and display type: text, int, boolean checkbox, strict list dropdown,
// COMBO free-text dropdown, password, textarea rows and file
func TestParamInputs(t *testing.T) {
	const path = "/kitchen-params"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/")

	requireEqual(t, "app_name type", p.attr("#param_app_name", "type"), "text")
	requireEqual(t, "app_name default", p.value("#param_app_name"), "orders-api")
	requireEqual(t, "replicas default", p.value("#param_replicas"), "2")
	requireEqual(t, "notify type", p.attr("#param_notify", "type"), "checkbox")
	if !p.el("#param_notify").MustProperty("checked").Bool() {
		t.Fatal("notify default True is not checked")
	}
	requireEqual(t, "api_token type", p.attr("#param_api_token", "type"), "password")

	// env: strict dropdown from the options_env list param
	p.el("#param_env_div searchable-select[data-strict] input#param_env[role=combobox]")
	requireEqual(t, "env default", p.value("#param_env"), "dev")
	requireEqual(t, "env options", p.optionValues("env"), "dev,staging,prod")
	p.pickOption("env", "staging")
	requireEqual(t, "env picked", p.value("#param_env"), "staging")
	p.setValue("#param_env", "nothing")
	p.Keyboard.MustType(input.Tab)
	requireEqual(t, "env strict revert", p.value("#param_env"), "staging")
	// A unique case-insensitive match is normalized to the option
	p.setValue("#param_env", "PROD")
	p.Keyboard.MustType(input.Tab)
	requireEqual(t, "env case normalized", p.value("#param_env"), "prod")

	// region: COMBO display type, free text allowed (no data-strict)
	p.el("#param_region_div searchable-select:not([data-strict]) input#param_region[role=combobox]")
	p.setValue("#param_region", "my-own-region")
	p.Keyboard.MustType(input.Tab)
	requireEqual(t, "combo free text kept", p.value("#param_region"), "my-own-region")

	// textarea:5 display type on the notes action, file on the upload one
	p.navigate(appURL(path) + "/notes")
	requireEqual(t, "notes rows", p.attr("textarea#param_notes", "rows"), "5")
	p.navigate(appURL(path) + "/upload")
	requireEqual(t, "upload type", p.attr("#param_upload", "type"), "file")
}

// TestValidate covers the Validate button (dry run): param errors land in
// the per-param error outputs, a valid form reports the dry run status and
// no report is rendered
func TestValidate(t *testing.T) {
	const path = "/kitchen-validate"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/")

	p.setValue("#param_replicas", "0")
	p.formButton("Validate")
	p.waitText("#ActionMessage", "Validation failed")
	p.waitText("#param_replicas_error [role=alert]", "at least 1 replica is required")
	requireEqual(t, "region error", p.paramError("region"), "region is required, use Suggest to pick one")
	requireEqual(t, "app_name error", p.paramError("app_name"), "")

	// Fixing the values clears the errors; validate renders no report
	p.setValue("#param_replicas", "3")
	p.setValue("#param_region", "us-east-1")
	p.formButton("Validate")
	p.waitText("#ActionMessage", "Validation passed, ready to deploy orders-api to dev")
	requireEqual(t, "replicas error cleared", p.paramError("replicas"), "")
	requireEqual(t, "region error cleared", p.paramError("region"), "")
	if txt := p.text("#action_result"); txt != "" {
		t.Fatalf("validate rendered a report: %q", txt)
	}

	// prod without a token: the error is on the password param
	p.pickOption("env", "prod")
	p.formButton("Validate")
	p.waitText("#param_api_token_error [role=alert]", "an API token is required for prod deploys")
}

// TestSuggest covers the Suggest button: the suggest handler fills
// dropdown options (region, a COMBO param, keeps free text) and plain
// values (replicas), re-suggests narrow a strict list param, and a string
// return is shown as the status
func TestSuggest(t *testing.T) {
	const path = "/kitchen-suggest"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/")

	// region empty: the handler suggests the region list and replicas=3
	requireEqual(t, "region starts empty", p.value("#param_region"), "")
	requireEqual(t, "region options before Suggest", p.optionValues("region"), "")
	p.formButton("Suggest")
	p.waitText("#ActionMessage", "Suggesting values")
	p.el("#param_region_div searchable-select input#param_region[role=combobox]")
	requireEqual(t, "region options", p.optionValues("region"), "us-east-1,us-west-2,eu-central-1,ap-south-1")
	requireEqual(t, "region first option selected", p.value("#param_region"), "us-east-1")
	requireEqual(t, "replicas suggested", p.value("#param_replicas"), "3")
	p.pickOption("region", "eu-central-1")
	requireEqual(t, "region picked", p.value("#param_region"), "eu-central-1")
	// COMBO: typing filters, free text still allowed after the suggest
	p.setValue("#param_region", "us-")
	p.el("#param_region_listbox:not([hidden])")
	if vis := p.MustEval(`() => Array.from(document.querySelectorAll("#param_region_listbox li[role=option]")).filter((o) => !o.hidden).length`).Int(); vis != 2 {
		t.Fatalf("typing us- shows %d options, want 2", vis)
	}
	p.Keyboard.MustType(input.Escape)
	p.el("#param_region_listbox[hidden]")
	p.setValue("#param_region", "custom-region")
	p.Keyboard.MustType(input.Tab)
	requireEqual(t, "combo free text after suggest", p.value("#param_region"), "custom-region")

	// prod without a token: env narrowed to prod/staging (strict list)
	p.pickOption("env", "prod")
	p.markParam("env")
	p.formButton("Suggest")
	p.el("#param_env_div > div:not([data-old]) searchable-select[data-strict] input#param_env[role=combobox]")
	requireEqual(t, "env options narrowed", p.optionValues("env"), "prod,staging")
	requireEqual(t, "env value", p.value("#param_env"), "prod")
	p.pickOption("env", "staging")
	requireEqual(t, "env picked after suggest", p.value("#param_env"), "staging")

	// Nothing left to suggest: the string return is the status
	p.setValue("#param_api_token", "tok")
	p.formButton("Suggest")
	p.waitText("#ActionMessage", "Suggestions complete, ready to run")
}

// TestSuggestDropdownAfterSwap covers the searchable-select after a
// Suggest swap turns a plain text input into a dropdown. The swapped-in
// input keeps the id of the text input it replaces (param_org); htmx 4
// settles id-matched elements, so for the settle delay the new input
// carries the OLD element's attributes (no role=combobox, the old value)
// and the custom element connects inside that window. The component once
// cached its parts at connect time, missed the input and came up dead: no
// option could be selected (regression 2026-11-02, reported with the
// quoted non-ASCII option). A second Suggest settles the listbox and the
// options too (same ids)
func TestSuggestDropdownAfterSwap(t *testing.T) {
	const path = "/kitchen-swap"
	createApp(t, fixtureSource("suggestapp"), path)
	p := open(t, appURL(path)+"/")
	p.el("#action_form input#param_org:not([role])")

	const special = `"test¢£¡¤©«µ³±¶¾¿ÀÆÊÑØÜÞßæçøÐ◦‣₩πψΣΞσ1234`
	pick := func(optIdx int) string {
		t.Helper()
		p.el("searchable-select button[aria-label='Show all options']").MustClick()
		p.el("#param_org_listbox:not([hidden])")
		p.el(fmt.Sprintf("#param_org_opt_%d", optIdx)).MustClick()
		p.el("#param_org_listbox[hidden]")
		return p.value("#param_org")
	}

	for round := 1; round <= 2; round++ {
		p.markParam("org")
		p.formButton("Suggest")
		p.waitText("#ActionMessage", "Suggesting values")
		p.el("#param_org_div > div:not([data-old]) searchable-select input#param_org[role=combobox]")
		// The suggest response selects the first option
		requireEqual(t, fmt.Sprintf("round %d value after suggest", round), p.value("#param_org"), special)

		if got := pick(2); got != "alpha" {
			t.Fatalf("round %d: value after picking option 2: %q, want alpha (dropdown dead after the swap?)", round, got)
		}
		requireEqual(t, fmt.Sprintf("round %d value after picking option 0", round), pick(0), special)

		// Strict mode: text matching no option reverts on blur
		p.setValue("#param_org", "nomatch")
		p.Keyboard.MustType(input.Tab)
		requireEqual(t, fmt.Sprintf("round %d value after nomatch and Tab", round), p.value("#param_org"), special)
		// Typing a prefix and Enter picks the first match
		p.setValue("#param_org", "Ω≈")
		p.el("#param_org_listbox:not([hidden])")
		p.Keyboard.MustType(input.Enter)
		requireEqual(t, fmt.Sprintf("round %d value after Ω≈ and Enter", round), p.value("#param_org"), "Ω≈∑test")
	}

	p.formButton("Run")
	p.waitText("#ActionMessage", "org is Ω≈∑test")
}

// TestTableReport: the Deploy run renders a TABLE report with one row per
// replica, and the run pushes the param values into the url
func TestTableReport(t *testing.T) {
	const path = "/kitchen-table"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/")
	p.setValue("#param_region", "us-east-1")
	p.MustEval(`() => { document.getElementById("param_notify").checked = false; }`)
	p.formButton("Run")
	p.waitText("#ActionMessage", "Deployed orders-api to dev (2 replicas)")
	// Report headings are uppercased by the section-heading style; rod
	// reads the rendered text
	p.waitText("#action_result h2", "REPORT")

	cols := []string{}
	for _, h := range p.MustElements("#action_result table thead th") {
		cols = append(cols, strings.TrimSpace(h.MustText()))
	}
	// The columns are the value keys, sorted
	requireEqual(t, "columns", strings.Join(cols, ","), "env,notified,region,state,unit")
	rows := p.MustElements("#action_result table tbody tr")
	if len(rows) != 2 {
		t.Fatalf("%d report rows, want 2", len(rows))
	}
	requireEqual(t, "row 0", strings.Join(strings.Fields(rows[0].MustText()), " "), "dev false us-east-1 running orders-api-0")
	requireEqual(t, "row 1", strings.Join(strings.Fields(rows[1].MustText()), " "), "dev false us-east-1 running orders-api-1")

	// HX-Push-Url: the run url carries the params, so a reload prefills
	// the form
	if u := p.url(); !strings.Contains(u, "region=us-east-1") || !strings.Contains(u, "notify=false") {
		t.Fatalf("run did not push the param values into the url: %s", u)
	}
	p.MustReload()
	p.waitLoaded()
	requireEqual(t, "region after reload", p.value("#param_region"), "us-east-1")
	if p.el("#param_notify").MustProperty("checked").Bool() {
		t.Fatal("notify=false not applied after reload")
	}
}

// TestTextReport: a TEXT report is a readonly textarea with one line per
// value
func TestTextReport(t *testing.T) {
	const path = "/kitchen-text"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/logs")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Recent logs for orders-api")
	p.waitText("#action_result h2", "OUTPUT")
	text := strings.TrimSpace(p.value("#action_result textarea[readonly]"))
	lines := strings.Split(text, "\n")
	if len(lines) != 4 {
		t.Fatalf("%d output lines, want 4:\n%s", len(lines), text)
	}
	requireEqual(t, "first line", lines[0], "orders-api [dev] request handled path=/api/orders status=200")
	requireEqual(t, "last line", lines[3], "orders-api [dev] scheduled job completed rows=1042")
}

// TestJSONReport: AUTO with nested values renders the JSON tree report
// with expand/collapse controls
func TestJSONReport(t *testing.T) {
	const path = "/kitchen-json"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/inspect")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Runtime details for orders-api")
	p.waitText("#action_result h2", "RESULT")
	tree := p.el("#action_result .json-container")
	// Nested nodes start collapsed (their text hidden) and toggle between
	// the expanded and collapsed classes; Collapse all keeps the root open
	count := func(sel string) int {
		return p.MustEval(`(sel) => document.querySelectorAll("#action_result .json-tree " + sel).length`, sel).Int()
	}
	if txt := tree.MustText(); strings.Contains(txt, "ghcr.io") || !strings.Contains(txt, `app: "orders-api"`) {
		t.Fatalf("initial tree should show the top level only:\n%s", txt)
	}
	before := count("li.expanded")
	p.elR("#action_result button", "^Expand all$").MustClick()
	if n := count("li.expanded"); n <= before {
		t.Fatalf("expand all: %d expanded nodes (was %d)", n, before)
	}
	if n := count("li.collapsed"); n != 0 {
		t.Fatalf("expand all left %d collapsed nodes", n)
	}
	for _, want := range []string{"ghcr.io/example/orders-api:v1.4.2", "Available", "512Mi"} {
		if txt := tree.MustText(); !strings.Contains(txt, want) {
			t.Fatalf("expanded json tree missing %q:\n%s", want, txt)
		}
	}
	p.elR("#action_result button", "^Collapse all$").MustClick()
	if n := count("li.expanded:not(.root)"); n != 0 {
		t.Fatalf("collapse all left %d expanded nodes", n)
	}
}

// TestCustomTemplateReport: a report naming an app template renders
// through it, and the handler's param error on the textarea param shows
// under the textarea
func TestCustomTemplateReport(t *testing.T) {
	const path = "/kitchen-custom"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/notes")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Validation failed")
	p.waitText("#param_notes_error [role=alert]", "release notes cannot be empty")

	p.setValue("textarea#param_notes", "v1.5 ships the new report")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Release notes for orders-api")
	p.waitText("#action_result h2", "RELEASE NOTES")
	requireEqual(t, "notes error cleared", p.paramError("notes"), "")
	requireEqual(t, "template app", p.text("#action_result span.font-mono"), "orders-api")
	requireEqual(t, "template notes", p.text("#action_result pre"), "v1.5 ships the new report")
}

// TestDownloadReport: a file upload param posted as multipart, the
// handler's missing-file param error, and a DOWNLOAD report whose link
// serves the processed file
func TestDownloadReport(t *testing.T) {
	const path = "/kitchen-download"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/upload")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Validation failed")
	p.waitText("#param_upload_error [role=alert]", "a file has to be uploaded")

	src := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(src, []byte("line one\nline two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p.el("#param_upload").MustSetFiles(src)
	p.formButton("Run")
	p.waitText("#ActionMessage", "File is ready for download")
	p.waitText("#action_result h2", "OUTPUT FILE")
	requireEqual(t, "download name", p.text("#action_result a.link"), "numbered_names.txt")
	href := p.attr("#action_result a.link", "href")
	body := p.MustEval(`async (href) => { const r = await fetch(href); return r.status + ":" + await r.text(); }`, href).String()
	if !strings.HasPrefix(body, "200:") || !strings.Contains(body, "1\tline one") || !strings.Contains(body, "2\tline two") {
		t.Fatalf("downloaded file from %s: %q", href, body)
	}
}

// TestImageReport: an IMAGE report renders the image (relative url
// resolved against the action page) with its name as caption
func TestImageReport(t *testing.T) {
	const path = "/kitchen-image"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/image")
	p.formButton("Run")
	p.waitText("#ActionMessage", "Generated the logo image")
	p.waitText("#action_result h2", "OUTPUT IMAGE")
	p.el("#action_result img[alt='openrun-logo.png']")
	requireEqual(t, "caption", p.text("#action_result figcaption"), "openrun-logo.png")
	loaded := p.MustEval(`async () => {
		const img = document.querySelector("#action_result img");
		if (!img.complete) await new Promise((r) => { img.onload = r; img.onerror = r; });
		return img.naturalWidth > 0 && img.currentSrc.endsWith("/static/openrun-logo.png");
	}`).Bool()
	if !loaded {
		t.Fatalf("image did not load from %s", p.attr("#action_result img", "src"))
	}
}

// TestHandlerError: a handler failure (fail()) is a 500 whose text is
// shown in the status line as an error; the next request clears the error
// style
func TestHandlerError(t *testing.T) {
	const path = "/kitchen-fail"
	createApp(t, kitchensinkSource(), path)
	p := open(t, appURL(path)+"/fail")
	p.formButton("Run")
	p.waitText("#ActionMessage.text-error", "API call failed")
	p.waitText("#ActionMessage", "intentional failure, testing action error handling")
	if txt := p.text("#action_result"); txt != "" {
		t.Fatalf("error response rendered a report: %q", txt)
	}
	// The error text is plain text, not swapped as markup: no OOB element
	// from the body is inserted
	if p.hasEl("#ActionMessage div[role=status]") {
		t.Fatal("error body was swapped as HTML")
	}

	p.navLink("Restricted").MustClick()
	p.waitText("h1.page-title", "Restricted")
	p.waitLoaded()
	p.formButton("Run")
	p.waitText("#ActionMessage", "Restricted action ran for orders-api")
	if p.hasEl("#ActionMessage.text-error") {
		t.Fatal("error style kept after a successful run")
	}
}

// TestAsyncRun: an async action's Start redirects to the run page, which
// polls until the run succeeds and shows the result status and the stored
// result; the action page links the run history, which lists the run
func TestAsyncRun(t *testing.T) {
	const path = "/kitchen-async"
	createApp(t, fixtureSource("asyncapp"), path)
	p := open(t, appURL(path)+"/rows")
	p.el("a[href$='/rows/runs']")
	p.setValue("#param_count", "3")
	p.setValue("#param_label", "browser")
	p.formButton("Start")
	p.waitText("#run_status", "Started")
	if u := p.url(); !strings.Contains(u, path+"/rows/runs/") {
		t.Fatalf("Start did not redirect to the run page: %s", u)
	}
	p.el("#run_status[data-run-status=succeeded]")
	p.waitText("#run_status [role=status]", "Built 3 rows")
	// The run card lists the arguments; the stored TABLE result renders
	// below like a sync run's report
	requireEqual(t, "run args", strings.Join(strings.Fields(p.text("#run_status ~ div table tbody tr")), " "), "3 browser")
	rows := p.MustElements("#action_result table tbody tr")
	if len(rows) != 3 {
		t.Fatalf("%d result rows on the run page, want 3", len(rows))
	}
	requireEqual(t, "row 0", strings.Join(strings.Fields(rows[0].MustText()), " "), "1 browser")

	// The runs list (Run History) has the run as succeeded, with the arg
	// columns
	p.navigate(appURL(path) + "/rows/runs")
	p.waitText("#runs_table tbody tr", "succeeded")
	p.waitText("#runs_table tbody tr", "browser")
}
