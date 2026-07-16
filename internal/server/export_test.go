// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
)

// TestExportFieldsClassified fails when a field is added to CreateAppRequest or
// CreateBindingRequest without classifying it for export. This forces the
// exporter (and formatApp/formatBinding) to be updated together with the
// declarative schema, so exports cannot silently become incomplete
func TestExportFieldsClassified(t *testing.T) {
	t.Parallel()
	checkFields := func(typ reflect.Type, classified map[string]bool) {
		fields := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			fields[tag] = true
			if !classified[tag] {
				t.Errorf("%s field %s (json %q) is not classified for export; update exportApp/formatApp and the classification map in export.go",
					typ.Name(), typ.Field(i).Name, tag)
			}
		}
		for tag := range classified {
			if !fields[tag] {
				t.Errorf("%s export classification has entry %q which is not a field", typ.Name(), tag)
			}
		}
	}
	checkFields(reflect.TypeOf(types.CreateAppRequest{}), appExportFields)
	checkFields(reflect.TypeOf(types.CreateBindingRequest{}), bindingExportFields)
}

// normalizeAppRequest maps empty collections and default values to a canonical
// form, since parsing an omitted kwarg produces empty (not nil) collections
func normalizeAppRequest(req *types.CreateAppRequest) {
	if len(req.ParamValues) == 0 {
		req.ParamValues = map[string]string{}
	}
	if len(req.AppConfig) == 0 {
		req.AppConfig = map[string]string{}
	}
	if len(req.ContainerOptions) == 0 {
		req.ContainerOptions = map[string]string{}
	}
	if len(req.ContainerArgs) == 0 {
		req.ContainerArgs = map[string]string{}
	}
	if len(req.ContainerVolumes) == 0 {
		req.ContainerVolumes = []string{}
	}
	if len(req.Bindings) == 0 {
		req.Bindings = []string{}
	}
}

func normalizeBindingRequest(req *types.CreateBindingRequest) {
	if len(req.Grants) == 0 {
		req.Grants = []string{}
	}
	if len(req.Config) == 0 {
		req.Config = map[string]string{}
	}
	req.ApplyInfo = nil
}

// TestExportFormatRoundTrip verifies that formatConfig output, when parsed by
// the apply loader, reproduces the exact requests that were formatted. This is
// the contract that makes exported config re-appliable
func TestExportFormatRoundTrip(t *testing.T) {
	t.Parallel()
	apps := []*types.CreateAppRequest{
		{
			Path:      "example.com:/apps/full",
			SourceUrl: "github.com/org/repo/app",
			AppAuthn:  "github_oauth",
			GitBranch: "main", GitCommit: "abcd1234", GitAuthName: "gh_key",
			Spec:        "python-flask",
			ParamValues: map[string]string{"p1": "v1", "json_list": `["1","2"]`, "int_param": "5"},
			AppConfig: map[string]string{
				"str": `"abc"`, "int": "11", "float": "1.5", "bool": "true",
				"arr": `["a", "b"]`, "table": "k = 1\n",
			},
			ContainerOptions: map[string]string{"co": "1"},
			ContainerArgs:    map[string]string{"ca": "x y"},
			ContainerVolumes: []string{"v1:/abc", "v2"},
			Bindings:         []string{"postgres", "/apps/base"},
			StageAt:          "path",
			Verify:           true,
		},
		{Path: "/apps/minimal", SourceUrl: "/tmp/app"},
		{Path: "/apps/devapp", SourceUrl: "/tmp/devsrc", IsDev: true},
	}
	bindingReqs := []*types.CreateBindingRequest{
		{Path: "/apps/base", Source: "postgres"},
		{Path: "/apps/derived", Source: "/apps/base", Grants: []string{"read:tbl", "create:*"},
			Config: map[string]string{"inherit_default": "true"}},
	}

	config, warnings := formatConfig(bindingReqs, apps)
	if len(warnings) != 0 {
		t.Fatalf("formatConfig warnings = %v, want none", warnings)
	}

	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{},
	}
	parsedApps, parsedBindings, err := server.loadApplyInfo("roundtrip.ace", []byte(config), "", false)
	if err != nil {
		t.Fatalf("loadApplyInfo on formatted config: %v\nconfig:\n%s", err, config)
	}

	if len(parsedApps) != len(apps) {
		t.Fatalf("parsed %d apps, want %d\nconfig:\n%s", len(parsedApps), len(apps), config)
	}
	for i, app := range apps {
		normalizeAppRequest(app)
		normalizeAppRequest(parsedApps[i])
		if !reflect.DeepEqual(app, parsedApps[i]) {
			t.Errorf("app %s did not round trip:\nwant %#v\ngot  %#v\nconfig:\n%s", app.Path, app, parsedApps[i], config)
		}
	}
	if len(parsedBindings) != len(bindingReqs) {
		t.Fatalf("parsed %d bindings, want %d\nconfig:\n%s", len(parsedBindings), len(bindingReqs), config)
	}
	for i, binding := range bindingReqs {
		normalizeBindingRequest(binding)
		normalizeBindingRequest(parsedBindings[i])
		if !reflect.DeepEqual(binding, parsedBindings[i]) {
			t.Errorf("binding %s did not round trip:\nwant %#v\ngot  %#v\nconfig:\n%s", binding.Path, binding, parsedBindings[i], config)
		}
	}
}

// TestExportAppConfigDecode covers the TOML encoded app_config values
func TestExportAppConfigDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stored  string
		literal string
		ok      bool
	}{
		{`"abc"`, `"abc"`, true},
		{`""`, `""`, true},
		{"11", "11", true},
		{"true", "True", true},
		{"false", "False", true},
		{"1.5", "1.5", true},
		{"2.0", "2.0", true},
		{`["a", "b"]`, `["a", "b"]`, true},
		{"[2, 3]", "[2, 3]", true},
		{"k = 1\n", `{"k": 1}`, true},
		{"abc", "", false}, // bare identifier is not valid TOML
		{"", "", false},    // empty value
		{"a = = b", "", false},
	}
	for _, test := range tests {
		literal, ok := decodeAppConfigValue(test.stored)
		if ok != test.ok || literal != test.literal {
			t.Errorf("decodeAppConfigValue(%q) = %q, %t; want %q, %t", test.stored, literal, ok, test.literal, test.ok)
		}
	}
}

func TestExportAppConfigDecodeFailureWarns(t *testing.T) {
	t.Parallel()
	app := &types.CreateAppRequest{
		Path: "/apps/warn", SourceUrl: "/tmp/app",
		AppConfig: map[string]string{"bad": "abc"},
	}
	config, warnings := formatConfig(nil, []*types.CreateAppRequest{app})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "app_config bad") {
		t.Fatalf("warnings = %v, want one app_config warning", warnings)
	}
	if !strings.Contains(config, `app_config={"bad": "abc"}`) {
		t.Fatalf("config missing string fallback for bad value:\n%s", config)
	}
}

// TestExportFormatWrapping verifies the concise formatting rules: short calls
// on one line, long calls one kwarg per line, over-long dicts one entry per
// line, and lists always on one line
func TestExportFormatWrapping(t *testing.T) {
	t.Parallel()
	short := &types.CreateAppRequest{Path: "/apps/short", SourceUrl: "/tmp/app",
		ParamValues: map[string]string{"a": "1"}}
	long := &types.CreateAppRequest{
		Path: "/apps/a-longer-path-name", SourceUrl: "/tmp/some/longer/source/path",
		ParamValues: map[string]string{
			"first_parameter_name":  "a somewhat longer value for the first parameter",
			"second_parameter_name": "another somewhat longer value for the second one",
		},
		ContainerVolumes: []string{"volume-one:/mount/point/one", "volume-two:/mount/point/two", "volume-three:/mount/point/three"},
	}
	config, warnings := formatConfig(nil, []*types.CreateAppRequest{short, long})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}

	expected := `app(path="/apps/short",
    source="/tmp/app",
    params={"a": "1"})

app(path="/apps/a-longer-path-name",
    source="/tmp/some/longer/source/path",
    params={
        "first_parameter_name": "a somewhat longer value for the first parameter",
        "second_parameter_name": "another somewhat longer value for the second one",
    },
    container_vols=["volume-one:/mount/point/one", "volume-two:/mount/point/two", "volume-three:/mount/point/three"])
`
	if config != expected {
		t.Fatalf("formatted config:\n%s\nwant:\n%s", config, expected)
	}

	// The wrapped output must still be valid config
	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{},
	}
	if _, _, err := server.loadApplyInfo("wrap.ace", []byte(config), "", false); err != nil {
		t.Fatalf("wrapped config does not parse: %v", err)
	}
}

// registerExportTestService registers the applytest service binding type and
// creates a default service instance for it
func registerExportTestService(t *testing.T, db interface {
	BeginTransaction(context.Context) (types.Transaction, error)
	CreateService(context.Context, types.Transaction, *types.Service) error
}, ctx context.Context, serviceName string) {
	t.Helper()
	previousBuilder, hadPreviousBuilder := bindings.ServiceBindings["applytest"]
	bindings.ServiceBindings["applytest"] = func() bindings.ServiceBinding {
		return &applyTestServiceBinding{}
	}
	t.Cleanup(func() {
		if hadPreviousBuilder {
			bindings.ServiceBindings["applytest"] = previousBuilder
		} else {
			delete(bindings.ServiceBindings, "applytest")
		}
	})

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "applytest",
		Name:        serviceName,
		ServiceType: "applytest",
		IsDefault:   true,
		Config:      map[string]string{},
	}
	if err := db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service: %v", err)
	}
}

func writeExportTestAppSource(t *testing.T) string {
	t.Helper()
	appSourceDir := filepath.Join(t.TempDir(), "app")
	if err := os.Mkdir(appSourceDir, 0700); err != nil {
		t.Fatalf("create app source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appSourceDir, "app.star"), []byte("app = ace.app(\"testApp\")\n"), 0600); err != nil {
		t.Fatalf("write app.star: %v", err)
	}
	return appSourceDir
}

// TestExportServer covers the full export flow: declarative and imperative
// apps and bindings, auto binding fold back, service ref modes, stage_at
// derivation, exclude-declarative filtering and deterministic output
func TestExportServer(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()
	registerExportTestService(t, db, ctx, "primary")

	appSourceDir := writeExportTestAppSource(t)

	applyPath := filepath.Join(t.TempDir(), "config.ace")
	applyData := fmt.Sprintf(`binding("/apps/base", "applytest/primary")
binding("/apps/derived", "/apps/base", grants=["read:*"])
app("/apps/declared", %q, bindings=["/apps/derived"], stage_at="path", params={"p1": "v1"})
`, appSourceDir)
	if err := os.WriteFile(applyPath, []byte(applyData), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
	if _, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "/apps/**", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Imperatively created app, with an auto binding to the applytest service
	if _, err := server.CreateApp(ctx, "/apps/imperative", false, false, &types.CreateAppRequest{
		SourceUrl:   appSourceDir,
		ParamValues: map[string]string{"ip": "iv"},
		Bindings:    []string{"applytest/primary"},
		StageAt:     "path",
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	exported, err := server.Export(ctx, "all", types.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	for _, want := range []string{
		// default mode drops the service name
		"binding(path=\"/apps/base\",\n    source=\"applytest\")",
		"binding(path=\"/apps/derived\",\n    source=\"/apps/base\",\n    grants=[\"read:*\"])",
		`bindings=["/apps/derived"]`,
		`stage_at="path"`,
		`params={"p1": "v1"}`,
		`bindings=["applytest"]`, // auto binding folded back to a service reference
		`params={"ip": "iv"}`,
		"# Requires services: applytest",
	} {
		if !strings.Contains(exported, want) {
			t.Errorf("export missing %q:\n%s", want, exported)
		}
	}
	if strings.Contains(exported, "/auto/") {
		t.Errorf("export leaked an auto binding path:\n%s", exported)
	}
	declaredIdx := strings.Index(exported, `app(path="/apps/declared"`)
	imperativeIdx := strings.Index(exported, `app(path="/apps/imperative"`)
	if declaredIdx == -1 || imperativeIdx == -1 || declaredIdx > imperativeIdx {
		t.Errorf("apps missing or not sorted by path:\n%s", exported)
	}

	// Deterministic output
	exported2, err := server.Export(ctx, "all", types.ExportOptions{})
	if err != nil {
		t.Fatalf("export again: %v", err)
	}
	if exported != exported2 {
		t.Errorf("export output is not deterministic:\n%s\n----\n%s", exported, exported2)
	}

	// The exported config must parse
	parsedApps, parsedBindings, err := server.loadApplyInfo("export.ace", []byte(exported), "", false)
	if err != nil {
		t.Fatalf("exported config does not parse: %v\n%s", err, exported)
	}
	if len(parsedApps) != 2 || len(parsedBindings) != 2 {
		t.Fatalf("parsed %d apps and %d bindings, want 2 and 2:\n%s", len(parsedApps), len(parsedBindings), exported)
	}

	// Exact service references keep the service name
	exact, err := server.Export(ctx, "all", types.ExportOptions{ServiceRef: types.ExportRefExact})
	if err != nil {
		t.Fatalf("export exact: %v", err)
	}
	for _, want := range []string{
		"binding(path=\"/apps/base\",\n    source=\"applytest/primary\")",
		`bindings=["applytest/primary"]`,
	} {
		if !strings.Contains(exact, want) {
			t.Errorf("exact export missing %q:\n%s", want, exact)
		}
	}

	// Declaratively managed apps and bindings are skipped with ExcludeDeclarative
	imperativeOnly, err := server.Export(ctx, "all", types.ExportOptions{ExcludeDeclarative: true})
	if err != nil {
		t.Fatalf("export exclude declarative: %v", err)
	}
	if strings.Contains(imperativeOnly, "/apps/declared") ||
		strings.Contains(imperativeOnly, `binding(path="/apps/base"`) ||
		strings.Contains(imperativeOnly, `binding(path="/apps/derived"`) {
		t.Errorf("exclude-declarative export contains declarative entries:\n%s", imperativeOnly)
	}
	if !strings.Contains(imperativeOnly, `app(path="/apps/imperative"`) {
		t.Errorf("exclude-declarative export missing the imperative app:\n%s", imperativeOnly)
	}

	// Glob filtering
	filtered, err := server.Export(ctx, "/apps/imperative", types.ExportOptions{})
	if err != nil {
		t.Fatalf("export glob: %v", err)
	}
	if strings.Contains(filtered, `app(path="/apps/declared"`) || !strings.Contains(filtered, `app(path="/apps/imperative"`) {
		t.Errorf("glob filtered export wrong apps:\n%s", filtered)
	}

	// Invalid option values are rejected
	if _, err := server.Export(ctx, "all", types.ExportOptions{ServiceRef: "bogus"}); err == nil {
		t.Error("export with invalid service ref did not fail")
	}
	if _, err := server.Export(ctx, "all", types.ExportOptions{GitAuthRef: "bogus"}); err == nil {
		t.Error("export with invalid git auth ref did not fail")
	}
}

// TestExportStageAtDefault verifies stage_at is omitted when the stage app is
// at this server's default stage location
func TestExportStageAtDefault(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/defstage", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	exported, err := server.Export(ctx, "all", types.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.Contains(exported, "stage_at") {
		t.Errorf("stage_at emitted for default stage location:\n%s", exported)
	}
}

// TestPrettyPrint verifies parsing and canonical re-emission of an existing
// config file, including evaluation of starlark helper logic
func TestPrettyPrint(t *testing.T) {
	t.Parallel()
	server := &Server{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		staticConfig: &types.ServerConfig{},
	}

	configFile := filepath.Join(t.TempDir(), "messy.ace")
	messy := `def path(p):
    return "/dev" + p


app(path("/one"), "/tmp/app1",
    params={"b": "2",   "a": "1"})

binding("/b1", "postgres/svc")


app("/two",   "/tmp/app2", dev=True)
`
	if err := os.WriteFile(configFile, []byte(messy), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	formatted, err := server.PrettyPrint(context.Background(), configFile)
	if err != nil {
		t.Fatalf("pretty print: %v", err)
	}
	expected := `binding(path="/b1",
    source="postgres/svc")


app(path="/dev/one",
    source="/tmp/app1",
    params={"a": "1", "b": "2"})

app(path="/two",
    source="/tmp/app2",
    dev=True)
`
	if formatted != expected {
		t.Fatalf("pretty print output:\n%s\nwant:\n%s", formatted, expected)
	}

	// Errors: missing file, directory, git url
	if _, err := server.PrettyPrint(context.Background(), filepath.Join(t.TempDir(), "missing.ace")); err == nil {
		t.Error("pretty print of missing file did not fail")
	}
	if _, err := server.PrettyPrint(context.Background(), t.TempDir()); err == nil {
		t.Error("pretty print of a directory did not fail")
	}
	if _, err := server.PrettyPrint(context.Background(), "github.com/org/repo/file.ace"); err == nil {
		t.Error("pretty print of a git url did not fail")
	}
}

// TestImperativeCreateHasNoApplyInfo pins the contract that exclude-declarative
// detection relies on: imperative app creation must not store ApplyInfo, while
// apply driven creation must
func TestImperativeCreateHasNoApplyInfo(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	appSourceDir := writeExportTestAppSource(t)
	if _, err := server.CreateApp(ctx, "/apps/imp", false, false, &types.CreateAppRequest{
		SourceUrl: appSourceDir,
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}

	applyPath := filepath.Join(t.TempDir(), "one.ace")
	if err := os.WriteFile(applyPath, []byte(fmt.Sprintf("app(\"/apps/dec\", %q)\n", appSourceDir)), 0600); err != nil {
		t.Fatalf("write apply file: %v", err)
	}
	if _, _, err := server.Apply(ctx, types.Transaction{}, applyPath, "all", false, false, false,
		types.AppReloadOptionNone, "", "", "", false, false, false, "", nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}

	tx, err := db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	imperative, err := db.GetAppEntryTx(ctx, tx, types.AppPathDomain{Path: "/apps/imp"})
	if err != nil {
		t.Fatalf("get imperative app: %v", err)
	}
	if len(imperative.Metadata.VersionMetadata.ApplyInfo) != 0 {
		t.Errorf("imperatively created app has ApplyInfo: %s", imperative.Metadata.VersionMetadata.ApplyInfo)
	}

	declarative, err := db.GetAppEntryTx(ctx, tx, types.AppPathDomain{Path: "/apps/dec"})
	if err != nil {
		t.Fatalf("get declarative app: %v", err)
	}
	if len(declarative.Metadata.VersionMetadata.ApplyInfo) == 0 {
		t.Error("apply created app has no ApplyInfo")
	}
}
