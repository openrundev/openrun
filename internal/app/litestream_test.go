// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
)

func newLitestreamTestHandler(appId types.AppId, serverConfig *types.ServerConfig, appBindings []*types.Binding) *ContainerHandler {
	return &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "ERROR"}),
		app: &App{AppEntry: &types.AppEntry{
			Id:    appId,
			Path:  "/ls-test",
			IsDev: strings.HasPrefix(string(appId), types.ID_PREFIX_APP_DEV),
		}},
		serverConfig: serverConfig,
		bindings:     appBindings,
	}
}

func litestreamTestServerConfig() *types.ServerConfig {
	return &types.ServerConfig{
		Litestream: map[string]types.LitestreamConfig{
			"mainbackup": {
				Bucket:          "openrun-backups",
				Endpoint:        "https://s3.example.com",
				Region:          "us-east-1",
				PathPrefix:      "openrun",
				ForcePathStyle:  true,
				SyncInterval:    "1s",
				Retention:       "72h",
				AccessKeyId:     "AKID",
				SecretAccessKey: "SECRET",
			},
			"localdisk": {Type: "file", Path: "/backups"},
		},
	}
}

func sqliteTestBinding(id, litestreamConfig string) *types.Binding {
	serviceConfig := map[string]string{}
	if litestreamConfig != "" {
		serviceConfig[bindings.SqliteConfigLitestream] = litestreamConfig
	}
	return &types.Binding{
		Id:             id,
		Path:           "/auto/app/sqlite",
		ServiceType:    "sqlite",
		ServiceName:    "main",
		Metadata:       types.BindingMetadata{Account: bindings.SqliteAccountForDir(bindings.SqliteDefaultDir)},
		StagedMetadata: types.BindingMetadata{Account: bindings.SqliteAccountForDir(bindings.SqliteDefaultDir)},
		ServiceConfig:  serviceConfig,
	}
}

func TestLitestreamSpec(t *testing.T) {
	t.Parallel()

	prodApp := types.AppId(types.ID_PREFIX_APP_PROD + "lstest")
	h := newLitestreamTestHandler(prodApp, litestreamTestServerConfig(),
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")})

	spec := h.litestreamSpec()
	if spec == nil {
		t.Fatal("spec is nil")
	}
	if spec.Image != "litestream/litestream:0.5" {
		t.Fatalf("image = %q", spec.Image)
	}
	if spec.Env["LITESTREAM_ACCESS_KEY_ID"] != "AKID" || spec.Env["LITESTREAM_SECRET_ACCESS_KEY"] != "SECRET" {
		t.Fatalf("env = %v", spec.Env)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].TargetDir != "/data" {
		t.Fatalf("mounts = %+v", spec.Mounts)
	}
	if spec.ConfigHash == "" {
		t.Fatal("config hash empty")
	}

	yaml := spec.ConfigYAML
	for _, want := range []string{
		"dir: /data\n",
		"pattern: \"*.db\"",
		"watch: true",
		"recursive: true",
		"meta-dir: /data/.litestream",
		"bucket: openrun-backups",
		"path: openrun/bindings/bnd_1/prod",
		"endpoint: https://s3.example.com",
		"force-path-style: true",
		"sync-interval: 1s",
		"retention: 72h",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("config yaml missing %q:\n%s", want, yaml)
		}
	}
	if strings.Contains(yaml, "AKID") || strings.Contains(yaml, "SECRET") {
		t.Fatalf("credentials leaked into config yaml:\n%s", yaml)
	}

	// Staged app replicates to a separate location
	stagedHandler := newLitestreamTestHandler(types.AppId(types.ID_PREFIX_APP_STAGE+"lstest"),
		litestreamTestServerConfig(), []*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")})
	stagedSpec := stagedHandler.litestreamSpec()
	if !strings.Contains(stagedSpec.ConfigYAML, "path: openrun/bindings/bnd_1/staged") {
		t.Fatalf("staged replica path missing:\n%s", stagedSpec.ConfigYAML)
	}

	// container_endpoint overrides the endpoint containers see (kubernetes
	// setups with a host-local endpoint); the server keeps the original
	overridden := litestreamTestServerConfig()
	cfg := overridden.Litestream["mainbackup"]
	cfg.ContainerEndpoint = "http://nodes.example.com:8333"
	overridden.Litestream["mainbackup"] = cfg
	overriddenSpec := newLitestreamTestHandler(prodApp, overridden,
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")}).litestreamSpec()
	if !strings.Contains(overriddenSpec.ConfigYAML, "endpoint: http://nodes.example.com:8333") {
		t.Fatalf("container endpoint override missing:\n%s", overriddenSpec.ConfigYAML)
	}
}

func TestLitestreamSpecSkips(t *testing.T) {
	t.Parallel()

	serverConfig := litestreamTestServerConfig()
	prodApp := types.AppId(types.ID_PREFIX_APP_PROD + "lstest")

	// No litestream config on the service
	h := newLitestreamTestHandler(prodApp, serverConfig, []*types.Binding{sqliteTestBinding("bnd_1", "")})
	if spec := h.litestreamSpec(); spec != nil {
		t.Fatalf("spec without litestream config = %+v", spec)
	}

	// Undefined config name: skipped, app keeps working
	h = newLitestreamTestHandler(prodApp, serverConfig, []*types.Binding{sqliteTestBinding("bnd_1", "removed")})
	if spec := h.litestreamSpec(); spec != nil {
		t.Fatalf("spec with undefined config = %+v", spec)
	}

	// File replica type is host-local, not supported for app bindings
	h = newLitestreamTestHandler(prodApp, serverConfig, []*types.Binding{sqliteTestBinding("bnd_1", "localdisk")})
	if spec := h.litestreamSpec(); spec != nil {
		t.Fatalf("spec with file replica type = %+v", spec)
	}

	// Dev apps do not replicate
	h = newLitestreamTestHandler(types.AppId(types.ID_PREFIX_APP_DEV+"lstest"), serverConfig,
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")})
	if spec := h.litestreamSpec(); spec != nil {
		t.Fatalf("spec for dev app = %+v", spec)
	}

	// Preview apps do not replicate either: they would share the staged
	// replica location with the real staging app
	h = newLitestreamTestHandler(types.AppId(types.ID_PREFIX_APP_PREVIEW+"lstest"), serverConfig,
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")})
	if spec := h.litestreamSpec(); spec != nil {
		t.Fatalf("spec for preview app = %+v", spec)
	}
}

func TestSqlitePermsImage(t *testing.T) {
	t.Parallel()

	prodApp := types.AppId(types.ID_PREFIX_APP_PROD + "lstest")

	// With replication enabled, the litestream image runs the volume chmod so
	// distroless app images work
	h := newLitestreamTestHandler(prodApp, litestreamTestServerConfig(),
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")})
	h.GenImageName = "cli-app:abc"
	if image := h.sqlitePermsImage(); image != "litestream/litestream:0.5" {
		t.Fatalf("perms image with litestream = %q", image)
	}

	// Local-only binding: the app image is the only one guaranteed present
	h = newLitestreamTestHandler(prodApp, litestreamTestServerConfig(),
		[]*types.Binding{sqliteTestBinding("bnd_1", "")})
	h.GenImageName = "cli-app:abc"
	if image := h.sqlitePermsImage(); image != "cli-app:abc" {
		t.Fatalf("perms image without litestream = %q", image)
	}
}

// TestLitestreamStagingServiceConfig covers a sqlite service with a linked
// staging service: staged apps follow the staging service's config (its own
// litestream config and path prefix), prod apps the primary's.
func TestLitestreamStagingServiceConfig(t *testing.T) {
	t.Parallel()

	serverConfig := litestreamTestServerConfig()
	serverConfig.Litestream["stagebackup"] = types.LitestreamConfig{
		Bucket:          "staging-backups",
		Endpoint:        "https://s3.example.com",
		PathPrefix:      "staging",
		AccessKeyId:     "STG_KEY",
		SecretAccessKey: "STG_SECRET",
	}

	binding := sqliteTestBinding("bnd_1", "mainbackup")
	binding.StagingServiceConfig = map[string]string{
		bindings.SqliteConfigLitestream: "stagebackup",
	}

	prodSpec := newLitestreamTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"lstest"),
		serverConfig, []*types.Binding{binding}).litestreamSpec()
	if !strings.Contains(prodSpec.ConfigYAML, "bucket: openrun-backups") ||
		!strings.Contains(prodSpec.ConfigYAML, "path: openrun/bindings/bnd_1/prod") {
		t.Fatalf("prod spec uses wrong config:\n%s", prodSpec.ConfigYAML)
	}

	stagedSpec := newLitestreamTestHandler(types.AppId(types.ID_PREFIX_APP_STAGE+"lstest"),
		serverConfig, []*types.Binding{binding}).litestreamSpec()
	if !strings.Contains(stagedSpec.ConfigYAML, "bucket: staging-backups") ||
		!strings.Contains(stagedSpec.ConfigYAML, "path: staging/bindings/bnd_1/staged") {
		t.Fatalf("staged spec does not use the staging service config:\n%s", stagedSpec.ConfigYAML)
	}
	if stagedSpec.Env["LITESTREAM_ACCESS_KEY_ID"] != "STG_KEY" {
		t.Fatalf("staged spec credentials = %v", stagedSpec.Env)
	}
}

func TestLitestreamConfigHashChangesRollApp(t *testing.T) {
	t.Parallel()

	prodApp := types.AppId(types.ID_PREFIX_APP_PROD + "lstest")
	base := newLitestreamTestHandler(prodApp, litestreamTestServerConfig(),
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")}).litestreamSpec()

	changed := litestreamTestServerConfig()
	cfg := changed.Litestream["mainbackup"]
	cfg.SyncInterval = "10s"
	changed.Litestream["mainbackup"] = cfg
	after := newLitestreamTestHandler(prodApp, changed,
		[]*types.Binding{sqliteTestBinding("bnd_1", "mainbackup")}).litestreamSpec()

	if base.ConfigHash == after.ConfigHash {
		t.Fatal("config hash did not change with sync interval change")
	}
}
