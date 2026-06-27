// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

type healthTestManager struct {
	hostNamePort    string
	running         bool
	supportsInPlace bool
	currentHash     string
	currentHashErr  error
}

func (m *healthTestManager) BuildImage(context.Context, container.ImageName, string, string, map[string]string) error {
	return nil
}

func (m *healthTestManager) ImageExists(context.Context, container.ImageName) (bool, error) {
	return true, nil
}

func (m *healthTestManager) RefreshImage(context.Context, container.ImageName) (string, error) {
	return "", nil
}

func (m *healthTestManager) GetContainerState(context.Context, container.ContainerName, string) (string, bool, error) {
	return m.hostNamePort, m.running, nil
}

func (m *healthTestManager) StartContainer(context.Context, container.ContainerName) error {
	return nil
}

func (m *healthTestManager) StopContainer(context.Context, container.ContainerName) error {
	return nil
}

func (m *healthTestManager) RunContainer(context.Context, *types.AppEntry, string, container.ContainerName,
	container.ImageName, int32, map[string]string, []*container.VolumeInfo, map[string]string, map[string]string, string, bool,
	*container.HealthProbe) error {
	return nil
}

func (m *healthTestManager) DeployContainer(context.Context, container.DeployRequest) (container.DeployResult, error) {
	return container.DeployResult{}, nil
}

func (m *healthTestManager) GetContainerLogs(context.Context, container.ContainerName, int) (string, error) {
	return "", nil
}

func (m *healthTestManager) VolumeExists(context.Context, container.VolumeName) bool {
	return true
}

func (m *healthTestManager) VolumeCreate(context.Context, container.VolumeName) error {
	return nil
}

func (m *healthTestManager) SupportsInPlaceUpdate() bool {
	return m.supportsInPlace
}

func (m *healthTestManager) CurrentVersionHash(context.Context, container.ContainerName) (string, error) {
	if m.currentHashErr != nil {
		return "", m.currentHashErr
	}
	return m.currentHash, nil
}

func TestWaitForHealthFailsOnNonOKStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not healthy", http.StatusInternalServerError)
	}))
	defer srv.Close()

	hostNamePort := strings.TrimPrefix(srv.URL, "http://")
	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			AppEntry: &types.AppEntry{
				Id:   types.AppId(types.ID_PREFIX_APP_PROD + "health_status_test"),
				Path: "/health-status",
			},
		},
		manager: &healthTestManager{
			hostNamePort: hostNamePort,
			running:      true,
		},
		scheme:       "http",
		health:       "health",
		stripAppPath: true,
		containerConfig: types.Container{
			HealthTimeoutSecs: 1,
		},
	}

	err := h.WaitForHealth(1, container.ContainerName("health-status-test"), "")
	if err == nil {
		t.Fatal("WaitForHealth returned nil for HTTP 500")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("WaitForHealth error = %q, want status 500", err.Error())
	}
}

func TestWaitForHealthUsesProxyPathAfterContainerReady(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok") //nolint:errcheck
	}))
	defer srv.Close()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			AppEntry: &types.AppEntry{
				Id:   types.AppId(types.ID_PREFIX_APP_PROD + "proxy_ready_test"),
				Path: "/proxy-ready",
			},
		},
		manager: &healthTestManager{
			hostNamePort: strings.TrimPrefix(srv.URL, "http://"),
			running:      true,
		},
		scheme:       "http",
		health:       "health",
		stripAppPath: true,
		containerConfig: types.Container{
			HealthTimeoutSecs: 1,
		},
	}

	if err := h.WaitForHealth(1, container.ContainerName("proxy-ready-test"), "hash"); err != nil {
		t.Fatalf("WaitForHealth returned error: %v", err)
	}
}

func TestBuildHealthProbeUsesDeployHealthConfig(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		app:    &App{AppEntry: &types.AppEntry{Path: "/my-app"}},
		port:   8080,
		health: "ready",
		containerConfig: types.Container{
			HealthAttemptsAfterStartup: 12,
			HealthTimeoutSecs:          5,
			StatusHealthAttempts:       4,
			DeployProbePeriodSecs:      2,
			DeployHealthAttempts:       9,
		},
	}

	probe := h.buildHealthProbe()
	if probe == nil {
		t.Fatal("buildHealthProbe returned nil")
	}
	if probe.PeriodSecs != 2 {
		t.Fatalf("PeriodSecs = %d, want 2", probe.PeriodSecs)
	}
	if probe.TimeoutSecs != 5 {
		t.Fatalf("TimeoutSecs = %d, want configured timeout 5", probe.TimeoutSecs)
	}
	if probe.FailureThreshold != 4 {
		t.Fatalf("FailureThreshold = %d, want 4", probe.FailureThreshold)
	}
	if probe.StartupFailures != 12 {
		t.Fatalf("StartupFailures = %d, want 12", probe.StartupFailures)
	}
}

func TestBuildHealthProbeDefaultsInvalidTimingValues(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		app:    &App{AppEntry: &types.AppEntry{Path: "/my-app"}},
		port:   8080,
		health: "ready",
	}

	probe := h.buildHealthProbe()
	if probe == nil {
		t.Fatal("buildHealthProbe returned nil")
	}
	if probe.PeriodSecs != 1 {
		t.Fatalf("PeriodSecs = %d, want default 1", probe.PeriodSecs)
	}
	if probe.TimeoutSecs != 1 {
		t.Fatalf("TimeoutSecs = %d, want default 1", probe.TimeoutSecs)
	}
	if probe.FailureThreshold != 1 {
		t.Fatalf("FailureThreshold = %d, want default 1", probe.FailureThreshold)
	}
	if probe.StartupFailures != 1 {
		t.Fatalf("StartupFailures = %d, want default 1", probe.StartupFailures)
	}
}

func TestStaleInPlaceHandlerDetectsNewerDeploymentVersion(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{AppEntry: &types.AppEntry{
			Id:   types.AppId(types.ID_PREFIX_APP_PROD + "stale_handler_test"),
			Path: "/stale-handler",
		}},
		manager: &healthTestManager{
			supportsInPlace: true,
			currentHash:     "new-version",
		},
	}

	if !h.staleInPlaceHandler(context.Background(), container.ContainerName("stale-handler-test"), "old-version") {
		t.Fatal("expected stale handler when live deployment hash differs from active hash")
	}
}

func TestStaleInPlaceHandlerAllowsCurrentDeploymentVersion(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{AppEntry: &types.AppEntry{
			Id:   types.AppId(types.ID_PREFIX_APP_PROD + "current_handler_test"),
			Path: "/current-handler",
		}},
		manager: &healthTestManager{
			supportsInPlace: true,
			currentHash:     "same-version",
		},
	}

	if h.staleInPlaceHandler(context.Background(), container.ContainerName("current-handler-test"), "same-version") {
		t.Fatal("did not expect stale handler when live deployment hash matches active hash")
	}
}

func TestStaleInPlaceHandlerTreatsMissingActiveHashAsStale(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{AppEntry: &types.AppEntry{
			Id:   types.AppId(types.ID_PREFIX_APP_PROD + "missing_hash_test"),
			Path: "/missing-hash",
		}},
		manager: &healthTestManager{supportsInPlace: true},
	}

	if !h.staleInPlaceHandler(context.Background(), container.ContainerName("missing-hash-test"), "") {
		t.Fatal("expected stale handler when in-place manager has no active hash recorded")
	}
}

func TestStaleInPlaceHandlerKeepsRunningOnVersionLookupError(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{AppEntry: &types.AppEntry{
			Id:   types.AppId(types.ID_PREFIX_APP_PROD + "lookup_error_test"),
			Path: "/lookup-error",
		}},
		manager: &healthTestManager{
			supportsInPlace: true,
			currentHashErr:  fmt.Errorf("temporary version lookup failure"),
		},
	}

	if h.staleInPlaceHandler(context.Background(), container.ContainerName("lookup-error-test"), "old-version") {
		t.Fatal("did not expect stale handler when current version lookup temporarily fails")
	}
}

func newVolumeTestHandler(t *testing.T) (*ContainerHandler, string) {
	t.Helper()

	home := t.TempDir()
	t.Setenv(types.OPENRUN_HOME, home)

	appID := types.AppId("app_prd_volume_test")
	return &ContainerHandler{
		app: &App{
			AppEntry: &types.AppEntry{
				Id:        appID,
				SourceUrl: filepath.Join(home, "source"),
			},
			AppRunPath: filepath.Join(home, "run", "app", string(appID)),
		},
		serverConfig: &types.ServerConfig{
			Security: types.SecurityConfig{
				AllowedMounts: []string{"$OPENRUN_HOME/mounts"},
			},
		},
	}, home
}

func TestParseVolumeStringAllowsAllowedMountSource(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "mounts", "config.yaml")

	vol, err := h.parseVolumeString("$OPENRUN_HOME/mounts/config.yaml:/etc/config.yaml:ro")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	if vol.VolumeName != "" {
		t.Fatalf("VolumeName = %q, want bind mount", vol.VolumeName)
	}
	if vol.SourcePath != source {
		t.Fatalf("SourcePath = %q, want %q", vol.SourcePath, source)
	}
	if vol.TargetPath != "/etc/config.yaml" {
		t.Fatalf("TargetPath = %q, want /etc/config.yaml", vol.TargetPath)
	}
	if !vol.ReadOnly {
		t.Fatal("ReadOnly = false, want true")
	}
}

func TestParseVolumeStringRejectsBindSourceOutsideAllowedMounts(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "outside", "config.yaml")

	if _, err := h.parseVolumeString(source + ":/etc/config.yaml"); err == nil {
		t.Fatal("parseVolumeString should reject bind sources outside allowed mount roots")
	}
}

func TestParseVolumeStringRejectsRelativeBindTraversal(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	if _, err := h.parseVolumeString("../config.yaml:/etc/config.yaml"); err == nil {
		t.Fatal("parseVolumeString should reject relative bind sources with parent traversal")
	}
}

func TestParseVolumeStringAllowsSourceRelativeBind(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	vol, err := h.parseVolumeString("./config.yaml:/etc/config.yaml")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	want := "." + string(filepath.Separator) + "config.yaml"
	if vol.SourcePath != want {
		t.Fatalf("SourcePath = %q, want %q", vol.SourcePath, want)
	}
}

func TestParseVolumeStringRejectsSecretSourceOutsideAllowedMounts(t *testing.T) {
	h, home := newVolumeTestHandler(t)
	source := filepath.Join(home, "outside", "secret.tmpl")

	if _, err := h.parseVolumeString(VOL_PREFIX_SECRET + source + ":/etc/secret"); err == nil {
		t.Fatal("parseVolumeString should reject absolute secret sources outside allowed mount roots")
	}
}

func TestParseVolumeStringLeavesNamedVolumesUnchanged(t *testing.T) {
	h, _ := newVolumeTestHandler(t)

	vol, err := h.parseVolumeString("cache:/var/cache")
	if err != nil {
		t.Fatalf("parseVolumeString returned error: %v", err)
	}
	if vol.VolumeName != "cache" {
		t.Fatalf("VolumeName = %q, want cache", vol.VolumeName)
	}
}

func newBindingEnvTestHandler(appID types.AppId, approvedSources []string, serverSources []string, bindingSource string) *ContainerHandler {
	return &ContainerHandler{
		app: &App{
			AppEntry: &types.AppEntry{
				Id:    appID,
				Path:  "/binding-env",
				IsDev: strings.HasPrefix(string(appID), types.ID_PREFIX_APP_DEV),
				Metadata: types.AppMetadata{
					ApprovedBindingSourcePerms: approvedSources,
				},
			},
		},
		serverConfig: &types.ServerConfig{
			Permissions: types.PermissionsConfig{
				BindingSourcePerms: serverSources,
			},
		},
		bindings: []*types.Binding{
			{
				Source:           bindingSource,
				ServiceType:      "postgres",
				ServiceName:      "default",
				ServiceIsDefault: true,
				Metadata: types.BindingMetadata{
					Account: map[string]string{
						"url":        "postgres://prod-substituted",
						"url_direct": "postgres://prod-direct",
					},
				},
				StagedMetadata: types.BindingMetadata{
					Account: map[string]string{
						"url":        "postgres://stage-substituted",
						"url_direct": "postgres://stage-direct",
					},
				},
			},
		},
	}
}

func TestGetBindingEnvRejectsUnapprovedBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"binding_env_test"), nil, nil, "postgres/private")

	_, err := h.getBindingEnv()
	if err == nil {
		t.Fatal("expected unapproved binding source error")
	}
	if !strings.Contains(err.Error(), "not approved to use binding source postgres/private") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestGetBindingEnvAllowsApprovedBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"binding_env_test"), []string{"postgres/private"}, nil, "postgres/private")

	env, err := h.getBindingEnv()
	if err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
	if env["POSTGRES_URL"] != "postgres://prod-substituted" {
		t.Fatalf("POSTGRES_URL = %q", env["POSTGRES_URL"])
	}
	if env["POSTGRES_URL_DIRECT"] != "postgres://prod-direct" {
		t.Fatalf("POSTGRES_URL_DIRECT = %q", env["POSTGRES_URL_DIRECT"])
	}
}

func TestGetBindingEnvUsesStagedAccountForDevApp(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_DEV+"binding_env_test"), []string{"postgres/private"}, nil, "postgres/private")

	env, err := h.getBindingEnv()
	if err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
	if env["POSTGRES_URL"] != "postgres://stage-substituted" {
		t.Fatalf("POSTGRES_URL = %q", env["POSTGRES_URL"])
	}
	if env["POSTGRES_URL_DIRECT"] != "postgres://stage-direct" {
		t.Fatalf("POSTGRES_URL_DIRECT = %q", env["POSTGRES_URL_DIRECT"])
	}
}

func TestGetBindingEnvAllowsServerBindingSource(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"binding_env_test"), nil, []string{"postgres/private"}, "postgres/private")

	if _, err := h.getBindingEnv(); err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
}

func TestBindingSourceMatchesDefaultServiceShorthand(t *testing.T) {
	t.Parallel()

	binding := &types.Binding{
		Source:           "postgres",
		ServiceType:      "postgres",
		ServiceName:      "default",
		ServiceIsDefault: true,
	}
	if !bindingSourceMatches(binding, "postgres/default") {
		t.Fatal("expected default service approval to allow shorthand source")
	}

	binding.Source = "postgres/default"
	if !bindingSourceMatches(binding, "postgres") {
		t.Fatal("expected shorthand approval to allow default service source")
	}

	binding.ServiceName = "private"
	binding.ServiceIsDefault = false
	if bindingSourceMatches(binding, "postgres") {
		t.Fatal("did not expect shorthand approval to allow non-default service source")
	}

	binding.Source = "postgres/private"
	if bindingSourceMatches(binding, "postgres") {
		t.Fatal("did not expect shorthand approval to allow explicit non-default service source")
	}
}
