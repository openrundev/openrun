// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

type healthTestManager struct {
	hostNamePort       string
	running            bool
	supportsInPlace    bool
	currentHash        string
	currentHashErr     error
	imageExists        bool
	deployReq          *container.DeployRequest
	runSourceDir       string
	stopContainerCalls int
}

func (m *healthTestManager) BuildImage(context.Context, container.ImageName, string, string, map[string]string) error {
	return nil
}

func (m *healthTestManager) ImageExists(context.Context, container.ImageName) (bool, error) {
	return m.imageExists, nil
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
	m.stopContainerCalls++
	return nil
}

func (m *healthTestManager) RunContainer(_ context.Context, _ *types.AppEntry, sourceDir string, _ container.ContainerName,
	_ container.ImageName, _ int32, _ map[string]string, _ []*container.VolumeInfo, _ map[string]string, _ map[string]string,
	_ string, _ bool, _ *container.HealthProbe) error {
	m.runSourceDir = sourceDir
	if m.hostNamePort == "" {
		m.hostNamePort = "container:5000"
	}
	m.running = true
	return nil
}

func (m *healthTestManager) DeployContainer(_ context.Context, req container.DeployRequest) (container.DeployResult, error) {
	reqCopy := req
	m.deployReq = &reqCopy
	return container.DeployResult{
		ContainerName: req.ContainerName,
		VersionHash:   req.VersionHash,
		HostNamePort:  m.hostNamePort,
	}, nil
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

type imageNameTestFS struct {
	hash        string
	sourceDir   string
	createCount int
}

func (f *imageNameTestFS) Open(string) (fs.File, error) {
	return nil, fs.ErrNotExist
}

func (f *imageNameTestFS) ReadFile(string) ([]byte, error) {
	return nil, fs.ErrNotExist
}

func (f *imageNameTestFS) Glob(string) ([]string, error) {
	return nil, nil
}

func (f *imageNameTestFS) Stat(string) (fs.FileInfo, error) {
	return nil, fs.ErrNotExist
}

func (f *imageNameTestFS) StatNoSpec(string) (fs.FileInfo, error) {
	return nil, fs.ErrNotExist
}

func (f *imageNameTestFS) Reset() {
}

func (f *imageNameTestFS) StaticFiles() []string {
	return nil
}

func (f *imageNameTestFS) FileHash([]string) (string, error) {
	return f.hash, nil
}

func (f *imageNameTestFS) CreateTempSourceDir() (string, error) {
	f.createCount++
	return f.sourceDir, nil
}

func newImageNameTestHandler(appID types.AppId, separateImages bool) *ContainerHandler {
	codeConfig := apptype.NewCodeConfig()
	codeConfig.Container.SeparateStageProdImages = separateImages
	return &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: appID}, codeConfig: codeConfig},
		sourceFS:      &imageNameTestFS{hash: "source-hash"},
		cargs:         map[string]string{"PYTHON_VERSION": "3.12"},
		containerFile: "Dockerfile",
		buildDir:      ".",
	}
}

func TestBuildImageNameSharesStageProdImageByDefault(t *testing.T) {
	t.Parallel()

	stage := newImageNameTestHandler(types.AppId(types.ID_PREFIX_APP_STAGE+"shared"), false)
	prod := newImageNameTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"shared"), false)

	stageImage, err := stage.buildImageName("stage-deploy-hash")
	if err != nil {
		t.Fatalf("stage buildImageName returned error: %v", err)
	}
	prodImage, err := prod.buildImageName("prod-deploy-hash")
	if err != nil {
		t.Fatalf("prod buildImageName returned error: %v", err)
	}

	if stageImage != prodImage {
		t.Fatalf("stage image = %q, prod image = %q, want shared image", stageImage, prodImage)
	}
	if strings.Contains(string(stageImage), types.ID_PREFIX_APP_STAGE) ||
		strings.Contains(string(stageImage), types.ID_PREFIX_APP_PROD) {
		t.Fatalf("shared image %q should strip stage/prod app id prefix", stageImage)
	}
}

func TestBuildImageNameKeepsSeparateStageProdImagesWhenConfigured(t *testing.T) {
	t.Parallel()

	stage := newImageNameTestHandler(types.AppId(types.ID_PREFIX_APP_STAGE+"reflex"), true)
	prod := newImageNameTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"reflex"), true)

	stageImage, err := stage.buildImageName("stage-deploy-hash")
	if err != nil {
		t.Fatalf("stage buildImageName returned error: %v", err)
	}
	prodImage, err := prod.buildImageName("prod-deploy-hash")
	if err != nil {
		t.Fatalf("prod buildImageName returned error: %v", err)
	}

	if stageImage == prodImage {
		t.Fatalf("stage image = prod image = %q, want separate images", stageImage)
	}
	if !strings.Contains(string(stageImage), types.ID_PREFIX_APP_STAGE) {
		t.Fatalf("stage image %q should keep stage app id prefix", stageImage)
	}
	if !strings.Contains(string(prodImage), types.ID_PREFIX_APP_PROD) {
		t.Fatalf("prod image %q should keep prod app id prefix", prodImage)
	}
}

func TestProdReloadKubernetesSkipsSourceDirWhenImageAlreadyExistsWithoutSourceBackedVolumes(t *testing.T) {
	t.Parallel()

	sourceDir := filepath.Join(t.TempDir(), "source")
	sourceFS := &imageNameTestFS{hash: "source-hash", sourceDir: sourceDir}
	manager := &healthTestManager{
		hostNamePort: "kube-svc:5000",
		running:      true,
		imageExists:  true,
	}
	h := &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "kube_no_source_dir")}},
		manager:       manager,
		sourceFS:      sourceFS,
		GenImageName:  container.ImageName("cli-kube-no-source-dir:test"),
		containerFile: "Dockerfile",
		volumeInfo: []*container.VolumeInfo{
			{
				VolumeName: "named-volume",
				SourcePath: "data",
				TargetPath: "/data",
			},
		},
	}

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false); err != nil {
		t.Fatalf("prodReloadKubernetes returned error: %v", err)
	}
	if manager.deployReq == nil {
		t.Fatal("DeployContainer was not called")
	}
	if manager.deployReq.SourceDir != "" {
		t.Fatalf("SourceDir = %q, want empty", manager.deployReq.SourceDir)
	}
	if sourceFS.createCount != 0 {
		t.Fatalf("CreateTempSourceDir called %d times, want 0", sourceFS.createCount)
	}
}

func TestProdReloadKubernetesKeepsSourceDirForSecretVolumeWhenImageAlreadyExists(t *testing.T) {
	t.Parallel()

	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	sourceFS := &imageNameTestFS{hash: "source-hash", sourceDir: sourceDir}
	manager := &healthTestManager{
		hostNamePort: "kube-svc:5000",
		running:      true,
		imageExists:  true,
	}
	h := &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "kube_source_dir")}},
		manager:       manager,
		sourceFS:      sourceFS,
		GenImageName:  container.ImageName("cli-kube-source-dir:test"),
		containerFile: "Dockerfile",
		volumeInfo: []*container.VolumeInfo{
			{
				IsSecret:   true,
				SourcePath: "secrets.toml.tmpl",
				TargetPath: "/app/.streamlit/secrets.toml",
			},
		},
	}

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false); err != nil {
		t.Fatalf("prodReloadKubernetes returned error: %v", err)
	}
	if manager.deployReq == nil {
		t.Fatal("DeployContainer was not called")
	}
	if manager.deployReq.SourceDir != sourceDir {
		t.Fatalf("SourceDir = %q, want %q", manager.deployReq.SourceDir, sourceDir)
	}
	if sourceFS.createCount != 1 {
		t.Fatalf("CreateTempSourceDir called %d times, want 1", sourceFS.createCount)
	}
}

func TestProdReloadKubernetesKeepsSourceDirForConfigMapVolumeWhenImageAlreadyExists(t *testing.T) {
	t.Parallel()

	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	sourceFS := &imageNameTestFS{hash: "source-hash", sourceDir: sourceDir}
	manager := &healthTestManager{
		hostNamePort: "kube-svc:5000",
		running:      true,
		imageExists:  true,
	}
	h := &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "kube_config_source_dir")}},
		manager:       manager,
		sourceFS:      sourceFS,
		GenImageName:  container.ImageName("cli-kube-config-source-dir:test"),
		containerFile: "Dockerfile",
		volumeInfo: []*container.VolumeInfo{
			{
				SourcePath: "settings.toml",
				TargetPath: "/app/settings.toml",
			},
		},
	}

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false); err != nil {
		t.Fatalf("prodReloadKubernetes returned error: %v", err)
	}
	if manager.deployReq == nil {
		t.Fatal("DeployContainer was not called")
	}
	if manager.deployReq.SourceDir != sourceDir {
		t.Fatalf("SourceDir = %q, want %q", manager.deployReq.SourceDir, sourceDir)
	}
	if sourceFS.createCount != 1 {
		t.Fatalf("CreateTempSourceDir called %d times, want 1", sourceFS.createCount)
	}
}

func TestProdReloadCommandKeepsSourceDirForSecretVolumeWhenImageAlreadyExists(t *testing.T) {
	t.Parallel()

	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	sourceFS := &imageNameTestFS{hash: "source-hash", sourceDir: sourceDir}
	manager := &healthTestManager{imageExists: true}
	serverConfig := &types.ServerConfig{Http: types.HttpConfig{Port: 8080}}
	h := &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "secret_source_dir")}, serverConfig: serverConfig},
		serverConfig:  serverConfig,
		manager:       manager,
		sourceFS:      sourceFS,
		containerFile: "Dockerfile",
		volumeInfo: []*container.VolumeInfo{
			{
				IsSecret:   true,
				SourcePath: "secrets.toml.tmpl",
				TargetPath: "/app/.streamlit/secrets.toml",
			},
		},
	}

	if err := h.ProdReload(context.Background(), false, false); err != nil {
		t.Fatalf("ProdReload returned error: %v", err)
	}
	if manager.runSourceDir != sourceDir {
		t.Fatalf("RunContainer sourceDir = %q, want %q", manager.runSourceDir, sourceDir)
	}
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

type exitCheckTestManager struct {
	healthTestManager
	exited     bool
	exitChecks int
}

func (m *exitCheckTestManager) ContainerExited(context.Context, container.ContainerName) (bool, string, error) {
	m.exitChecks++
	return m.exited, "Exited (1) 2 seconds ago", nil
}

func TestWaitForHealthFailsFastOnExitedContainer(t *testing.T) {
	t.Parallel()

	manager := &exitCheckTestManager{exited: true}
	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			AppEntry: &types.AppEntry{
				Id:   types.AppId(types.ID_PREFIX_APP_PROD + "exited_test"),
				Path: "/exited",
			},
		},
		manager:      manager,
		scheme:       "http",
		health:       "health",
		stripAppPath: true,
		containerConfig: types.Container{
			HealthTimeoutSecs: 1,
		},
	}

	err := h.WaitForHealth(75, container.ContainerName("exited-test"), "")
	if err == nil {
		t.Fatal("WaitForHealth returned nil for exited container")
	}
	if !strings.Contains(err.Error(), "exited") {
		t.Fatalf("WaitForHealth error = %q, want container exited", err.Error())
	}
	if manager.exitChecks != 1 {
		t.Fatalf("exit checks = %d, want 1 (fail fast on first attempt)", manager.exitChecks)
	}
}

func TestWaitForHealthRetriesWhenContainerNotExited(t *testing.T) {
	t.Parallel()

	manager := &exitCheckTestManager{exited: false}
	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			AppEntry: &types.AppEntry{
				Id:   types.AppId(types.ID_PREFIX_APP_PROD + "not_exited_test"),
				Path: "/not-exited",
			},
		},
		manager:      manager,
		scheme:       "http",
		health:       "health",
		stripAppPath: true,
		containerConfig: types.Container{
			HealthTimeoutSecs: 1,
		},
	}

	err := h.WaitForHealth(2, container.ContainerName("not-exited-test"), "")
	if err == nil {
		t.Fatal("WaitForHealth returned nil for container that never started")
	}
	if manager.exitChecks != 2 {
		t.Fatalf("exit checks = %d, want 2 (all attempts used)", manager.exitChecks)
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

func newBindingEnvTestHandler(appID types.AppId, bindingSource string) *ContainerHandler {
	return &ContainerHandler{
		app: &App{
			AppEntry: &types.AppEntry{
				Id:    appID,
				Path:  "/binding-env",
				IsDev: strings.HasPrefix(string(appID), types.ID_PREFIX_APP_DEV),
			},
		},
		serverConfig: &types.ServerConfig{},
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

func TestGetBindingEnvProdApp(t *testing.T) {
	t.Parallel()

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_PROD+"binding_env_test"), "postgres/private")

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

	h := newBindingEnvTestHandler(types.AppId(types.ID_PREFIX_APP_DEV+"binding_env_test"), "postgres/private")

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

// TestContainerHandlerIdleShutdownPauseResume covers the pause primitive
// used during a zero downtime in-place restart: idle detection is
// process-local, so the old process must not stop a container based on its
// own stale view of activity while the new process may already be serving
// it. See Server.PauseBackground
func TestContainerHandlerIdleShutdownPauseResume(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{}
	if h.idlePaused.Load() {
		t.Fatal("expected idle shutdown not paused by default")
	}

	h.PauseIdleShutdown()
	if !h.idlePaused.Load() {
		t.Fatal("expected idle shutdown paused after PauseIdleShutdown")
	}

	h.ResumeIdleShutdown()
	if h.idlePaused.Load() {
		t.Fatal("expected idle shutdown not paused after ResumeIdleShutdown")
	}
}

// TestAppPauseIdleShutdownDelegatesToContainerHandler covers App's thin
// wrapper: both methods must delegate to the container handler when present
// and be safe no-ops when it is nil (apps with no container: static, dev
// without a container, ...).
func TestAppPauseIdleShutdownDelegatesToContainerHandler(t *testing.T) {
	t.Parallel()

	var nilHandlerApp App
	nilHandlerApp.PauseIdleShutdown()  // must not panic with a nil containerHandler
	nilHandlerApp.ResumeIdleShutdown() // must not panic with a nil containerHandler

	withHandlerApp := App{containerHandler: &ContainerHandler{}}
	withHandlerApp.PauseIdleShutdown()
	if !withHandlerApp.containerHandler.idlePaused.Load() {
		t.Fatal("expected App.PauseIdleShutdown to pause its container handler")
	}
	withHandlerApp.ResumeIdleShutdown()
	if withHandlerApp.containerHandler.idlePaused.Load() {
		t.Fatal("expected App.ResumeIdleShutdown to resume its container handler")
	}
}

// blockingVersionManager blocks CurrentVersionHash until release is closed,
// signaling arrived first. Used to pin the idleAppShutdown goroutine at a
// known point inside staleInPlaceHandler -- reached only after the fast-path
// idlePaused check and the idle-time/byte-watermark checks have all already
// passed -- so a test can inject a pause with a real happens-before edge
// instead of racing a channel handshake against the goroutine's own
// continuation.
type blockingVersionManager struct {
	healthTestManager
	arrived chan struct{}
	release chan struct{}
}

func (m *blockingVersionManager) SupportsInPlaceUpdate() bool { return true }

func (m *blockingVersionManager) CurrentVersionHash(context.Context, container.ContainerName) (string, error) {
	close(m.arrived)
	<-m.release
	return "", nil // empty hash: staleInPlaceHandler treats this as not-stale and continues
}

// TestIdleAppShutdownRechecksPauseBeforeStoppingContainer drives the real
// idleAppShutdown loop and pauses it in the window between the fast-path
// idlePaused check at the top of the loop and the actual StopContainer call
// -- the exact gap a restart's PauseBackground can land in while this
// goroutine is already committed to an idle-shutdown decision (running
// getAppHash/staleInPlaceHandler/notifyClose). The recheck under stateLock
// immediately before StopContainer must catch a pause that arrives in that
// window instead of stopping the container anyway.
func TestIdleAppShutdownRechecksPauseBeforeStoppingContainer(t *testing.T) {
	t.Parallel()

	manager := &blockingVersionManager{
		arrived: make(chan struct{}),
		release: make(chan struct{}),
	}
	closeCh := make(chan struct{})
	// Short period so the loop body runs promptly; safe to keep firing after
	// the pause below since a paused tick is a no-op via the fast-path check
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
			AppEntry: &types.AppEntry{
				Id:    types.AppId(types.ID_PREFIX_APP_PROD + "idle_pause_race_test"),
				Path:  "/idle-pause-race",
				IsDev: true, // short-circuits getAppHash: no sourceFS needed
			},
		},
		manager:            manager,
		containerConfig:    types.Container{IdleShutdownSecs: 1},
		currentState:       ContainerStateRunning,
		activeVersionHash:  "some-version", // non-empty, so staleInPlaceHandler calls CurrentVersionHash
		idleShutdownTicker: ticker,
		closeCh:            closeCh,
	}
	h.app.lastRequestTime.Store(time.Now().Add(-time.Hour).Unix()) // well past the idle threshold

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.idleAppShutdown(context.Background())
	}()

	// Reaching CurrentVersionHash proves the fast-path idlePaused check (and
	// every check before it) already passed for this iteration
	select {
	case <-manager.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown did not reach staleInPlaceHandler in time")
	}

	// Pause here happens-before the goroutine's continuation past <-release
	// below (channel synchronization), which happens-before its recheck of
	// idlePaused: no race, unlike relying on a single channel handshake that
	// both confirms arrival and releases the goroutine in the same step
	h.PauseIdleShutdown()
	close(manager.release)
	close(closeCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown goroutine did not exit after closeCh was closed")
	}

	if manager.stopContainerCalls != 0 {
		t.Fatalf("expected StopContainer not to be called once idle shutdown was paused mid-decision, got %d calls", manager.stopContainerCalls)
	}
}

// blockingStopManager blocks StopContainer until release is closed,
// signaling arrived first. The idle runner calls StopContainer while holding
// stateLock, so this pins the runner inside a committed container stop
type blockingStopManager struct {
	healthTestManager
	stopArrived chan struct{}
	stopRelease chan struct{}
}

func (m *blockingStopManager) StopContainer(context.Context, container.ContainerName) error {
	close(m.stopArrived)
	<-m.stopRelease
	m.stopContainerCalls++
	return nil
}

// TestPauseIdleShutdownJoinsCommittedStop covers the pause-vs-committed-stop
// race: an idle shutdown that already passed its final pause recheck (and so
// holds stateLock through StopContainer) cannot be aborted, but
// PauseIdleShutdown must not return while that stop is still executing --
// the caller proceeds with a restart handoff on return, and the handoff must
// not overlap a container stop still in progress
func TestPauseIdleShutdownJoinsCommittedStop(t *testing.T) {
	t.Parallel()

	manager := &blockingStopManager{
		stopArrived: make(chan struct{}),
		stopRelease: make(chan struct{}),
	}
	closeCh := make(chan struct{})
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app: &App{
			Logger: types.NewLogger(&types.LogConfig{Level: "WARN"}),
			AppEntry: &types.AppEntry{
				Id:    types.AppId(types.ID_PREFIX_APP_PROD + "idle_pause_join_test"),
				Path:  "/idle-pause-join",
				IsDev: true, // short-circuits getAppHash: no sourceFS needed
			},
		},
		manager:            manager,
		containerConfig:    types.Container{IdleShutdownSecs: 1},
		currentState:       ContainerStateRunning,
		activeVersionHash:  "", // empty: staleInPlaceHandler returns without a version check
		idleShutdownTicker: ticker,
		closeCh:            closeCh,
	}
	h.app.lastRequestTime.Store(time.Now().Add(-time.Hour).Unix()) // well past the idle threshold

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.idleAppShutdown(context.Background())
	}()

	// stopArrived is closed inside StopContainer, which the runner calls
	// while holding stateLock: from here until stopRelease is closed, the
	// stop is committed and in progress
	select {
	case <-manager.stopArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown did not reach StopContainer in time")
	}

	pauseReturned := make(chan struct{})
	go func() {
		h.PauseIdleShutdown()
		close(pauseReturned)
	}()

	select {
	case <-pauseReturned:
		t.Fatal("PauseIdleShutdown returned while a committed container stop was still in progress")
	case <-time.After(100 * time.Millisecond):
	}

	close(manager.stopRelease)
	select {
	case <-pauseReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("PauseIdleShutdown did not return after the container stop finished")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown goroutine did not exit after the container stop")
	}
	if manager.stopContainerCalls != 1 {
		t.Fatalf("expected exactly one container stop, got %d", manager.stopContainerCalls)
	}
}
