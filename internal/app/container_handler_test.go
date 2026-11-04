// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

type devReloadTestFS struct {
	files fstest.MapFS
}

func (f *devReloadTestFS) Open(name string) (fs.File, error) {
	return f.files.Open(name)
}

func (f *devReloadTestFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(f.files, name)
}

func (f *devReloadTestFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(f.files, pattern)
}

func (f *devReloadTestFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(f.files, name)
}

func (f *devReloadTestFS) StatNoSpec(name string) (fs.FileInfo, error) {
	return fs.Stat(f.files, name)
}

func (f *devReloadTestFS) Reset() {}

func (f *devReloadTestFS) StaticFiles() []string { return nil }

func (f *devReloadTestFS) FileHash([]string) (string, error) {
	return "", errors.New("not implemented")
}

func (f *devReloadTestFS) CreateTempSourceDir() (string, error) {
	return "", errors.New("not implemented")
}

type devReloadTestManager struct {
	healthTestManager
	exists                bool
	matches               bool
	infoHostPort          string
	infoCalls             int
	getStateCalls         int
	restartCalls          int
	removeContainerCalls  int
	buildCalls            int
	runDevCalls           int
	removeSupersededCalls int
	restartErr            error
}

func (m *devReloadTestManager) GetContainerState(context.Context, container.ContainerName, string) (string, bool, error) {
	m.getStateCalls++
	return m.hostNamePort, m.running, nil
}

func (m *devReloadTestManager) RemoveImage(context.Context, container.ImageName) error { return nil }

func (m *devReloadTestManager) RemoveSupersededImages(context.Context, container.ImageName) error {
	m.removeSupersededCalls++
	return nil
}

func (m *devReloadTestManager) RemoveContainer(context.Context, container.ContainerName) error {
	m.removeContainerCalls++
	m.running = false
	return nil
}

func (m *devReloadTestManager) BuildImageTarget(context.Context, container.ImageName, string, string, map[string]string, string) error {
	m.buildCalls++
	m.imageExists = true
	return nil
}

func (m *devReloadTestManager) RunDevContainer(_ context.Context, _ *types.AppEntry, _ string, _ container.ContainerName,
	_ container.ImageName, _ int32, _ map[string]string, _ []*container.VolumeInfo, _ map[string]string, _ map[string]string,
	_ container.DevRunOptions) error {
	m.runDevCalls++
	m.running = true
	if m.hostNamePort == "" {
		m.hostNamePort = "127.0.0.1:49152"
	}
	return nil
}

func (m *devReloadTestManager) GetDevContainerInfo(context.Context, container.ContainerName, string) (bool, bool, string, bool, error) {
	m.infoCalls++
	return m.exists, m.matches, m.infoHostPort, m.running, nil
}

func (m *devReloadTestManager) RestartDevContainer(context.Context, container.ContainerName) error {
	m.restartCalls++
	if m.restartErr != nil {
		return m.restartErr
	}
	m.running = true
	return nil
}

func newDevReloadTestHandler(t *testing.T, manager *devReloadTestManager, reload string) *ContainerHandler {
	t.Helper()
	specFiles := types.SpecFiles{}
	serverConfig := &types.ServerConfig{}
	appEntry := &types.AppEntry{
		Id:        "app-dev-reload-test",
		Path:      "/dev-reload-test",
		SourceUrl: t.TempDir(),
		IsDev:     true,
		Metadata: types.AppMetadata{
			SpecFiles:        &specFiles,
			ContainerOptions: map[string]string{},
		},
	}
	app := &App{AppEntry: appEntry, serverConfig: serverConfig}
	return &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		manager:       manager,
		app:           app,
		serverConfig:  serverConfig,
		containerFile: "Containerfile",
		buildDir:      ".",
		sourceFS: &devReloadTestFS{files: fstest.MapFS{
			"Containerfile": &fstest.MapFile{Data: []byte("FROM alpine AS builder\n")},
		}},
		cargs:           map[string]string{},
		paramMap:        map[string]string{},
		devSettings:     &types.DevSettings{Target: "builder", Dir: "/app", Reload: reload},
		volumeInfo:      []*container.VolumeInfo{{SourcePath: appEntry.SourceUrl, TargetPath: "/app"}},
		lifetime:        "app",
		containerConfig: types.Container{HealthAttemptsAfterStartup: 1},
	}
}

func TestDevReloadFastHotReloadReusesSingleContainerLookup(t *testing.T) {
	t.Parallel()

	manager := &devReloadTestManager{
		healthTestManager: healthTestManager{running: true},
		exists:            true,
		matches:           true,
		infoHostPort:      "127.0.0.1:49152",
	}
	h := newDevReloadTestHandler(t, manager, types.DEV_RELOAD_NONE)

	if err := h.devReloadFast(context.Background(), manager); err != nil {
		t.Fatalf("devReloadFast returned error: %v", err)
	}
	if manager.infoCalls != 1 || manager.getStateCalls != 0 {
		t.Fatalf("container lookups = info:%d state:%d, want info:1 state:0", manager.infoCalls, manager.getStateCalls)
	}
	if manager.restartCalls != 0 || manager.runDevCalls != 0 || manager.buildCalls != 0 {
		t.Fatalf("unexpected mutations: restart=%d run=%d build=%d", manager.restartCalls, manager.runDevCalls, manager.buildCalls)
	}
	if h.hostNamePort != manager.infoHostPort || h.currentState != ContainerStateRunning {
		t.Fatalf("handler state = (%q, %q), want (%q, %q)", h.hostNamePort, h.currentState, manager.infoHostPort, ContainerStateRunning)
	}
}

func TestDevReloadFastRestartReusesPublishedPort(t *testing.T) {
	t.Parallel()

	manager := &devReloadTestManager{
		healthTestManager: healthTestManager{running: true},
		exists:            true,
		matches:           true,
		infoHostPort:      "127.0.0.1:49152",
	}
	h := newDevReloadTestHandler(t, manager, types.DEV_RELOAD_RESTART)

	if err := h.devReloadFast(context.Background(), manager); err != nil {
		t.Fatalf("devReloadFast returned error: %v", err)
	}
	if manager.restartCalls != 1 || manager.getStateCalls != 0 {
		t.Fatalf("restart/state calls = %d/%d, want 1/0", manager.restartCalls, manager.getStateCalls)
	}
	if manager.removeContainerCalls != 0 || manager.runDevCalls != 0 {
		t.Fatalf("unexpected recreate: remove=%d run=%d", manager.removeContainerCalls, manager.runDevCalls)
	}
}

func TestDevReloadFastRecreateUsesForceRemovalWithoutGracefulStop(t *testing.T) {
	t.Parallel()

	manager := &devReloadTestManager{
		healthTestManager: healthTestManager{running: true, imageExists: true},
		exists:            true,
		matches:           true,
		infoHostPort:      "127.0.0.1:49152",
	}
	h := newDevReloadTestHandler(t, manager, types.DEV_RELOAD_RECREATE)

	if err := h.devReloadFast(context.Background(), manager); err != nil {
		t.Fatalf("devReloadFast returned error: %v", err)
	}
	if manager.stopContainerCalls != 0 {
		t.Fatalf("StopContainer calls = %d, want 0", manager.stopContainerCalls)
	}
	if manager.removeContainerCalls != 1 || manager.runDevCalls != 1 {
		t.Fatalf("remove/run calls = %d/%d, want 1/1", manager.removeContainerCalls, manager.runDevCalls)
	}
	if manager.removeSupersededCalls != 1 {
		t.Fatalf("RemoveSupersededImages calls = %d, want 1", manager.removeSupersededCalls)
	}
}

func TestDevImageHashTracksDependencyFiles(t *testing.T) {
	t.Parallel()

	testFS := &devReloadTestFS{files: fstest.MapFS{
		"Containerfile":    &fstest.MapFile{Data: []byte("FROM alpine AS builder\n")},
		"requirements.txt": &fstest.MapFile{Data: []byte("flask==1\n")},
		"app.py":           &fstest.MapFile{Data: []byte("print('one')\n")},
	}}
	h := &ContainerHandler{
		containerFile: "Containerfile",
		buildDir:      ".",
		sourceFS:      testFS,
		cargs:         map[string]string{},
		devSettings: &types.DevSettings{
			Target:   "builder",
			EnvFiles: []string{"requirements.txt"},
		},
	}

	initial, err := h.devImageHash()
	if err != nil {
		t.Fatalf("initial devImageHash returned error: %v", err)
	}
	testFS.files["app.py"].Data = []byte("print('two')\n")
	afterSource, err := h.devImageHash()
	if err != nil {
		t.Fatalf("source devImageHash returned error: %v", err)
	}
	if afterSource != initial {
		t.Fatal("ordinary source change altered dev image hash")
	}
	testFS.files["requirements.txt"].Data = []byte("flask==2\n")
	afterDependency, err := h.devImageHash()
	if err != nil {
		t.Fatalf("dependency devImageHash returned error: %v", err)
	}
	if afterDependency == initial {
		t.Fatal("dependency change did not alter dev image hash")
	}
}

func TestParseDevSettings(t *testing.T) {
	t.Parallel()

	settings, err := parseDevSettings(map[string]any{
		"target":            "builder",
		"command":           "go run .",
		"dir":               "/app",
		"reload":            "none",
		"env_files":         []any{"go.mod", "go.sum"},
		"additional_mounts": []string{"go-cache:/go/pkg/mod"},
		"port":              int64(3000),
	})
	if err != nil {
		t.Fatalf("parseDevSettings returned error: %v", err)
	}
	if settings.Target != "builder" || settings.Command != "go run ." || settings.Dir != "/app" ||
		settings.Reload != types.DEV_RELOAD_NONE || settings.Port != 3000 {
		t.Fatalf("parseDevSettings returned unexpected settings: %+v", settings)
	}
	if strings.Join(settings.EnvFiles, ",") != "go.mod,go.sum" ||
		strings.Join(settings.AdditionalMounts, ",") != "go-cache:/go/pkg/mod" {
		t.Fatalf("parseDevSettings returned unexpected lists: %+v", settings)
	}

	settings, err = parseDevSettings(map[string]any{"dir": "/app"})
	if err != nil {
		t.Fatalf("parseDevSettings defaults returned error: %v", err)
	}
	if settings.Reload != types.DEV_RELOAD_RESTART {
		t.Fatalf("default reload = %q, want %q", settings.Reload, types.DEV_RELOAD_RESTART)
	}
	// dir is optional at parse time, it is inferred from the Containerfile
	settings, err = parseDevSettings(map[string]any{"dev_stage": "fastdev", "disable": true})
	if err != nil {
		t.Fatalf("parseDevSettings dev_stage returned error: %v", err)
	}
	if settings.DevStage != "fastdev" || !settings.Disable || settings.Dir != "" {
		t.Fatalf("parseDevSettings returned unexpected settings: %+v", settings)
	}
	settings, err = parseDevSettings(nil)
	if err != nil || settings != nil {
		t.Fatalf("empty parseDevSettings = (%+v, %v), want (nil, nil)", settings, err)
	}
}

func TestParseDevSettingsRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   map[string]any
		wantErr string
	}{
		{name: "relative dir", input: map[string]any{"dir": "app"}, wantErr: "must be an absolute path"},
		{name: "empty dev_stage", input: map[string]any{"dir": "/app", "dev_stage": ""}, wantErr: "dev_stage must not be empty"},
		{name: "disable type", input: map[string]any{"dir": "/app", "disable": "yes"}, wantErr: "disable must be a boolean"},
		{name: "reload", input: map[string]any{"dir": "/app", "reload": "invalid"}, wantErr: "must be one of"},
		{name: "port", input: map[string]any{"dir": "/app", "port": -1}, wantErr: "higher than or equal to zero"},
		{name: "env files", input: map[string]any{"dir": "/app", "env_files": []any{"ok", 1}}, wantErr: "list of strings"},
		{name: "unknown key", input: map[string]any{"dir": "/app", "envFiles": []string{"go.mod"}}, wantErr: "unsupported dev_settings key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDevSettings(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseDevSettings error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestHealthRetryBudgetPreservesOriginalStartupWindow(t *testing.T) {
	t.Parallel()

	if got, want := healthRetryBudget(10, 2000), 11_100*time.Millisecond; got != want {
		t.Fatalf("healthRetryBudget(10) = %s, want %s", got, want)
	}
	if got := healthRetryBudget(1, 2000); got != 0 {
		t.Fatalf("healthRetryBudget(1) = %s, want 0", got)
	}
}

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
	scaledDown         bool
	scaledDownCalls    atomic.Int32
}

func (m *healthTestManager) ContainerScaledDown(context.Context, container.ContainerName) (bool, error) {
	m.scaledDownCalls.Add(1)
	return m.scaledDown, nil
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

func (m *healthTestManager) VolumeCreate(context.Context, container.VolumeName, string) error {
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

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false, false); err != nil {
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

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false, false); err != nil {
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

	if err := h.prodReloadKubernetes(context.Background(), "deploy-hash", false, false); err != nil {
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

	if err := h.ProdReload(context.Background(), false, false, false); err != nil {
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

func TestSqliteBindingVolumesAndEnv(t *testing.T) {
	t.Parallel()

	sqliteBinding := func(id, dir, volumeSize string) *types.Binding {
		return &types.Binding{
			Id:             id,
			ServiceType:    "sqlite",
			ServiceName:    "main",
			Metadata:       types.BindingMetadata{Account: bindings.SqliteAccountForDir(dir)},
			StagedMetadata: types.BindingMetadata{Account: bindings.SqliteAccountForDir(dir)},
			ServiceConfig:  map[string]string{"volume_size": volumeSize},
		}
	}
	appBindings := []*types.Binding{
		{ServiceType: "postgres", ServiceName: "main"},
		sqliteBinding("bnd_1", "/data", "20Gi"),
	}

	vols := sqliteBindingVolumes(appBindings, true)
	if len(vols) != 1 {
		t.Fatalf("volumes = %d, want 1", len(vols))
	}
	if vols[0].TargetPath != "/data" || vols[0].VolumeName != "sqlite-bnd_1" {
		t.Fatalf("volume = %+v", vols[0])
	}
	if vols[0].Size != "20Gi" || !vols[0].InitPerms {
		t.Fatalf("volume size/perms = %+v", vols[0])
	}

	// The binding's "path" config (baked into the account) moves the mount
	custom := sqliteBindingVolumes([]*types.Binding{sqliteBinding("bnd_3", "/mydata/test", "")}, true)
	if len(custom) != 1 || custom[0].TargetPath != "/mydata/test" {
		t.Fatalf("custom path volume = %+v", custom[0])
	}

	// The volume follows the binding identity, not the mount position: a
	// binding swap on the app gets its own (fresh) volume, never the previous
	// binding's database
	swapped := sqliteBindingVolumes([]*types.Binding{sqliteBinding("bnd_2", "/data", "")}, true)
	if len(swapped) != 1 || swapped[0].VolumeName != "sqlite-bnd_2" ||
		swapped[0].TargetPath != "/data" {
		t.Fatalf("swapped volume = %+v", swapped[0])
	}

	h := &ContainerHandler{
		app: &App{AppEntry: &types.AppEntry{
			Id:   types.AppId(types.ID_PREFIX_APP_PROD + "sqlite_env_test"),
			Path: "/sqlite-env",
		}},
		serverConfig: &types.ServerConfig{},
		bindings:     appBindings,
	}
	env, err := h.getBindingEnv()
	if err != nil {
		t.Fatalf("getBindingEnv: %v", err)
	}
	if env["SQLITE_URL"] != "file:/data/data.db" {
		t.Fatalf("SQLITE_URL = %q", env["SQLITE_URL"])
	}
	if env["SQLITE_DIR"] != "/data" {
		t.Fatalf("SQLITE_DIR = %q", env["SQLITE_DIR"])
	}
	if env["SQLITE_DB_PATH"] != "/data/data.db" {
		t.Fatalf("SQLITE_DB_PATH = %q", env["SQLITE_DB_PATH"])
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

func TestIdleAppShutdownSkipsTheStopAfterADeploy(t *testing.T) {
	t.Parallel()

	manager := &blockingVersionManager{
		arrived: make(chan struct{}),
		release: make(chan struct{}),
	}
	closeCh := make(chan struct{})
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	gate := &recordingSwapGate{}
	app := &App{
		Logger:   types.NewLogger(&types.LogConfig{Level: "WARN"}),
		AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "idle_deploy_test"), Path: "/idle-deploy", IsDev: true},
	}
	app.SetDeploySwapGate(gate)
	h := &ContainerHandler{
		Logger:             types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:                app,
		manager:            manager,
		containerConfig:    types.Container{IdleShutdownSecs: 1},
		currentState:       ContainerStateRunning,
		activeVersionHash:  "some-version",
		idleShutdownTicker: ticker,
		closeCh:            closeCh,
	}
	h.app.lastRequestTime.Store(time.Now().Add(-time.Hour).Unix())

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.idleAppShutdown(context.Background())
	}()
	select {
	case <-manager.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown did not reach staleInPlaceHandler in time")
	}
	// A deploy of the app begins and ends (its rollback may have restarted
	// this very container) while the idle check is mid-decision: the stop
	// decided before the deploy is dropped
	pd := h.app.AppPathDomain()
	if err := gate.BeginSwap(context.Background(), pd, uint64(1), time.Minute, false); err != nil {
		t.Fatalf("BeginSwap: %v", err)
	}
	gate.EndSwap(pd)
	close(manager.release)
	close(closeCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idleAppShutdown goroutine did not exit after closeCh was closed")
	}
	if manager.stopContainerCalls != 0 {
		t.Fatalf("StopContainer called %d times after a deploy moved the epoch, want none", manager.stopContainerCalls)
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

func TestProdReloadCommandRecordsImageNameOnVersionAndDeployTxn(t *testing.T) {
	t.Parallel()

	sourceFS := &imageNameTestFS{hash: "source-hash", sourceDir: filepath.Join(t.TempDir(), "source")}
	manager := &healthTestManager{imageExists: true}
	serverConfig := &types.ServerConfig{Http: types.HttpConfig{Port: 8080}}
	h := &ContainerHandler{
		Logger:        types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:           &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "record_image")}, serverConfig: serverConfig},
		serverConfig:  serverConfig,
		manager:       manager,
		sourceFS:      sourceFS,
		containerFile: "Dockerfile",
	}

	dt := container.NewDeployTxn()
	defer dt.ReleaseImages()
	ctx := container.ContextWithDeployTxn(context.Background(), dt)
	if err := h.ProdReload(ctx, false, false, false); err != nil {
		t.Fatalf("ProdReload returned error: %v", err)
	}
	if h.GenImageName == "" || !strings.HasPrefix(string(h.GenImageName), container.IMAGE_NAME_PREFIX) {
		t.Fatalf("GenImageName = %q, want a generated image", h.GenImageName)
	}
	if got := h.app.Metadata.VersionMetadata.ImageName; got != string(h.GenImageName) {
		t.Fatalf("recorded image name = %q, want %q", got, h.GenImageName)
	}
	if names := dt.ImageNames(); len(names) != 1 || names[0] != h.GenImageName {
		t.Fatalf("deploy txn images = %v, want [%s]", names, h.GenImageName)
	}
}

func TestProdReloadCommandDoesNotRecordImageNameForImageSpecApps(t *testing.T) {
	t.Parallel()

	manager := &healthTestManager{imageExists: true}
	serverConfig := &types.ServerConfig{Http: types.HttpConfig{Port: 8080}}
	h := &ContainerHandler{
		Logger:       types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:          &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "image_spec")}, serverConfig: serverConfig},
		serverConfig: serverConfig,
		manager:      manager,
		sourceFS:     &imageNameTestFS{hash: "source-hash"},
		image:        "python:3.12",
	}

	dt := container.NewDeployTxn()
	if err := h.ProdReload(container.ContextWithDeployTxn(context.Background(), dt), false, false, false); err != nil {
		t.Fatalf("ProdReload returned error: %v", err)
	}
	if got := h.app.Metadata.VersionMetadata.ImageName; got != "" {
		t.Fatalf("recorded image name = %q, want none for an image spec app", got)
	}
	if names := dt.ImageNames(); len(names) != 0 {
		t.Fatalf("deploy txn images = %v, want none", names)
	}
}

// stopFirstTestManager adds the stop-by-version capability of the
// Docker/Podman manager, recording the order of the container operations
type stopFirstTestManager struct {
	healthTestManager
	previous []container.ContainerName // what StopSupersededContainers reports
	runErr   error
	stateErr error // returned by the next GetContainerState, once
	ops      []string
	// sidecars is the app's sidecar containers by name suffix ("-worker"),
	// with whether each runs; a sidecar listed before the reload exists
	// and matches its config, so the reload reuses it
	sidecars map[string]bool
}

func (m *stopFirstTestManager) sidecarKey(name container.ContainerName) (string, bool) {
	for key := range m.sidecars {
		if strings.HasSuffix(string(name), key) {
			return key, true
		}
	}
	return "", false
}

func (m *stopFirstTestManager) GetContainerState(ctx context.Context, name container.ContainerName, hash string) (string, bool, error) {
	if m.stateErr != nil {
		err := m.stateErr
		m.stateErr = nil
		return "", false, err
	}
	if key, ok := m.sidecarKey(name); ok {
		return "", m.sidecars[key], nil
	}
	return m.healthTestManager.GetContainerState(ctx, name, hash)
}

func (m *stopFirstTestManager) EnsureSidecarNetwork(context.Context, types.AppId) error { return nil }

func (m *stopFirstTestManager) GetSidecarInfo(_ context.Context, name container.ContainerName, _ string) (bool, bool, string, bool, error) {
	key, ok := m.sidecarKey(name)
	if !ok {
		return false, false, "", false, nil
	}
	return true, true, "", m.sidecars[key], nil
}

func (m *stopFirstTestManager) RunSidecar(_ context.Context, _ *types.AppEntry, _ string, _ container.ContainerName,
	name container.ContainerName, sidecar *container.ResolvedSidecar, _ map[string]string, _ map[string]string, _, _ string) error {
	m.ops = append(m.ops, "run-sidecar:"+string(name))
	if m.sidecars == nil {
		m.sidecars = map[string]bool{}
	}
	m.sidecars["-"+sidecar.Name] = true
	return nil
}

func (m *stopFirstTestManager) RemoveContainerIfExists(context.Context, container.ContainerName) error {
	return nil
}

func (m *stopFirstTestManager) StopSupersededContainers(_ context.Context, _ types.AppId, keep container.ContainerName) ([]container.SupersededContainer, error) {
	m.ops = append(m.ops, "stop-previous:"+string(keep))
	stopped := make([]container.SupersededContainer, 0, len(m.previous))
	for _, name := range m.previous {
		cont := container.SupersededContainer{Name: name}
		if strings.HasSuffix(string(name), "-db") {
			cont.IsSidecar = true
		}
		stopped = append(stopped, cont)
	}
	return stopped, nil
}

func (m *stopFirstTestManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, name container.ContainerName,
	image container.ImageName, port int32, env map[string]string, volumes []*container.VolumeInfo, opts map[string]string, params map[string]string,
	hash string, isImageSpec bool, probe *container.HealthProbe) error {
	m.ops = append(m.ops, "run:"+string(name))
	if m.runErr != nil {
		return m.runErr
	}
	return m.healthTestManager.RunContainer(ctx, appEntry, sourceDir, name, image, port, env, volumes, opts, params, hash, isImageSpec, probe)
}

func (m *stopFirstTestManager) StopContainer(_ context.Context, name container.ContainerName) error {
	m.ops = append(m.ops, "stop:"+string(name))
	if key, ok := m.sidecarKey(name); ok {
		m.sidecars[key] = false
		return nil
	}
	m.running = false
	// The app's sidecars crash when the app stops: listed as restarting by
	// the manager, not running, until stopped
	for key := range m.sidecars {
		m.sidecars[key] = false
	}
	return nil
}

func (m *stopFirstTestManager) RemoveSupersededContainers(_ context.Context, _ types.AppId, keep container.ContainerName) error {
	m.ops = append(m.ops, "remove-superseded:"+string(keep))
	return nil
}

// recordingSwapGate records the DeploySwapGate calls
type recordingSwapGate struct {
	mu     sync.Mutex
	events []string
	active int
	epoch  uint64
	onEnd  func() // called on EndSwap, to order it against the manager's ops
}

func (g *recordingSwapGate) BeginSwap(_ context.Context, pathDomain types.AppPathDomain, owner any, _ time.Duration, waitForOthers bool) error {
	if owner == nil {
		return errors.New("BeginSwap without an owner")
	}
	if _, isTxn := owner.(*container.DeployTxn); isTxn != waitForOthers {
		return fmt.Errorf("BeginSwap owner %T waits for others %v", owner, waitForOthers)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.events = append(g.events, "begin:"+pathDomain.String())
	g.active++
	g.epoch++
	return nil
}

func (g *recordingSwapGate) EndSwap(pathDomain types.AppPathDomain) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.events = append(g.events, "end:"+pathDomain.String())
	g.active--
	g.epoch++
	if g.onEnd != nil {
		g.onEnd()
	}
}

func (g *recordingSwapGate) SwapState(types.AppPathDomain) (bool, uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active > 0, g.epoch
}

func (g *recordingSwapGate) WithoutSwap(_ types.AppPathDomain, epoch uint64, fn func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active > 0 || epoch != g.epoch {
		return false
	}
	fn()
	return true
}

func (g *recordingSwapGate) PreviousVersionStopped(pathDomain types.AppPathDomain) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.events = append(g.events, "stopped:"+pathDomain.String())
}

func (g *recordingSwapGate) Events() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.events)
}

func newStopFirstTestHandler(manager container.ContainerManager, gate DeploySwapGate) *ContainerHandler {
	serverConfig := &types.ServerConfig{Http: types.HttpConfig{Port: 8080}}
	app := &App{AppEntry: &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "stop_first"), Path: "/stopfirst", Domain: ""}, serverConfig: serverConfig}
	app.SetDeploySwapGate(gate)
	return &ContainerHandler{
		Logger:          types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:             app,
		serverConfig:    serverConfig,
		manager:         manager,
		sourceFS:        &imageNameTestFS{hash: "source-hash"},
		containerFile:   "Dockerfile",
		containerConfig: types.Container{BlueGreenDeploy: types.BlueGreenDeployFalse, DeployHealthAttempts: 3, HealthTimeoutSecs: 1},
	}
}

func TestProdReloadStopFirstStopsPreviousVersionBeforeStartingTheNew(t *testing.T) {
	t.Parallel()

	manager := &stopFirstTestManager{
		healthTestManager: healthTestManager{imageExists: true},
		previous:          []container.ContainerName{"old-db", "old-app"},
	}
	gate := &recordingSwapGate{}
	h := newStopFirstTestHandler(manager, gate)

	if err := h.ProdReload(context.Background(), false, false, false); err != nil {
		t.Fatalf("ProdReload returned error: %v", err)
	}
	newName := string(container.GenContainerName(h.app.Id, h.activeVersionHash, false))
	wantOps := []string{"stop-previous:" + newName, "run:" + newName, "remove-superseded:" + newName}
	if !slices.Equal(manager.ops, wantOps) {
		t.Fatalf("ops = %v, want %v", manager.ops, wantOps)
	}
	// The gate is held from before the stop until the reload is over
	if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.events, want) {
		t.Fatalf("gate events = %v, want %v", gate.events, want)
	}
}

func TestProdReloadStopFirstStopsTheNewVersionWhenItFails(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		runErr  error
		health  string
		wantErr string
		wantOps []string // NEW is the new version's container
	}{
		// The container never started: nothing of the new version to stop
		{name: "the container fails to start", runErr: errors.New("boom"), wantErr: "boom",
			wantOps: []string{"stop-previous:NEW", "run:NEW"}},
		// The container runs but never serves: it is stopped, so the next
		// start of the app does not find it running and reuse it
		{name: "the container fails its health check", health: "health", wantErr: "error waiting for health",
			wantOps: []string{"stop-previous:NEW", "run:NEW", "stop:NEW"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &stopFirstTestManager{
				healthTestManager: healthTestManager{imageExists: true},
				previous:          []container.ContainerName{"old-db", "old-app"},
				runErr:            tc.runErr,
			}
			gate := &recordingSwapGate{}
			h := newStopFirstTestHandler(manager, gate)
			h.health = tc.health // the fake serves no HTTP: a health wait fails
			h.containerConfig.DeployHealthAttempts = 1

			err := h.ProdReload(context.Background(), false, false, false)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ProdReload error = %v, want %q", err, tc.wantErr)
			}
			// Without a deploy transaction the new version's running
			// containers are stopped at the end of the reload; the requests
			// are then released, and the next one starts the previous
			// version on its own reload
			newName := strings.TrimPrefix(manager.ops[0], "stop-previous:") // the failed reload records no active version
			wantOps := make([]string, 0, len(tc.wantOps))
			for _, op := range tc.wantOps {
				wantOps = append(wantOps, strings.ReplaceAll(op, "NEW", newName))
			}
			if !slices.Equal(manager.ops, wantOps) {
				t.Fatalf("ops = %v, want %v", manager.ops, wantOps)
			}
			if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.events, want) {
				t.Fatalf("gate events = %v, want %v", gate.events, want)
			}
		})
	}
}

func TestProdReloadStopFirstDeploysThroughTheDeployTxn(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		rollback   bool
		wantOps    []string
		wantEvents []string
	}{
		// The transaction stops the new container; the live instance of
		// the stopped previous version is dropped before the release, so the
		// released requests start that version again
		{name: "rollback stops the new version and drops the previous version's instance", rollback: true,
			wantOps:    []string{"stop:NEW", "end-swap"},
			wantEvents: []string{"begin:/stopfirst", "stopped:/stopfirst", "end:/stopfirst"}},
		// The app is released only after the superseded containers are
		// removed: a deploy waiting for the release never has its new
		// container removed by this one's cleanup
		{name: "commit removes the previous version then releases the gate", rollback: false,
			wantOps:    []string{"remove-superseded:NEW", "end-swap"},
			wantEvents: []string{"begin:/stopfirst", "end:/stopfirst"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &stopFirstTestManager{
				healthTestManager: healthTestManager{imageExists: true},
				previous:          []container.ContainerName{"old-db", "old-app"},
			}
			gate := &recordingSwapGate{}
			gate.onEnd = func() { manager.ops = append(manager.ops, "end-swap") }
			h := newStopFirstTestHandler(manager, gate)
			dt := container.NewDeployTxn()
			defer dt.ReleaseImages()
			ctx := container.ContextWithDeployTxn(context.Background(), dt)

			if err := h.ProdReload(ctx, false, false, false); err != nil {
				t.Fatalf("ProdReload returned error: %v", err)
			}
			newName := string(container.GenContainerName(h.app.Id, h.activeVersionHash, false))
			if want := []string{"stop-previous:" + newName, "run:" + newName}; !slices.Equal(manager.ops, want) {
				t.Fatalf("ops before commit = %v, want %v", manager.ops, want)
			}
			// The gate stays held until the operation commits or rolls back
			if want := []string{"begin:/stopfirst"}; !slices.Equal(gate.events, want) {
				t.Fatalf("gate events before commit = %v, want %v", gate.events, want)
			}
			manager.ops = nil

			var err error
			if tc.rollback {
				err = dt.RollbackAll(context.Background())
			} else {
				err = dt.CommitAll(context.Background())
			}
			if err != nil {
				t.Fatalf("deploy txn error: %v", err)
			}
			wantOps := make([]string, 0, len(tc.wantOps))
			for _, op := range tc.wantOps {
				wantOps = append(wantOps, strings.ReplaceAll(op, "NEW", newName))
			}
			if !slices.Equal(manager.ops, wantOps) {
				t.Fatalf("ops = %v, want %v", manager.ops, wantOps)
			}
			if !slices.Equal(gate.events, tc.wantEvents) {
				t.Fatalf("gate events = %v, want %v", gate.events, tc.wantEvents)
			}
		})
	}
}

func TestProdReloadStopFirstOwnsTheAppBeforeReusingItsContainer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		rollback bool
		wantOps  []string
	}{
		// Nothing was stopped: the rollback restarts nothing, the release
		// still comes after the entries of the reload
		{name: "rollback", rollback: true, wantOps: []string{"end-swap"}},
		{name: "commit", rollback: false, wantOps: []string{"remove-superseded:NEW", "end-swap"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The version's container runs already (an overlapping deploy of
			// the same version started it, or this operation's pre-pass)
			manager := &stopFirstTestManager{
				healthTestManager: healthTestManager{imageExists: true, running: true, hostNamePort: "container:5000"},
				previous:          []container.ContainerName{"old-db", "old-app"},
			}
			gate := &recordingSwapGate{}
			gate.onEnd = func() { manager.ops = append(manager.ops, "end-swap") }
			h := newStopFirstTestHandler(manager, gate)
			dt := container.NewDeployTxn()
			defer dt.ReleaseImages()
			ctx := container.ContextWithDeployTxn(context.Background(), dt)

			if err := h.ProdReload(ctx, false, false, false); err != nil {
				t.Fatalf("ProdReload returned error: %v", err)
			}
			// The app is owned before the container is found and reused;
			// the previous version is not stopped (the reuse replaces nothing)
			if len(manager.ops) != 0 {
				t.Fatalf("ops = %v, want none for a reused container", manager.ops)
			}
			if want := []string{"begin:/stopfirst"}; !slices.Equal(gate.events, want) {
				t.Fatalf("gate events = %v, want %v", gate.events, want)
			}
			var err error
			if tc.rollback {
				err = dt.RollbackAll(context.Background())
			} else {
				err = dt.CommitAll(context.Background())
			}
			if err != nil {
				t.Fatalf("deploy txn error: %v", err)
			}
			newName := string(container.GenContainerName(h.app.Id, h.activeVersionHash, false))
			wantOps := make([]string, 0, len(tc.wantOps))
			for _, op := range tc.wantOps {
				wantOps = append(wantOps, strings.ReplaceAll(op, "NEW", newName))
			}
			if !slices.Equal(manager.ops, wantOps) {
				t.Fatalf("ops = %v, want %v", manager.ops, wantOps)
			}
			if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.events, want) {
				t.Fatalf("gate events = %v, want %v", gate.events, want)
			}
		})
	}

	// A lazy start reuses the running container under the same ownership
	manager := &stopFirstTestManager{
		healthTestManager: healthTestManager{imageExists: true, running: true, hostNamePort: "container:5000"},
	}
	gate := &recordingSwapGate{}
	h := newStopFirstTestHandler(manager, gate)
	if err := h.ProdReload(context.Background(), false, false, false); err != nil {
		t.Fatalf("standalone ProdReload returned error: %v", err)
	}
	if len(manager.ops) != 0 {
		t.Fatalf("standalone ops = %v, want none for a reused container", manager.ops)
	}
	if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.events, want) {
		t.Fatalf("standalone gate events = %v, want %v", gate.events, want)
	}
}

func TestProdReloadStopFirstLeavesAContainerItDidNotStartAlone(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		txn  bool
	}{{name: "deploy transaction rollback", txn: true}, {name: "lazy start", txn: false}} {
		t.Run(tc.name, func(t *testing.T) {
			// The version's healthy container serves the app; the reload
			// fails before deciding to reuse it (a transient manager error)
			manager := &stopFirstTestManager{
				healthTestManager: healthTestManager{imageExists: true, running: true, hostNamePort: "container:5000"},
				stateErr:          errors.New("docker ps: connection reset"),
			}
			gate := &recordingSwapGate{}
			gate.onEnd = func() { manager.ops = append(manager.ops, "end-swap") }
			h := newStopFirstTestHandler(manager, gate)
			ctx := context.Background()
			var dt *container.DeployTxn
			if tc.txn {
				dt = container.NewDeployTxn()
				defer dt.ReleaseImages()
				ctx = container.ContextWithDeployTxn(ctx, dt)
			}
			err := h.ProdReload(ctx, false, false, false)
			if err == nil || !strings.Contains(err.Error(), "connection reset") {
				t.Fatalf("ProdReload error = %v, want the state error", err)
			}
			if tc.txn {
				if err := dt.RollbackAll(context.Background()); err != nil {
					t.Fatalf("rollback: %v", err)
				}
			}
			// The container this deploy never started is not stopped; the
			// instance still serves it
			if want := []string{"end-swap"}; !slices.Equal(manager.ops, want) {
				t.Fatalf("ops = %v, want %v", manager.ops, want)
			}
			if !manager.running {
				t.Fatal("the serving container was stopped")
			}
			if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.Events(), want) {
				t.Fatalf("gate events = %v, want %v", gate.Events(), want)
			}
		})
	}
}

func TestProdReloadStopFirstStopsOnlyTheSidecarsItStarted(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		existing map[string]bool // sidecars running before the reload
		txn      bool
		wantOps  []string
	}{
		// An always_on worker kept running through the idle shutdown: the
		// reload reuses it, and a failed app start leaves it alone
		{name: "reused worker on a lazy start", existing: map[string]bool{"-worker": true},
			wantOps: []string{"stop-previous:NEW", "run:NEW", "stop:NEW", "end-swap"}},
		{name: "reused worker on a rollback", existing: map[string]bool{"-worker": true}, txn: true,
			wantOps: []string{"stop:NEW", "end-swap"}},
		// A worker this reload started is stopped with the app, even though
		// the manager no longer lists it running (crashed, about to restart)
		{name: "started worker on a lazy start",
			wantOps: []string{"stop-previous:NEW", "run-sidecar:WORKER", "run:NEW", "stop:NEW", "stop:WORKER", "end-swap"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &stopFirstTestManager{
				healthTestManager: healthTestManager{imageExists: true},
				sidecars:          tc.existing,
			}
			gate := &recordingSwapGate{}
			gate.onEnd = func() { manager.ops = append(manager.ops, "end-swap") }
			h := newStopFirstTestHandler(manager, gate)
			h.sidecars = []sidecarConfig{{spec: types.SidecarSpec{Name: "worker", Image: "image:worker"}}}
			h.health = "health" // the fake serves no HTTP: the health wait fails
			h.containerConfig.DeployHealthAttempts = 1
			ctx := context.Background()
			var dt *container.DeployTxn
			if tc.txn {
				dt = container.NewDeployTxn()
				defer dt.ReleaseImages()
				ctx = container.ContextWithDeployTxn(ctx, dt)
			}
			if err := h.ProdReload(ctx, false, false, false); err == nil {
				t.Fatal("ProdReload succeeded without a health endpoint")
			}
			newName := strings.TrimPrefix(manager.ops[0], "stop-previous:")
			hash := strings.TrimPrefix(newName, "clc-"+string(h.app.Id)+"-")
			worker := string(container.SidecarContainerName(h.app.Id, hash, "worker"))
			if tc.txn {
				manager.ops = nil
				if err := dt.RollbackAll(context.Background()); err != nil {
					t.Fatalf("rollback: %v", err)
				}
			}
			wantOps := make([]string, 0, len(tc.wantOps))
			for _, op := range tc.wantOps {
				wantOps = append(wantOps, strings.NewReplacer("NEW", newName, "WORKER", worker).Replace(op))
			}
			if !slices.Equal(manager.ops, wantOps) {
				t.Fatalf("ops = %v, want %v", manager.ops, wantOps)
			}
		})
	}
}

func TestProdReloadStopFirstStopsAFailedFirstVersion(t *testing.T) {
	t.Parallel()

	// No previous version runs: nothing to restore, but the container which
	// failed its health check is stopped, so the next start does not find
	// it running and reuse it unchecked
	manager := &stopFirstTestManager{healthTestManager: healthTestManager{imageExists: true}}
	gate := &recordingSwapGate{}
	h := newStopFirstTestHandler(manager, gate)
	h.health = "health" // the fake serves no HTTP: the health wait fails
	h.containerConfig.DeployHealthAttempts = 1

	if err := h.ProdReload(context.Background(), false, false, false); err == nil {
		t.Fatal("ProdReload succeeded without a health endpoint")
	}
	newName := strings.TrimPrefix(manager.ops[0], "stop-previous:")
	if want := []string{"stop-previous:" + newName, "run:" + newName, "stop:" + newName}; !slices.Equal(manager.ops, want) {
		t.Fatalf("ops = %v, want %v", manager.ops, want)
	}
	if manager.running {
		t.Fatal("the failed container is still running")
	}
	if want := []string{"begin:/stopfirst", "end:/stopfirst"}; !slices.Equal(gate.events, want) {
		t.Fatalf("gate events = %v, want %v", gate.events, want)
	}
}

func TestProdReloadBlueGreenDoesNotStopThePreviousVersionFirst(t *testing.T) {
	t.Parallel()

	manager := &stopFirstTestManager{
		healthTestManager: healthTestManager{imageExists: true},
		previous:          []container.ContainerName{"old-app"},
	}
	gate := &recordingSwapGate{}
	h := newStopFirstTestHandler(manager, gate)
	h.containerConfig.BlueGreenDeploy = types.BlueGreenDeployTrue

	if err := h.ProdReload(context.Background(), false, false, false); err != nil {
		t.Fatalf("ProdReload returned error: %v", err)
	}
	newName := string(container.GenContainerName(h.app.Id, h.activeVersionHash, false))
	if want := []string{"run:" + newName, "remove-superseded:" + newName}; !slices.Equal(manager.ops, want) {
		t.Fatalf("ops = %v, want %v", manager.ops, want)
	}
	if len(gate.events) != 0 {
		t.Fatalf("gate events = %v, want none", gate.events)
	}
}

func TestStopFirstDeployAutoFollowsPersistentVolumes(t *testing.T) {
	t.Parallel()

	named := &container.VolumeInfo{VolumeName: "data", TargetPath: "/data"}
	unnamed := &container.VolumeInfo{VolumeName: container.UNNAMED_VOLUME, TargetPath: "/cache"}
	bind := &container.VolumeInfo{SourcePath: "/host/dir", TargetPath: "/mnt"}
	secret := &container.VolumeInfo{IsSecret: true, VolumeName: "x", SourcePath: "s.tmpl", TargetPath: "/app/s"}
	for _, tc := range []struct {
		name     string
		mode     types.BlueGreenDeployMode
		volumes  []*container.VolumeInfo
		sidecars []*container.VolumeInfo
		want     bool
	}{
		{name: "auto without volumes is blue-green", mode: types.BlueGreenDeployAuto, want: false},
		{name: "zero value is auto", mode: "", volumes: []*container.VolumeInfo{named}, want: true},
		{name: "auto with a named volume is stop-first", mode: types.BlueGreenDeployAuto, volumes: []*container.VolumeInfo{named}, want: true},
		{name: "auto with an unnamed volume is stop-first", mode: types.BlueGreenDeployAuto, volumes: []*container.VolumeInfo{unnamed}, want: true},
		{name: "auto with a sidecar volume is stop-first", mode: types.BlueGreenDeployAuto, sidecars: []*container.VolumeInfo{named}, want: true},
		{name: "auto ignores bind mounts and secrets", mode: types.BlueGreenDeployAuto, volumes: []*container.VolumeInfo{bind, secret}, want: false},
		{name: "true with a volume stays blue-green", mode: types.BlueGreenDeployTrue, volumes: []*container.VolumeInfo{named}, want: false},
		{name: "false without volumes is stop-first", mode: types.BlueGreenDeployFalse, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &ContainerHandler{containerConfig: types.Container{BlueGreenDeploy: tc.mode}, volumeInfo: tc.volumes}
			if tc.sidecars != nil {
				h.sidecars = []sidecarConfig{{volumes: tc.sidecars}}
			}
			if got := h.stopFirstDeploy(); got != tc.want {
				t.Fatalf("stopFirstDeploy() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSwapStateFollowsTheDeployGate(t *testing.T) {
	t.Parallel()

	h := &ContainerHandler{app: &App{AppEntry: &types.AppEntry{Id: "app_prd_swap", Path: "/swap"}}}
	if h.swapInProgress() {
		t.Fatal("swap reported without a gate")
	}
	gate := &recordingSwapGate{}
	h.app.SetDeploySwapGate(gate)
	_, epoch0 := h.swapState()
	if err := gate.BeginSwap(context.Background(), h.app.AppPathDomain(), uint64(1), time.Minute, false); err != nil {
		t.Fatalf("BeginSwap: %v", err)
	}
	if swapping, epoch := h.swapState(); !swapping || epoch == epoch0 {
		t.Fatalf("after begin: swapping=%v epoch=%d (was %d), want swapping with a new epoch", swapping, epoch, epoch0)
	}
	gate.EndSwap(h.app.AppPathDomain())
	if swapping, epoch := h.swapState(); swapping || epoch == epoch0 {
		t.Fatalf("after end: swapping=%v epoch=%d, want idle with the epoch moved on", swapping, epoch)
	}
}

// newScaledDownTestHandler is a running in-place (Kubernetes) handler whose
// health probe fails at once: the container is reported not running and the
// single attempt leaves no retry
func newScaledDownTestHandler(manager *healthTestManager, notifyClose chan *App) *ContainerHandler {
	app := &App{
		Logger:      types.NewLogger(&types.LogConfig{Level: "WARN"}),
		AppEntry:    &types.AppEntry{Id: types.AppId(types.ID_PREFIX_APP_PROD + "scaled_down_test"), Path: "/scaled-down"},
		notifyClose: notifyClose,
	}
	return &ContainerHandler{
		Logger:                types.NewLogger(&types.LogConfig{Level: "WARN"}),
		app:                   app,
		manager:               manager,
		containerConfig:       types.Container{StatusHealthAttempts: 1, HealthTimeoutSecs: 1},
		currentState:          ContainerStateRunning,
		activeContainerName:   "scaled-down-container",
		activeVersionHash:     "v1",
		healthCheckTicker:     time.NewTicker(10 * time.Millisecond),
		healthCheckStartDelay: time.Nanosecond,
		closeCh:               make(chan struct{}),
	}
}

func TestHealthCheckerClosesAppWhenWorkloadScaledDown(t *testing.T) {
	t.Parallel()

	notifyClose := make(chan *App)
	manager := &healthTestManager{supportsInPlace: true, scaledDown: true}
	h := newScaledDownTestHandler(manager, notifyClose)
	defer h.Close() //nolint:errcheck

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.healthChecker(context.Background())
	}()

	select {
	case instance := <-notifyClose:
		if instance != h.app {
			t.Fatalf("notifyClose for %s, want this instance", instance.AppPathDomain())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("health checker did not close the app after its workload was scaled to zero")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("health checker did not exit after closing the app")
	}
	h.stateLock.RLock()
	state := h.currentState
	h.stateLock.RUnlock()
	if state == ContainerStateRunning {
		t.Fatal("handler still reports the scaled down container as running")
	}
	if manager.stopContainerCalls != 0 {
		t.Fatalf("StopContainer called %d times, want 0: the workload is already stopped", manager.stopContainerCalls)
	}
}

func TestHealthCheckerLeavesUnhealthyInPlaceWorkloadRunning(t *testing.T) {
	t.Parallel()

	// An unhealthy (or mid-rollout) workload keeps its replicas: readiness
	// controls its traffic and the instance must stay
	notifyClose := make(chan *App)
	manager := &healthTestManager{supportsInPlace: true, scaledDown: false}
	h := newScaledDownTestHandler(manager, notifyClose)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.healthChecker(context.Background())
	}()

	deadline := time.After(5 * time.Second)
	for manager.scaledDownCalls.Load() < 3 {
		select {
		case instance := <-notifyClose:
			t.Fatalf("health checker closed %s although its workload was not scaled down", instance.AppPathDomain())
		case <-deadline:
			t.Fatal("health checker did not check the workload scale")
		case <-time.After(5 * time.Millisecond):
		}
	}
	h.Close() //nolint:errcheck
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("health checker did not exit after the handler was closed")
	}
	h.stateLock.RLock()
	state := h.currentState
	h.stateLock.RUnlock()
	if state != ContainerStateRunning {
		t.Fatalf("state = %s, want %s", state, ContainerStateRunning)
	}
}

func TestSendNotifyCloseSkipsClosedHandler(t *testing.T) {
	t.Parallel()

	// A closed handler's instance is already gone (possibly replaced): a
	// send would close the replacement, even with the server receiving
	notifyClose := make(chan *App, 1)
	h := newScaledDownTestHandler(&healthTestManager{}, notifyClose)
	h.Close() //nolint:errcheck
	h.sendNotifyClose()
	select {
	case instance := <-notifyClose:
		t.Fatalf("closed handler sent notifyClose for %s", instance.AppPathDomain())
	default:
	}
}

// refusedProxy is a reverse proxy to an address nothing listens on, with the
// container proxy error handler for h
func refusedProxy(t *testing.T, h *ContainerHandler) *httputil.ReverseProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close() // connections to addr are now refused
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: addr})
	proxy.ErrorHandler = containerProxyErrorHandler(h.Logger, h)
	return proxy
}

func TestContainerProxyErrorHandlerScaledDown(t *testing.T) {
	t.Parallel()

	notifyClose := make(chan *App, 1)
	h := newScaledDownTestHandler(&healthTestManager{supportsInPlace: true, scaledDown: true}, notifyClose)
	proxy := refusedProxy(t, h)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scaled-down/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	select {
	case instance := <-notifyClose:
		if instance != h.app {
			t.Fatalf("notifyClose for %s, want this instance", instance.AppPathDomain())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the scaled down instance was not closed")
	}

	// Requests already past the instance lookup keep getting the 503 (the
	// workload is still at zero), and the instance is closed only once
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scaled-down/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	select {
	case instance := <-notifyClose:
		t.Fatalf("instance closed a second time for %s", instance.AppPathDomain())
	case <-time.After(50 * time.Millisecond):
	}
}

func TestContainerProxyErrorHandlerNotScaledDown(t *testing.T) {
	t.Parallel()

	// A refused connection to a workload with replicas (crashed, mid
	// rollout) is a plain 502: readiness handles it, the instance stays
	notifyClose := make(chan *App, 1)
	manager := &healthTestManager{supportsInPlace: true, scaledDown: false}
	h := newScaledDownTestHandler(manager, notifyClose)

	rec := httptest.NewRecorder()
	refusedProxy(t, h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scaled-down/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if rec.Header().Get("Retry-After") != "" {
		t.Fatal("Retry-After set on a plain proxy failure")
	}
	if manager.scaledDownCalls.Load() != 1 {
		t.Fatalf("scale checks = %d, want 1", manager.scaledDownCalls.Load())
	}
	h.stateLock.RLock()
	state := h.currentState
	h.stateLock.RUnlock()
	if state != ContainerStateRunning {
		t.Fatalf("state = %s, want %s", state, ContainerStateRunning)
	}
	select {
	case instance := <-notifyClose:
		t.Fatalf("instance closed for %s although its workload was not scaled down", instance.AppPathDomain())
	default:
	}
}

func TestIsDialError(t *testing.T) {
	t.Parallel()

	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	if !isDialError(fmt.Errorf("proxy: %w", dialErr)) {
		t.Fatal("wrapped dial error not detected")
	}
	if isDialError(&net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset")}) {
		t.Fatal("read error reported as a dial error: the request may have reached the app")
	}
	if isDialError(context.DeadlineExceeded) {
		t.Fatal("timeout reported as a dial error")
	}
}

// commandLikeManager hides the test manager's optional capabilities, like the
// Docker/Podman manager, which cannot report a scale to zero
type commandLikeManager struct{ container.ContainerManager }

func TestContainerProxyErrorHandlerWithoutScaleCheck(t *testing.T) {
	t.Parallel()

	notifyClose := make(chan *App, 1)
	inner := &healthTestManager{scaledDown: true}
	h := newScaledDownTestHandler(inner, notifyClose)
	h.manager = commandLikeManager{inner}

	rec := httptest.NewRecorder()
	refusedProxy(t, h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scaled-down/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if inner.scaledDownCalls.Load() != 0 {
		t.Fatal("scale check reached through a manager without the capability")
	}
	select {
	case instance := <-notifyClose:
		t.Fatalf("instance closed for %s", instance.AppPathDomain())
	default:
	}
}

// The reported sequence: an action run pins the app, the server retires it
// (Close is deferred to the run's end), then a proxy failure on the retired
// instance finds the workload scaled down. The retired instance must not ask
// for a close (the server would evict the replacement), and its background
// checkers must stop at retirement (its idle checker would otherwise stop
// the container under the replacement)
func TestRetiredPinnedAppStopsBackgroundAndCloseRequests(t *testing.T) {
	t.Parallel()

	notifyClose := make(chan *App, 1)
	h := newScaledDownTestHandler(&healthTestManager{supportsInPlace: true, scaledDown: true}, notifyClose)
	h.app.containerHandler = h

	release, err := h.app.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.app.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.closeCh:
	default:
		t.Fatal("the retired pinned app's background checkers are still running")
	}

	h.proxyDialFailed(context.Background())
	select {
	case instance := <-notifyClose:
		t.Fatalf("retired instance requested a close of %s", instance.AppPathDomain())
	case <-time.After(100 * time.Millisecond):
	}
	release()
}
