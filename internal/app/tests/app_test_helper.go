// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"

	_ "github.com/openrundev/openrun/internal/app/store" // Register db plugin
	_ "github.com/openrundev/openrun/plugins"            // Register builtin plugins
)

func CreateDevModeTestApp(logger *types.Logger, fileData map[string]string) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, true, nil, nil, nil, "app_dev_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateTestApp(logger *types.Logger, fileData map[string]string) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, nil, nil, nil, "app_prd_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateTestAppConfig(logger *types.Logger, fileData map[string]string, appConfig types.AppConfig) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, nil, nil, nil, "app_prd_testapp", types.AppSettings{}, nil, &appConfig, nil)
}

func CreateTestAppParams(logger *types.Logger, fileData map[string]string, params map[string]string) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, nil, nil, nil, "app_prd_testapp", types.AppSettings{}, params, nil, nil)
}

func CreateTestAppRoot(logger *types.Logger, fileData map[string]string) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/", fileData, false, nil, nil, nil, "app_prd_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateTestAppPlugin(logger *types.Logger, fileData map[string]string,
	plugins []string, permissions []types.Permission, pluginConfig map[string]types.PluginSettings) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, plugins, permissions, pluginConfig, "app_prd_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateTestAppPluginRoot(logger *types.Logger, fileData map[string]string,
	plugins []string, permissions []types.Permission, pluginConfig map[string]types.PluginSettings) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/", fileData, false, plugins, permissions, pluginConfig, "app_prd_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateDevAppPlugin(logger *types.Logger, fileData map[string]string, plugins []string,
	permissions []types.Permission, pluginConfig map[string]types.PluginSettings) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, true, plugins, permissions, pluginConfig, "app_dev_testapp", types.AppSettings{}, nil, nil, nil)
}

func CreateTestAppPluginId(logger *types.Logger, fileData map[string]string,
	plugins []string, permissions []types.Permission, pluginConfig map[string]types.PluginSettings, id string, settings types.AppSettings) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, plugins, permissions, pluginConfig, id, settings, nil, nil, nil)
}

func CreateTestAppAuthorizer(logger *types.Logger, fileData map[string]string,
	plugins []string, permissions []types.Permission, pluginConfig map[string]types.PluginSettings, rbacApi rbac.RBACAPI) (*app.App, *appfs.WorkFs, error) {
	return CreateTestAppInt(logger, "/test", fileData, false, plugins, permissions, pluginConfig, "app_prd_testapp", types.AppSettings{}, nil, nil, rbacApi)
}

func CreateTestAppInt(logger *types.Logger, path string, fileData map[string]string, isDev bool,
	plugins []string, permissions []types.Permission, pluginConfig map[string]types.PluginSettings,
	id string, settings types.AppSettings, params map[string]string, appConfig *types.AppConfig,
	rbacApi rbac.RBACAPI) (*app.App, *appfs.WorkFs, error) {
	systemConfig := types.SystemConfig{TailwindCSSCommand: "", AllowedEnv: []string{"HOME"}}
	var fs appfs.ReadableFS
	if isDev {
		fs = &TestWriteFS{TestReadFS: &TestReadFS{fileData: fileData}}
	} else {
		fs = &TestReadFS{fileData: fileData}
	}
	sourceFS, err := appfs.NewSourceFs("", fs, isDev)
	if err != nil {
		return nil, nil, err
	}

	if plugins == nil {
		plugins = []string{}
	}
	if permissions == nil {
		permissions = []types.Permission{}
	}

	if pluginConfig == nil {
		pluginConfig = map[string]types.PluginSettings{}
	}

	if params == nil {
		params = map[string]string{}
	}

	if appConfig == nil {
		appConfig = &types.AppConfig{}
	}

	metadata := types.AppMetadata{
		Loads:       plugins,
		Permissions: permissions,
		ParamValues: params,
	}
	secretManager, err := system.NewSecretManager(context.Background(), map[string]types.SecretConfig{"env": types.SecretConfig{}}, "env")
	if err != nil {
		return nil, nil, err
	}
	workFS := appfs.NewWorkFs("", &TestWriteFS{TestReadFS: &TestReadFS{fileData: map[string]string{}}})
	a, err := app.NewApp(sourceFS, workFS, logger,
		createTestAppEntry(id, path, isDev, metadata), &systemConfig, pluginConfig, *appConfig,
		nil, secretManager.AppEvalTemplate, nil, &types.ServerConfig{}, rbacApi)
	if err != nil {
		return nil, nil, err
	}
	err = a.Initialize(types.DryRunFalse)
	return a, workFS, err
}

func createTestAppEntry(id, path string, isDev bool, metadata types.AppMetadata) *types.AppEntry {
	return &types.AppEntry{
		Id:        types.AppId(id),
		Path:      path,
		Domain:    "",
		SourceUrl: ".",
		IsDev:     isDev,
		Metadata:  metadata,
	}
}

type TestReadFS struct {
	fileData map[string]string
}

var _ appfs.ReadableFS = (*TestReadFS)(nil)

type TestWriteFS struct {
	*TestReadFS
}

var _ appfs.WritableFS = (*TestWriteFS)(nil)

type TestFileInfo struct {
	f *TestFile
}

func (fi *TestFileInfo) Name() string {
	return fi.f.name
}

func (fi *TestFileInfo) Size() int64 {
	return int64(len(fi.f.data))
}
func (fi *TestFileInfo) Mode() fs.FileMode {
	return 0
}
func (fi *TestFileInfo) ModTime() time.Time {
	return time.Now()
}
func (fi *TestFileInfo) IsDir() bool {
	return false
}
func (fi *TestFileInfo) Sys() any {
	return nil
}

type TestFile struct {
	name   string
	data   string
	reader *strings.Reader
}

func CreateTestFile(name string, data string) *TestFile {
	reader := strings.NewReader(data)
	return &TestFile{name: name, data: data, reader: reader}
}

func (f *TestFile) Stat() (fs.FileInfo, error) {
	return &TestFileInfo{f}, nil
}

func (f *TestFile) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

func (f *TestFile) Read(dst []byte) (int, error) {
	return f.reader.Read(dst)
}

func (f *TestFile) Close() error {
	return nil
}

func (f *TestReadFS) Open(name string) (fs.File, error) {
	name = strings.TrimPrefix(name, "/")
	if _, ok := f.fileData[name]; !ok {
		return nil, fs.ErrNotExist
	}

	return CreateTestFile(name, f.fileData[name]), nil
}

func (f *TestReadFS) ReadFile(name string) ([]byte, error) {
	name = strings.TrimPrefix(name, "/")
	data, ok := f.fileData[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(data), nil
}

func (f *TestReadFS) Glob(pattern string) ([]string, error) {
	matchedFiles := []string{}
	for name := range f.fileData {
		if matched, _ := path.Match(pattern, name); matched {
			matchedFiles = append(matchedFiles, name)
		}
	}

	return matchedFiles, nil
}

func (f *TestReadFS) ParseFS(funcMap template.FuncMap, patterns ...string) (*template.Template, error) {
	return template.New("openruntestapp").Funcs(funcMap).ParseFS(f, patterns...)
}

func (f *TestReadFS) Stat(name string) (fs.FileInfo, error) {
	name = strings.TrimPrefix(name, "/")
	if _, ok := f.fileData[name]; !ok {
		return nil, fs.ErrNotExist
	}

	file := CreateTestFile(name, f.fileData[name])
	return &TestFileInfo{file}, nil
}

func (f *TestReadFS) StatNoSpec(name string) (fs.FileInfo, error) {
	return f.Stat(name)
}

func (d *TestReadFS) StaticFiles() []string {
	staticFiles := []string{}
	for name := range d.fileData {
		if strings.HasPrefix(name, "static/") || strings.HasPrefix(name, "static_root/") {
			staticFiles = append(staticFiles, name)
		}
	}
	return staticFiles
}

func (d *TestReadFS) FileHash(excludeGlob []string) (string, error) {
	return "", fmt.Errorf("FileHash not implemented for test fs")
}

func (d *TestReadFS) CreateTempSourceDir() (string, error) {
	return "", fmt.Errorf("CreateTempSourceDir not implemented for test fs")
}

func (f *TestReadFS) Reset() {
	// do nothing
}

func (f *TestWriteFS) Write(name string, bytes []byte) error {
	name = strings.TrimPrefix(name, "/")
	f.fileData[name] = string(bytes)
	return nil
}

func (f *TestWriteFS) Remove(name string) error {
	name = strings.TrimPrefix(name, "/")
	delete(f.fileData, name)
	return nil
}
