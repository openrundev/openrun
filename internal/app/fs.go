// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

const (
	DEFAULT_FILE_LIMIT = 10_000
	MAX_FILE_LIMIT     = 100_000

	// FS_FILE_ACCESS_SETTING carries the allowed directory list into the fs
	// module's settings; the compiled-in registration injects it from the
	// app config (app_config.fs.file_access)
	FS_FILE_ACCESS_SETTING = "file_access"
)

var runtimeGOOS = runtime.GOOS

type AccessType string

const (
	UserAccess AccessType = "user"
	AppAccess  AccessType = "app"
)

func initFS() {
	RegisterLocalProvider("fs", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"fs": {
				Builder: NewFSModule,
				Functions: []sdk.FuncDef{
					{Name: "abs", Type: sdk.READ, Method: "Abs"},
					{Name: "list", Type: sdk.READ, Method: "List"},
					{Name: "find", Type: sdk.READ, Method: "Find"},
					{Name: "serve_tmp_file", Type: sdk.READ, Method: "ServeTmpFile"},
				},
				Constants: map[string]any{
					strings.ToUpper(string(UserAccess)): string(UserAccess),
					strings.ToUpper(string(AppAccess)):  string(AppAccess),
				},
			},
		},
	}, LocalProviderOptions{
		SettingsHook: func(a *App, module string, settings map[string]any) map[string]any {
			// The allowed directory list is app config, not plugin settings
			out := make(map[string]any, len(settings)+1)
			maps.Copy(out, settings)
			out[FS_FILE_ACCESS_SETTING] = a.AppConfig.FS.FileAccess
			return out
		},
	})
}

type fsModule struct {
	accessAllowed []string
	settings      map[string]any
	appId         string
	appPath       string
	logger        *types.Logger
}

func NewFSModule() sdk.Module {
	return &fsModule{}
}

func (f *fsModule) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	fileAccess, err := stringListSetting(init.Settings[FS_FILE_ACCESS_SETTING])
	if err != nil {
		return fmt.Errorf("invalid %s setting: %w", FS_FILE_ACCESS_SETTING, err)
	}
	accessAllowed, err := resolveDirs(fileAccess)
	if err != nil {
		return err
	}
	f.accessAllowed = accessAllowed
	f.settings = init.Settings
	f.appId = init.AppId
	f.appPath = init.AppPath
	f.logger = &types.Logger{Logger: init.Logger.Logger}
	return nil
}

func (f *fsModule) Close(ctx context.Context) error {
	return nil
}

// stringListSetting accepts both the in-process shape ([]string) and the
// decoded wire shape ([]any of string) for a settings list.
func stringListSetting(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return x, nil
	case []any:
		out := make([]string, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected string, got %T", item)
			}
			out[i] = s
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected list of strings, got %T", v)
	}
}

func resolveDirs(allowed []string) ([]string, error) {
	tempDir := os.TempDir()
	ret := []string{}
	for _, key := range allowed {
		if key == "$TEMPDIR" {
			key = tempDir
		}

		// Resolve symbolic links and canonicalize the paths
		realPath, err := filepath.EvalSymlinks(key)
		if err != nil {
			if runtimeGOOS == "windows" && key == "/tmp" && os.IsNotExist(err) {
				// Skip missing /tmp directory on Windows
				continue
			}
			return nil, fmt.Errorf("failed to resolve path symlinks: %w", err)
		}

		absDir, err := filepath.Abs(realPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute directory: %w", err)
		}

		if !strings.HasSuffix(absDir, string(filepath.Separator)) {
			absDir += string(filepath.Separator)
		}

		ret = append(ret, absDir)
	}
	return ret, nil
}

func (f *fsModule) checkAccess(filePath string) (bool, error) {
	realPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve path symlinks: %w", err)
	}

	absPath, err := filepath.Abs(realPath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path: %w", err)
	}

	for _, dir := range f.accessAllowed {
		inside, err := system.PathWithinDir(dir, absPath)
		if err != nil {
			return false, fmt.Errorf("failed to check path access: %w", err)
		}

		if inside {
			return true, nil
		}
	}
	return false, nil
}

func (f *fsModule) Abs(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	if err := sdk.UnpackArgs("abs", call, "path", &path); err != nil {
		return nil, err
	}

	return filepath.Abs(path)
}

func (f *fsModule) List(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	var recursiveSize, ignoreError bool
	if err := sdk.UnpackArgs("list", call, "path", &path, "recursive_size?", &recursiveSize, "ignore_errors?", &ignoreError); err != nil {
		return nil, err
	}

	return listDir(ctx, f.logger, path, recursiveSize, ignoreError)
}

func (f *fsModule) Find(ctx context.Context, call *sdk.Call) (any, error) {
	var path, nameGlob string
	var minSize, limit int64
	var ignoreError bool

	if err := sdk.UnpackArgs("find", call, "path", &path, "name?", &nameGlob, "limit?", &limit, "min_size?", &minSize, "ignore_errors?", &ignoreError); err != nil {
		return nil, err
	}

	if limit > MAX_FILE_LIMIT {
		return nil, fmt.Errorf("file limit %d exceeds max limit %d", limit, MAX_FILE_LIMIT)
	}
	if limit <= 0 {
		limit = DEFAULT_FILE_LIMIT
	}

	return find(ctx, f.logger, path, nameGlob, limit, minSize, ignoreError)
}

// ServeTmpFile registers a file on the server's filesystem for download by
// the app's users, returning its id, download url, and name.
func (f *fsModule) ServeTmpFile(ctx context.Context, call *sdk.Call) (any, error) {
	var pathVal, fileName string
	visibility := string(UserAccess)
	mimeType := "application/octet-stream"
	expiryMinutes := int64(60)
	singleAccess := true

	if err := sdk.UnpackArgs("serve_tmp_file", call, "path", &pathVal, "name?", &fileName, "visibility?", &visibility,
		"mime_type?", &mimeType, "expiry_minutes?", &expiryMinutes, "single_access?", &singleAccess); err != nil {
		return nil, err
	}

	pathStr, err := filepath.Abs(pathVal)
	if err != nil {
		return nil, err
	}

	ok, err := f.checkAccess(pathStr)
	if err != nil {
		return nil, fmt.Errorf("error during access check for %s: %w", pathStr, err)
	}
	if !ok {
		return nil, fmt.Errorf("file access denied for %s", pathStr)
	}

	connectString, err := system.GetConnectString(&types.PluginContext{Config: f.settings})
	if err != nil {
		return nil, err
	}

	if err := InitFileStore(connectString); err != nil {
		return nil, err
	}

	createTime := time.Now()
	expireAt := createTime.Add(time.Duration(expiryMinutes) * time.Minute)
	if expiryMinutes <= 0 {
		expireAt = time.Unix(0, int64(^uint64(0)>>1))
	}

	id, err := ksuid.NewRandom()
	if err != nil {
		return nil, err
	}

	if fileName == "" {
		fileName = filepath.Base(pathStr)
	}

	userFile := &types.UserFile{
		Id:           "usr_file_" + id.String(),
		AppId:        f.appId,
		FilePath:     "file://" + pathStr,
		FileName:     fileName,
		MimeType:     mimeType,
		CreateTime:   createTime,
		ExpireAt:     expireAt,
		CreatedBy:    call.Thread.UserId,
		SingleAccess: singleAccess,
		Visibility:   visibility,
		Metadata:     make(map[string]any),
	}

	if err := AddUserFile(ctx, userFile); err != nil {
		return nil, err
	}

	appPath := f.appPath
	if appPath == "/" {
		appPath = ""
	}
	downloadUrl := fmt.Sprintf("%s%s/file/%s", appPath, types.APP_INTERNAL_URL_PREFIX, userFile.Id)

	return map[string]string{
		"id":   userFile.Id,
		"url":  downloadUrl,
		"name": userFile.FileName,
	}, nil
}

type FileInfo struct {
	Name  string
	Size  int64
	IsDir bool
	Mode  int
}

// recoverToError wraps an errgroup goroutine body so a panic is logged and
// returned as an error instead of killing the process (panics in these
// goroutines are not covered by the http handler recovery)
func recoverToError(logger *types.Logger, name string, fn func() error) func() error {
	return func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic in %s: %v", name, r)
				if logger != nil {
					logger.Error().Str("stack", string(debug.Stack())).Msgf("Recovered from panic in %s: %v", name, r)
				}
			}
		}()
		return fn()
	}
}

func listDir(ctx context.Context, logger *types.Logger, path string, recursiveSize, ignoreError bool) ([]map[string]any, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	blockSize := int64(4 * 1024) // syscall.Statfs is not available on Windows, using 4K as block size
	fileInfo := map[string]*FileInfo{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}

		fileInfo[entry.Name()] = &FileInfo{
			Name:  entry.Name(),
			Size:  convertToBlockSize(info.Size(), blockSize),
			IsDir: info.IsDir(),
			Mode:  int(info.Mode()),
		}
	}

	if recursiveSize {
		errs, ctx := errgroup.WithContext(ctx)
		for name, info := range fileInfo {
			name := name
			info := info
			if info.IsDir {
				errs.Go(recoverToError(logger, "fs.list dir size", func() error {
					size, err := dirSize(ctx, filepath.Join(path, name), blockSize, ignoreError)
					if err != nil {
						return err
					}
					fileInfo[name].Size = size
					return nil
				}))
			}
		}

		if err := errs.Wait(); err != nil {
			if !ignoreError {
				return nil, err
			}
		}
	}

	var totalSize int64
	ret := make([]map[string]any, 0, len(fileInfo))
	for _, info := range fileInfo {
		fi := map[string]any{
			"name":   filepath.Join(path, info.Name),
			"size":   info.Size,
			"is_dir": info.IsDir,
			"mode":   info.Mode,
		}
		totalSize += info.Size
		ret = append(ret, fi)
	}

	topLevel := map[string]any{
		"name":   path,
		"size":   totalSize,
		"is_dir": true,
		"mode":   0,
	}

	ret = append(ret, topLevel)
	return ret, nil
}

func dirSize(ctx context.Context, path string, blockSize int64, ignoreError bool) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if !ignoreError {
				return err
			}
			if d == nil {
				// WalkDir passes a nil entry when the root itself cannot be
				// statted, e.g. deleted after being listed
				return nil
			}
		}
		info, err := d.Info()
		if err != nil {
			if ignoreError {
				return nil
			}
			return err
		}

		size += convertToBlockSize(info.Size(), blockSize)
		return nil
	})
	return size, err
}

func convertToBlockSize(size, blockSize int64) int64 {
	if size%blockSize == 0 {
		return size
	}
	return ((size / blockSize) + 1) * blockSize
}

func find(ctx context.Context, logger *types.Logger, path, nameGlob string, limit, minSize int64, ignoreError bool) ([]map[string]any, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	blockSize := int64(4 * 1024) // syscall.Statfs is not available on Windows, using 4K as block size
	fileInfo := []*FileInfo{}
	dirs := []string{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			if matchFile(entry.Name(), nameGlob, info.Size(), minSize) {
				fileInfo = append(fileInfo, &FileInfo{
					Name:  filepath.Join(path, entry.Name()),
					Size:  convertToBlockSize(info.Size(), blockSize),
					IsDir: info.IsDir(),
					Mode:  int(info.Mode()),
				})
			}
		} else {
			dirs = append(dirs, entry.Name())
		}
	}

	fileInfo = truncateList(fileInfo, limit)

	var mu sync.Mutex
	errs, ctx := errgroup.WithContext(ctx)
	for _, dir := range dirs {
		dir := dir
		errs.Go(recoverToError(logger, "fs.find match", func() error {
			files, err := matchFiles(ctx, filepath.Join(path, dir), nameGlob, limit, minSize, ignoreError)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()
			fileInfo = append(fileInfo, files...)
			fileInfo = truncateList(fileInfo, limit)
			return nil
		}))
	}

	if err := errs.Wait(); err != nil {
		if !ignoreError {
			return nil, err
		}
	}

	ret := make([]map[string]any, 0, len(fileInfo))
	for _, info := range fileInfo {
		fi := map[string]any{
			"name":   info.Name,
			"size":   info.Size,
			"is_dir": info.IsDir,
			"mode":   info.Mode,
		}
		ret = append(ret, fi)
	}
	return ret, nil
}

func truncateList(entries []*FileInfo, limit int64) []*FileInfo {
	if limit > 0 && int64(len(entries)) >= limit {
		copyInfo := make([]*FileInfo, limit)
		slices.SortFunc(entries, func(i, j *FileInfo) int {
			return int((*j).Size - (*i).Size)
		})

		copy(copyInfo, entries)
		return copyInfo
	}
	return entries
}

func matchFile(name, nameGlob string, size, minSize int64) bool {
	if nameGlob != "" {
		matched, err := filepath.Match(nameGlob, name)
		if err != nil {
			return false
		}
		if !matched {
			return false
		}
	}

	if minSize != 0 && size < minSize {
		return false
	}

	return true
}

func matchFiles(ctx context.Context, path string, nameGlob string, limit, minSize int64, ignoreError bool) ([]*FileInfo, error) {
	files := []*FileInfo{}
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if !ignoreError {
				return err
			}
			if d == nil {
				// WalkDir passes a nil entry when the root itself cannot be
				// statted, e.g. deleted after being listed
				return nil
			}
		}
		info, err := d.Info()
		if err != nil {
			if ignoreError {
				return nil
			}
			return err
		}

		if !info.IsDir() {
			if matchFile(d.Name(), nameGlob, info.Size(), int64(minSize)) {
				files = append(files, &FileInfo{
					Name:  path,
					Size:  info.Size(),
					IsDir: info.IsDir(),
					Mode:  int(info.Mode()),
				})

				if limit > 0 && int64(len(files)) >= 10*limit {
					files = truncateList(files, limit)
				}
			}
		}

		return nil
	})

	files = truncateList(files, limit)
	return files, err
}
