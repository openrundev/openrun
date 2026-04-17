// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

type DiskReadFS struct {
	*types.Logger
	root      string
	cleanRoot string
	fs        fs.FS
	specFiles types.SpecFiles
}

var _ ReadableFS = (*DiskReadFS)(nil)

func NewDiskReadFS(logger *types.Logger, root string, specFiles types.SpecFiles) *DiskReadFS {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		cleanRoot = filepath.Clean(root)
	}
	if resolvedRoot, err := filepath.EvalSymlinks(cleanRoot); err == nil {
		cleanRoot = resolvedRoot
	}

	return &DiskReadFS{
		Logger:    logger,
		root:      cleanRoot,
		fs:        os.DirFS(cleanRoot),
		cleanRoot: cleanRoot,
		specFiles: specFiles,
	}
}

type DiskWriteFS struct {
	*DiskReadFS
}

func (d *DiskReadFS) Open(name string) (fs.File, error) {
	f, err := d.fs.Open(name)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		if _, ok := d.specFiles[name]; ok {
			// File found in spec files, use that
			df := NewDiskFile(name, []byte(d.specFiles[name]), DiskFileInfo{
				name:    name,
				len:     int64(len(d.specFiles[name])),
				modTime: time.Now(),
			})
			return df, nil
		}
	}
	return f, err
}

func (d *DiskReadFS) ReadFile(name string) ([]byte, error) {
	if dir, ok := d.fs.(fs.ReadFileFS); ok {
		if name[0] == '/' {
			name = name[1:]
		}
		bytes, err := dir.ReadFile(name)
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			if _, ok := d.specFiles[name]; ok {
				// File found in spec files, use that
				return []byte(d.specFiles[name]), nil
			}
		}
		return bytes, err
	}

	file, err := d.fs.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, ok := d.specFiles[name]; ok {
				// File found in spec files, use that
				return []byte(d.specFiles[name]), nil
			}
		}
		return nil, err
	}

	defer file.Close() //nolint:errcheck

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, file)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *DiskReadFS) Stat(name string) (fs.FileInfo, error) {
	absName, err := system.PathInDir(d.root, name)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(absName)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		if _, ok := d.specFiles[name]; ok {
			fi := DiskFileInfo{
				name:    name,
				len:     int64(len(d.specFiles[name])),
				modTime: time.Now(),
			}
			return &fi, nil
		}
	}

	return fi, err
}

func (d *DiskReadFS) StatNoSpec(name string) (fs.FileInfo, error) {
	absName, err := system.PathInDir(d.root, name)
	if err != nil {
		return nil, err
	}
	return os.Stat(absName)
}

func (d *DiskReadFS) Glob(pattern string) (matches []string, err error) {
	// TODO glob does not look at spec files
	return fs.Glob(d.fs, pattern)
}

func (d *DiskReadFS) StaticFiles() []string {
	staticFiles, err := doublestar.Glob(d.fs, "static/**/*")
	if err != nil {
		d.Logger.Err(err).Msg("error getting static files")
		return nil
	}

	var staticRootFiles []string
	staticRootFiles, err = doublestar.Glob(d.fs, "static_root/**/*")
	if err != nil {
		d.Logger.Err(err).Msg("error getting static_root files")
		return nil
	}
	staticFiles = append(staticFiles, staticRootFiles...)
	return staticFiles
}

func (d *DiskReadFS) FileHash(excludeGlob []string) (string, error) {
	return "", fmt.Errorf("FileHash not implemented for dev apps : DiskReadFS")
}

func (d *DiskReadFS) CreateTempSourceDir() (string, error) {
	return "", fmt.Errorf("CreateTempSourceDir not implemented for dev apps : DiskReadFS")
}

func (d *DiskReadFS) Reset() {
	// do nothing
}

func (d *DiskWriteFS) Write(name string, bytes []byte) error {
	absName, err := system.PathInDir(d.root, name)
	if err != nil {
		return err
	}
	dirName := path.Dir(absName)
	if err := os.MkdirAll(dirName, 0700); err != nil {
		return fmt.Errorf("error creating directory %s : %s", dirName, err)
	}
	return os.WriteFile(absName, bytes, 0600)
}

func (d *DiskWriteFS) Remove(name string) error {
	absName, err := system.PathInDir(d.root, name)
	if err != nil {
		return err
	}
	return os.Remove(absName)
}

type DiskFile struct {
	name   string
	fi     DiskFileInfo
	reader *bytes.Reader
}

var _ fs.File = (*DiskFile)(nil)

func NewDiskFile(name string, data []byte, fi DiskFileInfo) *DiskFile {
	reader := bytes.NewReader(data)
	return &DiskFile{name: name, fi: fi, reader: reader}
}

func (f *DiskFile) Read(dst []byte) (int, error) {
	return f.reader.Read(dst)
}

func (f *DiskFile) Name() string {
	return f.name
}

func (f *DiskFile) Stat() (fs.FileInfo, error) {
	return &f.fi, nil
}

func (f *DiskFile) Seek(offset int64, whence int) (int64, error) {
	// Seek is called by http.ServeContent in source_fs for the unoptimized case only
	// The data is decompressed and then recompressed if required in the unoptimized case
	return f.reader.Seek(offset, whence)
}

func (f *DiskFile) Close() error {
	return nil
}

type DiskFileInfo struct {
	name    string
	len     int64
	modTime time.Time
}

var _ fs.FileInfo = (*DiskFileInfo)(nil)

func (fi *DiskFileInfo) Name() string {
	return fi.name
}

func (fi *DiskFileInfo) Size() int64 {
	return fi.len
}
func (fi *DiskFileInfo) Mode() fs.FileMode {
	return 0
}
func (fi *DiskFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi *DiskFileInfo) IsDir() bool {
	return false
}
func (fi *DiskFileInfo) Sys() any {
	return nil
}
