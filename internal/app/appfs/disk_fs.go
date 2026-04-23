// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

type DiskReadFS struct {
	*types.Logger
	root      string
	specFiles types.SpecFiles
}

var _ ReadableFS = (*DiskReadFS)(nil)

func NewDiskReadFS(logger *types.Logger, root string, specFiles types.SpecFiles) *DiskReadFS {
	cleanRoot, err := system.CleanAbsolutePath(root)
	if err != nil {
		cleanRoot = filepath.Clean(root)
	}

	return &DiskReadFS{
		Logger:    logger,
		root:      cleanRoot,
		specFiles: specFiles,
	}
}

type DiskWriteFS struct {
	*DiskReadFS
}

func (d *DiskReadFS) Open(name string) (fs.File, error) {
	localName, specName, err := d.cleanName(name)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck

	f, err := root.Open(localName)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		if _, ok := d.specFiles[specName]; ok {
			// File found in spec files, use that
			df := NewDiskFile(specName, []byte(d.specFiles[specName]), DiskFileInfo{
				name:    specName,
				len:     int64(len(d.specFiles[specName])),
				modTime: time.Now(),
			})
			return df, nil
		}
	}
	return f, err
}

func (d *DiskReadFS) ReadFile(name string) ([]byte, error) {
	localName, specName, err := d.cleanName(name)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck

	bytes, err := root.ReadFile(localName)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		if _, ok := d.specFiles[specName]; ok {
			// File found in spec files, use that
			return []byte(d.specFiles[specName]), nil
		}
	}
	return bytes, err
}

func (d *DiskReadFS) Stat(name string) (fs.FileInfo, error) {
	localName, specName, err := d.cleanName(name)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck

	fi, err := root.Stat(localName)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		if _, ok := d.specFiles[specName]; ok {
			fi := DiskFileInfo{
				name:    specName,
				len:     int64(len(d.specFiles[specName])),
				modTime: time.Now(),
			}
			return &fi, nil
		}
	}

	return fi, err
}

func (d *DiskReadFS) StatNoSpec(name string) (fs.FileInfo, error) {
	localName, _, err := d.cleanName(name)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck

	return root.Stat(localName)
}

func (d *DiskReadFS) Glob(pattern string) (matches []string, err error) {
	// TODO glob does not look at spec files
	cleanPattern, err := system.CleanRelativePath(pattern)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck

	return fs.Glob(root.FS(), cleanPattern)
}

func (d *DiskReadFS) StaticFiles() []string {
	root, err := os.OpenRoot(d.root)
	if err != nil {
		d.Logger.Err(err).Msg("error opening root for static files")
		return nil
	}
	defer root.Close() //nolint:errcheck

	rootFS := root.FS()
	staticFiles, err := doublestar.Glob(rootFS, "static/**/*")
	if err != nil {
		d.Logger.Err(err).Msg("error getting static files")
		return nil
	}

	var staticRootFiles []string
	staticRootFiles, err = doublestar.Glob(rootFS, "static_root/**/*")
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
	localName, _, err := d.cleanName(name)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(d.root, 0700); err != nil {
		return fmt.Errorf("error creating root directory %s : %s", d.root, err)
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck

	dirName := filepath.Dir(localName)
	if dirName != "." {
		if err := root.MkdirAll(dirName, 0700); err != nil {
			return fmt.Errorf("error creating directory %s : %s", dirName, err)
		}
	}
	return root.WriteFile(localName, bytes, 0600)
}

func (d *DiskWriteFS) Remove(name string) error {
	localName, _, err := d.cleanName(name)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(d.root)
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck

	return root.Remove(localName)
}

func (d *DiskReadFS) cleanName(name string) (localName string, specName string, err error) {
	specName, err = system.CleanRelativePath(name)
	if err != nil {
		return "", "", err
	}
	return filepath.FromSlash(specName), specName, nil
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
