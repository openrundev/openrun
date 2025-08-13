// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/types"
)

type EmbedReadFS struct {
	*types.Logger
	fs embed.FS
}

var _ ReadableFS = (*EmbedReadFS)(nil)

func NewEmbedReadFS(logger *types.Logger, embedFS embed.FS) *EmbedReadFS {
	return &EmbedReadFS{
		Logger: logger,
		fs:     embedFS,
	}
}

func (e *EmbedReadFS) Open(name string) (fs.File, error) {
	return e.fs.Open(name)
}

func (e *EmbedReadFS) ReadFile(name string) ([]byte, error) {
	file, err := e.fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, file)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *EmbedReadFS) Stat(name string) (fs.FileInfo, error) {
	bytes, err := e.ReadFile(name)
	if err != nil {
		return nil, err
	}

	fi := DiskFileInfo{
		name:    name,
		len:     int64(len(bytes)),
		modTime: time.Now(),
	}
	return &fi, nil
}

func (e *EmbedReadFS) StatNoSpec(name string) (fs.FileInfo, error) {
	return e.Stat(name)
}

func (e *EmbedReadFS) Glob(pattern string) (matches []string, err error) {
	return fs.Glob(e.fs, pattern)
}

func (e *EmbedReadFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(e.fs, name)
}

func (e *EmbedReadFS) StaticFiles() []string {
	staticFiles, err := doublestar.Glob(e.fs, "static/**/*")
	if err != nil {
		e.Logger.Err(err).Msg("error getting static files")
		return nil
	}

	var staticRootFiles []string
	staticRootFiles, err = doublestar.Glob(e.fs, "static_root/**/*")
	if err != nil {
		e.Logger.Err(err).Msg("error getting static_root files")
		return nil
	}
	staticFiles = append(staticFiles, staticRootFiles...)
	return staticFiles
}

func (e *EmbedReadFS) FileHash(excludeGlob []string) (string, error) {
	return "", fmt.Errorf("FileHash not implemented for dev apps : DiskReadFS")
}

func (e *EmbedReadFS) CreateTempSourceDir() (string, error) {
	return "", fmt.Errorf("CreateTempSourceDir not implemented for dev apps : DiskReadFS")
}

func (e *EmbedReadFS) Reset() {
	// do nothing
}
