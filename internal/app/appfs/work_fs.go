// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import "io"

// WorkFs is the implementation of work file system
type WorkFs struct {
	WritableFS
	Root string
}

var _ WritableFS = (*WorkFs)(nil)

// NewWorkFs creates a new work file system
func NewWorkFs(dir string, fs WritableFS) *WorkFs {
	return &WorkFs{
		Root:       dir,
		WritableFS: fs,
	}
}

// Close releases any resources held by the underlying file system, such as
// the cached root directory handle of a DiskReadFS.
func (w *WorkFs) Close() error {
	if closer, ok := w.WritableFS.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
