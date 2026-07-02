// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func newBenchSourceFS(b *testing.B) *SourceFs {
	rootDir := b.TempDir()
	if err := os.MkdirAll(filepath.Join(rootDir, "nested"), 0700); err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 16*1024)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "index.html"), data, 0600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "nested", "file.txt"), data, 0600); err != nil {
		b.Fatal(err)
	}

	sourceFS, err := NewSourceFs(rootDir, NewDiskReadFS(testutil.TestLogger(), rootDir, nil), false)
	if err != nil {
		b.Fatal(err)
	}
	return sourceFS
}

// BenchmarkDiskFileServer measures the static_disk serving hot path:
// fsHandler -> SourceFs.open -> DiskReadFS.Open -> http.ServeContent.
func BenchmarkDiskFileServer(b *testing.B) {
	handler := FileServer(newBenchSourceFS(b), "index.html")

	req := httptest.NewRequest("GET", "/nested/file.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

func BenchmarkDiskReadFSOpen(b *testing.B) {
	sourceFS := newBenchSourceFS(b)

	b.ReportAllocs()
	for b.Loop() {
		f, err := sourceFS.Open("nested/file.txt")
		if err != nil {
			b.Fatal(err)
		}
		f.Close() //nolint:errcheck
	}
}
