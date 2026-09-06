// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/app/appfs"
)

type staticResourceFS struct {
	appfs.ReadableFS
	file fs.File
}

func (f staticResourceFS) StaticFiles() []string        { return []string{"static_root/test.txt"} }
func (f staticResourceFS) Open(string) (fs.File, error) { return f.file, nil }

type staticResourceFile struct {
	*strings.Reader
	info    fs.FileInfo
	statErr error
	closes  int
}

func (f *staticResourceFile) Stat() (fs.FileInfo, error) { return f.info, f.statErr }
func (f *staticResourceFile) Close() error               { f.closes++; return nil }

func TestStaticRootClosesFiles(t *testing.T) {
	for _, scenario := range []string{"success", "no seek", "stat error", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			info, err := fs.Stat(fstest.MapFS{"test.txt": &fstest.MapFile{Data: []byte("hello")}}, "test.txt")
			if err != nil {
				t.Fatal(err)
			}
			f := &staticResourceFile{Reader: strings.NewReader("hello"), info: info}
			var file fs.File = f
			wantCode := http.StatusInternalServerError
			switch scenario {
			case "success":
				wantCode = http.StatusOK
			case "no seek":
				file = struct{ fs.File }{f}
			case "stat error":
				f.statErr = errors.New("stat failed")
			case "directory":
				f.info, err = fs.Stat(fstest.MapFS{}, ".")
				if err != nil {
					t.Fatal(err)
				}
			}
			source, err := appfs.NewSourceFs("", staticResourceFS{file: file}, true)
			if err != nil {
				t.Fatal(err)
			}
			a := &App{sourceFS: source}
			router := chi.NewRouter()
			if err := a.addStaticRoot(router); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test.txt", nil))
			if response.Code != wantCode {
				t.Fatalf("status = %d, want %d", response.Code, wantCode)
			}
			if f.closes != 1 {
				t.Fatalf("file closed %d times, want 1", f.closes)
			}
		})
	}
}
