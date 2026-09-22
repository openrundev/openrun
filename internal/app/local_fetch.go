// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/app/action"
)

// App local urls served in-process, for the callers of actions which have no
// app session to fetch a result file with (the CLI through the management
// API, MCP clients). The request goes through the app router as the identity
// in ctx, so the app's own rules for the url apply (the visibility and single
// access of fs.serve_tmp_file files, the static file handling)

// ServeLocal serves a GET of an app local url (server path with the app path,
// and an optional query) to w
func (a *App) ServeLocal(ctx context.Context, w http.ResponseWriter, localURL string) {
	// ctx comes from the request being served (the management API route, the
	// MCP endpoint): its chi route context carries that request's routing
	// state (RoutePath), which would misroute this one. Start a fresh one
	ctx = context.WithValue(ctx, chi.RouteCtxKey, chi.NewRouteContext())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, localURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.ServeHTTP(w, request)
}

// FetchLocal reads an app local url into memory. A file over the limit is
// not read to the end, so a single access file is not consumed by the failed
// fetch (action.ErrFileTooLarge)
func (a *App) FetchLocal(ctx context.Context, localURL string, limit int64) (*action.FetchedFile, error) {
	recorder := &limitedRecorder{header: http.Header{}, limit: limit}
	a.ServeLocal(ctx, recorder, localURL)
	if recorder.overflow {
		return nil, action.ErrFileTooLarge
	}
	if recorder.status != 0 && recorder.status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", recorder.status, strings.TrimSpace(firstBytes(recorder.body.Bytes(), 200)))
	}

	data := recorder.body.Bytes()
	mimeType, _, _ := mime.ParseMediaType(recorder.header.Get("Content-Type"))
	if mimeType == "" || mimeType == "application/octet-stream" {
		// fs.serve_tmp_file defaults to octet-stream: look at the content
		mimeType, _, _ = mime.ParseMediaType(http.DetectContentType(data))
	}
	return &action.FetchedFile{Data: data, MimeType: mimeType}, nil
}

func firstBytes(data []byte, count int) string {
	if len(data) > count {
		data = data[:count]
	}
	return string(data)
}

// limitedRecorder is an in-memory response writer which fails the write that
// takes the body over the limit
type limitedRecorder struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	limit    int64
	overflow bool
}

func (l *limitedRecorder) Header() http.Header {
	return l.header
}

func (l *limitedRecorder) WriteHeader(status int) {
	if l.status == 0 {
		l.status = status
	}
}

func (l *limitedRecorder) Write(data []byte) (int, error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	if int64(l.body.Len()+len(data)) > l.limit {
		l.overflow = true
		return 0, action.ErrFileTooLarge
	}
	return l.body.Write(data)
}
