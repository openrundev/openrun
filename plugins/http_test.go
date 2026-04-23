// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type contextAwareBody struct {
	ctx    context.Context
	data   []byte
	read   bool
	closed bool
}

func (b *contextAwareBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	n := copy(p, b.data)
	return n, io.EOF
}

func (b *contextAwareBody) Close() error {
	b.closed = true
	return nil
}

// Copied from https://github.com/qri-io/starlib/blob/master/http/http_test.go
func TestSetBody(t *testing.T) {
	fd := map[string]string{
		"foo": "bar baz",
	}

	cases := []struct {
		rawBody      starlark.String
		formData     map[string]string
		formEncoding starlark.String
		jsonData     starlark.Value
		body         string
		err          string
	}{
		{starlark.String("hallo"), nil, starlark.String(""), nil, "hallo", ""},
		{starlark.String(""), fd, starlark.String(""), nil, "foo=bar+baz", ""},
		// TODO - this should check multipart form data is being set
		{starlark.String(""), fd, starlark.String("multipart/form-data"), nil, "", ""},
		{starlark.String(""), nil, starlark.String(""), starlark.Tuple{starlark.Bool(true), starlark.MakeInt(1), starlark.String("der")}, "[true,1,\"der\"]", ""},
	}

	for i, c := range cases {
		var formData *starlark.Dict
		if c.formData != nil {
			formData = starlark.NewDict(len(c.formData))
			for k, v := range c.formData {
				if err := formData.SetKey(starlark.String(k), starlark.String(v)); err != nil {
					t.Fatal(err)
				}
			}
		}

		req := httptest.NewRequest("get", "https://example.com", nil)
		err := setBody(req, c.rawBody, formData, c.formEncoding, c.jsonData)
		if !(err == nil && c.err == "" || (err != nil && err.Error() == c.err)) { //nolint:staticcheck
			t.Errorf("case %d error mismatch. expected: %s, got: %s", i, c.err, err)
			continue
		}

		if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data;") {
			if err := req.ParseMultipartForm(0); err != nil {
				t.Fatal(err)
			}

			for k, v := range c.formData {
				fv := req.FormValue(k)
				if fv != v {
					t.Errorf("case %d error mismatch. expected %s=%s, got: %s", i, k, v, fv)
				}
			}
		} else {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != c.body {
				t.Errorf("case %d body mismatch. expected: %s, got: %s", i, c.body, string(body))
			}
		}
	}
}

func TestReqMethodUsesThreadLocalContextAndDefaultTimeout(t *testing.T) {
	type ctxKey string

	var gotValue string
	var deadline time.Time

	plugin := &httpPlugin{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				gotValue, _ = req.Context().Value(ctxKey("request_id")).(string)
				var ok bool
				deadline, ok = req.Context().Deadline()
				if !ok {
					t.Fatal("expected request deadline")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
					Request:    req,
				}, nil
			}),
		},
	}

	thread := &starlark.Thread{Name: "test"}
	thread.SetLocal(types.TL_CONTEXT, context.WithValue(context.Background(), ctxKey("request_id"), "req-123"))
	thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, "http.in")

	_, err := plugin.reqMethod("get")(thread, nil, starlark.Tuple{starlark.String("https://example.com")}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotValue != "req-123" {
		t.Fatalf("expected thread-local context value, got %q", gotValue)
	}

	remaining := time.Until(deadline)
	if remaining < 295*time.Second || remaining > 305*time.Second {
		t.Fatalf("expected default timeout near 300s, got %v", remaining)
	}
}

func TestReqMethodUsesExplicitTimeout(t *testing.T) {
	var deadline time.Time

	plugin := &httpPlugin{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var ok bool
				deadline, ok = req.Context().Deadline()
				if !ok {
					t.Fatal("expected request deadline")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
					Request:    req,
				}, nil
			}),
		},
	}

	thread := &starlark.Thread{Name: "test"}
	thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, "http.in")
	kwargs := []starlark.Tuple{{starlark.String("timeout"), starlark.MakeInt(2)}}

	_, err := plugin.reqMethod("get")(thread, nil, starlark.Tuple{starlark.String("https://example.com")}, kwargs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remaining := time.Until(deadline)
	if remaining < time.Second || remaining > 3*time.Second {
		t.Fatalf("expected explicit timeout near 2s, got %v", remaining)
	}
}

func TestReqMethodCancelsContextOnDoError(t *testing.T) {
	var reqCtx context.Context

	plugin := &httpPlugin{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				reqCtx = req.Context()
				return nil, errors.New("boom")
			}),
		},
	}

	thread := &starlark.Thread{Name: "test"}
	thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, "http.in")

	_, err := plugin.reqMethod("get")(thread, nil, starlark.Tuple{starlark.String("https://example.com")}, nil)
	if err == nil {
		t.Fatal("expected request error")
	}
	if reqCtx == nil {
		t.Fatal("expected transport to receive request context")
	}
	if reqCtx.Err() == nil {
		t.Fatal("expected request context to be canceled after error")
	}
}

func TestReqMethodDeferredCleanupClosesResponseBody(t *testing.T) {
	body := &contextAwareBody{data: []byte("ok")}
	plugin := &httpPlugin{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body.ctx = req.Context()
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       body,
					Request:    req,
				}, nil
			}),
		},
	}

	thread := &starlark.Thread{Name: "test"}
	thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, "http.in")

	_, err := plugin.reqMethod("get")(thread, nil, starlark.Tuple{starlark.String("https://example.com")}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if body.closed {
		t.Fatal("response body should remain open until deferred cleanup runs")
	}

	if err := action.RunDeferredCleanup(thread); err != nil {
		t.Fatalf("unexpected deferred cleanup error: %v", err)
	}

	if !body.closed {
		t.Fatal("expected deferred cleanup to close response body")
	}
}

func TestReqMethodBodyReadClearsDeferredCleanup(t *testing.T) {
	body := &contextAwareBody{data: []byte("ok")}
	plugin := &httpPlugin{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body.ctx = req.Context()
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       body,
					Request:    req,
				}, nil
			}),
		},
	}

	thread := &starlark.Thread{Name: "test"}
	thread.SetLocal(types.TL_CURRENT_MODULE_FULL_PATH, "http.in")

	respValue, err := plugin.reqMethod("get")(thread, nil, starlark.Tuple{starlark.String("https://example.com")}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := respValue.(*app.PluginResponse)
	if !ok {
		t.Fatalf("expected plugin response, got %T", respValue)
	}

	value, err := resp.Attr("value")
	if err != nil {
		t.Fatalf("unexpected value error: %v", err)
	}

	valueAttrs, ok := value.(starlark.HasAttrs)
	if !ok {
		t.Fatalf("expected starlark struct, got %T", value)
	}

	bodyFn, err := valueAttrs.Attr("body")
	if err != nil {
		t.Fatalf("unexpected body attr error: %v", err)
	}

	bodyCallable, ok := bodyFn.(starlark.Callable)
	if !ok {
		t.Fatalf("expected body callable, got %T", bodyFn)
	}

	bodyValue, err := starlark.Call(thread, bodyCallable, nil, nil)
	if err != nil {
		t.Fatalf("unexpected body read error: %v", err)
	}

	if got := string(bodyValue.(starlark.String)); got != "ok" {
		t.Fatalf("expected body contents, got %q", got)
	}

	if err := action.RunDeferredCleanup(thread); err != nil {
		t.Fatalf("unexpected deferred cleanup error: %v", err)
	}

	if !body.closed {
		t.Fatal("expected body() to close the original response body")
	}
}
