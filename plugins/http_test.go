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

	sdk "github.com/openrundev/openrun/pkg/plugin"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedBody struct {
	data   []byte
	read   bool
	closed bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	n := copy(p, b.data)
	return n, io.EOF
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

// Copied from https://github.com/qri-io/starlib/blob/master/http/http_test.go
func TestSetBody(t *testing.T) {
	fd := map[string]any{
		"foo": "bar baz",
	}

	cases := []struct {
		rawBody      string
		formData     map[string]any
		formEncoding string
		jsonData     any
		body         string
		err          string
	}{
		{"hallo", nil, "", nil, "hallo", ""},
		{"", fd, "", nil, "foo=bar+baz", ""},
		// TODO - this should check multipart form data is being set
		{"", fd, "multipart/form-data", nil, "", ""},
		{"", nil, "", sdk.Tuple{true, int64(1), "der"}, "[true,1,\"der\"]", ""},
	}

	for i, c := range cases {
		req := httptest.NewRequest("get", "https://example.com", nil)
		err := setBody(req, c.rawBody, c.formData, c.formEncoding, c.jsonData)
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

func testCall(args ...any) *sdk.Call {
	return &sdk.Call{Function: "get", Args: args, Session: sdk.NewSession("test")}
}

func okResponse(req *http.Request, body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       body,
		Request:    req,
	}
}

// The request runs on the session context (the response body may be read by
// a later body() call, so the per-call context cannot own it), with the
// default timeout applied.
func TestRequestUsesSessionContextAndDefaultTimeout(t *testing.T) {
	var deadline time.Time

	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var ok bool
				deadline, ok = req.Context().Deadline()
				if !ok {
					t.Fatal("expected request deadline")
				}
				return okResponse(req, io.NopCloser(strings.NewReader("ok"))), nil
			}),
		},
	}

	_, err := module.request(context.Background(), testCall("https://example.com"), "get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remaining := time.Until(deadline)
	if remaining < 295*time.Second || remaining > 305*time.Second {
		t.Fatalf("expected default timeout near 300s, got %v", remaining)
	}
}

func TestRequestUsesExplicitTimeout(t *testing.T) {
	var deadline time.Time

	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var ok bool
				deadline, ok = req.Context().Deadline()
				if !ok {
					t.Fatal("expected request deadline")
				}
				return okResponse(req, io.NopCloser(strings.NewReader("ok"))), nil
			}),
		},
	}

	call := testCall("https://example.com")
	call.Kwargs = []sdk.Kwarg{{Name: "timeout", Value: int64(2)}}
	_, err := module.request(context.Background(), call, "get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remaining := time.Until(deadline)
	if remaining < time.Second || remaining > 3*time.Second {
		t.Fatalf("expected explicit timeout near 2s, got %v", remaining)
	}
}

func TestRequestCancelsContextOnDoError(t *testing.T) {
	var reqCtx context.Context

	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				reqCtx = req.Context()
				return nil, errors.New("boom")
			}),
		},
	}

	_, err := module.request(context.Background(), testCall("https://example.com"), "get")
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

// The response body stays unread until a _read_body func ref call; body()
// reads and closes it, and the data is cached for repeated calls.
func TestRequestBodyReadLazily(t *testing.T) {
	body := &trackedBody{data: []byte(`{"a": 1}`)}
	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return okResponse(req, body), nil
			}),
		},
	}

	call := testCall("https://example.com")
	result, err := module.request(context.Background(), call, "get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if body.closed {
		t.Fatal("expected response body to stay open until body() is called")
	}

	response, ok := result.(*sdk.Struct)
	if !ok {
		t.Fatalf("expected struct response, got %T", result)
	}
	if int64(200) != response.Fields["status_code"] {
		t.Fatalf("unexpected status code: %v", response.Fields["status_code"])
	}

	bodyRef, ok := response.Fields["body"].(*sdk.FuncRef)
	if !ok {
		t.Fatalf("expected body func ref, got %T", response.Fields["body"])
	}

	readCall := &sdk.Call{Function: bodyRef.Function, Args: bodyRef.Args, Session: call.Session}
	text, err := module.ReadBody(context.Background(), readCall)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if text != `{"a": 1}` {
		t.Fatalf("unexpected body value: %v", text)
	}
	if !body.closed {
		t.Fatal("expected body() to close the response body")
	}

	// Repeated reads use the cached data; json mode parses it
	jsonRef := response.Fields["json"].(*sdk.FuncRef)
	jsonCall := &sdk.Call{Function: jsonRef.Function, Args: jsonRef.Args, Session: call.Session}
	parsedVal, err := module.ReadBody(context.Background(), jsonCall)
	if err != nil {
		t.Fatalf("unexpected json read error: %v", err)
	}
	parsed, ok := parsedVal.(map[string]any)
	if !ok || parsed["a"] != float64(1) {
		t.Fatalf("unexpected json value: %#v", parsedVal)
	}
}

// An unread response body is closed by the session cleanup at request end.
func TestRequestUnreadBodyClosedBySession(t *testing.T) {
	body := &trackedBody{data: []byte("ok")}
	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return okResponse(req, body), nil
			}),
		},
	}

	call := testCall("https://example.com")
	if _, err := module.request(context.Background(), call, "get"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body.closed {
		t.Fatal("expected body to stay open until session end")
	}
	if err := call.Session.End(context.Background()); err != nil {
		t.Fatalf("unexpected session end error: %v", err)
	}
	if !body.closed {
		t.Fatal("expected session end to close the response body")
	}
}

// A body that is not valid JSON fails at response.json() call time, but the
// request itself succeeds.
func TestRequestJsonParseError(t *testing.T) {
	module := &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return okResponse(req, io.NopCloser(strings.NewReader("not json"))), nil
			}),
		},
	}

	call := testCall("https://example.com")
	result, err := module.request(context.Background(), call, "get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	response := result.(*sdk.Struct)
	jsonRef := response.Fields["json"].(*sdk.FuncRef)
	jsonCall := &sdk.Call{Function: jsonRef.Function, Args: jsonRef.Args, Session: call.Session}
	if _, err := module.ReadBody(context.Background(), jsonCall); err == nil {
		t.Fatal("expected json parse error for invalid JSON body")
	}
}
