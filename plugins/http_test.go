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

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
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
		{"", fd, "multipart/form-data", nil, "", ""}, // multipart bodies are checked by parsing the form below
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
			if req.ContentLength <= 0 {
				t.Errorf("case %d expected content length to be set for multipart body, got %d", i, req.ContentLength)
			}
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

// testHost is a HostServices with fixed values
type testHost map[string]any

func (h testHost) Value(key string) any { return h[key] }

func recordingModule(urls *[]string, respond func(req *http.Request) *http.Response) *httpModule {
	return &httpModule{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				*urls = append(*urls, req.URL.String())
				if respond != nil {
					return respond(req), nil
				}
				return okResponse(req, io.NopCloser(strings.NewReader("ok"))), nil
			}),
		},
	}
}

// The <CONTAINER_URL> placeholder is checked by the permission patterns before
// it is replaced by the container address, so the url after the replacement
// must still point at the container (GHSA-qgqh-4fgp-rf5c)
func TestContainerUrlStaysOnContainer(t *testing.T) {
	host := testHost{types.TL_CONTAINER_URL: "http://127.0.0.1:9000"}
	tests := []struct {
		url     string
		want    string
		wantErr bool
	}{
		{apptype.CONTAINER_URL, "http://127.0.0.1:9000", false},
		{apptype.CONTAINER_URL + "/path?x=1", "http://127.0.0.1:9000/path?x=1", false},
		{apptype.CONTAINER_URL + "@10.0.0.5/admin", "", true},
		{apptype.CONTAINER_URL + ":1234/", "", true},
		{apptype.CONTAINER_URL + ".evil.example/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			var urls []string
			module := recordingModule(&urls, nil)
			call := testCall(tt.url)
			call.Host = host
			_, err := module.request(context.Background(), call, "get")
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "invalid container url") {
					t.Fatalf("expected invalid container url error, got %v (requests %v)", err, urls)
				}
				if len(urls) != 0 {
					t.Fatalf("expected no request, got %v", urls)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(urls) != 1 || urls[0] != tt.want {
				t.Fatalf("expected request to %s, got %v", tt.want, urls)
			}
		})
	}
}

func redirectThen(location string) func(req *http.Request) *http.Response {
	return func(req *http.Request) *http.Response {
		if strings.HasSuffix(req.URL.Path, "/start") {
			res := okResponse(req, io.NopCloser(strings.NewReader("")))
			res.StatusCode = http.StatusFound
			res.Status = "302 Found"
			res.Header.Set("Location", location)
			return res
		}
		return okResponse(req, io.NopCloser(strings.NewReader("ok")))
	}
}

// Each redirect target goes through the host's argument check before it is
// followed; without a host check redirects are refused (GHSA-qgqh-4fgp-rf5c)
func TestRedirectTargetChecked(t *testing.T) {
	t.Run("permitted target followed", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, redirectThen("https://other.example/next"))
		call := testCall("https://example.com/start")
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			checked = append(checked, function+" "+arg)
			return nil
		})}
		result, err := module.request(context.Background(), call, "get")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 1 || checked[0] != "get https://other.example/next" {
			t.Fatalf("expected the redirect target to be checked, got %v", checked)
		}
		if len(urls) != 2 || urls[1] != "https://other.example/next" {
			t.Fatalf("expected the redirect to be followed, got %v", urls)
		}
		if got := result.(*sdk.Struct).Fields["url"]; got != "https://other.example/next" {
			t.Fatalf("expected final url, got %v", got)
		}
	})

	t.Run("refused target not followed", func(t *testing.T) {
		var urls []string
		module := recordingModule(&urls, redirectThen("http://169.254.169.254/"))
		call := testCall("https://example.com/start")
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			return errors.New("blocked by test")
		})}
		_, err := module.request(context.Background(), call, "get")
		if err == nil || !strings.Contains(err.Error(), "redirect to http://169.254.169.254 not followed: blocked by test") {
			t.Fatalf("expected refused redirect error, got %v", err)
		}
		if len(urls) != 1 {
			t.Fatalf("expected the redirect target not to be requested, got %v", urls)
		}
	})

	t.Run("no host check refuses redirects", func(t *testing.T) {
		var urls []string
		module := recordingModule(&urls, redirectThen("https://other.example/next"))
		_, err := module.request(context.Background(), testCall("https://example.com/start"), "get")
		if err == nil || !strings.Contains(err.Error(), "cannot be checked against the app permissions") {
			t.Fatalf("expected refused redirect error, got %v", err)
		}
		if len(urls) != 1 {
			t.Fatalf("expected the redirect target not to be requested, got %v", urls)
		}
	})

	t.Run("container target checked as <CONTAINER_URL>", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, redirectThen("http://127.0.0.1:9000/next?x=1"))
		call := testCall(apptype.CONTAINER_URL + "/start")
		call.Host = testHost{
			types.TL_CONTAINER_URL: "http://127.0.0.1:9000",
			types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
				checked = append(checked, arg)
				return nil
			}),
		}
		if _, err := module.request(context.Background(), call, "get"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 1 || checked[0] != apptype.CONTAINER_URL+"/next?x=1" {
			t.Fatalf("expected the container form to be checked, got %v", checked)
		}
	})

	t.Run("303 after post checked as get", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, func(req *http.Request) *http.Response {
			if req.Method == http.MethodPost {
				res := okResponse(req, io.NopCloser(strings.NewReader("")))
				res.StatusCode = http.StatusSeeOther
				res.Status = "303 See Other"
				res.Header.Set("Location", "https://example.com/result")
				return res
			}
			return okResponse(req, io.NopCloser(strings.NewReader("ok")))
		})
		call := testCall("https://example.com/start")
		call.Function = "post"
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			checked = append(checked, function+" "+arg)
			return nil
		})}
		if _, err := module.request(context.Background(), call, "post"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 1 || checked[0] != "get https://example.com/result" {
			t.Fatalf("expected the target to be checked as a get, got %v", checked)
		}
	})
}

// The params values are merged into the url's query after the permission
// checks saw the url argument, so the url the request goes out with is
// checked through the host as the url argument of the call
func TestParamsUrlChecked(t *testing.T) {
	t.Run("merged url checked as the call's url", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, nil)
		call := testCall("https://example.com/items?mode=safe", map[string]any{"mode": "admin"})
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			checked = append(checked, function+"|"+arg)
			return nil
		})}
		if _, err := module.request(context.Background(), call, "get"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 1 || checked[0] != "|https://example.com/items?mode=admin" {
			t.Fatalf("expected the merged url to be checked, got %v", checked)
		}
		if len(urls) != 1 || urls[0] != "https://example.com/items?mode=admin" {
			t.Fatalf("unexpected request urls %v", urls)
		}
	})

	t.Run("refused merged url not requested", func(t *testing.T) {
		var urls []string
		module := recordingModule(&urls, nil)
		call := testCall("https://example.com/items", map[string]any{"k": "s3cr3t"})
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			return errors.New("blocked by test")
		})}
		_, err := module.request(context.Background(), call, "get")
		if err == nil || !strings.Contains(err.Error(), "url with params not permitted: blocked by test") {
			t.Fatalf("expected refused error, got %v", err)
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("param value leaked in error: %v", err)
		}
		if len(urls) != 0 {
			t.Fatalf("expected no request, got %v", urls)
		}
	})

	t.Run("no params leaves the url unchecked", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, nil)
		call := testCall("https://example.com/items?a=b")
		call.Host = testHost{types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
			checked = append(checked, arg)
			return nil
		})}
		if _, err := module.request(context.Background(), call, "get"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 0 {
			t.Fatalf("expected no check, got %v", checked)
		}
	})

	t.Run("container url checked as <CONTAINER_URL>", func(t *testing.T) {
		var urls, checked []string
		module := recordingModule(&urls, nil)
		call := testCall(apptype.CONTAINER_URL+"/items", map[string]any{"x": "1"})
		call.Host = testHost{
			types.TL_CONTAINER_URL: "http://127.0.0.1:9000",
			types.TL_PLUGIN_ARG_CHECK: types.PluginArgCheckFunc(func(function, arg string) error {
				checked = append(checked, arg)
				return nil
			}),
		}
		if _, err := module.request(context.Background(), call, "get"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checked) != 1 || checked[0] != apptype.CONTAINER_URL+"/items?x=1" {
			t.Fatalf("expected the container form to be checked, got %v", checked)
		}
	})
}
