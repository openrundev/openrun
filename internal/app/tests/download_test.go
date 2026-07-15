// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// The download response (ace.response(..., download=name)) streams the body
// verbatim as an attachment: no template, no json/html escaping, and a
// Content-Disposition header. It is the mechanism the console zip downloads
// use to stream a version/source bundle without staging it to disk or the db.

func TestDownloadResponse(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response("col1,col2\n1,2\n", download="report.csv", content_type="text/csv")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "text/csv", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "disposition", `attachment; filename="report.csv"`,
		response.Header().Get("Content-Disposition"))
	testutil.AssertEqualsString(t, "body", "col1,col2\n1,2\n", response.Body.String())
	// No Content-Length: the body streams out with chunked transfer encoding
	testutil.AssertEqualsString(t, "content-length", "", response.Header().Get("Content-Length"))
}

// A download with no content_type falls back to application/octet-stream.
func TestDownloadResponseDefaultContentType(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response("data", download="blob.bin")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/octet-stream", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "disposition", `attachment; filename="blob.bin"`,
		response.Header().Get("Content-Disposition"))
	testutil.AssertEqualsString(t, "body", "data", response.Body.String())
}

// The body is written byte-for-byte, without the json/html escaping the other
// response types apply. Content that json or template rendering would alter
// (quotes, backslashes, angle brackets, newlines) must survive verbatim.
func TestDownloadResponseVerbatim(t *testing.T) {
	logger := testutil.TestLogger()
	// A payload full of characters that JSON encoding (< > & as \uXXXX) or
	// HTML template rendering (< as &lt;) would escape. A single-quoted
	// starlark literal keeps the embedded double quotes readable.
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response('<tag attr="v">& raw \n end', download="raw.txt", content_type="application/json")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	want := "<tag attr=\"v\">& raw \n end"
	testutil.AssertEqualsString(t, "body", want, response.Body.String())
}

// A starlark bytes value (b"...") carries arbitrary bytes, including invalid
// UTF-8 sequences, and must stream byte-for-byte. This is the property the zip
// downloads rely on: the corruption bug was a json round-trip replacing such
// bytes with U+FFFD.
func TestDownloadResponseBinaryBytes(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	# PK zip magic followed by bytes that are not valid UTF-8
	return ace.response(b"PK\x03\x04\xff\xfe\x00\x89\xc0", download="a.zip", content_type="application/zip")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/zip", response.Header().Get("Content-Type"))
	want := []byte{'P', 'K', 0x03, 0x04, 0xff, 0xfe, 0x00, 0x89, 0xc0}
	got := response.Body.Bytes()
	if string(got) != string(want) {
		t.Fatalf("binary body corrupted:\n want % x\n  got % x", want, got)
	}
}

// A large body (bigger than net/http's internal write buffer) exercises the
// streaming path and confirms the whole payload is delivered intact.
func TestDownloadResponseLarge(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response("A" * 200000, download="big.txt")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsInt(t, "len", 200000, response.Body.Len())
	if strings.Trim(response.Body.String(), "A") != "" {
		t.Fatalf("large body has unexpected content")
	}
}

// The filename is quoted, so a name with a space or quote cannot break the
// Content-Disposition header.
func TestDownloadResponseFilenameQuoting(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response("x", download='my report ".txt')`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "disposition", `attachment; filename="my report \".txt"`,
		response.Header().Get("Content-Disposition"))
}

// A download with an explicit code sends that status, not a hard-coded 200.
func TestDownloadResponseCode(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/")])

def handler(req):
	return ace.response("partial", download="part.bin", code=206)`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 206, response.Code)
	testutil.AssertEqualsString(t, "body", "partial", response.Body.String())
}

// testStreamPlugin returns download-stream values, the lazily produced
// download bodies the zip download plugin APIs use. get(size=N, fail=True)
// produces N bytes of "A" in 64KB writes and then optionally fails, letting
// the tests drive the producer past (or keep it under) the 16MB response
// buffer.
type testStreamPlugin struct{}

func (p *testStreamPlugin) Get(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size starlark.Int
	var fail starlark.Bool
	if err := starlark.UnpackArgs("get", args, kwargs, "size", &size, "fail?", &fail); err != nil {
		return nil, err
	}
	total, _ := size.Int64()
	stream := starlark_type.NewDownloadStream("stream.bin", func(w io.Writer) error {
		chunk := bytes.Repeat([]byte{'A'}, 64*1024)
		remaining := total
		for remaining > 0 {
			n := min(remaining, int64(len(chunk)))
			if _, err := w.Write(chunk[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		if bool(fail) {
			return fmt.Errorf("producer failed after %d bytes", total)
		}
		return nil
	})
	dict := starlark.NewDict(2)
	dict.SetKey(starlark.String("content"), stream)                     //nolint:errcheck
	dict.SetKey(starlark.String("name"), starlark.String("stream.bin")) //nolint:errcheck
	return dict, nil
}

func init() {
	p := &testStreamPlugin{}
	app.RegisterPlugin("teststream", func(pluginContext *types.PluginContext) (any, error) {
		return &testStreamPlugin{}, nil
	}, []plugin.PluginFunc{
		app.CreatePluginApiName(p.Get, app.READ, "get"),
	})
}

func streamTestApp(t *testing.T, call string) *app.App {
	t.Helper()
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("teststream.in", "teststream")
app = ace.app("testApp", routes = [ace.html("/")],
	permissions=[ace.permission("teststream.in", "get")])

def handler(req):
	ret = %s
	return ace.response(ret.value["content"], download=ret.value["name"],
		content_type="application/octet-stream")`, call),
		"index.go.html": `{{.}}`,
	}
	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"teststream.in"},
		[]types.Permission{{Plugin: "teststream.in", Method: "get"}}, nil)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	return a
}

// A plugin download stream produces the body at response-write time: the
// bytes must arrive intact with the download headers and chunked transfer
// (no Content-Length), same as a string body.
func TestDownloadResponseStream(t *testing.T) {
	a := streamTestApp(t, `teststream.get(size=200000)`)

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "type", "application/octet-stream", response.Header().Get("Content-Type"))
	testutil.AssertEqualsString(t, "disposition", `attachment; filename="stream.bin"`,
		response.Header().Get("Content-Disposition"))
	testutil.AssertEqualsString(t, "content-length", "", response.Header().Get("Content-Length"))
	testutil.AssertEqualsInt(t, "len", 200000, response.Body.Len())
	if strings.Trim(response.Body.String(), "A") != "" {
		t.Fatalf("stream body has unexpected content")
	}
}

// A producer error before anything is flushed (the body stayed under the
// response buffer size) returns a clean 500, not a truncated 200.
func TestDownloadResponseStreamErrorClean(t *testing.T) {
	a := streamTestApp(t, `teststream.get(size=1000, fail=True)`)

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "error producing download stream.bin")
	testutil.AssertEqualsString(t, "disposition", "", response.Header().Get("Content-Disposition"))
}

// A producer error after the response buffer has flushed (status and body
// bytes already on the wire) aborts the connection with http.ErrAbortHandler
// instead of finalizing a truncated body as a successful download.
func TestDownloadResponseStreamAbort(t *testing.T) {
	// 2MB forces a flush of the 1MB buffer before the failure
	a := streamTestApp(t, `teststream.get(size=2*1024*1024, fail=True)`)

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	defer func() {
		r := recover()
		if r != http.ErrAbortHandler {
			t.Fatalf("expected http.ErrAbortHandler panic, got %v", r)
		}
		// The status and the first buffer-full went out before the abort
		testutil.AssertEqualsInt(t, "code", 200, response.Code)
		testutil.AssertEqualsInt(t, "flushed", 1024*1024, response.Body.Len())
	}()
	a.ServeHTTP(response, request)
	t.Fatalf("expected ServeHTTP to panic")
}

// A download response needs no template block even on an html route: the
// download branch is taken before the block/type validation that would
// otherwise reject a blockless html response.
func TestDownloadResponseNoBlockNeeded(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", routes = [ace.html("/", fragments=[ace.fragment("dl")])])

def handler(req):
	return ace.response("payload", download="f.txt")`,
	}
	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/dl", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertEqualsString(t, "body", "payload", response.Body.String())
}
