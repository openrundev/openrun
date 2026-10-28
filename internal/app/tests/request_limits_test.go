// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// A form body over the app's max_request_body_bytes is refused with 413
// before the handler runs; a body within the cap is served
func TestHandlerRequestBodyCap(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/", fragments=[ace.fragment("f", method="POST")])])

def handler(req):
	return {"b": req.Form.get("b", ["NONE"])[0]}
		`,
		"index.go.html": `b[{{.Data.b}}]`,
	}
	a, _, err := CreateTestAppConfig(logger, fileData, types.AppConfig{MaxRequestBodyBytes: 64})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	small := httptest.NewRequest("POST", "/test/f", strings.NewReader("b=small"))
	small.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	a.ServeHTTP(resp, small)
	testutil.AssertEqualsInt(t, "small code", 200, resp.Code)
	testutil.AssertEqualsString(t, "small body", `b[small]`, resp.Body.String())

	large := httptest.NewRequest("POST", "/test/f", strings.NewReader("b="+strings.Repeat("x", 100)))
	large.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()
	a.ServeHTTP(resp, large)
	testutil.AssertEqualsInt(t, "large code", 413, resp.Code)
	testutil.AssertStringContains(t, resp.Body.String(), "larger than 64 bytes")
}

// int() on a request value refuses a string over the parse length cap with
// an error instead of a quadratic parse, and parses ordinary values as usual
func TestIntBuiltinLengthCap(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	n = int(req.Query["n"][0])
	return {"n": len(str(n)), "kw": int(x=req.Query["n"][0], base=10) == n}
		`,
		"index.go.html": `n[{{.Data.n}}] kw[{{.Data.kw}}]`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	resp := httptest.NewRecorder()
	a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?n=41", nil))
	testutil.AssertEqualsInt(t, "ok code", 200, resp.Code)
	testutil.AssertEqualsString(t, "ok body", `n[2] kw[true]`, resp.Body.String())

	// Within the cap, a long value still parses
	resp = httptest.NewRecorder()
	a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?n="+strings.Repeat("9", 4096), nil))
	testutil.AssertEqualsInt(t, "cap code", 200, resp.Code)
	testutil.AssertEqualsString(t, "cap body", `n[4096] kw[true]`, resp.Body.String())

	resp = httptest.NewRecorder()
	a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?n="+strings.Repeat("9", 4097), nil))
	testutil.AssertEqualsInt(t, "over cap code", 500, resp.Code)
	testutil.AssertStringContains(t, resp.Body.String(), "int: string of 4097 characters is too long")
}

// The collection builtins refuse an iterable of known length over the
// element cap: list(range(n)) with n from a request value fails instead of
// preallocating n elements
func TestCollectionBuiltinCaps(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	n = int(req.Query["n"][0])
	fn = req.Query["fn"][0]
	if fn == "list":
		return {"len": len(list(range(n)))}
	elif fn == "sorted":
		return {"len": len(sorted(range(n)))}
	elif fn == "sorted_kw":
		return {"len": len(sorted(iterable=range(n)))}
	elif fn == "enumerate":
		return {"len": len(enumerate(range(n)))}
	elif fn == "zip":
		return {"len": len(zip(range(n), range(n)))}
	elif fn == "set":
		return {"len": len(set(range(n)))}
	elif fn == "tuple":
		return {"len": len(tuple(range(n)))}
	return {"len": len(reversed(range(n)))}
		`,
		"index.go.html": `len[{{.Data.len}}]`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	// sorted also takes the iterable by keyword
	for _, fn := range []string{"list", "sorted", "sorted_kw", "enumerate", "zip", "set", "tuple", "reversed"} {
		resp := httptest.NewRecorder()
		a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?fn="+fn+"&n=1000", nil))
		testutil.AssertEqualsInt(t, fn+" ok code", 200, resp.Code)
		testutil.AssertEqualsString(t, fn+" ok body", `len[1000]`, resp.Body.String())

		resp = httptest.NewRecorder()
		a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?fn="+fn+"&n=100000000000", nil))
		testutil.AssertEqualsInt(t, fn+" over cap code", 500, resp.Code)
		testutil.AssertStringContains(t, resp.Body.String(), strings.TrimSuffix(fn, "_kw")+": 100000000000 elements exceeds the limit")
	}
}

// A handler recursing past the call depth cap fails with an error well
// before the interpreter's own frame limit
func TestHandlerCallDepthCap(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def depth(n):
	if n == 0:
		return 0
	return depth(n - 1) + 1

def handler(req):
	return {"d": depth(int(req.Query["n"][0]))}
		`,
		"index.go.html": `d[{{.Data.d}}]`,
	}
	a, _, err := CreateTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	resp := httptest.NewRecorder()
	a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?n=5000", nil))
	testutil.AssertEqualsInt(t, "ok code", 200, resp.Code)
	testutil.AssertEqualsString(t, "ok body", `d[5000]`, resp.Body.String())

	resp = httptest.NewRecorder()
	a.ServeHTTP(resp, httptest.NewRequest("GET", "/test?n=50000", nil))
	testutil.AssertEqualsInt(t, "over cap code", 500, resp.Code)
	testutil.AssertStringContains(t, resp.Body.String(), "exceeds the limit of 10000")
}
