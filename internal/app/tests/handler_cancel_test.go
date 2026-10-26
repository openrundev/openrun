// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// A handler that never returns on its own must stop when the request context
// ends (client disconnect), instead of pinning the goroutine forever
func TestHandlerStopsOnRequestCancel(t *testing.T) {
	logger := testutil.TestLogger()
	a, _, err := CreateTestApp(logger, map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")])

def handler(req):
	for i in range(1000000000000):
		pass
	return {"key": "done"}
		`,
		"index.go.html": `Template got {{ .Data.key }}.`,
	})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.ServeHTTP(response, request)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler kept running after the request context was canceled")
	}
	testutil.AssertEqualsInt(t, "code", http.StatusInternalServerError, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "canceled")
}

// A streamed action response runs for as long as the command does: the
// server write timeout, which is absolute from the request start, must not
// cut the stream while the client is reading
func TestStreamOutlivesServerWriteTimeout(t *testing.T) {
	a := streamActionApp(t, `for i in 1 2 3 4 5 6; do echo $i; sleep 0.2; done`, `	return ace.result("Running", stream=ret)`)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// exec is a system plugin: the server middleware normally sets the user
		a.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), types.USER_ID, "testuser")))
	}))
	server.Config.WriteTimeout = 300 * time.Millisecond
	server.Start()
	defer server.Close()

	request, err := http.NewRequest("POST", server.URL+"/test/api/actions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "code", 200, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("stream cut by the write timeout: %s", err)
	}
	testutil.AssertEqualsString(t, "body", "1\n2\n3\n4\n5\n6\n", string(body))
	testutil.AssertEqualsString(t, "exit trailer", "0", response.Trailer.Get("OpenRun-Exit-Status"))
}

// An upstream event stream proxied to the client is open-ended too: the
// proxy must clear the server write timeout for it
func TestProxiedEventStreamOutlivesServerWriteTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 1; i <= 6; i++ {
			if _, err := io.WriteString(w, "data: tick\n\n"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	handler := newProxyTestHandler(t, upstream.URL, false)
	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = 300 * time.Millisecond
	server.Start()
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/test/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	testutil.AssertEqualsInt(t, "code", 200, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("proxied stream cut by the write timeout: %s", err)
	}
	testutil.AssertEqualsInt(t, "events", 6, strings.Count(string(body), "data: tick\n\n"))
}
