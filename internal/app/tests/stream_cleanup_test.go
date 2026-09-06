// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

type streamResourceKey struct{}
type streamResourceState struct {
	closed, next    int
	cleanupError    bool
	startupError    bool
	midstreamError  bool
	sawCancellation bool
	cancel          context.CancelFunc
}
type resourceStreamModule struct{}

func (*resourceStreamModule) InitModule(context.Context, sdk.ModuleInit) error { return nil }
func (*resourceStreamModule) Close(context.Context) error                      { return nil }
func (*resourceStreamModule) Open(ctx context.Context, call *sdk.Call) (any, error) {
	state := ctx.Value(streamResourceKey{}).(*streamResourceState)
	if state.cleanupError {
		call.Session.Defer("failure", true, func(context.Context) error { return errors.New("cleanup failed") })
	}
	return &sdk.Cursor{
		TypeName: "resource stream", Stream: true,
		Next: func(ctx context.Context, max int) ([]any, bool, error) {
			state.next++
			if state.midstreamError {
				if state.next == 1 {
					return []any{"output"}, false, nil
				}
				return nil, false, errors.New("stream failed after output")
			}
			if state.startupError {
				return nil, false, errors.New("stream startup failed")
			}
			if state.cancel != nil {
				state.cancel()
				state.sawCancellation = errors.Is(ctx.Err(), context.Canceled)
				// Verify that the response consumer passes the request context.
				if ctx.Err() == nil {
					return nil, false, errors.New("request context was lost")
				}
				return nil, false, ctx.Err()
			}
			state.closed++ // Exhaustion owns the terminal close.
			return []any{"output"}, true, nil
		},
		Close: func(context.Context) error { state.closed++; return nil },
	}, nil
}

func init() {
	app.RegisterLocalProvider("resourcestream", &sdk.ServeConfig{
		ProviderVersion: "test",
		Modules: map[string]sdk.ModuleDef{"resourcestream": {
			Builder:   func() sdk.Module { return &resourceStreamModule{} },
			Functions: []sdk.FuncDef{{Name: "open", Type: sdk.READ, Method: "Open"}},
		}},
	}, app.LocalProviderOptions{})
}

// Hiding Flush exercises a response setup failure before the iterator starts.
type noFlushResponseWriter struct{ http.ResponseWriter }

func TestStreamResourceCleanup(t *testing.T) {
	for _, scenario := range []string{"unused", "handler error", "exhausted", "cleanup error", "no flusher", "canceled", "startup error", "midstream error"} {
		t.Run(scenario, func(t *testing.T) {
			statement := "return stream"
			if scenario == "unused" {
				statement = "return {}"
			}
			if scenario == "handler error" {
				statement = `fail("handler failed")`
			}
			files := map[string]string{"app.star": fmt.Sprintf(`
load("resourcestream.in", "resourcestream")
app = ace.app("testApp", routes=[ace.api("/")])
def handler(req):
	stream = resourcestream.open()
	%s
`, statement)}
			a, _, err := CreateTestAppPlugin(testutil.TestLogger(), files, []string{"resourcestream.in"},
				[]types.Permission{{Plugin: "resourcestream.in", Method: "open"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			state := &streamResourceState{cleanupError: scenario == "cleanup error", startupError: scenario == "startup error", midstreamError: scenario == "midstream error"}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), streamResourceKey{}, state))
			defer cancel()
			if scenario == "canceled" {
				state.cancel = cancel
			}
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			if scenario == "no flusher" {
				writer = noFlushResponseWriter{recorder}
			}
			func() {
				defer func() {
					recovered := recover()
					if scenario == "midstream error" {
						if recovered != http.ErrAbortHandler {
							t.Errorf("midstream failure did not abort: %v", recovered)
						}
					} else if recovered != nil {
						panic(recovered)
					}
				}()
				a.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx))
			}()
			if state.closed != 1 {
				t.Fatalf("resource closed %d times, want 1; response: %s", state.closed, recorder.Body.String())
			}
			wantNext := 0
			if scenario == "exhausted" || scenario == "canceled" || scenario == "startup error" {
				wantNext = 1
			}
			if scenario == "midstream error" {
				wantNext = 2
			}
			if state.next != wantNext {
				t.Fatalf("Next called %d times, want %d", state.next, wantNext)
			}
			if scenario == "startup error" && recorder.Code != http.StatusInternalServerError {
				t.Fatalf("startup error returned HTTP %d: %s", recorder.Code, recorder.Body.String())
			}
			if scenario == "canceled" && !state.sawCancellation {
				t.Fatal("stream did not receive request cancellation")
			}
			if scenario == "exhausted" && recorder.Body.String() != "\"output\"\n" {
				t.Fatalf("unexpected stream body: %s", recorder.Body.String())
			}
		})
	}
}
