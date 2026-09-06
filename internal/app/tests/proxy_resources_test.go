// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestProxyConnectionsReleasedOnReloadAndClose(t *testing.T) {
	for _, operation := range []string{"reload", "close"} {
		t.Run(operation, func(t *testing.T) {
			closed := make(chan struct{}, 10)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closed <- struct{}{}
				}
			}
			upstream.Start()
			defer upstream.Close()
			files := map[string]string{"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")
app = ace.app("testApp", routes = [ace.proxy("/", proxy.config(%q))],
    permissions = [ace.permission("proxy.in", "config")])`, upstream.URL)}
			a, _, err := CreateTestAppPlugin(testutil.TestLogger(), files, []string{"proxy.in"},
				[]types.Permission{{Plugin: "proxy.in", Method: "config"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close() //nolint:errcheck
			request := func() {
				t.Helper()
				response := httptest.NewRecorder()
				a.ServeHTTP(response, httptest.NewRequest("GET", "http://app/test/", nil))
				if response.Code != http.StatusOK || response.Body.String() != "ok" {
					t.Fatalf("proxy response: %d %q", response.Code, response.Body.String())
				}
			}
			request()
			if operation == "reload" {
				// A rejected replacement must leave the working router usable.
				original := files["app.star"]
				files["app.star"] = "invalid syntax!"
				if _, err := a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{}); err == nil {
					t.Fatal("invalid app reload succeeded")
				}
				select {
				case <-closed:
					t.Fatal("failed reload retired the working proxy")
				default:
				}
				request()
				files["app.star"] = original
				if _, err := a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{}); err != nil {
					t.Fatal(err)
				}
			} else if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("app retained the upstream connection")
			}
			if operation == "reload" {
				request()
			}
		})
	}
}
