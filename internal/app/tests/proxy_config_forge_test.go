// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// The proxy route config has to be the result of the proxy.config plugin
// call: a struct built by the app with the same attributes has not gone
// through the plugin permission check and is refused
func TestProxyConfigForgedStructRefused(t *testing.T) {
	var hits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer upstream.Close()

	fileData := map[string]string{
		"schema.star": `
type("PR", fields=[field("error", STRING), field("value", STRING)])
type("PC", fields=[field("url", STRING), field("preserve_host", BOOLEAN), field("strip_app", BOOLEAN),
	field("strip_path", STRING), field("response_headers", DICT)])`,
		"app.star": fmt.Sprintf(`
pc = doc.PC(url=%q, preserve_host=False, strip_app=True, strip_path="", response_headers={})
cfg = doc.PR(error="", value="")
cfg.value = pc
app = ace.app("testApp", routes = [ace.proxy("/", cfg)])`, upstream.URL),
	}
	handler, _, err := CreateTestAppPlugin(testutil.TestLogger(), fileData, []string{}, []types.Permission{}, map[string]types.PluginSettings{})
	if err == nil {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/test/abc", nil))
		if response.Code == http.StatusOK {
			t.Fatalf("forged proxy config was served, upstream hits %d", hits)
		}
	} else {
		testutil.AssertStringContains(t, err.Error(), "has to be the value returned by proxy.config")
	}
	if hits != 0 {
		t.Fatalf("forged proxy config reached the upstream %d times", hits)
	}
}

// The result of proxy.config is read only: the url cannot be changed after
// the permission check on the call
func TestProxyConfigMutationRefused(t *testing.T) {
	var approvedHits, otherHits int
	approved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		approvedHits++
	}))
	defer approved.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits++
	}))
	defer other.Close()

	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
load("proxy.in", "proxy")

cfg = proxy.config(%q)
cfg.value.url = %q
app = ace.app("testApp", routes = [ace.proxy("/", cfg)],
permissions=[
	ace.permission("proxy.in", "config", [%q]),
]
)`, approved.URL, other.URL, approved.URL),
	}
	handler, _, err := CreateTestAppPlugin(testutil.TestLogger(), fileData, []string{"proxy.in"},
		[]types.Permission{{Plugin: "proxy.in", Method: "config", Arguments: []string{approved.URL}}}, map[string]types.PluginSettings{})
	if err == nil {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/test/abc", nil))
	} else {
		testutil.AssertStringContains(t, err.Error(), "read only")
	}
	if otherHits != 0 {
		t.Fatalf("the unapproved url was proxied to %d times", otherHits)
	}
}
