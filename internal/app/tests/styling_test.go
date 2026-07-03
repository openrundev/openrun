// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/app/dev"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestStyleNone(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
settings={"style":{"library": ""}})`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/gen/css/style.css", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "", response.Body.String())
}

func TestStyleOther(t *testing.T) {
	// Create a test server to serve the css file
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "mystyle contents") //nolint:errcheck
	}))
	testUrl := testServer.URL + "/static/mystyle.css"

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": fmt.Sprintf(`
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
			     style=ace.style("%s"))`, testUrl),
		"static/mystyle.css": `mystyle contents`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test/static/gen/css/style.css", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	testutil.AssertStringMatch(t, "body", "mystyle contents", response.Body.String())
}

func TestStyleTailwindCSS(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
		        style=ace.style(library="tailwindcss"))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
	`, string(data))
}

func TestStyleDaisyUI(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui"))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: emerald --default, night --prefersdark;
		}
	`, string(data))
}

func TestStyleDaisyUIThemes(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", themes=["dark", "cupcake"]))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: cupcake, dark, emerald --default, night --prefersdark;
		}
	`, string(data))
}

func TestStyleDaisyUILight(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", themes=["cupcake"], light="abc", dark="xyz"))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: abc --default, cupcake, xyz --prefersdark;
		}
	`, string(data))
}

func TestStyleDaisyUICustomThemes(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", light="mylight", dark="mydark",
					custom_themes={
						"mylight": {
							"color-scheme": "light",
							"--color-base-100": "#ffffff",
							"--color-primary": "#007700",
						},
						"mydark": {
							"color-scheme": "dark",
							"--color-base-100": "#17221a",
							"--color-primary": "#00c200",
						},
					}))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: false;
		}
		@plugin "daisyui/theme" {
		  name: "mylight";
		  default: true;
		  prefersdark: false;
		  color-scheme: light;
		  --color-base-100: #ffffff;
		  --color-primary: #007700;
		}
		@plugin "daisyui/theme" {
		  name: "mydark";
		  default: false;
		  prefersdark: true;
		  color-scheme: dark;
		  --color-base-100: #17221a;
		  --color-primary: #00c200;
		}
	`, string(data))
}

func TestStyleDaisyUICustomThemesWithBuiltin(t *testing.T) {
	// Custom themes can be mixed with bundled themes; the custom names are
	// left out of the bundled themes list
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", themes=["cupcake"], dark="mydark",
					custom_themes={
						"mydark": {
							"color-scheme": "dark",
							"--color-primary": "#00c200",
						},
					}))`,
	}

	_, workFS, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: cupcake, emerald --default;
		}
		@plugin "daisyui/theme" {
		  name: "mydark";
		  default: false;
		  prefersdark: true;
		  color-scheme: dark;
		  --color-primary: #00c200;
		}
	`, string(data))
}

func TestStyleDaisyUICustomThemesLegacyError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", custom_themes={"mytheme": {"color-scheme": "light"}}))`,
	}

	_, _, err := CreateDevModeTestAppTailwindVersion(logger, fileData, types.TailwindVersionLegacy)
	testutil.AssertErrorContains(t, err, "custom_themes require tailwind_version 4")
}

func TestStyleDaisyUIStandalonePlugin(t *testing.T) {
	// When a tailwind CLI is configured, the prebundled daisyui plugin is
	// downloaded next to input.css so no node_modules setup is required
	logger := testutil.TestLogger()
	pluginData := "// daisyui prebundled plugin"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, pluginData) //nolint:errcheck
	}))
	defer ts.Close()

	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", disable_watcher=True))`,
	}

	systemConfig := testSystemConfig()
	systemConfig.TailwindCSSCommand = "tailwindcss"
	systemConfig.DaisyUIURL = ts.URL
	_, workFS, err := CreateDevModeTestAppSystemConfig(logger, fileData, systemConfig)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/" + dev.DaisyUIPluginFile(ts.URL))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "daisyui plugin", pluginData, string(data))

	data, err = workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", fmt.Sprintf(`
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "./%s" {
		  themes: emerald --default, night --prefersdark;
		}
	`, dev.DaisyUIPluginFile(ts.URL)), string(data))
}

func TestStyleDaisyUIStandalonePluginDownloadFail(t *testing.T) {
	// If the daisyui plugin download fails, fall back to the node_modules
	// based plugin reference
	logger := testutil.TestLogger()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", disable_watcher=True))`,
	}

	systemConfig := testSystemConfig()
	systemConfig.TailwindCSSCommand = "tailwindcss"
	systemConfig.DaisyUIURL = ts.URL
	_, workFS, err := CreateDevModeTestAppSystemConfig(logger, fileData, systemConfig)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", `
		@import "tailwindcss" source(none);
		@source "action/*.go.html";
		@source "*.go.html";
		@source "base_templates/*.go.html";
		@source "static/*.js";
		@plugin "daisyui" {
		  themes: emerald --default, night --prefersdark;
		}
	`, string(data))
}

func TestStyleDaisyUILegacyTailwindVersion(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
				style=ace.style(library="daisyui", themes=["dark", "cupcake"]))`,
	}

	_, workFS, err := CreateDevModeTestAppTailwindVersion(logger, fileData, types.TailwindVersionLegacy)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	data, err := workFS.ReadFile("style/input.css")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "input.css", "@tailwind base; @tailwind components; @tailwind utilities;", string(data))

	data, err = workFS.ReadFile("style/tailwind.config.js")
	testutil.AssertNoError(t, err)
	testutil.AssertStringMatch(t, "tailwind.config.js", `module.exports = { content: ['action/*.go.html', '*.go.html', 'base_templates/*.go.html', 'static/*.js'], theme: { extend: {}, }, plugins: [ require("daisyui") ], daisyui: { themes: ["cupcake", "dark", "emerald", "night"], }, }`, string(data))
}

func TestStyleCustom(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=False, routes = [ace.html("/")])`,
		"static/css/style.css": "body { background-color: red; }",
		"app.go.html":          `{{block "openrun_body" .}}ABC{{end}}`,
	}

	a, _, err := CreateDevModeTestApp(logger, fileData)
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)
	// Since custom style static/css/style.css is present, that should be included in the header
	testutil.AssertStringContains(t, response.Body.String(),
		`<link rel="stylesheet" href="/test/static/css/style-ac05e05bbc5e5410e5c9e7531bbd20c45803d479bb10e5a6e9d3c61d40e3e811.css" />`)
}

func TestStyleError(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.html("/")],
                style=ace.style(library="unknown"))`,
	}

	_, _, err := CreateDevModeTestApp(logger, fileData)
	testutil.AssertErrorContains(t, err, "invalid style library config : unknown")
}
