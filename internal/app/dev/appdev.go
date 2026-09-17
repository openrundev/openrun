// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"embed"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
)

//go:embed index_gen.go.html openrun_gen.go.html
var embedHtml embed.FS
var indexEmbed, openrunGenEmbed []byte

func init() {
	var err error
	if indexEmbed, err = embedHtml.ReadFile(apptype.INDEX_GEN_FILE); err != nil {
		panic(err)
	}
	if openrunGenEmbed, err = embedHtml.ReadFile(apptype.CLACE_GEN_FILE); err != nil {
		panic(err)
	}
}

// AppDev is the main object that represents a OpenRun app in dev mode. It is created when the app is loaded with is_dev true
// and handles the styling and js library related functionalities. Access to this is synced through the initMutex in App.
// The reload method in App is the main access point to this object
type AppDev struct {
	*types.Logger

	CustomLayout bool
	Config       *apptype.CodeConfig
	systemConfig *types.SystemConfig
	sourceFS     *appfs.WritableSourceFs
	workFS       *appfs.WorkFs
	AppStyle     *AppStyle

	filesDownloaded map[string][]string
	JsLibs          []types.JSLibrary
	jsCache         map[types.JSLibrary]string
}

func NewAppDev(logger *types.Logger, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs, appStyle *AppStyle, systemConfig *types.SystemConfig) *AppDev {
	dev := &AppDev{
		Logger:          logger,
		sourceFS:        sourceFS,
		workFS:          workFS,
		AppStyle:        appStyle,
		systemConfig:    systemConfig,
		filesDownloaded: make(map[string][]string),
		jsCache:         make(map[types.JSLibrary]string),
		JsLibs:          []types.JSLibrary{},
	}
	return dev
}

// downloadFile downloads the files from the url, unless it was already loaded for this app in the current
// server session.
func (a *AppDev) downloadFile(url string, appFS *appfs.WritableSourceFs, path string) error {
	var ok bool
	var alreadyDone []string
	if alreadyDone, ok = a.filesDownloaded[url]; ok {
		if slices.Contains(alreadyDone, path) {
			a.Trace().Msgf("File %s:%s already downloaded", url, path)
			return nil
		}

		a.Trace().Msgf("File %s downloaded to different path", url)
	}

	a.Info().Msgf("Downloading %s into %s", url, path)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	var buf bytes.Buffer
	if _, err = io.Copy(&buf, resp.Body); err != nil {
		return err
	}
	if err = appFS.Write(path, buf.Bytes()); err != nil {
		return err
	}
	alreadyDone = append(alreadyDone, path)
	a.filesDownloaded[url] = alreadyDone
	return nil
}

// downloadWorkFile downloads the url into the app work directory, unless it was
// already downloaded for this app in the current server session.
func (a *AppDev) downloadWorkFile(url string, path string) error {
	if alreadyDone, ok := a.filesDownloaded[url]; ok && slices.Contains(alreadyDone, path) {
		a.Trace().Msgf("File %s:%s already downloaded", url, path)
		return nil
	}

	a.Info().Msgf("Downloading %s into %s", url, path)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error downloading %s : status %d", url, resp.StatusCode)
	}

	var buf bytes.Buffer
	if _, err = io.Copy(&buf, resp.Body); err != nil {
		return err
	}
	if err = a.workFS.Write(path, buf.Bytes()); err != nil {
		return err
	}
	a.filesDownloaded[url] = append(a.filesDownloaded[url], path)
	return nil
}

// htmxSSEFileName is the path (under static/gen/lib) the generated import
// template loads the SSE extension from, for both extension generations.
const htmxSSEFileName = "sse.js"

// htmxRuntimeVersion extracts the version pinned by an htmx runtime library
// url, like https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js
var htmxRuntimeVersion = regexp.MustCompile(`htmx\.org@([^/]+)`)

// isHtmxRuntime reports whether the library url is the htmx runtime itself
// (rather than one of its extensions).
func isHtmxRuntime(url string) bool {
	return strings.Contains(url, "htmx.org") && !strings.Contains(url, "ext")
}

// htmxSSELibrary reports whether the library url is an htmx SSE extension,
// and whether it is the htmx 4 hx-sse extension (else the htmx 1/2 one).
func htmxSSELibrary(url string) (isSSE bool, isHtmx4 bool) {
	switch {
	case strings.Contains(url, "htmx.org") && strings.Contains(url, "ext/hx-sse"):
		return true, true
	case strings.Contains(url, "htmx.org") && strings.Contains(url, "ext/sse.js"),
		strings.Contains(url, "htmx-ext-sse"):
		return true, false
	}
	return false, false
}

// ResolveHtmxVersion returns the version of the htmx runtime served to the
// app: the version pinned by an explicit htmx runtime library in the app's
// libraries, else the configured one. The SSE extension and the generated
// live reload markup have to match the runtime, not the config.
func ResolveHtmxVersion(libs []types.JSLibrary, configured string) string {
	for _, lib := range libs {
		if lib.LibType != types.Library || !isHtmxRuntime(lib.DirectUrl) {
			continue
		}
		if m := htmxRuntimeVersion.FindStringSubmatch(lib.DirectUrl); m != nil {
			return m[1]
		}
	}
	return configured
}

// Htmx4 reports whether the htmx version uses the runtime, extension and
// template APIs introduced in htmx 4. A non-release version (a dist-tag like
// "latest", which npm keeps on the 2.x line) selects the htmx 1/2 APIs.
func Htmx4(version string) bool {
	major, _, _ := strings.Cut(version, ".")
	return major == "4"
}

// HtmxVersion returns the htmx runtime version served to the app.
func (a *AppDev) HtmxVersion() string {
	return ResolveHtmxVersion(a.JsLibs, a.Config.Htmx.Version)
}

// newHtmxSSELibrary returns the SSE extension matching the htmx version.
func newHtmxSSELibrary(version string) *types.JSLibrary {
	url := "https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"
	if Htmx4(version) {
		url = "https://unpkg.com/htmx.org@" + version + "/dist/ext/hx-sse.min.js"
	}
	sse := NewLibrary(url)
	sse.SanitizedFileName = htmxSSEFileName
	return sse
}

// SetupJsLibs sets up the js libraries for the app.
func (a *AppDev) SetupJsLibs() error {
	version := a.HtmxVersion()
	if version == "" || version[0] < '0' || version[0] > '9' {
		a.Warn().Msgf("htmx version %q is not a release version, using the htmx 1/2 live reload APIs", version)
	}
	hasHtmx := false
	hasHtmxSSE := false
	for i, jsLib := range a.JsLibs {
		if jsLib.LibType != types.Library {
			continue
		}
		if isHtmxRuntime(jsLib.DirectUrl) {
			hasHtmx = true
		}
		if isSSE, isHtmx4 := htmxSSELibrary(jsLib.DirectUrl); isSSE {
			hasHtmxSSE = true
			a.JsLibs[i].SanitizedFileName = htmxSSEFileName
			if isHtmx4 != Htmx4(version) {
				a.Warn().Msgf("SSE extension %s does not match htmx %s, live reload will not work", jsLib.DirectUrl, version)
			}
		}
	}
	if !hasHtmx {
		a.JsLibs = append(a.JsLibs, *NewLibrary("https://unpkg.com/htmx.org@" + version + "/dist/htmx.min.js"))
	} else {
		a.Trace().Msg("htmx already included, skipping")
	}
	if !hasHtmxSSE {
		a.JsLibs = append(a.JsLibs, *newHtmxSSELibrary(version))
	}

	for _, jsLib := range a.JsLibs {
		if _, ok := a.jsCache[jsLib]; ok {
			a.Trace().Msgf("JsLib %s already setup, skipping", jsLib)
			continue
		}

		jsLibManager := JsLibManager{jsLib}
		targetFile, err := jsLibManager.Setup(a, a.sourceFS, a.workFS)
		if err != nil {
			if targetFile == "" {
				// Setup failed and cannot check if file exists, error out
				return err
			}
			_, err2 := a.sourceFS.Stat(targetFile)
			if err2 != nil {
				// Setup failed and file does not exist, error out with original error
				return err
			}
			a.Warn().Err(err).Msgf("Error setting up %s, using existing file", targetFile)
		}
		// Cache that this lib is setup
		a.jsCache[jsLib] = targetFile
	}

	// A version change can replace a library at the same path. Do not delete
	// the replacement when evicting the previous version from the cache.
	activeTargets := make(map[string]bool, len(a.JsLibs))
	for _, lib := range a.JsLibs {
		activeTargets[a.jsCache[lib]] = true
	}
	for lib, target := range a.jsCache {
		if target != "" && (!slices.Contains(a.JsLibs[:], lib)) {
			// This lib is in the cache, but not in current list of libs. Remove it
			// from the disk and from cache.
			if !activeTargets[target] {
				a.Trace().Msgf("Removing js lib %s", target)
				if err := a.sourceFS.Remove(target); err != nil {
					a.Warn().Msgf("Error removing js lib %s : %s", target, err)
				}
			}
			delete(a.jsCache, lib)
			delete(a.filesDownloaded, lib.DirectUrl)
		}
	}

	return nil
}

// GenerateHTML generates the default HTML template files for the app.
func (a *AppDev) GenerateHTML() error {
	// The header name of contents have changed, recreate it. Since reload creates the header
	// file and updating the file causes the FS watcher to call reload, we have to make sure the
	// file is updated only if there is an actual content change
	if !a.CustomLayout {
		indexData, err := a.sourceFS.ReadFile(apptype.INDEX_GEN_FILE)
		if err != nil || !bytes.Equal(indexData, indexEmbed) {
			if err := a.sourceFS.Write(apptype.INDEX_GEN_FILE, indexEmbed); err != nil {
				return err
			}
		}
	} else {
		_, statErr := a.sourceFS.Stat(apptype.INDEX_GEN_FILE)
		if statErr == nil {
			// If generated index file exists, remove it
			if err := a.sourceFS.Remove(apptype.INDEX_GEN_FILE); err != nil {
				return err
			}
		}
	}

	// When the app has base templates (structured mode), the base template set
	// is parsed only from the base_templates folder, so the generated file must
	// live there for its definitions to be usable from the base and page
	// templates. Otherwise it lives at the app root, where the unstructured
	// template glob picks it up. The mode check ignores the generated file
	// itself, so a leftover copy in base_templates does not keep the app in
	// structured mode; the copy at the location for the other mode is removed.
	baseDir := "base_templates"
	if a.Config.Routing.BaseTemplates != "" {
		baseDir = a.Config.Routing.BaseTemplates
	}
	baseGenFile := path.Join(baseDir, apptype.CLACE_GEN_FILE)
	baseFiles, err := a.sourceFS.Glob(path.Join(baseDir, "*.go.html"))
	if err != nil {
		return err
	}
	structured := slices.ContainsFunc(baseFiles, func(file string) bool {
		return file != baseGenFile
	})

	genFile, staleGenFile := apptype.CLACE_GEN_FILE, baseGenFile
	if structured {
		genFile, staleGenFile = baseGenFile, apptype.CLACE_GEN_FILE
	}

	openrunGenData, err := a.sourceFS.ReadFile(genFile)
	if err != nil || !bytes.Equal(openrunGenData, openrunGenEmbed) {
		if err := a.sourceFS.Write(genFile, openrunGenEmbed); err != nil {
			return err
		}
	}
	if _, err := a.sourceFS.Stat(staleGenFile); err == nil {
		if err := a.sourceFS.Remove(staleGenFile); err != nil {
			return err
		}
	}

	return nil
}

func (a *AppDev) SaveConfigLockFile() error {
	buf, err := json.Marshal(a.Config, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	err = a.sourceFS.Write(apptype.CONFIG_LOCK_FILE_NAME, buf)
	return err
}

// Close the app dev session
func (a *AppDev) Close() error {
	if err := a.AppStyle.StopWatcher(); err != nil {
		a.Warn().Err(err).Msg("Error stopping watcher")
	}
	if a.workFS != nil {
		if err := a.workFS.Close(); err != nil {
			a.Warn().Err(err).Msg("Error closing work fs")
		}
	}
	return nil
}
