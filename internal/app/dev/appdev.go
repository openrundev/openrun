// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"context"
	"embed"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"golang.org/x/net/idna"
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

const (
	downloadAttempts = 3
	downloadTimeout  = 30 * time.Second
	// downloadMaxBytes caps a downloaded library or stylesheet
	downloadMaxBytes     = 128 << 20
	downloadMaxRedirects = 5
)

// The download transports, package vars so that tests can stub them. Both use
// the proxy from the server's environment (HTTPS_PROXY, NO_PROXY), set by the
// operator. appDownloadTransport fetches the urls named by app code (the
// style library and the js libraries): a direct connection must be to a
// public address, checked after DNS resolution on every connection including
// redirect hops; a proxied request is refused when its host is, or resolves
// here to, a private address, the proxy's egress policy covering the rest.
// serverDownloadTransport fetches the urls from the server config
// (daisyui_url), which may name an internal mirror
var (
	appDownloadTransport    http.RoundTripper = newAppDownloadTransport(http.ProxyFromEnvironment)
	serverDownloadTransport http.RoundTripper = newDownloadTransport(http.ProxyFromEnvironment, nil)
)

func newDownloadTransport(proxy func(*http.Request) (*url.URL, error),
	control func(network, address string, c syscall.RawConn) error) *http.Transport {
	dialer := &net.Dialer{Timeout: downloadTimeout, Control: control}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		Proxy:                 proxy,
		TLSHandshakeTimeout:   downloadTimeout,
		ResponseHeaderTimeout: downloadTimeout,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
	}
}

// appDownloads routes each request (each redirect hop is a separate request)
// to one of two transports, so that whether a connection is checked is fixed
// by the transport making it, not by state shared between requests. direct
// never uses a proxy and dials public addresses only. proxied dials only the
// proxy, which may be on a private address: its Proxy function fails a
// request the proxy does not apply to instead of letting it dial direct
type appDownloads struct {
	proxy   func(*http.Request) (*url.URL, error)
	direct  *http.Transport
	proxied *http.Transport
}

func newAppDownloadTransport(proxy func(*http.Request) (*url.URL, error)) *appDownloads {
	a := &appDownloads{proxy: proxy}
	a.direct = newDownloadTransport(nil, system.PublicOnlyDialControl("download"))
	a.proxied = newDownloadTransport(func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if err == nil && proxyURL == nil {
			err = fmt.Errorf("download of %s is not proxied", req.URL.Host)
		}
		return proxyURL, err
	}, nil)
	return a
}

func (a *appDownloads) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := a.proxy(req)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return a.direct.RoundTrip(req)
	}
	// The proxy dials the target, the host is checked here, as the transport
	// sends it, so a fullwidth １０.１.２.３ is checked as 10.1.2.3
	if err := system.CheckPublicHost(req.Context(), "download", canonicalHost(req.URL)); err != nil {
		return nil, err
	}
	return a.proxied.RoundTrip(req)
}

// canonicalHost is u's host as net/http sends it in a proxy CONNECT (its
// canonicalAddr): a non-ASCII host is mapped through IDNA, so a fullwidth
// １２７.０.０.１ becomes 127.0.0.1
func canonicalHost(u *url.URL) string {
	host := u.Hostname()
	if !isASCII(host) {
		if v, err := idna.Lookup.ToASCII(host); err == nil {
			host = v
		}
	}
	return host
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// AllowPrivateDownloadsForTest lets the app download transport reach local
// test servers, returning the function restoring the guarded transport
func AllowPrivateDownloadsForTest() func() {
	old := appDownloadTransport
	appDownloadTransport = newDownloadTransport(http.ProxyFromEnvironment, nil)
	return func() { appDownloadTransport = old }
}

// checkDownloadRedirect follows a few redirects (CDN and GitHub release
// urls redirect to their storage hosts); each hop is dialed through the
// same transport, so the public address check applies to it. A downgrade
// from https to http is refused at any hop. via holds the requests made so
// far, the original one included, so len(via) is the number of this redirect
func checkDownloadRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > downloadMaxRedirects {
		return fmt.Errorf("stopped after %d redirects", downloadMaxRedirects)
	}
	if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect from https to %s refused", req.URL.Scheme)
	}
	return nil
}

// fetchUrl downloads a url, retrying a transient failure (a connection or
// TLS handshake error, a timeout, a 5xx or 429 response) a few times with a
// backoff, so that a brief CDN hiccup does not fail the app load. A 4xx
// response is returned at once
func fetchUrl(transport http.RoundTripper, url string) ([]byte, error) {
	client := &http.Client{Transport: transport, CheckRedirect: checkDownloadRedirect}
	var lastErr error
	for attempt := 1; attempt <= downloadAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * time.Second)
		}
		data, retry, err := fetchUrlOnce(client, url)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, lastErr
}

// fetchUrlOnce is one attempt of fetchUrl; retry reports whether the
// failure is worth another attempt
func fetchUrlOnce(client *http.Client, url string) (data []byte, retry bool, err error) {
	// The timeout bounds the whole attempt
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// A refused address fails the same way on every attempt
		return nil, !errors.Is(err, system.ErrPrivateAddress), err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		retry = resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests
		return nil, retry, fmt.Errorf("error downloading %s : status %d", url, resp.StatusCode)
	}
	if data, err = io.ReadAll(io.LimitReader(resp.Body, downloadMaxBytes+1)); err != nil {
		return nil, true, err
	}
	if len(data) > downloadMaxBytes {
		return nil, false, fmt.Errorf("error downloading %s : larger than %d bytes", url, downloadMaxBytes)
	}
	return data, false, nil
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

	// The url comes from app code
	data, err := fetchUrl(appDownloadTransport, url)
	if err != nil {
		return err
	}
	if err = appFS.Write(path, data); err != nil {
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

	// The url comes from the server config (daisyui_url)
	data, err := fetchUrl(serverDownloadTransport, url)
	if err != nil {
		return err
	}
	if err = a.workFS.Write(path, data); err != nil {
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
