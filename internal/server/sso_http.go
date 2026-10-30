// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ssoMaxRedirects bounds the redirects an IdP fetch follows. Each hop is
// dialed through the same guarded transport, so the private address check
// applies to it; a downgrade from https to http is refused at any hop
const ssoMaxRedirects = 3

// ssoHTTPClient builds the client for the fetches an [auth.*] (OIDC) or
// [saml.*] entry causes: the discovery document or IdP metadata, and for
// OIDC the JWKS, token and userinfo calls. Those urls can be set dynamically
// by config:update holders, so unless security.sso_allow_private_hosts is
// set the client refuses loopback, private and link-local targets (cloud
// metadata included) after DNS resolution, through HTTPS_PROXY as well.
// what names the fetch in errors; timeout bounds each request
func ssoHTTPClient(what string, allowPrivate bool, timeout time.Duration) *http.Client {
	newTransport := func(proxy func(*http.Request) (*url.URL, error),
		control func(network, address string, c syscall.RawConn) error) *http.Transport {
		dialer := &net.Dialer{Timeout: timeout, Control: control}
		return &http.Transport{
			DialContext:           dialer.DialContext,
			Proxy:                 proxy,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	var transport http.RoundTripper
	if allowPrivate {
		transport = newTransport(http.ProxyFromEnvironment, nil)
	} else {
		transport = system.NewPublicOnlyTransport(what, http.ProxyFromEnvironment, newTransport)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > ssoMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", ssoMaxRedirects)
			}
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect from https to %s refused", req.URL.Scheme)
			}
			return nil
		},
	}
}

// ssoAllowPrivateHosts reads security.sso_allow_private_hosts, a static
// setting, from the startup config (nil in some unit tests: refuse)
func ssoAllowPrivateHosts(config *types.ServerConfig) bool {
	return config != nil && config.Security.SSOAllowPrivateHosts
}
