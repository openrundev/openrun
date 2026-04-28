// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

const (
	ApplicationJson        = "application/json"
	OpenRunServiceLocation = "openrun"
)

type HttpClient struct {
	client    *http.Client
	serverUri string
	user      string
	password  string
}

// NewHttpClient creates a new HttpClient instance
func NewHttpClient(serverUri, user, password string, skipCertCheck bool) *HttpClient {
	serverUri = os.ExpandEnv(serverUri)

	// Change to OPENRUN_HOME directory, helps avoid length limit on UDS file (around 104 chars)
	clHome := os.Getenv("OPENRUN_HOME")
	if clHome != "" {
		err := os.Chdir(clHome)
		if err != nil {
			return nil
		}
	}

	var client *http.Client
	if !strings.HasPrefix(serverUri, "http://") && !strings.HasPrefix(serverUri, "https://") {
		if clHome != "" && strings.HasPrefix(serverUri, clHome) {
			serverUri = path.Join(".", serverUri[len(clHome):]) // use relative path
		}

		transport := &Transport{}
		// Using unix domain sockets
		transport.RegisterLocation(OpenRunServiceLocation, serverUri)
		t := &http.Transport{}
		t.RegisterProtocol(Scheme, transport)
		client = &http.Client{
			Transport: transport,
			Timeout:   time.Duration(180) * time.Second,
		}

		serverUri = fmt.Sprintf("%s://%s", Scheme, OpenRunServiceLocation)
	} else {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: skipCertCheck}
		customTransport.MaxIdleConns = 500
		customTransport.MaxIdleConnsPerHost = 500
		client = &http.Client{
			Transport: customTransport,
			Timeout:   time.Duration(180) * time.Second,
		}
	}

	return &HttpClient{
		client:    client,
		serverUri: serverUri,
		user:      user,
		password:  password,
	}
}

func (h *HttpClient) Get(url string, params url.Values, output any) error {
	return h.request(http.MethodGet, url, params, nil, output)
}

func (h *HttpClient) Post(url string, params url.Values, input any, output any) error {
	return h.request(http.MethodPost, url, params, input, output)
}

func (h *HttpClient) Put(url string, params url.Values, input any, output any) error {
	return h.request(http.MethodPut, url, params, input, output)
}

func (h *HttpClient) Delete(url string, params url.Values, output any) error {
	return h.request(http.MethodDelete, url, params, nil, output)
}

func (h *HttpClient) request(method, apiPath string, params url.Values, input any, output any) error {
	var resp *http.Response
	var payloadBuf bytes.Buffer

	if input != nil {
		if err := json.NewEncoder(&payloadBuf).Encode(input); err != nil {
			return fmt.Errorf("error encoding request: %w", err)
		}
	}

	u, err := url.Parse(h.serverUri)
	if err != nil {
		return err
	}

	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	request, err := http.NewRequest(method, u.String(), &payloadBuf)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	request.SetBasicAuth(h.user, h.password)
	request.Header.Set("Accept", ApplicationJson)

	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		request.Header.Set("Content-Type", ApplicationJson)
	}

	resp, err = h.client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var errResp types.RequestError
		parseErr := json.Unmarshal(errBody, &errResp)
		if parseErr != nil || errResp.Code == 0 {
			errResp.Code = resp.StatusCode
			errResp.Message = string(errBody)
		}
		return errResp
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return fmt.Errorf("error parsing response: %w", err)
		}
	}
	return nil
}

func MapServerHost(host string) string {
	if host == "0.0.0.0" {
		return ""
	}
	return host
}

// GetRequestScheme returns "https" if the request was received over TLS locally,
// or if the direct peer is listed in trustedProxies and set X-Forwarded-Proto: https.
// Otherwise it returns "http". Only the first value of X-Forwarded-Proto is honored
// and only when the direct peer is a trusted proxy.
func GetRequestScheme(r *http.Request, trustedProxies []string) string {
	if r != nil && r.TLS != nil {
		return "https"
	}

	if r == nil {
		return "http"
	}

	peerIP := parseIPValue(r.RemoteAddr)
	if peerIP != nil && isTrustedProxy(peerIP, trustedProxies) {
		forwarded := r.Header.Get("X-Forwarded-Proto")
		if forwarded != "" {
			// When a request traverses multiple proxies the header can be a
			// comma-separated list like "https, http"; the leftmost value is
			// the client-facing scheme. SplitN with n=2 avoids scanning the
			// full string when there are many hops.
			proto := strings.ToLower(strings.TrimSpace(strings.SplitN(forwarded, ",", 2)[0]))
			if proto == "https" || proto == "http" {
				return proto
			}
		}
	}

	return "http"
}

// IsOrigRequestHTTPS reports whether the request is (or originally came in as) HTTPS,
// honoring X-Forwarded-Proto only when the direct peer is a trusted proxy.
func IsOrigRequestHTTPS(r *http.Request, trustedProxies []string) bool {
	return GetRequestScheme(r, trustedProxies) == "https"
}

func GetRequestUrl(r *http.Request, trustedProxies []string) string {
	ret := strings.Builder{}
	ret.WriteString(GetRequestScheme(r, trustedProxies))
	ret.WriteString("://")
	if r.Host == "" {
		ret.WriteString(r.URL.Host)
	} else {
		ret.WriteString(r.Host)
	}
	ret.WriteString(r.URL.RequestURI())
	return ret.String()
}

// GetHostname returns the hostname portion of an HTTP host header, handling
// hostnames, IPv4 addresses, and bracketed or bare IPv6 literals.
func GetHostname(host string) string {
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(parsedHost, "[]")
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.Trim(host, "[]")
	}

	if strings.Count(host, ":") > 1 {
		return strings.Trim(host, "[]")
	}

	return host
}

// GetClientIP returns the caller IP, honoring forwarding headers only when the
// direct peer is explicitly configured as a trusted proxy.
func GetClientIP(r *http.Request, trustedProxies []string) string {
	peerIP := parseIPValue(r.RemoteAddr)
	if peerIP == nil {
		return ""
	}

	if !isTrustedProxy(peerIP, trustedProxies) {
		return peerIP.String()
	}

	if forwardedIP := forwardedClientIP(r.Header.Values("X-Forwarded-For"), trustedProxies); forwardedIP != nil {
		return forwardedIP.String()
	}

	if realIP := parseIPValue(r.Header.Get("X-Real-IP")); realIP != nil {
		return realIP.String()
	}

	return peerIP.String()
}

func forwardedClientIP(values []string, trustedProxies []string) net.IP {
	var parsed []net.IP
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if ip := parseIPValue(part); ip != nil {
				parsed = append(parsed, ip)
			}
		}
	}

	for i := len(parsed) - 1; i >= 0; i-- {
		if !isTrustedProxy(parsed[i], trustedProxies) {
			return parsed[i]
		}
	}
	if len(parsed) == 0 {
		return nil
	}
	return parsed[0]
}

func isTrustedProxy(ip net.IP, trustedProxies []string) bool {
	if ip == nil {
		return false
	}

	for _, entry := range trustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if proxyIP := net.ParseIP(entry); proxyIP != nil && proxyIP.Equal(ip) {
			return true
		}

		_, network, err := net.ParseCIDR(entry)
		if err == nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

func parseIPValue(value string) net.IP {
	value = strings.TrimSpace(strings.Trim(value, `"`))
	if value == "" {
		return nil
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else {
		value = strings.Trim(value, "[]")
	}

	return net.ParseIP(value)
}
