// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
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
	"golang.org/x/net/http/httpguts"
)

const (
	ApplicationJson        = "application/json"
	OpenRunServiceLocation = "openrun"
)

type HttpClient struct {
	client     *http.Client
	serverUri  string
	displayUri string // the configured server uri (socket path or url), for messages
	apiKey     string
	headers    map[string]string // extra headers sent with every request
}

// NewHttpClient creates a new HttpClient instance. apiKey is the bearer
// credential for remote (TCP) servers; over the unix domain socket no
// credential is needed (filesystem permissions authenticate the caller)
func NewHttpClient(serverUri, apiKey string, skipCertCheck bool) *HttpClient {
	serverUri = os.ExpandEnv(serverUri)
	displayUri := serverUri

	// Change to OPENRUN_HOME directory, helps avoid length limit on UDS file (around 104 chars).
	// If the directory does not exist (server never started), skip the chdir and
	// use the absolute socket path; the connection failure is reported by the caller
	clHome := os.Getenv("OPENRUN_HOME")
	if clHome != "" {
		if err := os.Chdir(clHome); err != nil {
			clHome = ""
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
		client:     client,
		serverUri:  serverUri,
		displayUri: displayUri,
		apiKey:     apiKey,
	}
}

// NewPlainHttpClient returns a plain *http.Client for direct requests
// (well-known metadata fetches), honoring skip_cert_check
func NewPlainHttpClient(skipCertCheck bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: skipCertCheck}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// CloseIdleConnections releases pooled connections when the client is no longer needed.
func (h *HttpClient) CloseIdleConnections() {
	h.client.CloseIdleConnections()
}

// SetHeader adds a header sent with every request made by this client
func (h *HttpClient) SetHeader(name, value string) {
	if h.headers == nil {
		h.headers = map[string]string{}
	}
	h.headers[name] = value
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

// PostRaw sends a POST with the given body and returns the raw response, for
// APIs whose response is not a single JSON document (an action result can be
// a stream, with the exit status in a trailer). No overall timeout applies:
// the response is read for as long as the server keeps producing it, cancel
// through ctx. The caller closes the response body
func (h *HttpClient) PostRaw(ctx context.Context, apiPath string, params url.Values, contentType string, body io.Reader) (*http.Response, error) {
	return h.rawRequest(ctx, http.MethodPost, apiPath, params, contentType, body)
}

// GetRaw sends a GET and returns the raw response, see PostRaw (a file download)
func (h *HttpClient) GetRaw(ctx context.Context, apiPath string, params url.Values) (*http.Response, error) {
	return h.rawRequest(ctx, http.MethodGet, apiPath, params, "", nil)
}

func (h *HttpClient) rawRequest(ctx context.Context, method, apiPath string, params url.Values, contentType string, body io.Reader) (*http.Response, error) {
	u, err := url.Parse(h.serverUri)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	if h.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+h.apiKey)
	}
	for name, value := range h.headers {
		request.Header.Set(name, value)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	streamClient := *h.client
	streamClient.Timeout = 0
	resp, err := streamClient.Do(request)
	if err != nil {
		return nil, h.transportError(err)
	}
	return resp, nil
}

// IsRemote reports whether the client talks to a TCP server (http/https)
// rather than the trusted unix domain socket
func (h *HttpClient) IsRemote() bool {
	return strings.HasPrefix(h.displayUri, "http://") || strings.HasPrefix(h.displayUri, "https://")
}

// ResponseError turns a non-success response of the management API into
// the error the CLI reports. All response error handling goes through here
// so every command gets the same message shape: the server's structured
// error when the body is one (RequestError, or an {"error": ...} document),
// the body text otherwise, with a hint added for the statuses where the
// client knows what to do about it (401: how to provide a credential)
func (h *HttpClient) ResponseError(status int, body []byte) error {
	text := strings.TrimSpace(string(body))
	if status == http.StatusUnauthorized && h.IsRemote() {
		return h.unauthorizedError(text)
	}
	var reqErr types.RequestError
	if json.Unmarshal(body, &reqErr) == nil && (reqErr.Code != 0 || reqErr.Message != "") {
		if reqErr.Code == 0 {
			reqErr.Code = status
		}
		return reqErr
	}
	var doc struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &doc) == nil && doc.Error != "" {
		return types.RequestError{Code: status, Message: doc.Error}
	}
	if text == "" {
		text = http.StatusText(status)
	}
	return types.RequestError{Code: status, Message: text}
}

// unauthorizedError explains a 401 from a remote server: the server body is a
// bare "Unauthorized", which does not tell the user whether no credential was
// sent or the one sent was rejected
func (h *HttpClient) unauthorizedError(body string) types.RequestError {
	if h.apiKey == "" {
		return types.RequestError{Code: http.StatusUnauthorized, Message: fmt.Sprintf(
			"Unauthorized: no credential for %s. Run 'openrun login --server %s', or set OPENRUN_API_KEY (or client.api_key) to a key from 'openrun apikey create'",
			h.displayUri, h.displayUri)}
	}
	detail := ""
	if body != "" && body != "Unauthorized" {
		detail = " (" + body + ")"
	}
	return types.RequestError{Code: http.StatusUnauthorized, Message: fmt.Sprintf(
		"Unauthorized: %s rejected the credential%s. The login or api key may be expired or revoked: run 'openrun login --server %s' again or check OPENRUN_API_KEY / client.api_key",
		h.displayUri, detail, h.displayUri)}
}

// transportError explains a request that got no response: a server that is
// not running (unix socket) or not reachable, or a TLS certificate the client
// does not trust. The Go error text ('Get "http+unix://openrun/...": dial
// unix ...') names internals the user never configured, so the message is
// rebuilt around the configured server uri
func (h *HttpClient) transportError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		if !h.IsRemote() {
			return fmt.Errorf("cannot connect to the openrun server at %s: %w. Is the server running? Start it with 'openrun server start'", h.displayUri, err)
		}
		return fmt.Errorf("cannot connect to %s: %w", h.displayUri, err)
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return fmt.Errorf("cannot verify the certificate of %s: %w. For a self-signed certificate set client.skip_cert_check = true", h.displayUri, err)
	}
	return fmt.Errorf("request to %s failed: %w", h.displayUri, err)
}

func (h *HttpClient) request(method, apiPath string, params url.Values, input any, output any) error {
	var resp *http.Response
	var payloadBuf bytes.Buffer

	if input != nil {
		if err := json.MarshalWrite(&payloadBuf, input); err != nil {
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

	if h.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+h.apiKey)
	}
	request.Header.Set("Accept", ApplicationJson)
	for name, value := range h.headers {
		request.Header.Set(name, value)
	}

	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		request.Header.Set("Content-Type", ApplicationJson)
	}

	resp, err = h.client.Do(request)
	if err != nil {
		return h.transportError(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return h.ResponseError(resp.StatusCode, errBody)
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if output != nil {
		if err := json.UnmarshalRead(resp.Body, output); err != nil {
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

// ValidHostHeader reports whether host is well-formed enough to be used as an
// HTTP Host value. Empty is rejected — OpenRun's TCP router and app proxying
// always require a concrete authority.
func ValidHostHeader(host string) bool {
	return host != "" && httpguts.ValidHostHeader(host)
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
