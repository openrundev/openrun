// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Based on code from https://github.com/qri-io/starlib/blob/master/http/http.go

package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

// Encodings for form data.
//
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
const (
	formEncodingMultipart = "multipart/form-data"
	formEncodingURL       = "application/x-www-form-urlencoded"
	defaultTimeoutSeconds = 300
)

func init() {
	app.RegisterLocalProvider("http", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"http": {
				Builder: NewHttpModule,
				Functions: []sdk.FuncDef{
					{Name: "get", Type: sdk.READ, Method: "Get"},
					{Name: "head", Type: sdk.READ, Method: "Head"},
					{Name: "options", Type: sdk.READ, Method: "Options"},
					{Name: "post", Type: sdk.WRITE, Method: "Post"},
					{Name: "put", Type: sdk.WRITE, Method: "Put"},
					{Name: "delete", Type: sdk.WRITE, Method: "Delete"},
					{Name: "patch", Type: sdk.WRITE, Method: "Patch"},
					// internal: backs response.body() and response.json(),
					// callable only through the returned func refs
					{Name: "_read_body", Type: sdk.READ, Method: "ReadBody"},
				},
			},
		},
	}, app.LocalProviderOptions{})
}

type httpModule struct {
	client      *http.Client
	respCounter atomic.Uint64
}

// openResponse is an HTTP response held open in the session: the body is
// read only when the app calls response.body() or response.json(), and an
// unread body is closed by the session cleanup at request end.
type openResponse struct {
	res    *http.Response
	cancel context.CancelFunc
}

func (o *openResponse) close() error {
	var err error
	if o.res.Body != nil {
		err = o.res.Body.Close()
	}
	if o.cancel != nil {
		o.cancel()
	}
	return err
}

func NewHttpModule() sdk.Module {
	return &httpModule{}
}

func (h *httpModule) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	h.client = http.DefaultClient
	return nil
}

func (h *httpModule) Close(ctx context.Context) error {
	return nil
}

func (h *httpModule) Get(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "get")
}

func (h *httpModule) Head(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "head")
}

func (h *httpModule) Options(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "options")
}

func (h *httpModule) Post(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "post")
}

func (h *httpModule) Put(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "put")
}

func (h *httpModule) Delete(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "delete")
}

func (h *httpModule) Patch(ctx context.Context, call *sdk.Call) (any, error) {
	return h.request(ctx, call, "patch")
}

func (h *httpModule) request(ctx context.Context, call *sdk.Call, method string) (any, error) {
	var rawurl, body, formEncoding string
	var params, headers, formBody, signAuth map[string]any
	var jsonBody, basicAuth any
	errorOnFail := true
	timeout := int64(defaultTimeoutSeconds)

	if err := sdk.UnpackArgs(method, call, "url", &rawurl, "params?", &params, "headers?",
		&headers, "body?", &body, "form_body?", &formBody, "form_encoding?", &formEncoding,
		"json_body?", &jsonBody, "auth_basic?", &basicAuth, "auth_signature?", &signAuth,
		"error_on_fail?", &errorOnFail, "timeout?", &timeout); err != nil {
		return nil, err
	}

	if strings.HasPrefix(rawurl, apptype.CONTAINER_URL) {
		// If the url starts with the container url, we need to replace it with
		// the container proxy url. The proxy url is host-process state, so
		// container calls work with the compiled-in http plugin only
		rawurl = strings.TrimPrefix(rawurl, apptype.CONTAINER_URL)
		var containerProxyUrl string
		if call.Host != nil {
			containerProxyUrl, _ = call.Host.Value(types.TL_CONTAINER_URL).(string)
		}
		if containerProxyUrl == "" {
			return nil, fmt.Errorf("container proxy url not set")
		}
		rawurl = containerProxyUrl + rawurl
	}

	if err := setQueryParams(&rawurl, params); err != nil {
		return nil, err
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be a positive integer number of seconds")
	}

	// The response body may be read by a later response.body() call, so the
	// timeout context must outlive this call: it hangs off the session
	// context (alive until request end), not the per-call context
	requestCtx, cancel := context.WithTimeout(call.Session.Context(), time.Duration(timeout)*time.Second)
	cancelOnError := true
	defer func() {
		if cancelOnError {
			cancel()
		}
	}()
	req, err := http.NewRequestWithContext(requestCtx, strings.ToUpper(method), rawurl, nil)
	if err != nil {
		return nil, err
	}

	if err = setHeaders(req, headers); err != nil {
		return nil, err
	}
	if err = setBasicAuth(req, basicAuth); err != nil {
		return nil, err
	}

	if err = setBody(req, body, formBody, formEncoding, jsonBody); err != nil {
		return nil, err
	}

	if len(signAuth) > 0 {
		if err = setSignAuth(req, signAuth); err != nil {
			return nil, err
		}
	}

	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}

	if errorOnFail && (res.StatusCode < 200 || res.StatusCode >= 300) { // 1xx and 3xx are also failed by default
		res.Body.Close() //nolint:errcheck
		return nil, fmt.Errorf("http request failed with status code %d: %s", res.StatusCode, res.Status)
	}

	// The body stays unread: response.body() and response.json() are func
	// refs into _read_body, which reads it lazily from the session-held
	// response. An unread body is closed by the session cleanup at request
	// end (so a status-only request to a streaming endpoint does not block)
	handleId := fmt.Sprintf("httpresp_%d", h.respCounter.Add(1))
	open := &openResponse{res: res, cancel: cancel}
	call.Session.Set(handleId, open)
	call.Session.Defer(handleId, false, func(ctx context.Context) error {
		return open.close()
	})
	cancelOnError = false

	responseHeaders := make(map[string]string, len(res.Header))
	for key, vals := range res.Header {
		responseHeaders[key] = strings.Join(vals, ",")
	}

	return &sdk.Struct{Fields: map[string]any{
		"url":         res.Request.URL.String(),
		"status_code": int64(res.StatusCode),
		"headers":     responseHeaders,
		"encoding":    strings.Join(res.TransferEncoding, ","),

		"body": &sdk.FuncRef{Function: "_read_body", Args: []any{handleId, "text"}},
		"json": &sdk.FuncRef{Function: "_read_body", Args: []any{handleId, "json"}},
	}}, nil
}

// ReadBody backs the response.body() and response.json() func refs: it reads
// the session-held response body (once; the data is cached in the session
// for repeated calls), closes it, and returns the text or parsed JSON.
func (h *httpModule) ReadBody(ctx context.Context, call *sdk.Call) (any, error) {
	var handleId, mode string
	if err := sdk.UnpackArgs("_read_body", call, "handle", &handleId, "mode", &mode); err != nil {
		return nil, err
	}

	dataKey := handleId + "_data"
	data, ok := call.Session.Get(dataKey).([]byte)
	if !ok {
		open, ok := call.Session.Get(handleId).(*openResponse)
		if !ok {
			return nil, fmt.Errorf("http response is no longer available")
		}
		var err error
		data, err = io.ReadAll(open.res.Body)
		closeErr := open.close()
		call.Session.ClearDefer(handleId)
		call.Session.Set(handleId, nil)
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		call.Session.Set(dataKey, data)
	}

	if mode == "json" {
		var parsed any
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}
	return string(data), nil
}

func setQueryParams(rawurl *string, params map[string]any) error {
	if len(params) == 0 {
		return nil
	}

	u, err := url.Parse(*rawurl)
	if err != nil {
		return err
	}

	q := u.Query()
	for key, val := range params {
		valstr, ok := val.(string)
		if !ok {
			return fmt.Errorf("expected param value for key '%s' to be a string. got: '%T'", key, val)
		}
		q.Set(key, valstr)
	}
	if q.Encode() != "" {
		u.RawQuery = q.Encode()
	}
	*rawurl = u.String()
	return nil
}

func setBasicAuth(req *http.Request, auth any) error {
	if auth == nil {
		return nil
	}
	tuple, ok := auth.(sdk.Tuple)
	if !ok {
		return fmt.Errorf("expected two values for auth params tuple")
	}
	if len(tuple) != 2 {
		return fmt.Errorf("expected two values for auth params tuple")
	}
	username, ok := tuple[0].(string)
	if !ok {
		return fmt.Errorf("parsing auth username string: expected string, got %T", tuple[0])
	}
	password, ok := tuple[1].(string)
	if !ok {
		return fmt.Errorf("parsing auth password string: expected string, got %T", tuple[1])
	}
	req.SetBasicAuth(username, password)
	return nil
}

func getKeyAsString(dict map[string]any, key string) (string, error) {
	val, ok := dict[key]
	if !ok {
		return "", fmt.Errorf("key %s not found", key)
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("key %s is not a string", key)
	}
	return s, nil
}

func setSignAuth(req *http.Request, auth map[string]any) error {
	signType, err := getKeyAsString(auth, "type")
	if err != nil {
		return err
	}
	userId, err := getKeyAsString(auth, "user")
	if err != nil {
		return err
	}
	apiKey, err := getKeyAsString(auth, "api_key")
	if err != nil {
		return err
	}

	var authHeaders map[string]string
	switch signType {
	case "SL":
		authHeaders, err = createSLAuthHeader(req, userId, apiKey)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown auth type: %s", signType)
	}
	for key, val := range authHeaders {
		req.Header.Set(key, val)
	}
	return nil
}

func createSLAuthHeader(req *http.Request, userId, apiKey string) (map[string]string, error) {
	parsedUrl, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(parsedUrl.Host)
	if err != nil {
		host = parsedUrl.Host
	}
	pathQS := parsedUrl.Path
	if parsedUrl.RawQuery != "" {
		pathQS = fmt.Sprintf("%s?%s", pathQS, parsedUrl.RawQuery)
	}

	if strings.Contains(host, ":") {
		// If IPv6 address, unescape the % chars if present and add square brackets
		unescapedHost, err := url.PathUnescape(host)
		if err != nil {
			return nil, err
		}

		host = fmt.Sprintf("[%s]", unescapedHost)
	}

	headerKeys := make([]string, 0, len(req.Header))
	headerValues := make([]string, 0, len(req.Header))

	hasDate := false
	for k, v := range req.Header {
		if len(v) == 0 {
			continue
		}
		lowerKey := strings.ToLower(k)
		if lowerKey == "referer" {
			// Referer header is not include in signature
			continue
		}
		headerKeys = append(headerKeys, lowerKey)
		headerValues = append(headerValues, strings.ToLower(v[0]))
		if lowerKey == "date" {
			hasDate = true
		}
	}

	retHeaders := map[string]string{}
	if !hasDate {
		// Add date header if not already present
		headerKeys = append(headerKeys, "date")
		dateValue := time.Now().Format(time.RFC1123)
		headerValues = append(headerValues, dateValue)
		retHeaders["date"] = dateValue
	}

	unhashedSig := fmt.Sprintf("%s%s;%s;%s",
		host, pathQS, strings.Join(headerValues, ";"), apiKey)
	sha256 := fmt.Sprintf("%s", sha256.Sum256([]byte(unhashedSig)))
	hashedSig := base64.StdEncoding.EncodeToString([]byte(sha256))

	authHeader := fmt.Sprintf("SLSignature keyId=%s, headers=%s, %s", userId, strings.Join(headerKeys, ";"), hashedSig)
	retHeaders["Authorization"] = authHeader
	return retHeaders, nil
}

func setHeaders(req *http.Request, headers map[string]any) error {
	for key, val := range headers {
		valstr, ok := val.(string)
		if !ok {
			return fmt.Errorf("expected param value for key '%s' to be a string. got: '%T'", key, val)
		}
		req.Header.Add(key, valstr)
	}
	return nil
}

func setBody(req *http.Request, body string, formData map[string]any, formEncoding string, jsondata any) error {
	if body != "" {
		req.Body = io.NopCloser(strings.NewReader(body))
		// Specifying the Content-Length ensures that https://go.dev/src/net/http/transfer.go doesnt specify Transfer-Encoding: chunked which is not supported by some endpoints.
		// This is required when using ioutil.NopCloser method for the request body (see ShouldSendChunkedRequestBody() in the library mentioned above).
		req.ContentLength = int64(len(body))

		return nil
	}

	if jsondata != nil {
		req.Header.Set("Content-Type", "application/json")

		data, err := json.Marshal(jsonCompatible(jsondata))
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(data))
		req.ContentLength = int64(len(data))
	}

	if len(formData) > 0 {
		form := url.Values{}
		for key, val := range formData {
			valstr, ok := val.(string)
			if !ok {
				return fmt.Errorf("expected param value for key '%s' to be a string. got: '%T'", key, val)
			}
			form.Add(key, valstr)
		}

		var contentType string
		switch formEncoding {
		case formEncodingURL, "":
			contentType = formEncodingURL
			req.Body = io.NopCloser(strings.NewReader(form.Encode()))
			req.ContentLength = int64(len(form.Encode()))

		case formEncodingMultipart:
			var b bytes.Buffer
			mw := multipart.NewWriter(&b)
			defer mw.Close() //nolint:errcheck

			contentType = mw.FormDataContentType()

			for k, values := range form {
				for _, v := range values {
					w, err := mw.CreateFormField(k)
					if err != nil {
						return err
					}
					if _, err := w.Write([]byte(v)); err != nil {
						return err
					}
				}
			}

			req.Body = io.NopCloser(&b)

		default:
			return fmt.Errorf("unknown form encoding: %s", formEncoding)
		}

		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", contentType)
		}
	}

	return nil
}

// jsonCompatible converts SDK value shapes (tuples, sets, ordered dicts,
// typed structs) into plain values encoding/json/v2 can marshal.
func jsonCompatible(v any) any {
	switch x := v.(type) {
	case sdk.Tuple:
		return jsonCompatibleSlice(x)
	case sdk.Set:
		return jsonCompatibleSlice(x)
	case []any:
		return jsonCompatibleSlice(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = jsonCompatible(item)
		}
		return out
	case *sdk.Dict:
		out := make(map[string]any, len(x.Entries))
		for _, entry := range x.Entries {
			out[fmt.Sprintf("%v", entry.Key)] = jsonCompatible(entry.Value)
		}
		return out
	case *sdk.Struct:
		out := make(map[string]any, len(x.Fields))
		for k, item := range x.Fields {
			out[k] = jsonCompatible(item)
		}
		return out
	default:
		return v
	}
}

func jsonCompatibleSlice(items []any) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = jsonCompatible(item)
	}
	return out
}
