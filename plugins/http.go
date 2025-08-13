// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Based on code from https://github.com/qri-io/starlib/blob/master/http/http.go

package plugins

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// AsString unquotes a starlark string value
func AsString(x starlark.Value) (string, error) {
	return strconv.Unquote(x.String())
}

// Encodings for form data.
//
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
const (
	formEncodingMultipart = "multipart/form-data"
	formEncodingURL       = "application/x-www-form-urlencoded"
)

func init() {
	h := &httpPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApi(h.Get, app.READ),
		app.CreatePluginApi(h.Head, app.READ),
		app.CreatePluginApi(h.Options, app.READ),
		app.CreatePluginApi(h.Post, app.WRITE),
		app.CreatePluginApi(h.Put, app.WRITE),
		app.CreatePluginApi(h.Delete, app.WRITE),
		app.CreatePluginApi(h.Patch, app.WRITE),
	}
	app.RegisterPlugin("http", NewHttpPlugin, pluginFuncs)
}

type httpPlugin struct {
	client *http.Client
}

func NewHttpPlugin(pluginContext *types.PluginContext) (any, error) {
	return &httpPlugin{client: http.DefaultClient}, nil
}

func (h *httpPlugin) Get(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("get")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Head(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("head")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Options(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("options")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Post(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("post")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Put(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("put")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Delete(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("delete")
	return httpFunc(thread, builtin, args, kwargs)
}

func (h *httpPlugin) Patch(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	httpFunc := h.reqMethod("patch")
	return httpFunc(thread, builtin, args, kwargs)
}

// reqMethod is a factory function for generating starlark builtin functions for different http request methods
func (h *httpPlugin) reqMethod(method string) func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var (
			urlv         starlark.String
			params       = &starlark.Dict{}
			headers      = &starlark.Dict{}
			formBody     = &starlark.Dict{}
			signAuth     = &starlark.Dict{}
			formEncoding starlark.String
			basicAuth    starlark.Tuple
			body         starlark.String
			jsonBody     starlark.Value
			errorOnFail  starlark.Bool = starlark.True
		)

		if err := starlark.UnpackArgs(method, args, kwargs, "url", &urlv, "params?", &params, "headers",
			&headers, "body", &body, "form_body", &formBody, "form_encoding", &formEncoding,
			"json_body", &jsonBody, "auth_basic", &basicAuth, "auth_signature", &signAuth,
			"error_on_fail", &errorOnFail); err != nil {
			return nil, err
		}

		rawurl, err := AsString(urlv)
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(rawurl, apptype.CONTAINER_URL) {
			// If the url starts with the container url, we need to replace it with the container proxy url
			rawurl = strings.TrimPrefix(rawurl, apptype.CONTAINER_URL)
			containerProxyUrl := thread.Local(types.TL_CONTAINER_URL)
			containerProxyUrlStr, ok := containerProxyUrl.(string)
			if !ok || containerProxyUrlStr == "" {
				return nil, fmt.Errorf("container proxy url not set")
			}
			rawurl = containerProxyUrlStr + rawurl
		}

		if err = setQueryParams(&rawurl, params); err != nil {
			return nil, err
		}

		req, err := http.NewRequest(strings.ToUpper(method), rawurl, nil)
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

		if signAuth.Len() > 0 {
			if err = setSignAuth(req, signAuth); err != nil {
				return nil, err
			}
		}

		res, err := h.client.Do(req)
		if err != nil {
			return nil, err
		}

		if errorOnFail && (res.StatusCode < 200 || res.StatusCode >= 300) { // 1xx and 3xx are also failed by default
			return nil, fmt.Errorf("http request failed with status code %d: %s", res.StatusCode, res.Status)
		}

		r := &Response{*res}
		return app.NewResponse(r.Struct()), nil
	}
}

func setQueryParams(rawurl *string, params *starlark.Dict) error {
	keys := params.Keys()
	if len(keys) == 0 {
		return nil
	}

	u, err := url.Parse(*rawurl)
	if err != nil {
		return err
	}

	q := u.Query()
	for _, key := range keys {
		keystr, err := AsString(key)
		if err != nil {
			return err
		}

		val, _, err := params.Get(key)
		if err != nil {
			return err
		}
		if val.Type() != "string" {
			return fmt.Errorf("expected param value for key '%s' to be a string. got: '%s'", key, val.Type())
		}
		valstr, err := AsString(val)
		if err != nil {
			return err
		}

		q.Set(keystr, valstr)
	}
	if q.Encode() != "" {
		u.RawQuery = q.Encode()
	}
	*rawurl = u.String()
	return nil
}

func setBasicAuth(req *http.Request, auth starlark.Tuple) error {
	if len(auth) == 0 {
		return nil
	} else if len(auth) == 2 {
		username, err := AsString(auth[0])
		if err != nil {
			return fmt.Errorf("parsing auth username string: %s", err.Error())
		}
		password, err := AsString(auth[1])
		if err != nil {
			return fmt.Errorf("parsing auth password string: %s", err.Error())
		}
		req.SetBasicAuth(username, password)
		return nil
	}
	return fmt.Errorf("expected two values for auth params tuple")
}

func getKeyAsString(dict *starlark.Dict, key string) (string, error) {
	val, ok, err := dict.Get(starlark.String(key))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("key %s not found", key)
	}
	return AsString(val)
}

func setSignAuth(req *http.Request, auth *starlark.Dict) error {
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

func setHeaders(req *http.Request, headers *starlark.Dict) error {
	keys := headers.Keys()
	if len(keys) == 0 {
		return nil
	}

	for _, key := range keys {
		keystr, err := AsString(key)
		if err != nil {
			return err
		}

		val, _, err := headers.Get(key)
		if err != nil {
			return err
		}
		if val.Type() != "string" {
			return fmt.Errorf("expected param value for key '%s' to be a string. got: '%s'", key, val.Type())
		}
		valstr, err := AsString(val)
		if err != nil {
			return err
		}

		req.Header.Add(keystr, valstr)
	}

	return nil
}

func setBody(req *http.Request, body starlark.String, formData *starlark.Dict, formEncoding starlark.String, jsondata starlark.Value) error {
	if !starlark_type.IsEmptyStarlarkString(body) {
		uq, err := strconv.Unquote(body.String())
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(strings.NewReader(uq))
		// Specifying the Content-Length ensures that https://go.dev/src/net/http/transfer.go doesnt specify Transfer-Encoding: chunked which is not supported by some endpoints.
		// This is required when using ioutil.NopCloser method for the request body (see ShouldSendChunkedRequestBody() in the library mentioned above).
		req.ContentLength = int64(len(uq))

		return nil
	}

	if jsondata != nil && jsondata.String() != "" {
		req.Header.Set("Content-Type", "application/json")

		v, err := starlark_type.UnmarshalStarlark(jsondata)
		if err != nil {
			return err
		}
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(data))
		req.ContentLength = int64(len(data))
	}

	if formData != nil && formData.Len() > 0 {
		form := url.Values{}
		for _, key := range formData.Keys() {
			keystr, err := AsString(key)
			if err != nil {
				return err
			}

			val, _, err := formData.Get(key)
			if err != nil {
				return err
			}
			if val.Type() != "string" {
				return fmt.Errorf("expected param value for key '%s' to be a string. got: '%s'", key, val.Type())
			}
			valstr, err := AsString(val)
			if err != nil {
				return err
			}

			form.Add(keystr, valstr)
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
			defer mw.Close()

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

// Response represents an HTTP response, wrapping a go http.Response with
// starlark methods
type Response struct {
	http.Response
}

// Struct turns a response into a *starlark.Struct
func (r *Response) Struct() *starlarkstruct.Struct {
	return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"url":         starlark.String(r.Request.URL.String()),
		"status_code": starlark.MakeInt(r.StatusCode),
		"headers":     r.HeadersDict(),
		"encoding":    starlark.String(strings.Join(r.TransferEncoding, ",")),

		"body": starlark.NewBuiltin("body", r.Text),
		"json": starlark.NewBuiltin("json", r.JSON),
	})
}

// HeadersDict flops
func (r *Response) HeadersDict() *starlark.Dict {
	d := new(starlark.Dict)
	for key, vals := range r.Header {
		if err := d.SetKey(starlark.String(key), starlark.String(strings.Join(vals, ","))); err != nil {
			panic(err)
		}
	}
	return d
}

// Text returns the raw data as a string
func (r *Response) Text(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	// reset reader to allow multiple calls
	r.Body = io.NopCloser(bytes.NewReader(data))

	return starlark.String(string(data)), nil
}

// JSON attempts to parse the response body as JSON
func (r *Response) JSON(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data interface{}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	r.Body.Close()
	// reset reader to allow multiple calls
	r.Body = io.NopCloser(bytes.NewReader(body))
	return starlark_type.MarshalStarlark(data)
}
