// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
		os.Chdir(clHome)
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
	defer resp.Body.Close()
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
