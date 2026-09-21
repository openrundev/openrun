// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

// mcpHealthBody is a legacy (2025-06-18) initialize request. A legacy MCP
// server answers it 200; a 2026-07-28-only server rejects it with a
// JSON-RPC error (400 unsupported version / missing header, or 404 method
// not found), which equally proves the endpoint is up. Anything else
// (a plain 404 from the wrong path, a 405, a 5xx, no JSON-RPC body) is
// unhealthy
const mcpHealthBody = `{"jsonrpc":"2.0","id":"openrun-health","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"openrun-health","version":"1"}}}`

const mcpHealthBodyLimit = 64 * 1024

// mcpHealthProbe POSTs the probe and reports healthy/status
func mcpHealthProbe(client *http.Client, url string) (bool, string, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(mcpHealthBody)))
	if err != nil {
		return false, "N/A", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	resp, err := client.Do(req)
	if err != nil {
		return false, "N/A", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, mcpHealthBodyLimit))
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		// A stateful (legacy) server opened a session for the probe; end it
		// so periodic probes do not accumulate sessions. Best effort: a
		// server that does not support DELETE answers 405 and that is fine
		if del, err := http.NewRequest(http.MethodDelete, url, nil); err == nil {
			del.Header.Set("Mcp-Session-Id", sid)
			del.Header.Set("MCP-Protocol-Version", "2025-06-18")
			if delResp, err := client.Do(del); err == nil {
				delResp.Body.Close() //nolint:errcheck
			}
		}
	}
	return mcpProbeHealthy(resp.StatusCode, body), strconv.Itoa(resp.StatusCode), nil
}

// mcpProbeHealthy decides from the probe response whether the MCP endpoint
// is serving: 200, or a modern server's JSON-RPC rejection of the legacy
// request
func mcpProbeHealthy(status int, body []byte) bool {
	switch status {
	case http.StatusOK:
		return true
	case http.StatusBadRequest, http.StatusNotFound:
		return bytes.Contains(body, []byte(`"jsonrpc"`))
	}
	return false
}

// mcpVerifyVersion returns the Kubernetes version check for MCP apps: the
// pod probes are TCP (a native probe cannot POST), so OpenRun sends the
// JSON-RPC probe to the new version itself (blue-green: through a temporary
// per-version Service before the traffic switch; in-place: after the
// rollout, with snapshot rollback) and fails the deploy if the endpoint does
// not answer as an MCP server. nil for non-MCP apps
func (h *ContainerHandler) mcpVerifyVersion() func(context.Context, string) error {
	if h.mcpHealthPath == "" {
		return nil
	}
	return func(ctx context.Context, hostNamePort string) error {
		probeUrl := &url.URL{Scheme: "http", Host: hostNamePort}
		if h.scheme == "https" {
			probeUrl.Scheme = "https"
		}
		probePath := h.mcpHealthPath
		if !h.stripAppPath {
			probePath = path.Join("/", h.app.Path, probePath)
		}
		probeUrl = probeUrl.JoinPath(probePath)
		client := &http.Client{Timeout: time.Duration(max(h.containerConfig.HealthTimeoutSecs, 1)) * time.Second}
		attempts := max(h.containerConfig.DeployHealthAttempts, 1)
		var lastErr error
		for attempt := 1; attempt <= attempts; attempt++ {
			healthy, status, err := mcpHealthProbe(client, probeUrl.String())
			if err == nil && healthy {
				return nil
			}
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("mcp probe returned status %s", status)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		return fmt.Errorf("mcp endpoint %s did not answer the JSON-RPC probe: %w", probeUrl, lastErr)
	}
}
