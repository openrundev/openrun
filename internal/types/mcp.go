// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/v2"
	"fmt"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
)

// MCPConfig marks an app as an MCP (Model Context Protocol) server whose
// endpoint OpenRun protects with OAuth: the MCP region of the app accepts
// only OpenRun-issued bearer tokens bound to this app, never cookies.
// Stored in AppMetadata (version controlled). See docs/Applications/MCP
type MCPConfig struct {
	// Path is the MCP region within the app: "/" (default) makes the
	// whole app the MCP endpoint; "/mcp" makes only that subtree the
	// endpoint while the rest of the app keeps its human auth
	Path string `json:"path"`
	// ContainerPath is the path the upstream (container or proxied url)
	// serves MCP at when it differs from Path. Only allowed with Path "/":
	// the app root is rewritten to this path when proxying, so the public
	// MCP URL is the app URL regardless of the image's endpoint path
	ContainerPath string `json:"container_path,omitempty"`
	// Scopes is the app's own scope vocabulary offered at consent and
	// advertised in the protected resource metadata. Empty = unscoped
	// tokens, access is governed by RBAC app:access alone
	Scopes []string `json:"scopes,omitempty"`
	// DefaultScope is advertised in the 401 challenge and granted when a
	// client requests no scope. Must be one of Scopes
	DefaultScope string `json:"default_scope,omitempty"`
	// Tools maps a tool name to the scope a tools/call for it requires.
	// Values must be in Scopes. Unlisted tools need no specific scope
	Tools map[string]string `json:"tools,omitempty"`
	// AllowedOrigins lists browser origins (scheme://host[:port]) admitted
	// on the region. A request carrying any other Origin header is
	// refused; requests without an Origin (native clients) are unaffected
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
}

// UpstreamPath returns the path the upstream serves MCP at: the container
// path when set, else the region path
func (m *MCPConfig) UpstreamPath() string {
	if m.ContainerPath != "" {
		return m.ContainerPath
	}
	return m.Path
}

// Canonical returns the normalized JSON document
func (m *MCPConfig) Canonical() string {
	doc, _ := json.Marshal(m)
	return string(doc)
}

func normalizeMCPPath(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	if strings.ContainsAny(value, " ?#") || strings.Contains(value, "..") {
		return "", fmt.Errorf("mcp %s %q is not a valid path", name, value)
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	cleaned := path.Clean(value)
	if cleaned != value && cleaned+"/" != value {
		return "", fmt.Errorf("mcp %s %q is not a normalized path (use %q)", name, value, cleaned)
	}
	return cleaned, nil
}

// ParseMCPConfig parses and validates an mcp JSON document
func ParseMCPConfig(doc string) (*MCPConfig, error) {
	var config MCPConfig
	if err := json.Unmarshal([]byte(doc), &config); err != nil {
		return nil, fmt.Errorf("invalid mcp config: %w", err)
	}
	var err error
	if config.Path, err = normalizeMCPPath("path", config.Path); err != nil {
		return nil, err
	}
	if config.ContainerPath != "" {
		if config.ContainerPath, err = normalizeMCPPath("container_path", config.ContainerPath); err != nil {
			return nil, err
		}
		if config.ContainerPath == "/" {
			config.ContainerPath = ""
		} else if config.Path != "/" {
			return nil, fmt.Errorf("mcp container_path is only allowed with path \"/\": with a region path the upstream serves the same path")
		}
	}
	scopeSet := map[string]bool{}
	for _, scope := range config.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\"\\") {
			return nil, fmt.Errorf("mcp scope %q is not a valid scope token", scope)
		}
		if scopeSet[scope] {
			return nil, fmt.Errorf("mcp scope %q is listed twice", scope)
		}
		scopeSet[scope] = true
	}
	if config.DefaultScope != "" && !scopeSet[config.DefaultScope] {
		return nil, fmt.Errorf("mcp default_scope %q is not in scopes", config.DefaultScope)
	}
	toolNames := make([]string, 0, len(config.Tools))
	for tool, scope := range config.Tools {
		if strings.TrimSpace(tool) == "" {
			return nil, fmt.Errorf("mcp tools has an empty tool name")
		}
		if !scopeSet[scope] {
			return nil, fmt.Errorf("mcp tool %q requires scope %q which is not in scopes", tool, scope)
		}
		toolNames = append(toolNames, tool)
	}
	sort.Strings(toolNames)
	for i, origin := range config.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return nil, fmt.Errorf("mcp allowed_origins entry %q must be scheme://host[:port]", origin)
		}
		config.AllowedOrigins[i] = strings.ToLower(parsed.Scheme + "://" + parsed.Host)
	}
	return &config, nil
}

// ParseMCPArg expands the CLI --mcp shorthand forms to the canonical JSON
// document: "" or "true" (bare flag) = the whole app is the endpoint served
// at the upstream root; "/path" = the whole app is the endpoint, rewritten
// to that upstream path; "{...}" = the full document; "@file" = a local
// file holding the document (CLI only: the server never reads files named
// by a request, see ParseMCPValue). Returns "" for "false"
func ParseMCPArg(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "@") {
		data, err := os.ReadFile(value[1:])
		if err != nil {
			return "", fmt.Errorf("reading mcp config file: %w", err)
		}
		value = strings.TrimSpace(string(data))
		if strings.HasPrefix(value, "@") {
			return "", fmt.Errorf("mcp config file must hold the document, not another @file reference")
		}
	}
	return ParseMCPValue(value)
}

// ParseMCPValue is ParseMCPArg without the @file form: the server-side
// parser for API requests, metadata updates and apply files, which must
// never read a file named by the caller
func ParseMCPValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch {
	case value == "false":
		return "", nil
	case value == "" || value == "true":
		return (&MCPConfig{Path: "/"}).Canonical(), nil
	case strings.HasPrefix(value, "@"):
		return "", fmt.Errorf("mcp @file references are expanded by the CLI; pass the document itself")
	}
	var doc string
	if strings.HasPrefix(value, "{") {
		doc = value
	} else if strings.HasPrefix(value, "/") {
		containerPath, err := normalizeMCPPath("container path", value)
		if err != nil {
			return "", err
		}
		doc = (&MCPConfig{Path: "/", ContainerPath: containerPath}).Canonical()
	} else {
		return "", fmt.Errorf("invalid mcp value %q: expected a container path (/mcp), a JSON object or @file", value)
	}
	config, err := ParseMCPConfig(doc)
	if err != nil {
		return "", err
	}
	return config.Canonical(), nil
}
