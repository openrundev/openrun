// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"embed"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openrundev/openrun/internal/types"
)

const DEFAULT_CONFIG = "openrun.default.toml"

//go:embed "openrun.default.toml"
var f embed.FS

func getEmbeddedToml() (string, error) {
	file, err := f.Open(DEFAULT_CONFIG)
	if err != nil {
		return "", err
	}

	defer file.Close() //nolint:errcheck
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(file)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// NewServerConfigEmbedded reads the embedded toml file and creates a ServerConfig
func NewServerConfigEmbedded() (*types.ServerConfig, error) {
	contents, err := getEmbeddedToml()
	if err != nil {
		return nil, err
	}

	var config types.ServerConfig
	err = LoadServerConfig(contents, &config)
	return &config, err
}

// LoadServerConfig loads a ServerConfig from the given contents
func LoadServerConfig(contents string, config *types.ServerConfig) error {
	if _, err := toml.Decode(contents, config); err != nil {
		return err
	}
	return NormalizeServerConfig(config)
}

// NewClientConfigEmbedded reads the embedded toml file and creates a ClientConfig
func NewClientConfigEmbedded() (*types.ClientConfig, error) {
	contents, err := getEmbeddedToml()
	if err != nil {
		return nil, err
	}

	var config types.ClientConfig
	err = LoadClientConfig(contents, &config)
	return &config, err
}

// LoadClientConfig load a ClientConfig from the given contents
func LoadClientConfig(contents string, config *types.ClientConfig) error {
	_, err := toml.Decode(contents, &config)
	return err
}

// LoadGlobalConfig load a GlobalConfig from the given contents
func LoadGlobalConfig(contents string, config *types.GlobalConfig) error {
	_, err := toml.Decode(contents, &config)
	return err
}

func GetDefaultConfigs() (*types.GlobalConfig, *types.ClientConfig, *types.ServerConfig, error) {
	contents, err := getEmbeddedToml()
	if err != nil {
		return nil, nil, nil, err
	}

	var globalConfig types.GlobalConfig
	var clientConfig types.ClientConfig
	var serverConfig types.ServerConfig
	if _, err := toml.Decode(contents, &globalConfig); err != nil {
		return nil, nil, nil, err
	}
	if _, err := toml.Decode(contents, &clientConfig); err != nil {
		return nil, nil, nil, err
	}
	if _, err := toml.Decode(contents, &serverConfig); err != nil {
		return nil, nil, nil, err
	}
	if err := NormalizeServerConfig(&serverConfig); err != nil {
		return nil, nil, nil, err
	}

	return &globalConfig, &clientConfig, &serverConfig, nil
}

// NormalizeServerConfig applies the defaults and normalizations every
// server config needs before use. It runs at toml load and again in
// server.NewServer, so a config an embedder builds or edits in Go
// (pkg/api.NewServerConfig then field assignments) is normalized too
func NormalizeServerConfig(config *types.ServerConfig) error {
	if config.System.TailwindVersion == 0 {
		config.System.TailwindVersion = types.TailwindVersionDefault
	}
	if config.System.TailwindVersion < types.TailwindVersionMin {
		return fmt.Errorf("tailwind_version must be >= %d, got %d", types.TailwindVersionMin, config.System.TailwindVersion)
	}
	// The origin settings are concatenated with /_openrun/... paths by the
	// OAuth/SAML providers, the webhooks and the issuer: a trailing slash
	// would double up, so it is dropped once here. security.callback_url is
	// static config, so load and NewServer are its normalization points;
	// api.external_url is also dynamically settable and is trimmed again
	// where it is resolved
	config.Security.CallbackUrl = strings.TrimSuffix(strings.TrimSpace(config.Security.CallbackUrl), "/")
	config.Api.ExternalUrl = strings.TrimSuffix(strings.TrimSpace(config.Api.ExternalUrl), "/")
	return nil
}
