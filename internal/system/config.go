// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"embed"

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

	defer file.Close()
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
	_, err := toml.Decode(contents, &config)
	return err
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

	return &globalConfig, &clientConfig, &serverConfig, nil
}
