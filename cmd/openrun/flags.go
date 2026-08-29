// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	FORMAT_TABLE        = "table"
	FORMAT_BASIC        = "basic"
	FORMAT_JSON         = "json"
	FORMAT_JSONL        = "jsonl"
	FORMAT_JSONL_PRETTY = "jsonl_pretty"
	FORMAT_CSV          = "csv"
)

var validFormats = []string{FORMAT_TABLE, FORMAT_BASIC, FORMAT_CSV, FORMAT_JSON, FORMAT_JSONL, FORMAT_JSONL_PRETTY}

// newFormatFlag creates the output format flag, validating the value at parse
// time so an invalid format is reported as an error instead of a panic
func newFormatFlag() *cli.StringFlag {
	return &cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Usage:   "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty",
		Action: func(_ *cli.Context, value string) error {
			if !slices.Contains(validFormats, value) {
				return fmt.Errorf("invalid format %q: valid options are %s", value, strings.Join(validFormats, ", "))
			}
			return nil
		},
	}
}

// Terminal colors, empty strings when the terminal does not support ANSI escape sequences
var RESET, RED, GREEN, YELLOW = initColors()

func initColors() (string, string, string, string) {
	if colorsSupported() {
		return "\033[0m", "\033[31m", "\033[32m", "\033[33m"
	}
	return "", "", "", ""
}

// colorsSupported reports whether colored output should be used: disabled if
// NO_COLOR is set, TERM is dumb, stdout/stderr are not terminals, or the
// platform cannot process ANSI escape sequences
func colorsSupported() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(os.Stdout) && isTerminal(os.Stderr) && enableVirtualTerminal()
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func newStringFlag(name, alias, usage, value string) *cli.StringFlag {
	var aliases []string
	if alias != "" {
		aliases = []string{alias}
	}
	return &cli.StringFlag{
		Name:    name,
		Aliases: aliases,
		Usage:   usage,
		Value:   value,
	}
}

func newIntFlag(name, alias, usage string, value int) *cli.IntFlag {
	var aliases []string
	if alias != "" {
		aliases = []string{alias}
	}
	return &cli.IntFlag{
		Name:    name,
		Aliases: aliases,
		Usage:   usage,
		Value:   value,
	}
}

func newBoolFlag(name, alias, usage string, value bool) *cli.BoolFlag {
	var aliases []string
	if alias != "" {
		aliases = []string{alias}
	}
	return &cli.BoolFlag{
		Name:    name,
		Aliases: aliases,
		Usage:   usage,
		Value:   value,
	}
}

// newHttpClient creates the management API client from the client config,
// applying the --as user header when set. The bearer credential resolves
// from OPENRUN_API_KEY, then client.api_key; over the unix socket no
// credential is needed
func newHttpClient(clientConfig *types.ClientConfig) *system.HttpClient {
	apiKey := cmp.Or(os.Getenv("OPENRUN_API_KEY"), clientConfig.Client.ApiKey)
	if apiKey == "" && (strings.HasPrefix(clientConfig.ServerUri, "https://") || strings.HasPrefix(clientConfig.ServerUri, "http://")) {
		// Fall back to a stored openrun login for the server, refreshing the
		// access token transparently when it is stale
		apiKey = system.ResolveLoginToken(clientConfig.ServerUri, clientConfig.Client.SkipCertCheck)
	}
	client := system.NewHttpClient(clientConfig.ServerUri, apiKey, clientConfig.Client.SkipCertCheck)
	if client != nil && clientConfig.Client.AsUser != "" {
		client.SetHeader(types.OPENRUN_HEADER_AS_USER, clientConfig.Client.AsUser)
	}
	return client
}

func validateNoFlagLikeValues(flagName string, valueName string, values []string) error {
	for _, value := range values {
		if strings.HasPrefix(value, "--") {
			return fmt.Errorf("invalid %s value %q for %s: values cannot start with --; did you forget to provide a value for %s?", valueName, value, flagName, flagName)
		}
	}
	return nil
}

// makeAbsolute converts a relative path to an absolute path.
// This needs to be called in the client before the call to system.NewHttpClient
// since that changes the cwd to $OPENRUN_HOME
func makeAbsolute(sourceUrl string) (string, error) {
	if sourceUrl == "-" || system.IsGit(sourceUrl) {
		return sourceUrl, nil
	}

	var err error
	// Convert to absolute path so that server can find it
	sourceUrl, err = filepath.Abs(sourceUrl)
	if err != nil {
		return "", fmt.Errorf("error getting absolute path for %s: %w", sourceUrl, err)
	}
	_, err = os.Stat(sourceUrl)
	if err != nil {
		return "", fmt.Errorf("path does not exist %s: %w", sourceUrl, err)
	}
	return sourceUrl, nil
}
