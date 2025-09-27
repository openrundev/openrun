// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openrundev/openrun/internal/system"
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
const (
	//Terminal colors
	RESET  = "\033[0m"
	RED    = "\033[31m"
	GREEN  = "\033[32m"
	YELLOW = "\033[33m"
)

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
