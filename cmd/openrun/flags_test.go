// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func TestValidateNoFlagLikeValues(t *testing.T) {
	err := validateNoFlagLikeValues("--cvol", "container volume", []string{"/data:/data", "--promote"})
	if err == nil {
		t.Fatal("expected error for value starting with --")
	}
	if !strings.Contains(err.Error(), "did you forget to provide a value for --cvol?") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateNoFlagLikeValues("--cvol", "container volume", []string{"/data:/data"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAppCreateRejectsFlagLikeContainerVolume(t *testing.T) {
	app := cli.NewApp()
	app.Writer = &bytes.Buffer{}
	app.ErrWriter = &bytes.Buffer{}
	app.Commands = []*cli.Command{
		appCreateCommand(nil, &types.ClientConfig{}),
	}

	err := app.Run([]string{"openrun", "create", "--cvol", "--promote", ".", "/test"})
	if err == nil {
		t.Fatal("expected app create to reject --promote as a container volume")
	}
	if !strings.Contains(err.Error(), "invalid container volume value \"--promote\"") {
		t.Fatalf("unexpected error: %v", err)
	}
}
