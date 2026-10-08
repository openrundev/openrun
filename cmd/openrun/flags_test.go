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

// TestStageFlagAliases verifies the --stage flag of the single-app commands
// is settable as -s, --staging and --stage=false, and that the string
// --stage of the service commands reports IsSet through its --staging alias,
// including for the empty value which clears the staging service
func TestStageFlagAliases(t *testing.T) {
	var stage bool
	app := cli.NewApp()
	app.Writer = &bytes.Buffer{}
	app.Commands = []*cli.Command{{
		Name:  "c",
		Flags: []cli.Flag{stageFlag("stage")},
		Action: func(cCtx *cli.Context) error {
			stage = cCtx.Bool(STAGE_FLAG)
			return nil
		},
	}}
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"openrun", "c"}, false},
		{[]string{"openrun", "c", "--stage"}, true},
		{[]string{"openrun", "c", "-s"}, true},
		{[]string{"openrun", "c", "--staging"}, true},
		{[]string{"openrun", "c", "--stage=false"}, false},
		{[]string{"openrun", "c", "--staging=false"}, false},
	} {
		stage = !tc.want
		if err := app.Run(tc.args); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if stage != tc.want {
			t.Errorf("%v: stage = %t, want %t", tc.args, stage, tc.want)
		}
	}

	var set bool
	var value string
	serviceApp := cli.NewApp()
	serviceApp.Writer = &bytes.Buffer{}
	serviceApp.Commands = []*cli.Command{{
		Name:  "c",
		Flags: []cli.Flag{stagingServiceFlag("staging service")},
		Action: func(cCtx *cli.Context) error {
			set, value = cCtx.IsSet(STAGE_FLAG), cCtx.String(STAGE_FLAG)
			return nil
		},
	}}
	for _, tc := range []struct {
		args    []string
		wantSet bool
		want    string
	}{
		{[]string{"openrun", "c"}, false, ""},
		{[]string{"openrun", "c", "--stage", "s1"}, true, "s1"},
		{[]string{"openrun", "c", "--staging", "s1"}, true, "s1"},
		{[]string{"openrun", "c", "--stage", ""}, true, ""},
		{[]string{"openrun", "c", "--staging", ""}, true, ""},
	} {
		set, value = !tc.wantSet, "unset"
		if err := serviceApp.Run(tc.args); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if set != tc.wantSet || value != tc.want {
			t.Errorf("%v: set=%t value=%q, want set=%t value=%q", tc.args, set, value, tc.wantSet, tc.want)
		}
	}
}
