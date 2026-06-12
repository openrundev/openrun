// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestNormalizeInterspersedFlagsNestedCommand(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "service",
				Subcommands: []*cli.Command{
					{
						Name: "create",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "is-default"},
							&cli.StringSliceFlag{Name: "config", Aliases: []string{"c"}},
						},
					},
				},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "service", "create", "postgres/main", "--is-default",
		"--config", "url=postgres://host/db", "-c=role=primary",
	})
	want := []string{
		"openrun", "service", "create", "--is-default", "--config",
		"url=postgres://host/db", "-c=role=primary", "postgres/main",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeInterspersedFlagsTopLevelCommand(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "apply",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "promote", Aliases: []string{"p"}},
					&cli.StringFlag{Name: "reload"},
				},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "apply", "./app.star", "all", "--promote", "--reload=updated",
	})
	want := []string{
		"openrun", "apply", "--promote", "--reload=updated", "./app.star", "all",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeInterspersedFlagsKeepsUnknownFlagLikePositionals(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "run",
				Flags: []cli.Flag{&cli.BoolFlag{Name: "staging"}},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "run", "task", "--not-an-openrun-flag", "--staging",
	})
	want := []string{
		"openrun", "run", "--staging", "task", "--not-an-openrun-flag",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeInterspersedFlagsHonorsDoubleDash(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "run",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "staging"},
				},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "run", "task", "--", "--staging",
	})
	want := []string{
		"openrun", "run", "task", "--", "--staging",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeInterspersedFlagsKeepsShellCompletionFlagLast(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "apply",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "promote"},
					&cli.StringFlag{Name: "reload"},
				},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "apply", "./app.star", "--promote", "--re", "--generate-bash-completion",
	})
	want := []string{
		"openrun", "apply", "--promote", "./app.star", "--re", "--generate-bash-completion",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeInterspersedFlagsLeavesTrailingValueFlagAfterPositionals(t *testing.T) {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "apply",
				Flags: []cli.Flag{&cli.StringFlag{Name: "reload"}},
			},
		},
	}

	got := normalizeInterspersedFlags(app, []string{
		"openrun", "apply", "./app.star", "--reload",
	})
	want := []string{
		"openrun", "apply", "./app.star", "--reload",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}
