// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"

	"github.com/urfave/cli/v2"
)

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

func globalFlagTestApp() *cli.App {
	return &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config-file", Aliases: []string{"c"}},
			&cli.StringFlag{Name: "server-uri"},
			&cli.StringFlag{Name: "as"},
			&cli.BoolFlag{Name: "client-version", Aliases: []string{"version", "v"}},
		},
		Commands: []*cli.Command{
			{
				Name: "action",
				Subcommands: []*cli.Command{
					{
						Name:  "list",
						Flags: []cli.Flag{&cli.StringFlag{Name: "format", Aliases: []string{"f"}}},
					},
				},
			},
			{
				Name: "service",
				Subcommands: []*cli.Command{
					{
						Name:  "create",
						Flags: []cli.Flag{&cli.StringFlag{Name: "config", Aliases: []string{"c"}}},
					},
				},
			},
		},
	}
}

func TestNormalizeInterspersedFlagsHoistsGlobalFlagsAfterCommand(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "global flag after leaf command",
			argv: []string{"openrun", "action", "list", "--as", "builtin:test1"},
			want: []string{"openrun", "--as", "builtin:test1", "action", "list"},
		},
		{
			name: "global flag between commands",
			argv: []string{"openrun", "action", "--server-uri=https://h:1", "list", "/app"},
			want: []string{"openrun", "--server-uri=https://h:1", "action", "list", "/app"},
		},
		{
			name: "global flag mixed with command flags and positionals",
			argv: []string{"openrun", "action", "list", "/app", "--as", "builtin:test1", "-f", "json"},
			want: []string{"openrun", "--as", "builtin:test1", "action", "list", "-f", "json", "/app"},
		},
		{
			name: "existing root flags stay ahead of hoisted ones",
			argv: []string{"openrun", "-c", "/etc/openrun.toml", "action", "list", "--as", "u"},
			want: []string{"openrun", "-c", "/etc/openrun.toml", "--as", "u", "action", "list"},
		},
		{
			name: "command flag shadows global alias",
			argv: []string{"openrun", "service", "create", "-c", "cfg.toml", "mysvc"},
			want: []string{"openrun", "service", "create", "-c", "cfg.toml", "mysvc"},
		},
		{
			name: "version flag is hoisted",
			argv: []string{"openrun", "action", "list", "--version"},
			want: []string{"openrun", "--version", "action", "list"},
		},
		{
			name: "global flag after double dash stays positional",
			argv: []string{"openrun", "action", "list", "--", "--as", "u"},
			want: []string{"openrun", "action", "list", "--", "--as", "u"},
		},
		{
			name: "global flag value matching a command name is not a command",
			argv: []string{"openrun", "action", "--as", "list", "list"},
			want: []string{"openrun", "--as", "list", "action", "list"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeInterspersedFlags(globalFlagTestApp(), tt.argv)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalized args mismatch\ngot:  %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

func TestFormatVersion(t *testing.T) {
	got := formatVersion("openrun_server", "1.2611.120", "5acea6d9", "tip", "Apache-2.0")
	if want := "openrun_server 1.2611.120 (5acea6d9, tip, Apache-2.0)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// server older than the release channel split
	got = formatVersion("openrun_server", "0.15.0", "abcd1234", "", "")
	if want := "openrun_server 0.15.0 (abcd1234)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
