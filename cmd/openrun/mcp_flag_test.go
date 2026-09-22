// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/urfave/cli/v2"
)

// The --mcp flag is bool-shaped with an optional value: bare --mcp must not
// swallow the source/path positionals, and the = forms carry a value
func TestMCPFlagParsing(t *testing.T) {
	for name, tc := range map[string]struct {
		args    []string
		wantDoc string
		wantErr bool
	}{
		"absent":    {[]string{"./src", "/app"}, "", false},
		"bare":      {[]string{"--mcp", "./src", "/app"}, `{"path":"/"}`, false},
		"path":      {[]string{"--mcp=/mcp", "./src", "/app"}, `{"path":"/","container_path":"/mcp"}`, false},
		"actions":   {[]string{"--mcp=actions", "./src", "/app"}, `{"path":"/mcp","source":"actions"}`, false},
		"json":      {[]string{`--mcp={"path":"/mcp"}`, "./src", "/app"}, `{"path":"/mcp"}`, false},
		"bad value": {[]string{"--mcp=nope", "./src", "/app"}, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			var doc string
			var err error
			var positional []string
			app := &cli.App{
				Flags: []cli.Flag{&cli.GenericFlag{Name: "mcp", Value: &mcpFlagValue{}}},
				Action: func(cCtx *cli.Context) error {
					positional = cCtx.Args().Slice()
					doc, err = mcpFlagDoc(cCtx)
					return err
				},
			}
			runErr := app.Run(append([]string{"openrun"}, tc.args...))
			if tc.wantErr {
				if runErr == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			if doc != tc.wantDoc {
				t.Fatalf("doc: want %q got %q", tc.wantDoc, doc)
			}
			if len(positional) != 2 || positional[0] != "./src" || positional[1] != "/app" {
				t.Fatalf("positionals must be untouched, got %v", positional)
			}
		})
	}
}
