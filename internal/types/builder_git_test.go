// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"testing"
)

func gitTestConfig() *ServerConfig {
	return &ServerConfig{
		BuilderGit: map[string]BuilderGitConfig{
			"beta":  {Repo: "github.com/org/beta", Branch: "beta-branch", Auth: "beta_auth"},
			"alpha": {Repo: "github.com/org/alpha"},
		},
		BuilderPrompt: map[string]BuilderPromptConfig{
			"tool":   {Prompt: "p", GitConfig: "beta"},
			"nopref": {Prompt: "p"},
			"badref": {Prompt: "p", GitConfig: "missing"},
		},
	}
}

func TestResolveBuilderGitPresetWins(t *testing.T) {
	c := gitTestConfig()
	c.AppBuilder.DefaultGitConfig = "alpha"
	got, err := c.ResolveBuilderGit("tool")
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "github.com/org/beta" || got.Branch != "beta-branch" || got.Auth != "beta_auth" {
		t.Errorf("preset git_config not used: %+v", got)
	}
	if got.AppsFile != "apps.star" || got.SourceDir != "apps" {
		t.Errorf("defaults not applied: %+v", got)
	}
}

func TestResolveBuilderGitDefault(t *testing.T) {
	c := gitTestConfig()
	c.AppBuilder.DefaultGitConfig = "alpha"
	for _, preset := range []string{"", "nopref"} {
		got, err := c.ResolveBuilderGit(preset)
		if err != nil {
			t.Fatal(err)
		}
		if got.Repo != "github.com/org/alpha" {
			t.Errorf("preset %q: default_git_config not used: %+v", preset, got)
		}
		if got.Branch != "main" || got.AppsFile != "apps.star" || got.SourceDir != "apps" {
			t.Errorf("preset %q: defaults not applied: %+v", preset, got)
		}
	}
}

func TestResolveBuilderGitLocalMode(t *testing.T) {
	// No preset choice and no default: local mode, even with entries present
	c := gitTestConfig()
	for _, preset := range []string{"", "nopref"} {
		got, err := c.ResolveBuilderGit(preset)
		if err != nil {
			t.Fatal(err)
		}
		if got.Repo != "" {
			t.Errorf("preset %q: expected local mode (empty repo), got %+v", preset, got)
		}
		if got.AppsFile != "apps.star" {
			t.Errorf("preset %q: local mode needs the apps_file default: %+v", preset, got)
		}
	}
}

func TestResolveBuilderGitErrors(t *testing.T) {
	c := gitTestConfig()
	if _, err := c.ResolveBuilderGit("badref"); err == nil || !strings.Contains(err.Error(), "builder_git.missing") {
		t.Errorf("expected missing git entry error, got %v", err)
	}
	if _, err := c.ResolveBuilderGit("nosuchpreset"); err == nil || !strings.Contains(err.Error(), "builder_prompt.nosuchpreset") {
		t.Errorf("expected missing preset error, got %v", err)
	}
	c.AppBuilder.DefaultGitConfig = "missing"
	if _, err := c.ResolveBuilderGit(""); err == nil || !strings.Contains(err.Error(), "builder_git.missing") {
		t.Errorf("expected missing default entry error, got %v", err)
	}
}
