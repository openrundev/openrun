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
		BuilderProfile: map[string]BuilderProfileConfig{
			"tool":   {Agent: "opencode", GitConfig: "beta"},
			"nogit":  {Agent: "opencode"},
			"badref": {Agent: "opencode", GitConfig: "missing"},
		},
	}
}

func TestResolveBuilderGitProfile(t *testing.T) {
	c := gitTestConfig()
	got, err := c.ResolveBuilderGit("tool")
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "github.com/org/beta" || got.Branch != "beta-branch" || got.Auth != "beta_auth" {
		t.Errorf("profile git_config not used: %+v", got)
	}
	if got.AppsFile != "apps.star" || got.SourceDir != "apps" {
		t.Errorf("defaults not applied: %+v", got)
	}
}

func TestResolveBuilderGitLocalMode(t *testing.T) {
	// No profile git target (or no profile choice at all): local mode, even
	// with git entries present
	c := gitTestConfig()
	for _, profile := range []string{"nogit"} {
		got, err := c.ResolveBuilderGit(profile)
		if err != nil {
			t.Fatal(err)
		}
		if got.Repo != "" {
			t.Errorf("profile %q: expected local mode (empty repo), got %+v", profile, got)
		}
		if got.AppsFile != "apps.star" {
			t.Errorf("profile %q: local mode needs the apps_file default: %+v", profile, got)
		}
	}
}

func TestResolveBuilderGitErrors(t *testing.T) {
	c := gitTestConfig()
	if _, err := c.ResolveBuilderGit("badref"); err == nil || !strings.Contains(err.Error(), "builder_git.missing") {
		t.Errorf("expected missing git entry error, got %v", err)
	}
	if _, err := c.ResolveBuilderGit("nosuchprofile"); err == nil || !strings.Contains(err.Error(), "builder_profile.nosuchprofile") {
		t.Errorf("expected missing profile error, got %v", err)
	}
}

func TestChooseBuilderProfile(t *testing.T) {
	// No profiles configured: empty choice resolves the implicit default
	c := &ServerConfig{}
	name, profile, err := c.ChooseBuilderProfile("")
	if err != nil || name != "" || profile != nil {
		t.Errorf("expected the implicit default, got name=%q profile=%+v err=%v", name, profile, err)
	}
	if _, _, err := c.ChooseBuilderProfile("missing"); err == nil {
		t.Error("expected an error for an unknown profile name")
	}

	// Exactly one profile: used automatically
	c.BuilderProfile = map[string]BuilderProfileConfig{"only": {Agent: "opencode"}}
	name, profile, err = c.ChooseBuilderProfile("")
	if err != nil || name != "only" || profile == nil {
		t.Errorf("expected the single profile, got name=%q profile=%+v err=%v", name, profile, err)
	}

	// Multiple profiles: the caller must pick
	c.BuilderProfile["second"] = BuilderProfileConfig{Agent: "opencode"}
	if _, _, err := c.ChooseBuilderProfile(""); err == nil {
		t.Error("expected an error when several profiles exist and none was picked")
	}
	name, profile, err = c.ChooseBuilderProfile("second")
	if err != nil || name != "second" || profile == nil {
		t.Errorf("expected the named profile, got name=%q err=%v", name, err)
	}

	// A configured default resolves the empty choice even with several
	// profiles; an explicit choice still wins over the default
	c.AppBuilder.DefaultBuilderProfile = "second"
	name, profile, err = c.ChooseBuilderProfile("")
	if err != nil || name != "second" || profile == nil {
		t.Errorf("expected the default profile, got name=%q err=%v", name, err)
	}
	name, _, err = c.ChooseBuilderProfile("only")
	if err != nil || name != "only" {
		t.Errorf("explicit choice must win over the default, got name=%q err=%v", name, err)
	}
	c.AppBuilder.DefaultBuilderProfile = "missing"
	if _, _, err := c.ChooseBuilderProfile(""); err == nil {
		t.Error("expected an error for a default naming a missing profile")
	}
}

func TestResolveBuilderProfileStored(t *testing.T) {
	// A stored empty profile name is the implicit default - the create-time
	// defaulting (default profile, single-profile auto, pick-one error)
	// never applies to existing sessions
	c := gitTestConfig()
	c.AppBuilder.DefaultBuilderProfile = "tool"
	name, profile, err := c.ResolveBuilderProfile("")
	if err != nil || name != "" || profile != nil {
		t.Errorf("stored empty profile must stay the implicit default, got name=%q profile=%+v err=%v", name, profile, err)
	}
	if _, _, err := c.ResolveBuilderProfile("missing"); err == nil {
		t.Error("expected an error for a stored profile that no longer exists")
	}
}
