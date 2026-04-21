// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"slices"
	"strings"
	"testing"
)

func TestCommandOptionArgsAllowedExactAndRegex(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{
			"init":  "",
			"label": "team=platform",
		},
	}, map[string]string{
		"init":  "",
		"label": "regex:^team=platform$",
	})
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--init", "--label=team=platform"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestParseCommandOptionsFiltersByContainerCommand(t *testing.T) {
	got, err := ParseCommandOptions("/usr/local/bin/docker", map[string]string{
		"docker.init":    "",
		"command.label":  "team=platform",
		"podman.ignored": "",
		"ignored.option": "ignored",
	})
	if err != nil {
		t.Fatalf("ParseCommandOptions returned error: %v", err)
	}

	if got.Other["init"] != "" {
		t.Fatalf("Other[init] = %#v, want empty string", got.Other["init"])
	}
	if got.Other["label"] != "team=platform" {
		t.Fatalf("Other[label] = %#v, want %q", got.Other["label"], "team=platform")
	}
	if _, ok := got.Other["ignored"]; ok {
		t.Fatalf("podman option should not be decoded, got %#v", got.Other["ignored"])
	}
	if _, ok := got.Other["ignored.option"]; ok {
		t.Fatalf("unprefixed unknown option should not be decoded, got %#v", got.Other["ignored.option"])
	}
}

func TestCommandOptionArgsRejectsDisallowedArg(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"privileged": ""},
	}, map[string]string{"init": ""})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject disallowed arg")
	}
	if !strings.Contains(err.Error(), `container argument "privileged" is not allowed`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsAllowsExactValue(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"security-opt": "label=disable"},
	}, map[string]string{"security-opt": "label=disable"})
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--security-opt=label=disable"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestCommandOptionArgsRejectsInvalidRegex(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"init": ""},
	}, map[string]string{"init": "regex:["})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid allowed container arg") {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsRejectsValueForValuelessArg(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"init": "true"},
	}, map[string]string{"init": ""})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject value for valueless arg")
	}
	if !strings.Contains(err.Error(), `container argument "init" does not allow a value`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsRejectsWrongValue(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"security-opt": "apparmor=unconfined"},
	}, map[string]string{"security-opt": "label=disable"})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject wrong value")
	}
	if !strings.Contains(err.Error(), `container argument "security-opt" value "apparmor=unconfined" is not allowed`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsParsesBuiltInLimits(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Cpus:   "500m",
		Memory: "512m",
	}, nil)
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--cpus", "0.5", "--memory", "536870912"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestCommandOptionArgsRejectsInvalidBuiltInLimits(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{Cpus: "not-cpu"}, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing cpus value") {
		t.Fatalf("CommandOptionArgs cpu error = %v, want cpu parse error", err)
	}

	_, err = CommandOptionArgs(CommandOptions{Memory: "not-memory"}, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing memory value") {
		t.Fatalf("CommandOptionArgs memory error = %v, want memory parse error", err)
	}
}

func TestParseCommandOptionsKeepsBuiltInLimitsOutOfOther(t *testing.T) {
	got, err := ParseCommandOptions("docker", map[string]string{
		"docker.cpus":    "0.5",
		"command.memory": "512m",
	})
	if err != nil {
		t.Fatalf("parseCommandOptions returned error: %v", err)
	}
	if got.Cpus != "0.5" {
		t.Fatalf("Cpus = %q, want %q", got.Cpus, "0.5")
	}
	if got.Memory != "512m" {
		t.Fatalf("Memory = %q, want %q", got.Memory, "512m")
	}
	if len(got.Other) != 0 {
		t.Fatalf("Other = %#v, want empty", got.Other)
	}
}
