// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func noFile(string) ([]byte, error) { return nil, fmt.Errorf("not found") }

func TestAgentTypeFromName(t *testing.T) {
	cases := map[string]string{
		"opencode":       "opencode",
		"opencode_dev":   "opencode",
		"claude":         "claude",
		"codex_team":     "codex",
		"pi":             "pi",
		"custom_myagent": "custom",
		"custom":         "custom",
	}
	for name, wantType := range cases {
		gotType, err := AgentTypeFromName(name)
		if err != nil || gotType != wantType {
			t.Fatalf("%s: got %q err %v, want %q", name, gotType, err, wantType)
		}
	}
	for _, bad := range []string{"myagent", "gpt_dev", "opencodex", ""} {
		if _, err := AgentTypeFromName(bad); err == nil {
			t.Fatalf("%s: expected error", bad)
		}
	}
}

func TestResolveProfilePredefined(t *testing.T) {
	for _, agentType := range AgentTypes() {
		for _, name := range []string{agentType, agentType + "_dev"} {
			p, err := resolveProfile(name, types.BuilderAgentConfig{}, noFile)
			if err != nil {
				t.Fatalf("name %s: %v", name, err)
			}
			if p.agentType != agentType {
				t.Fatalf("name %s: type %s, want %s", name, p.agentType, agentType)
			}
			if len(p.command) == 0 {
				t.Fatalf("name %s: no command", name)
			}
			if len(p.dockerfile) == 0 || !strings.Contains(string(p.dockerfile), "FROM ubuntu") {
				t.Fatalf("name %s: missing embedded dockerfile", name)
			}
		}
	}
}

func TestResolveProfileExplicitTypeMustMatch(t *testing.T) {
	if _, err := resolveProfile("opencode_dev", types.BuilderAgentConfig{Type: "claude"}, noFile); err == nil {
		t.Fatal("mismatched explicit type should fail")
	}
	if _, err := resolveProfile("opencode_dev", types.BuilderAgentConfig{Type: "opencode"}, noFile); err != nil {
		t.Fatalf("matching explicit type should pass: %v", err)
	}
}

func TestResolveProfileCustomRequiresDockerfileAndCommand(t *testing.T) {
	readOk := func(string) ([]byte, error) { return []byte("FROM x"), nil }
	if _, err := resolveProfile("custom_myagent", types.BuilderAgentConfig{Command: []string{"x"}}, noFile); err == nil {
		t.Fatal("custom without dockerfile should fail")
	}
	if _, err := resolveProfile("custom_myagent", types.BuilderAgentConfig{Dockerfile: "df"}, readOk); err == nil {
		t.Fatal("custom without command should fail")
	}
	p, err := resolveProfile("custom_myagent", types.BuilderAgentConfig{Dockerfile: "df", Command: []string{"my-acp"}}, readOk)
	if err != nil {
		t.Fatal(err)
	}
	if p.imageTag() != "openrun_agent_custom_myagent:"+contentHash([]byte("FROM x")) {
		t.Fatalf("unexpected image tag %s", p.imageTag())
	}
}

func TestParseConfigMount(t *testing.T) {
	mount, err := parseConfigMount("/etc/x.json:/root/.config/x.json:ro")
	if err != nil {
		t.Fatal(err)
	}
	if mount.host != "/etc/x.json" || mount.container != "/root/.config/x.json" || !mount.readOnly {
		t.Fatalf("unexpected mount %+v", mount)
	}
	if _, err := parseConfigMount("/etc/x.json"); err == nil {
		t.Fatal("missing container path should fail")
	}
	if _, err := parseConfigMount("/a:/b:rw"); err == nil {
		t.Fatal("rw option should fail")
	}
	if _, err := parseConfigMount("/a:relative"); err == nil {
		t.Fatal("relative container path should fail")
	}
}

func TestDockerfileChangesImageTag(t *testing.T) {
	read1 := func(string) ([]byte, error) { return []byte("FROM ubuntu:24.04\nRUN a"), nil }
	read2 := func(string) ([]byte, error) { return []byte("FROM ubuntu:24.04\nRUN b"), nil }
	config := types.BuilderAgentConfig{Dockerfile: "df", Command: []string{"x"}}
	p1, err := resolveProfile("custom_prof", config, read1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := resolveProfile("custom_prof", config, read2)
	if err != nil {
		t.Fatal(err)
	}
	if p1.imageTag() == p2.imageTag() {
		t.Fatal("editing the Dockerfile must change the image tag")
	}
}
