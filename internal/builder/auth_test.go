// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	acp "github.com/coder/acp-go-sdk"
)

func TestIsAuthRequired(t *testing.T) {
	if !isAuthRequired(acp.NewAuthRequired(nil)) {
		t.Error("auth required error not detected")
	}
	if !isAuthRequired(fmt.Errorf("wrapped: %w", acp.NewAuthRequired(map[string]any{"type": "agent"}))) {
		t.Error("wrapped auth required error not detected")
	}
	if isAuthRequired(acp.NewMethodNotFound("session/new")) {
		t.Error("unrelated request error detected as auth required")
	}
	if isAuthRequired(errors.New("plain error")) {
		t.Error("plain error detected as auth required")
	}
}

func TestAgentAuthMethods(t *testing.T) {
	methods := []acp.AuthMethod{
		{Terminal: &acp.AuthMethodTerminalInline{Id: "term", Name: "Terminal", Type: "terminal"}},
		{Agent: &acp.AuthMethodAgent{Id: "api-key", Name: "API Key"}},
		{Agent: &acp.AuthMethodAgent{Id: "chat-gpt", Name: "ChatGPT"}},
	}
	agentMethods := agentAuthMethods(methods)
	if len(agentMethods) != 2 || agentMethods[0].Id != "api-key" || agentMethods[1].Id != "chat-gpt" {
		t.Errorf("expected [api-key chat-gpt] in advertised order, got %v", agentMethods)
	}
	if got := agentAuthMethods(methods[:1]); len(got) != 0 {
		t.Errorf("terminal-only methods should yield no agent methods, got %v", got)
	}
}

func TestDescribeAuthMethods(t *testing.T) {
	link := "https://platform.openai.com/api-keys"
	methods := []acp.AuthMethod{
		{EnvVar: &acp.AuthMethodEnvVarInline{
			Id: "api-key", Name: "API key", Type: "env_var", Link: &link,
			Vars: []acp.AuthEnvVar{{Name: "OPENAI_API_KEY"}, {Name: "OPENAI_ORG", Optional: true}},
		}},
		{Agent: &acp.AuthMethodAgent{Id: "oauth", Name: "ChatGPT login"}},
		{Terminal: &acp.AuthMethodTerminalInline{Id: "setup", Name: "Terminal setup", Type: "terminal"}},
	}

	sandboxMsg := describeAuthMethods(methods, "codex_prod", false)
	for _, want := range []string{
		"OPENAI_API_KEY", "OPENAI_ORG (optional)", "[builder_agent.codex_prod] env", link,
		"ChatGPT login", "unsafe_agent_without_sandbox",
		"Terminal setup", "not supported",
	} {
		if !strings.Contains(sandboxMsg, want) {
			t.Errorf("sandbox message missing %q: %s", want, sandboxMsg)
		}
	}

	hostMsg := describeAuthMethods(methods, "codex", true)
	if strings.Contains(hostMsg, "unsafe_agent_without_sandbox") {
		t.Errorf("host mode message should not mention the sandbox flag: %s", hostMsg)
	}

	emptyMsg := describeAuthMethods(nil, "myagent", false)
	if !strings.Contains(emptyMsg, "[builder_agent.myagent]") {
		t.Errorf("empty methods message should point at the agent config: %s", emptyMsg)
	}
}
