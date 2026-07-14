// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	acp "github.com/coder/acp-go-sdk"
)

// ACP authentication support (agentclientprotocol registry AUTHENTICATION.md):
// the agent advertises authMethods in the initialize response and returns the
// auth-required error from session/new when it has no credentials. Env-var
// methods map to the profile's env config. Agent-managed methods (the agent
// runs its own OAuth flow, opening a browser and serving the callback on
// localhost) only work in unsafe_agent_without_sandbox host mode: a sandboxed
// agent has no browser and its callback port is unreachable. Terminal methods
// (interactive TUI login) are not supported.

// authTimeout bounds the agent-managed authentication flow: the agent opens
// a browser on the host and waits for the user to complete the OAuth flow
const authTimeout = 5 * time.Minute

// acpAuthRequiredCode is the ACP error code for "Authentication required"
const acpAuthRequiredCode = -32000

func isAuthRequired(err error) bool {
	var reqErr *acp.RequestError
	return errors.As(err, &reqErr) && reqErr.Code == acpAuthRequiredCode
}

// agentAuthMethods returns the advertised agent-managed auth methods, in
// advertised order. Agents may offer several (codex-acp: "api-key" which
// needs a key in the process env and fails instantly without one, then
// "chat-gpt" which runs the browser OAuth flow), so callers try each in turn
func agentAuthMethods(methods []acp.AuthMethod) []*acp.AuthMethodAgent {
	var agentMethods []*acp.AuthMethodAgent
	for _, method := range methods {
		if method.Agent != nil {
			agentMethods = append(agentMethods, method.Agent)
		}
	}
	return agentMethods
}

// newSessionWithAuth runs session/new, resolving the ACP auth-required error
// where possible. In host mode an advertised agent-managed method is invoked
// via authenticate — the agent opens a browser on the server host and stores
// the credentials itself — and session/new is retried once. Otherwise the
// advertised methods are folded into the error as remediation guidance.
// notify reports auth progress (activity log / session events)
func (m *Manager) newSessionWithAuth(ctx context.Context, conn *acp.ClientSideConnection, sb *sandbox,
	cwd, agentName string, authMethods []acp.AuthMethod, notify func(string)) (*acp.NewSessionResponse, error) {

	newSession, err := m.tryNewSession(ctx, conn, cwd)
	if err == nil {
		return newSession, nil
	}
	if !isAuthRequired(err) {
		return nil, fmt.Errorf("ACP session/new failed: %w (agent stderr: %s)", err, sb.stderr())
	}

	if m.hostMode() {
		var authFailures []string
		for _, method := range agentAuthMethods(authMethods) {
			notify(fmt.Sprintf("agent login required, starting %q authentication (a browser window may open on the server host)", method.Name))
			authErr := m.authenticate(ctx, conn, method.Id)
			if authErr != nil {
				notify(fmt.Sprintf("authentication method %q did not succeed", method.Name))
				authFailures = append(authFailures, fmt.Sprintf("%s: %v", method.Id, authErr))
				continue
			}
			notify("agent authentication completed")
			newSession, err = m.tryNewSession(ctx, conn, cwd)
			if err == nil {
				return newSession, nil
			}
			return nil, fmt.Errorf("ACP session/new failed after authentication: %w (agent stderr: %s)", err, sb.stderr())
		}
		if len(authFailures) > 0 {
			return nil, fmt.Errorf("agent authentication failed (%s). %s", strings.Join(authFailures, "; "),
				describeAuthMethods(authMethods, agentName, true))
		}
	}
	return nil, fmt.Errorf("agent authentication required. %s", describeAuthMethods(authMethods, agentName, m.hostMode()))
}

func (m *Manager) authenticate(ctx context.Context, conn *acp.ClientSideConnection, methodId string) error {
	authCtx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	_, err := conn.Authenticate(authCtx, acp.AuthenticateRequest{MethodId: methodId})
	return err
}

func (m *Manager) tryNewSession(ctx context.Context, conn *acp.ClientSideConnection, cwd string) (*acp.NewSessionResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	resp, err := conn.NewSession(callCtx, acp.NewSessionRequest{Cwd: cwd, McpServers: []acp.McpServer{}})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// describeAuthMethods renders the agent's advertised auth methods as
// remediation guidance for the returned error
func describeAuthMethods(methods []acp.AuthMethod, agentName string, hostMode bool) string {
	if len(methods) == 0 {
		return fmt.Sprintf("The agent advertised no authentication methods; configure its credentials via [builder_agent.%s] env or config_files.", agentName)
	}
	var options []string
	for _, method := range methods {
		switch {
		case method.EnvVar != nil:
			vars := make([]string, 0, len(method.EnvVar.Vars))
			for _, envVar := range method.EnvVar.Vars {
				name := envVar.Name
				if envVar.Optional {
					name += " (optional)"
				}
				vars = append(vars, name)
			}
			option := fmt.Sprintf("set %s in the [builder_agent.%s] env config", strings.Join(vars, ", "), agentName)
			if method.EnvVar.Link != nil && *method.EnvVar.Link != "" {
				option += fmt.Sprintf(" (get credentials at %s)", *method.EnvVar.Link)
			}
			options = append(options, option)
		case method.Agent != nil:
			if hostMode {
				options = append(options, fmt.Sprintf("%s (agent-managed browser login)", method.Agent.Name))
			} else {
				options = append(options, fmt.Sprintf("%s (agent-managed browser login; only available with security.unsafe_agent_without_sandbox - a sandboxed agent cannot open a browser)", method.Agent.Name))
			}
		case method.Terminal != nil:
			options = append(options, fmt.Sprintf("%s (interactive terminal login, not supported by OpenRun)", method.Terminal.Name))
		}
	}
	return "Options: " + strings.Join(options, "; ")
}
