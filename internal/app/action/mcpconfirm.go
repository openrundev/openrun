// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"encoding/json/jsontext"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
)

// Destructive confirmation for MCP tools (multi round-trip requests,
// SEP-2322): an action declared destructive=True is not run on the first
// call from a capable client. The call runs the validate pass instead and
// answers input_required with an elicitation; the client retries the same
// call with the user's answer, and the action runs only on an accepted
// answer. Shared by the per-app tools (mcp.go) and the management run_action
// tool (server/mcp.go). Clients on an older protocol, or without an
// elicitation capability, cannot complete the round trip and run at once, as
// before confirmation existed

// MCPConfirmKey is the input request id of the confirmation
const MCPConfirmKey = "confirm"

// MCPConfirmSupported reports whether the calling client can complete a
// confirmation round trip in stateless mode: protocol 2026-07-28 or later
// (the input_required retry is client-driven; older clients would need the
// server-side live elicitation bridge, which stateless mode cannot serve)
// and a declared form elicitation capability, the mode the confirmation
// uses. An elicitation capability naming no mode means form (the shape of
// clients before modes existed); a client naming url only cannot answer a
// form and runs at once, as a client without elicitation does. In stateless
// mode the SDK fills the initialize params from the _meta of each request
func MCPConfirmSupported(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	iparams := req.Session.InitializeParams()
	if iparams == nil || iparams.ProtocolVersion < "2026-07-28" || iparams.Capabilities == nil {
		return false
	}
	elicitation := iparams.Capabilities.Elicitation
	if elicitation == nil {
		return false
	}
	return elicitation.Form != nil || elicitation.URL == nil
}

// MCPConfirmAnswer reports whether the call carries the answer to the
// confirmation (the retry) and whether the user accepted
func MCPConfirmAnswer(req *mcp.CallToolRequest) (answered, accepted bool) {
	if req == nil || req.Params == nil {
		return false, false
	}
	response, ok := req.Params.InputResponses[MCPConfirmKey]
	if !ok {
		return false, false
	}
	elicit, ok := response.(*mcp.ElicitResult)
	return true, ok && elicit.Action == "accept"
}

// MCPConfirmRequest is the input_required result asking the user to confirm
func MCPConfirmRequest(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			MCPConfirmKey: &mcp.ElicitParams{
				Mode:            "form",
				Message:         message,
				RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			},
		},
	}
}

// MCPDeclinedStatus is the status of a declined confirmation
const MCPDeclinedStatus = "declined by the user, no changes were made"

// MCPDeclinedResult is the result of a declined confirmation: not an error,
// nothing ran
func MCPDeclinedResult() *mcp.CallToolResult {
	return &mcp.CallToolResult{
		StructuredContent: map[string]any{"status": MCPDeclinedStatus, "confirmed": false},
		Content:           []mcp.Content{&mcp.TextContent{Text: MCPDeclinedStatus + "\n"}},
	}
}

// MCPConfirmMessage builds the confirmation prompt of an action: the action,
// its app and description, the args as name=value lines (password params
// hidden) and the status the validate pass reported
func (a *Action) MCPConfirmMessage(args map[string]jsontext.Value, previewStatus string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Confirm %s on %s", a.name, a.appPath)
	if desc := strings.TrimSpace(a.description); desc != "" {
		b.WriteString(": " + desc)
	}
	b.WriteString("\n")
	if len(args) > 0 {
		b.WriteString("Arguments:\n")
		for _, name := range slices.Sorted(maps.Keys(args)) {
			value := strings.TrimSpace(string(args[name]))
			if a.isPasswordParam(name) {
				value = "<hidden>"
			}
			fmt.Fprintf(&b, "  %s=%s\n", name, value)
		}
	}
	if previewStatus = strings.TrimSpace(previewStatus); previewStatus != "" {
		b.WriteString(previewStatus + "\n")
	}
	b.WriteString("Accept to run the action, decline to leave everything unchanged.")
	return b.String()
}

func (a *Action) isPasswordParam(name string) bool {
	for _, p := range a.params {
		if p.Name == name {
			return p.DisplayType == apptype.DisplayTypePassword
		}
	}
	return false
}

// mcpConfirmSkipped reports whether the server config turns confirmation
// off ([api.mcp] skip_destructive_confirm, shared with the management
// tools). Read from the effective config at call time: the setting is
// dynamic and the config the action was loaded with may be stale
func (a *Action) mcpConfirmSkipped() bool {
	config := a.serverConfig
	if a.configSource != nil {
		config = a.configSource()
	}
	return config != nil && config.Api.MCP.SkipDestructiveConfirm
}

// mcpAnnotations maps the hints an action declares to its tool annotations;
// nil when the action declares none, so that its tool carries no annotations
// block (clients then assume the worst, as they did before hints existed).
// read_only implies not destructive and idempotent unless declared otherwise
func mcpAnnotations(hints *types.ActionHints) *mcp.ToolAnnotations {
	if hints == nil {
		return nil
	}
	annotations := &mcp.ToolAnnotations{}
	if hints.IsReadOnly() {
		notDestructive := false
		annotations.ReadOnlyHint = true
		annotations.DestructiveHint = &notDestructive
		annotations.IdempotentHint = true
	}
	if hints.Destructive != nil {
		destructive := *hints.Destructive
		annotations.DestructiveHint = &destructive
	}
	if hints.Idempotent != nil {
		annotations.IdempotentHint = *hints.Idempotent
	}
	if hints.OpenWorld != nil {
		openWorld := *hints.OpenWorld
		annotations.OpenWorldHint = &openWorld
	}
	return annotations
}
