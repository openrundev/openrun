// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"fmt"
	"strings"

	acp "github.com/coder/acp-go-sdk"
)

// configOptionSetter is the subset of the ACP connection used to set session
// config options, split out so tests can fake the agent side
type configOptionSetter interface {
	SetSessionConfigOption(ctx context.Context, params acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error)
}

// applySessionConfig sets the profile's model and reasoning effort on a new
// ACP session through the session config options the agent advertised in
// session/new. Best-effort: a missing option or a failed set produces a
// warning, not an error - the OPENRUN_AGENT_MODEL/EFFORT env vars set at
// sandbox start remain the fallback for agents without config options
func applySessionConfig(ctx context.Context, conn configOptionSetter, sessionId acp.SessionId,
	options []acp.SessionConfigOption, model, effort string) []string {

	var warnings []string
	apply := func(kind, value string, match func(*acp.SessionConfigOptionSelect) bool) {
		if value == "" {
			return
		}
		for _, option := range options {
			sel := option.Select
			if sel == nil || !match(sel) {
				continue
			}
			chosen, ok := matchOptionValue(sel, value)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("agent %s option has no value %q (agent offers: %s)",
					kind, value, strings.Join(optionValues(sel), ", ")))
				return
			}
			if _, err := conn.SetSessionConfigOption(ctx, acp.SetSessionConfigOptionRequest{
				ValueId: &acp.SetSessionConfigOptionValueId{SessionId: sessionId, ConfigId: sel.Id, Value: chosen},
			}); err != nil {
				warnings = append(warnings, fmt.Sprintf("setting agent %s to %q failed: %s", kind, value, err))
			}
			return
		}
		warnings = append(warnings, fmt.Sprintf(
			"agent does not advertise a %s config option, the configured %s %q may be ignored", kind, kind, value))
	}

	apply("model", model, func(sel *acp.SessionConfigOptionSelect) bool {
		return strings.EqualFold(string(sel.Id), "model") ||
			(sel.Category != nil && *sel.Category == acp.SessionConfigOptionCategoryModel)
	})
	apply("effort", effort, func(sel *acp.SessionConfigOptionSelect) bool {
		id := strings.ToLower(string(sel.Id))
		return strings.Contains(id, "effort") || strings.Contains(id, "thinking") || strings.Contains(id, "reasoning") ||
			(sel.Category != nil && *sel.Category == acp.SessionConfigOptionCategoryThoughtLevel)
	})
	return warnings
}

// selectOptions flattens a select's grouped or ungrouped value list
func selectOptions(sel *acp.SessionConfigOptionSelect) []acp.SessionConfigSelectOption {
	if sel.Options.Ungrouped != nil {
		return *sel.Options.Ungrouped
	}
	var flat []acp.SessionConfigSelectOption
	if sel.Options.Grouped != nil {
		for _, group := range *sel.Options.Grouped {
			flat = append(flat, group.Options...)
		}
	}
	return flat
}

// matchOptionValue finds the advertised option value for a configured
// string: exact value id, then case-insensitive name, then a provider-suffix
// match so "claude-opus-4-8" picks "anthropic/claude-opus-4-8"
func matchOptionValue(sel *acp.SessionConfigOptionSelect, value string) (acp.SessionConfigValueId, bool) {
	flat := selectOptions(sel)
	for _, opt := range flat {
		if string(opt.Value) == value {
			return opt.Value, true
		}
	}
	for _, opt := range flat {
		if strings.EqualFold(opt.Name, value) {
			return opt.Value, true
		}
	}
	for _, opt := range flat {
		if strings.HasSuffix(string(opt.Value), "/"+value) {
			return opt.Value, true
		}
	}
	return "", false
}

func optionValues(sel *acp.SessionConfigOptionSelect) []string {
	flat := selectOptions(sel)
	values := make([]string, 0, len(flat))
	for _, opt := range flat {
		values = append(values, string(opt.Value))
	}
	return values
}
