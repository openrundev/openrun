// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// slugName converts a display name to a lowercase identifier: runs of
// characters other than letters and digits become a single underscore
func slugName(name string) string {
	var b strings.Builder
	pendingSep := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if pendingSep && b.Len() > 0 {
				b.WriteByte('_')
			}
			pendingSep = false
			b.WriteRune(r)
		} else {
			pendingSep = true
		}
	}
	return b.String()
}

// ToolNames returns a unique tool name for each action: the name an action is
// selected by in the CLI, the MCP tool name and the name in the OpenAPI
// operation ids (run_<name>, validate_<name>, ...). The name is derived from the
// action path (/orders/cancel is orders_cancel), the action at the root path
// takes the slug of its action name instead (Cancel Order is cancel_order),
// no caller should have to type "root". Colliding names get a numeric suffix,
// chosen so it does not clash with the name of any other action either
func ToolNames(actions []*Action) map[*Action]string {
	paths, actionNames := make([]string, len(actions)), make([]string, len(actions))
	for i, act := range actions {
		paths[i], actionNames[i] = act.actionPath, act.name
	}
	toolNames := toolNamesFor(paths, actionNames)
	names := make(map[*Action]string, len(actions))
	for i, act := range actions {
		names[act] = toolNames[i]
	}
	return names
}

// ToolNamesOfDefs is ToolNames for the action definitions persisted in the app
// metadata: the same names, in the order of the definitions
func ToolNamesOfDefs(defs []types.ActionDef) []string {
	paths, actionNames := make([]string, len(defs)), make([]string, len(defs))
	for i, def := range defs {
		paths[i], actionNames[i] = def.Path, def.Name
	}
	return toolNamesFor(paths, actionNames)
}

// Defs returns the definitions of the actions as persisted in the app metadata
func Defs(actions []*Action) []types.ActionDef {
	defs := make([]types.ActionDef, 0, len(actions))
	for _, act := range actions {
		defs = append(defs, types.ActionDef{
			Name:        act.name,
			Path:        act.actionPath,
			Description: act.description,
			Suggest:     act.suggest != nil,
			Permit:      slices.Clone(act.permit),
		})
	}
	return defs
}

func toolNamesFor(paths, actionNames []string) []string {
	baseNames := make([]string, len(paths))
	reserved := map[string]bool{}
	for i := range paths {
		name := slugName(strings.ReplaceAll(strings.Trim(paths[i], "/"), "/", " "))
		if name == "" {
			name = slugName(actionNames[i])
		}
		if name == "" {
			name = "root"
		}
		baseNames[i] = name
		reserved[name] = true
	}

	names := make([]string, len(paths))
	used := map[string]bool{}
	for i := range paths {
		name := baseNames[i]
		if used[name] {
			for suffix := 2; ; suffix++ {
				candidate := fmt.Sprintf("%s_%d", name, suffix)
				if !used[candidate] && !reserved[candidate] {
					name = candidate
					break
				}
			}
		}
		used[name] = true
		names[i] = name
	}
	return names
}

// FindAction resolves an action selector: a tool name (cancel_order) or an
// action path (/cancel). An empty selector selects the only action of a
// single action app
func FindAction(actions []*Action, selector string) (*Action, error) {
	if selector == "" {
		if len(actions) == 1 {
			return actions[0], nil
		}
		return nil, fmt.Errorf("app has %d actions, specify the action to use", len(actions))
	}

	names := ToolNames(actions)
	for _, act := range actions {
		if names[act] == selector {
			return act, nil
		}
	}
	if strings.HasPrefix(selector, "/") {
		for _, act := range actions {
			if act.actionPath == selector || strings.TrimSuffix(selector, "/") == act.actionPath {
				return act, nil
			}
		}
	}
	return nil, fmt.Errorf("action %q not found", selector)
}
