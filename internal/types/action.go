// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import "encoding/json/jsontext"

// Types for the management API of app actions (openrun action ..., and the
// list_actions/get_action/run_action/suggest_action MCP tools)

// ActionDef is what the list of actions needs to know of an action defined by
// an app: persisted in the version metadata when the app definition loads
// (AppMetadata.DefinitionActions), so that actions are listed from the
// database without loading apps. The params are not part of it: describing
// and running an action use the loaded definition
type ActionDef struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Description string   `json:"description,omitempty"`
	Suggest     bool     `json:"suggest,omitempty"`
	Permit      []string `json:"permit,omitempty"` // custom permissions of which the caller needs one
}

// ActionInfo is one action of an app, as listed for a caller who can run it
type ActionInfo struct {
	AppPath     string `json:"app_path"`
	Name        string `json:"name"`
	Tool        string `json:"tool"` // the name the action is selected by
	Path        string `json:"path"` // the action path within the app
	Description string `json:"description,omitempty"`
	Suggest     bool   `json:"suggest"`
}

// ActionListResponse is the response of the list actions API. Warnings has
// the apps whose definition could not be loaded
type ActionListResponse struct {
	Actions  []ActionInfo `json:"actions"`
	Warnings []string     `json:"warnings,omitempty"`
}

// ActionParam is a param of an action
type ActionParam struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Required    bool     `json:"required"`
	DisplayType string   `json:"display_type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// ActionDetailResponse is the response of the get action API
type ActionDetailResponse struct {
	ActionInfo
	Url         string         `json:"url"` // the form UI of the action
	Params      []ActionParam  `json:"params"`
	InputSchema map[string]any `json:"input_schema"` // JSON schema of the args
}

// ActionRunRequest is the body of the run and suggest action APIs. With file
// upload params the request is multipart/form-data: this document in the
// "request" field, one file part per file param
type ActionRunRequest struct {
	AppPath string                    `json:"app_path"`
	Action  string                    `json:"action,omitempty"` // tool name or action path; optional for a single action app
	Stage   bool                      `json:"stage,omitempty"`  // use the staging instance of the app
	DryRun  bool                      `json:"dry_run,omitempty"`
	Args    map[string]jsontext.Value `json:"args,omitempty"`
}

// ActionResult is the response of the run action API for a result which is
// not a stream. A stream result is answered as chunked text/plain, with the
// status in the OpenRun-Action-Status header and the exit status in the
// OpenRun-Exit-Status trailer, as the actions REST API does
type ActionResult struct {
	Status      string            `json:"status"`
	Report      string            `json:"report,omitempty"`
	Values      []any             `json:"values,omitempty"`
	ParamErrors map[string]string `json:"param_errors,omitempty"`
}

// ActionSuggestResponse is the response of the suggest action API
type ActionSuggestResponse struct {
	Status string         `json:"status"`
	Params map[string]any `json:"params,omitempty"`
}

// Headers and trailers of a streamed action result
const (
	ACTION_STATUS_HEADER = "OpenRun-Action-Status"
	ACTION_EXIT_TRAILER  = "OpenRun-Exit-Status"
)
