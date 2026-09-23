// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/jsontext"
	"time"
)

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
	Async       bool     `json:"async,omitempty"`  // the handler runs in the background (arch/docs/async-actions.md)
}

// ActionInfo is one action of an app, as listed for a caller who can run it
type ActionInfo struct {
	AppPath     string `json:"app_path"`
	Name        string `json:"name"`
	Tool        string `json:"tool"` // the name the action is selected by
	Path        string `json:"path"` // the action path within the app
	Description string `json:"description,omitempty"`
	Suggest     bool   `json:"suggest"`
	Async       bool   `json:"async"` // the handler runs in the background, the run APIs manage the runs
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

// Async action run statuses
const (
	ActionRunRunning   = "running"
	ActionRunSucceeded = "succeeded"
	ActionRunFailed    = "failed"
	ActionRunTimedOut  = "timed_out"
	ActionRunCanceled  = "canceled"
	ActionRunLost      = "lost"
)

// ActionRun is the record of an async action run (the action_runs table).
// The payload fields (Output*, Result, ParamErrors) are loaded on request
type ActionRun struct {
	Id         string            `json:"id"`
	AppId      AppId             `json:"app_id"`
	AppPath    string            `json:"app_path"`
	ActionPath string            `json:"action_path"`
	ActionName string            `json:"action_name"`
	Source     string            `json:"source"` // ui, api, mgmt or mcp
	Actor      string            `json:"actor"`
	RequestId  string            `json:"request_id,omitempty"`
	Version    int               `json:"version"`
	Args       map[string]string `json:"args,omitempty"` // redacted: no password params, file params as file names
	StartedAt  time.Time         `json:"started_at"`
	EndedAt    *time.Time        `json:"ended_at,omitempty"`
	Status     string            `json:"status"`
	Message    string            `json:"message,omitempty"` // error text
	NodeId     string            `json:"node_id"`
	LeaseUntil *time.Time        `json:"lease_until,omitempty"`

	IsStream           bool   `json:"is_stream"`
	ExitCode           *int   `json:"exit_code,omitempty"`
	OutputBytes        int64  `json:"output_bytes"`         // total output produced
	OutputOmittedBytes int64  `json:"output_omitted_bytes"` // bytes dropped between the head and the tail
	OutputHead         string `json:"output_head,omitempty"`
	OutputTail         string `json:"output_tail,omitempty"`

	ResultStatus    string            `json:"result_status,omitempty"` // the ace.result status text
	Report          string            `json:"report,omitempty"`        // effective report type
	Result          string            `json:"result,omitempty"`        // JSON list of the result values
	ParamErrors     map[string]string `json:"param_errors,omitempty"`
	ResultRows      int               `json:"result_rows"` // rows the handler returned
	ResultTruncated bool              `json:"result_truncated"`
}

// IsActive reports whether the run is still executing
func (r *ActionRun) IsActive() bool {
	return r.Status == ActionRunRunning
}

// BasicView returns the run without its payload columns, for lists
func (r ActionRun) BasicView() ActionRun {
	r.OutputHead, r.OutputTail, r.Result, r.ParamErrors = "", "", "", nil
	return r
}

// ActionRunStarted is the response of the run action API when the action is
// async: the run was started, its record is read with the run APIs
type ActionRunStarted struct {
	RunId  string `json:"run_id"`
	Status string `json:"status"`
	Url    string `json:"url,omitempty"` // the run page in the app UI
}

// ActionRunResponse is the response of the get and cancel run APIs
type ActionRunResponse struct {
	Run ActionRun `json:"run"`
}

// ActionRunsResponse is the response of the list runs API
type ActionRunsResponse struct {
	Runs []ActionRun `json:"runs"`
}

// ActionRunOutputResponse is the response of the run output API: the output
// from the requested offset (the head, an omitted marker and the tail when
// starting from zero), and the total produced so far for the next read
type ActionRunOutputResponse struct {
	Run    ActionRun `json:"run"`
	Output string    `json:"output"`
	Since  int64     `json:"since"` // offset the output starts at
}

// Headers and trailers of a streamed action result
const (
	ACTION_STATUS_HEADER = "OpenRun-Action-Status"
	ACTION_EXIT_TRAILER  = "OpenRun-Exit-Status"
)
