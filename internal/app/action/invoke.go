// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// The invocation core: every surface an action is reachable through (the form
// UI, the actions REST API, the management API used by the CLI and the MCP
// tools) builds an Invocation, calls Invoke and renders the Outcome. Arg
// coercion, the handler call, result decoding, stream start, plugin cleanup
// and the audit events live here so the surfaces cannot drift

// Op is the operation to run on an action
type Op int

const (
	OpRun      Op = iota // run the handler
	OpValidate           // run the handler with dry_run=True
	OpSuggest            // run the suggest handler
)

// Audit operation prefixes, one per surface. The audit operation is
// <source>_execute|suggest|validate, the form UI uses the bare names
const (
	SourceUI   = ""
	SourceAPI  = "api"
	SourceMgmt = "mgmt"
	SourceMCP  = "mcp"
)

// AuditOp returns the audit operation name for an op on a surface
func AuditOp(source string, op Op) string {
	name := "execute"
	switch op {
	case OpValidate:
		name = "validate"
	case OpSuggest:
		name = "suggest"
	}
	if source == "" {
		return name
	}
	return source + "_" + name
}

// UploadedFile is a file submitted for a file upload param
type UploadedFile struct {
	Filename string
	Open     func() (io.ReadCloser, error)
}

// Invocation is one call of an action
type Invocation struct {
	Op      Op
	AuditOp string // audit operation name, see AuditOp

	// JSONArgs are the arg values keyed by param name. Params not present
	// retain the app level param values. Used when IsForm is false
	JSONArgs map[string]jsontext.Value

	// IsForm selects form semantics: Form holds the submitted fields, a
	// boolean param missing from the form is false (unchecked checkbox) and a
	// missing file is the empty string
	IsForm bool
	Form   url.Values

	// Files are the uploads for file upload params, keyed by param name
	Files map[string]UploadedFile
}

// InvokeError is a failed invocation, Code has the HTTP status semantics
// (400 bad args, 403 not permitted, 500 handler failure, 501 no suggest)
type InvokeError struct {
	Code int
	Msg  string
}

func (e *InvokeError) Error() string {
	return e.Msg
}

func invokeErr(code int, format string, args ...any) *InvokeError {
	return &InvokeError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Outcome is the result of an invocation. Close must be called once the
// outcome has been rendered: it releases the stream, the uploaded files and
// writes the audit events
type Outcome struct {
	Status      string
	Report      string // report type as returned by the handler, can be AUTO
	ValuesStr   []string
	ValuesMap   []map[string]any
	ParamErrors map[string]any
	Suggest     starlark.Value   // the suggest handler response, for OpSuggest
	QueryParams url.Values       // non password form values, for the UI push url
	Run         *types.ActionRun // the started run of an async action; the other fields are unset

	stream func(yield func(any, error) bool)
	event  *types.AuditEvent
	finish func()
}

// IsStream reports whether the handler returned a stream result
func (o *Outcome) IsStream() bool {
	return o.stream != nil
}

// Close releases the resources of the invocation and records the audit events
func (o *Outcome) Close() {
	o.finish()
}

// Authorized reports whether the caller has access to the action, as per the
// action's permit list
func (a *Action) Authorized(ctx context.Context) (bool, error) {
	if a.rbacApi == nil || len(a.permit) == 0 {
		return true, nil
	}
	return a.rbacApi.AuthorizeAny(ctx, a.permit)
}

// Invoke authorizes the caller against the permit list and calls the action
func (a *Action) Invoke(ctx context.Context, inv Invocation) (*Outcome, *InvokeError) {
	authorized, err := a.Authorized(ctx)
	if err != nil {
		return nil, invokeErr(http.StatusInternalServerError, "%s", err)
	}
	if !authorized {
		return nil, invokeErr(http.StatusForbidden, "Forbidden : %s does not have access to action %s",
			system.GetContextUserId(ctx), a.name)
	}
	return a.invoke(ctx, inv)
}

// invoke calls the action, the caller has been authorized already
func (a *Action) invoke(ctx context.Context, inv Invocation) (retOutcome *Outcome, retErr *InvokeError) {
	if inv.Op == OpSuggest && a.suggest == nil {
		return nil, invokeErr(http.StatusNotImplemented, "suggest not supported for this action")
	}

	thread := &starlark.Thread{
		Name:  a.name,
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) },
	}

	// Status starts as Failed and is set to Success only after the action
	// handler runs without error, so that arg errors and panics are not
	// recorded as a success
	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(ctx),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(ctx),
		AppId:      system.GetContextAppId(ctx),
		EventType:  types.EventTypeAction,
		Operation:  inv.AuditOp,
		Target:     a.name,
		Status:     string(types.EventStatusFailure),
	}

	customEvent := types.AuditEvent{
		RequestId:  system.GetContextRequestId(ctx),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(ctx),
		AppId:      system.GetContextAppId(ctx),
		EventType:  types.EventTypeCustom,
	}

	var tempDir string
	var streamVal apptype.StreamValue
	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() {
			// A no-op after the explicit cleanup below, unless the
			// invocation is being abandoned on an error path
			if err := RunDeferredCleanup(thread); err != nil {
				a.Error().Err(err).Msg("error cleaning up plugins")
			}
			if streamVal != nil {
				streamVal.CloseStream()
			}
			if tempDir != "" {
				if remErr := os.RemoveAll(tempDir); remErr != nil {
					a.Error().Err(remErr).Msg("error removing temp dir")
				}
			}
			if a.auditInsert == nil {
				return
			}
			if err := a.auditInsert(&event); err != nil {
				a.Error().Err(err).Msg("error inserting audit event")
			}

			customEvent.Status = event.Status
			customEvent.Operation = system.GetThreadLocalKey(thread, types.TL_AUDIT_OPERATION)
			customEvent.Target = system.GetThreadLocalKey(thread, types.TL_AUDIT_TARGET)
			customEvent.Detail = system.GetThreadLocalKey(thread, types.TL_AUDIT_DETAIL)
			if customEvent.Operation != "" {
				// Audit event was set in handler, insert it
				if err := a.auditInsert(&customEvent); err != nil {
					a.Error().Err(err).Msg("error inserting custom audit event")
				}
			}
		})
	}
	defer func() {
		// Error returns and panics: nothing is handed to the caller to close
		if retOutcome == nil {
			finish()
		}
	}()

	// Save the request context in the starlark thread local
	// Same code as createHandlerFunc
	thread.SetLocal(types.TL_CONTEXT, ctx)
	if a.containerProxyUrl != "" {
		thread.SetLocal(types.TL_CONTAINER_URL, a.containerProxyUrl)
	}
	if a.containerHandler != nil {
		thread.SetLocal(types.TL_CONTAINER_HANDLER, a.containerHandler)
	}
	thread.SetLocal(types.TL_APP_URL, types.GetAppUrl(a.appPathDomain, a.serverConfig))

	args := starlark.StringDict{}
	// Make a copy of the app level param dict
	for k, v := range a.paramDict {
		args[k] = v
	}

	options, optionsErr := a.paramOptions()
	if optionsErr != nil {
		return nil, invokeErr(http.StatusBadRequest, "%s", optionsErr)
	}

	qsParams := url.Values{}
	if !inv.IsForm {
		if err := a.buildArgsFromJSON(args, inv.JSONArgs, options); err != nil {
			return nil, invokeErr(http.StatusBadRequest, "%s", err)
		}
	}

	// Update args with the uploaded files and the submitted form values
	for _, param := range a.params {
		if a.hidden[param.Name] {
			continue
		}

		if param.DisplayType == apptype.DisplayTypeFileUpload {
			upload, ok := inv.Files[param.Name]
			if !ok {
				if inv.IsForm {
					args[param.Name] = starlark.String("")
				}
				continue
			}

			if tempDir == "" {
				var err error
				tempDir, err = os.MkdirTemp("", "openrun-file-upload-*")
				if err != nil {
					return nil, invokeErr(http.StatusInternalServerError, "%s", err)
				}
			}
			fullPath, saveErr := saveUploadedFile(tempDir, param.Name, upload)
			if saveErr != nil {
				return nil, saveErr
			}
			args[param.Name] = starlark.String(fullPath)
			continue
		}

		if !inv.IsForm {
			continue // args were built from the JSON args
		}

		hasValue := inv.Form.Has(param.Name)
		formValue := inv.Form.Get(param.Name)
		if param.Type == starlark_type.BOOLEAN && !hasValue {
			// Form does not submit unchecked checkboxes, set to false
			args[param.Name] = starlark.Bool(false)
			qsParams.Add(param.Name, "false")
		} else if hasValue {
			// Dropdown params are strict by default: a non-empty value
			// must be one of the configured options (COMBO display type
			// allows free text; empty is left for the handler's own
			// required-value validation). Suggest provided lists are
			// transient and are not checked here
			opts := options[param.Name]
			if len(opts) > 0 && formValue != "" && param.DisplayType != apptype.DisplayTypeCombo &&
				!slices.Contains(opts, formValue) {
				return nil, invokeErr(http.StatusBadRequest, "invalid value for %s: must be one of the configured options", param.Name)
			}

			newVal, err := apptype.ParamStringToType(param.Name, param.Type, formValue)
			if err != nil {
				return nil, invokeErr(http.StatusBadRequest, "%s", err)
			}
			args[param.Name] = newVal

			if param.DisplayType != apptype.DisplayTypePassword {
				qsParams.Add(param.Name, formValue)
			}
		}
	}

	if inv.Op == OpRun && a.IsAsync() {
		// An async action: the run executes in the background with the args
		// built above; the uploaded files now belong to the run. The
		// submission's audit event records the run id
		run, runErr := a.startRun(ctx, inv, args, tempDir)
		if runErr != nil {
			return nil, runErr
		}
		tempDir = ""
		event.Status = string(types.EventStatusSuccess)
		event.Detail = run.Id
		return &Outcome{QueryParams: qsParams, Run: run, event: &event, finish: finish}, nil
	}

	argsValue := Args{members: args}

	callable := a.run
	callInput := starlark.Tuple{starlark.Bool(inv.Op == OpValidate), &argsValue}
	if inv.Op == OpSuggest {
		callable = a.suggest
		callInput = starlark.Tuple{&argsValue}
	}

	// Call the handler function
	ret, callErr := a.callHandler(thread, callable, callInput)
	if callErr != nil {
		return nil, callErr
	}
	event.Status = string(types.EventStatusSuccess)

	outcome := &Outcome{QueryParams: qsParams, Report: apptype.AUTO, event: &event, finish: finish}
	if inv.Op == OpSuggest {
		outcome.Suggest = ret
		if cleanupErr := RunDeferredCleanup(thread); cleanupErr != nil {
			a.Error().Err(cleanupErr).Msg("error cleaning up plugins")
			return nil, invokeErr(http.StatusInternalServerError, "%s", cleanupErr)
		}
		return outcome, nil
	}

	decoded, decodeErr := decodeResult(ret)
	if decodeErr != nil {
		return nil, decodeErr
	}
	outcome.Status, outcome.Report = decoded.status, decoded.report
	outcome.ValuesMap, outcome.ValuesStr, outcome.ParamErrors = decoded.valuesMap, decoded.valuesStr, decoded.paramErrors
	streamVal = decoded.stream

	if streamVal != nil {
		if inv.Op == OpValidate {
			// Validation must not start commands; finish releases the process
			return nil, invokeErr(http.StatusInternalServerError, "validate handler returned a stream: the run handler must return before starting commands when dry_run is true")
		}
		// Detach the stream from the plugin cleanup below, which would
		// otherwise close it as an unconsumed resource
		streamSeq, streamErr := streamVal.StartStream()
		if streamErr != nil {
			return nil, invokeErr(http.StatusInternalServerError, "error starting result stream: %s", streamErr)
		}
		outcome.stream = streamSeq
		// Success is recorded only once the command has exited cleanly
		event.Status = string(types.EventStatusFailure)
	}

	if cleanupErr := RunDeferredCleanup(thread); cleanupErr != nil {
		a.Error().Err(cleanupErr).Msg("error cleaning up plugins")
		return nil, invokeErr(http.StatusInternalServerError, "%s", cleanupErr)
	}

	return outcome, nil
}

// callHandler calls an action handler on the thread, promoting a plugin API
// failure to an error and mapping errors to the invocation error the
// surfaces report (the first frame appended for dev apps)
func (a *Action) callHandler(thread *starlark.Thread, callable starlark.Callable, callInput starlark.Tuple) (starlark.Value, *InvokeError) {
	ret, err := starlark.Call(thread, callable, callInput, nil)
	if err == nil {
		pluginErrLocal := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR)
		if pluginErrLocal != nil {
			pluginErr := pluginErrLocal.(error)
			a.Error().Err(pluginErr).Msg("handler had plugin API failure")
			err = pluginErr // handle as if the handler had returned an error
		}
	}
	if err == nil {
		return ret, nil
	}
	a.Error().Err(err).Msg("error calling action run handler")

	firstFrame := ""
	if evalErr, ok := err.(*starlark.EvalError); ok {
		// Iterate through the CallFrame stack for debugging information
		for i, frame := range evalErr.CallStack {
			a.Warn().Msgf("Function: %s, Position: %s\n", frame.Name, frame.Pos)
			if i == 0 {
				firstFrame = fmt.Sprintf("Function %s, Position %s", frame.Name, frame.Pos)
			}
		}
	}

	msg := err.Error()
	if firstFrame != "" && a.isDev {
		msg = msg + " : " + firstFrame
	}
	// err handler is not supported for actions
	return nil, invokeErr(http.StatusInternalServerError, "%s", msg)
}

// decodedResult is a run handler's return value, decoded
type decodedResult struct {
	status      string
	report      string
	valuesMap   []map[string]any
	valuesStr   []string
	paramErrors map[string]any
	stream      apptype.StreamValue
}

// decodeResult decodes what a run handler returned: an ace.result struct, a
// stream returned directly (shorthand for ace.result("", stream=ret)), or
// any other value whose string form is the status
func decodeResult(ret starlark.Value) (*decodedResult, *InvokeError) {
	decoded := &decodedResult{report: apptype.AUTO}
	var err error
	resultStruct, ok := ret.(*starlarkstruct.Struct)
	if ok {
		decoded.status, err = apptype.GetOptionalStringAttr(resultStruct, "status")
		if err != nil {
			return nil, invokeErr(http.StatusInternalServerError, "error getting result status: %s", err)
		}

		decoded.valuesMap, err = apptype.GetListMapAttr(resultStruct, "values", true)
		if err != nil {
			decoded.valuesStr, err = apptype.GetListStringAttr(resultStruct, "values", true)
			if err != nil {
				return nil, invokeErr(http.StatusInternalServerError, "error getting result values, not a list of string or list of maps: %s", err)
			}
		}

		decoded.paramErrors, err = apptype.GetDictAttr(resultStruct, "param_errors", true)
		if err != nil {
			return nil, invokeErr(http.StatusInternalServerError, "error getting result attr paramErrors: %s", err)
		}

		decoded.report, err = apptype.GetOptionalStringAttr(resultStruct, "report")
		if err != nil {
			return nil, invokeErr(http.StatusInternalServerError, "error getting result report: %s", err)
		}

		streamAttr, attrErr := resultStruct.Attr("stream")
		if attrErr == nil && streamAttr != nil && streamAttr != starlark.None {
			sv, isStream := streamAttr.(apptype.StreamValue)
			if !isStream {
				return nil, invokeErr(http.StatusInternalServerError, "result stream must be the response of a plugin call made with stream=True")
			}
			decoded.stream = sv
		}
	} else if sv, isStream := ret.(apptype.StreamValue); isStream {
		decoded.stream = sv
	} else {
		// Not a result struct
		decoded.status = strings.Trim(ret.String(), "\"")
	}
	return decoded, nil
}

// auditRejectedRequest records the failed action event for a request a
// transport refused before the invocation (a body which cannot be parsed or
// is over the size limit): a rejected attempt is part of the action audit
// trail, as the attempts which fail in invoke are
func (a *Action) auditRejectedRequest(ctx context.Context, auditOp string) {
	if a.auditInsert == nil {
		return
	}
	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(ctx),
		CreateTime: time.Now(),
		UserId:     system.GetContextUserId(ctx),
		AppId:      system.GetContextAppId(ctx),
		EventType:  types.EventTypeAction,
		Operation:  auditOp,
		Target:     a.name,
		Status:     string(types.EventStatusFailure),
	}
	if err := a.auditInsert(&event); err != nil {
		a.Error().Err(err).Msg("error inserting audit event")
	}
}

// saveUploadedFile writes an upload into the temp dir of the invocation
func saveUploadedFile(tempDir, paramName string, upload UploadedFile) (string, *InvokeError) {
	f, err := upload.Open()
	if err != nil {
		return "", invokeErr(http.StatusBadRequest, "error getting file %s: %s", paramName, err)
	}

	fullPath, err := uploadedFilePath(tempDir, upload.Filename)
	if err != nil {
		_ = f.Close()
		return "", invokeErr(http.StatusBadRequest, "%s", err)
	}

	destFile, err := os.Create(fullPath)
	if err != nil {
		_ = f.Close()
		return "", invokeErr(http.StatusInternalServerError, "%s", err)
	}

	// Write contents of uploaded file to destFile
	_, copyErr := io.Copy(destFile, f)
	closeErr := errors.Join(destFile.Close(), f.Close())
	if err = errors.Join(copyErr, closeErr); err != nil {
		return "", invokeErr(http.StatusInternalServerError, "%s", err)
	}
	return fullPath, nil
}

// ConsumeStream drains the result stream, passing each output chunk (with
// its trailing newline restored) to emit, and records the stream outcome for
// the audit event. It returns the command's exit status when the stream ended
// through a process exit (0 for a clean end without an exit error), or an
// error for a caller disconnect, an emit failure or a stream failure that is
// not an exit status
func (o *Outcome) ConsumeStream(ctx context.Context, emit func(chunk string) error) (int, error) {
	exitStatus, err := consumeStream(ctx, o.stream, emit)
	recordStreamOutcome(o.event, exitStatus, err)
	return exitStatus, err
}
