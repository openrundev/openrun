// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
	"context"
	"embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html/template"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/benbjohnson/hashfs"
	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

//go:embed *.go.html astatic/*
var embedHtml embed.FS
var embedFS = hashfs.NewFS(embedHtml)

const (
	defaultMaxRequestBodyBytes int64 = 32 << 20
	multipartMaxMemoryBytes    int64 = 10 << 20
)

type ActionLink struct {
	Name       string
	Path       string
	Permits    []string
	Authorized bool
	Active     bool // whether this link is the currently shown action
}

// Action represents a single action that is exposed by the App. Actions
// provide a way to trigger app operations, with an auto-generated form UI
// and an API interface
type Action struct {
	*types.Logger
	isDev               bool
	name                string
	description         string
	appName             string
	appPath             string
	actionPath          string
	run                 starlark.Callable
	suggest             starlark.Callable
	params              []apptype.AppParam
	paramValuesStr      map[string]string
	paramDict           starlark.StringDict
	actionTemplate      *template.Template
	pagePath            string
	AppTemplate         *template.Template
	StyleType           types.StyleType
	LightTheme          string
	DarkTheme           string
	containerProxyUrl   string
	hidden              map[string]bool // params which are not shown in the UI
	Links               []ActionLink    // links to other actions
	showValidate        bool
	auditInsert         func(*types.AuditEvent) error
	containerHandler    any // Container manager, if available, used to run commands in the container
	esmLibs             []types.JSLibrary
	appPathDomain       types.AppPathDomain
	serverConfig        *types.ServerConfig
	maxRequestBodyBytes int64
	permit              []string
	rbacApi             rbac.RBACAPI
	fetchFile           FileFetcher // fetches result files through the app router, see files.go
	config              types.ActionConfig
	async               bool                       // the handler runs in the background (ace.action is_async=True)
	hints               *types.ActionHints         // side-effect hints declared with ace.action, nil when none
	configSource        func() *types.ServerConfig // the effective server config, for the dynamic settings; serverConfig when nil
	timeout             time.Duration              // async run timeout
	runHost             *RunHost                   // the server services async runs need, nil until SetRunHost
}

// NewAction creates a new action
func NewAction(logger *types.Logger, sourceFS *appfs.SourceFs, isDev bool, name, description, appName, apath string, run, suggest starlark.Callable,
	params []apptype.AppParam, paramValuesStr map[string]string, paramDict starlark.StringDict,
	appPath string, styleType types.StyleType, containerProxyUrl string, hidden []string, showValidate bool,
	auditInsert func(*types.AuditEvent) error, containerManager any, jsLibs []types.JSLibrary, appPathDomain types.AppPathDomain,
	serverConfig *types.ServerConfig, actionConfig types.ActionConfig, permit []string, rbacApi rbac.RBACAPI,
	async bool, timeout string) (*Action, error) {

	funcMap := system.GetFuncMap()

	funcMap["static"] = func(name string) string {
		staticPath := path.Join("static", name)
		fullPath := path.Join(appPath, sourceFS.HashName(staticPath))
		return fullPath
	}

	funcMap["astatic"] = func(name string) string {
		fullPath := path.Join(appPath, embedFS.HashName(name))
		return fullPath
	}

	funcMap["fileNonEmpty"] = func(name string) bool {
		staticPath := path.Join("static", name)
		fi, err := sourceFS.Stat(staticPath)
		if err != nil {
			return false
		}
		return fi.Size() > 0
	}

	tmpl, err := template.New("form").Funcs(funcMap).ParseFS(embedFS, "*.go.html")
	if err != nil {
		return nil, err
	}

	slices.SortFunc(params, func(a, b apptype.AppParam) int {
		return a.Index - b.Index
	})

	subLogger := logger.With().Str("action", name).Logger()
	appLogger := types.Logger{Logger: &subLogger}

	pagePath := path.Join(appPath, apath)
	if pagePath == "/" {
		pagePath = ""
	}

	hiddenParams := make(map[string]bool)
	for _, h := range hidden {
		hiddenParams[h] = true
	}

	esmLibs := []types.JSLibrary{}
	for _, lib := range jsLibs {
		if lib.LibType == types.ESModule {
			esmLibs = append(esmLibs, lib)
		}
	}
	if actionConfig.MaxRequestBodyBytes <= 0 {
		actionConfig.MaxRequestBodyBytes = defaultMaxRequestBodyBytes
	}
	actionConfig = withRunDefaults(actionConfig)
	runTimeout, err := runTimeoutOf(timeout, actionConfig)
	if err != nil {
		return nil, err
	}

	return &Action{
		Logger:            &appLogger,
		isDev:             isDev,
		name:              name,
		description:       description,
		appName:           appName,
		appPath:           appPath,
		actionPath:        apath,
		pagePath:          pagePath,
		run:               run,
		suggest:           suggest,
		params:            params,
		paramValuesStr:    paramValuesStr,
		paramDict:         paramDict,
		actionTemplate:    tmpl,
		StyleType:         styleType,
		containerProxyUrl: containerProxyUrl,
		hidden:            hiddenParams,
		showValidate:      showValidate,
		auditInsert:       auditInsert,
		containerHandler:  containerManager,
		esmLibs:           esmLibs,
		// Links, AppTemplate and Theme names are initialized later
		appPathDomain:       appPathDomain,
		serverConfig:        serverConfig,
		maxRequestBodyBytes: actionConfig.MaxRequestBodyBytes,
		permit:              permit,
		rbacApi:             rbacApi,
		config:              actionConfig,
		async:               async,
		timeout:             runTimeout,
	}, nil
}

// IsAsync reports whether the action runs in the background (is_async=True)
func (a *Action) IsAsync() bool {
	return a.async
}

// SetConfigSource sets the accessor of the effective server config, for
// the settings which change dynamically (the MCP confirmation switch)
func (a *Action) SetConfigSource(source func() *types.ServerConfig) {
	a.configSource = source
}

// SetHints sets the side-effect hints declared with ace.action
func (a *Action) SetHints(hints *types.ActionHints) {
	a.hints = hints
}

// Hints returns the side-effect hints declared with ace.action, nil when the
// action declares none
func (a *Action) Hints() *types.ActionHints {
	return a.hints
}

// IsDestructive reports whether the action declares destructive=True: the
// MCP tools ask capable clients to confirm before running it, the form shows
// a badge
func (a *Action) IsDestructive() bool {
	return a.hints.IsDestructive()
}

// Timeout returns the async run timeout
func (a *Action) Timeout() time.Duration {
	return a.timeout
}

func (a *Action) GetLink() ActionLink {
	return ActionLink{
		Name:    a.name,
		Path:    a.pagePath,
		Permits: a.permit,
	}
}

func (a *Action) BuildRouter() (*chi.Mux, error) {
	r := chi.NewRouter()
	r.Get("/", a.getForm)
	r.Post("/", a.runAction)
	r.Post("/suggest", a.suggestAction)
	r.Post("/validate", a.validateAction)
	if a.IsAsync() {
		r.Get("/runs", a.getRunsPage)
		r.Get("/runs/{runId}", a.getRunPage)
		r.Get("/runs/{runId}/status", a.getRunStatusFragment)
		r.Get("/runs/{runId}/output", a.getRunOutput)
		r.Get("/runs/{runId}/result.json", a.getRunResultJSON)
		r.Post("/runs/{runId}/cancel", a.cancelRunUI)
	}

	r.Handle("/astatic/*", http.StripPrefix(path.Join(a.pagePath), hashfs.FileServer(embedFS)))
	return r, nil
}

func (a *Action) runAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, false, false, "execute", false)
}

func (a *Action) suggestAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, true, false, "suggest", false)
}

func (a *Action) validateAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, false, true, "validate", false)
}

func (a *Action) apiRunAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, false, false, "api_execute", true)
}

func (a *Action) apiSuggestAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, true, false, "api_suggest", true)
}

func (a *Action) apiValidateAction(w http.ResponseWriter, r *http.Request) {
	a.execAction(w, r, false, true, "api_validate", true)
}

// writeActionError writes an error response, as plain text for the form UI
// and as a JSON error envelope for the actions REST API
func writeActionError(w http.ResponseWriter, apiMode bool, msg string, code int) {
	if apiMode {
		writeJSONError(w, msg, code)
	} else {
		http.Error(w, msg, code)
	}
}

func (a *Action) authorizeAction(w http.ResponseWriter, r *http.Request, apiMode bool) bool {
	if a.rbacApi != nil && len(a.permit) > 0 {
		authorized, err := a.rbacApi.AuthorizeAny(r.Context(), a.permit)
		if err != nil {
			writeActionError(w, apiMode, err.Error(), http.StatusInternalServerError)
			return false
		}
		if !authorized {
			// Authenticated but not authorized (no matching custom permission): 403
			userId := system.GetContextUserId(r.Context())
			writeActionError(w, apiMode, fmt.Sprintf("Forbidden : %s does not have access to action %s", userId, a.name), http.StatusForbidden)
			return false
		}
	}
	return true
}

func (a *Action) execAction(w http.ResponseWriter, r *http.Request, isSuggest, isValidate bool, op string, apiMode bool) {
	writeError := func(msg string, code int) {
		writeActionError(w, apiMode, msg, code)
	}

	if !a.authorizeAction(w, r, apiMode) {
		return
	}

	if isSuggest && a.suggest == nil {
		writeError("suggest not supported for this action", http.StatusNotImplemented)
		return
	}

	inv := Invocation{Op: OpRun, AuditOp: op}
	if isSuggest {
		inv.Op = OpSuggest
	} else if isValidate {
		inv.Op = OpValidate
	}
	isHtmxRequest := r.Header.Get("HX-Request") == "true"

	r.Body = http.MaxBytesReader(w, r.Body, a.maxRequestBodyBytes)

	// A request which cannot be parsed never reaches invoke, which writes the
	// action audit events: the rejected attempt is recorded here
	if apiMode && requestHasJSONBody(r) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			a.auditRejectedRequest(r.Context(), op, "")
			writeRequestParseError(w, err, a.maxRequestBodyBytes, apiMode)
			return
		}
		if len(bytes.TrimSpace(body)) > 0 { // empty body means use the app level param values
			if err := json.Unmarshal(body, &inv.JSONArgs); err != nil {
				a.auditRejectedRequest(r.Context(), op, "")
				writeRequestParseError(w, err, a.maxRequestBodyBytes, apiMode)
				return
			}
		}
	} else {
		if err := r.ParseMultipartForm(multipartMaxMemoryBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			a.auditRejectedRequest(r.Context(), op, "")
			writeRequestParseError(w, err, a.maxRequestBodyBytes, apiMode)
			return
		}
		if r.MultipartForm == nil {
			// A file upload param can be submitted only in a multipart post
			for _, param := range a.params {
				if param.DisplayType == apptype.DisplayTypeFileUpload && !a.hidden[param.Name] {
					a.auditRejectedRequest(r.Context(), op, "")
					writeError(fmt.Sprintf("error getting file %s: %s", param.Name, http.ErrNotMultipart), http.StatusBadRequest)
					return
				}
			}
		}
		inv.IsForm = true
		inv.Form = r.Form
		inv.Files = multipartFiles(r.MultipartForm)
	}

	outcome, invErr := a.invoke(r.Context(), inv)
	if invErr != nil {
		writeError(invErr.Msg, invErr.Code)
		return
	}
	defer outcome.Close()

	if isSuggest {
		if apiMode {
			a.writeAPISuggestResponse(w, outcome.Suggest)
		} else {
			a.handleSuggestResponse(w, outcome.Suggest)
		}
		return
	}

	if outcome.Run != nil {
		// An async action: the run was started, show its card
		if apiMode {
			writeJSON(w, http.StatusAccepted, a.RunStarted(outcome.Run))
			return
		}
		a.writeRunCard(w, r, outcome.Run, isHtmxRequest)
		return
	}

	if outcome.IsStream() {
		if apiMode || !isHtmxRequest {
			a.WriteStreamText(w, r, outcome)
		} else {
			a.writeStreamSSE(w, r, outcome)
		}
		return
	}

	if apiMode {
		response, code := a.APIResult(outcome, isValidate)
		writeJSON(w, code, response)
		return
	}

	pageInput := map[string]any{
		"name":        a.name,
		"description": a.description,
		"appName":     a.appName,
		"appPath":     a.appPath,
		"pagePath":    a.pagePath,
		"styleType":   string(a.StyleType),
		"lightTheme":  a.LightTheme,
		"darkTheme":   a.DarkTheme,
		"esmLibs":     a.esmLibs,
		"links":       a.getNavLinks(r.Context()),
	}

	if !isHtmxRequest {
		err := a.actionTemplate.ExecuteTemplate(w, "header", pageInput)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// Set the push URL for HTMX
		w.Header().Set("HX-Push-Url", a.pagePath+"?"+outcome.QueryParams.Encode())
	}

	// Render the result message
	err := a.actionTemplate.ExecuteTemplate(w, "status", outcome.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Render the param error messages, using HTMX OOB
	if err = a.renderParamErrors(w, outcome.ParamErrors); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isValidate {
		// No need to render the results
		return
	}

	err = a.renderResults(w, outcome.Report, outcome.ValuesMap, outcome.ValuesStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !isHtmxRequest {
		err = a.actionTemplate.ExecuteTemplate(w, "footer", pageInput)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// multipartFiles returns the first uploaded file for each form field
func multipartFiles(form *multipart.Form) map[string]UploadedFile {
	if form == nil {
		return nil
	}
	files := make(map[string]UploadedFile, len(form.File))
	for name, headers := range form.File {
		if len(headers) == 0 {
			continue
		}
		fh := headers[0]
		files[name] = UploadedFile{
			Filename: fh.Filename,
			Open:     func() (io.ReadCloser, error) { return fh.Open() },
		}
	}
	return files
}

func writeRequestParseError(w http.ResponseWriter, err error, maxRequestBodyBytes int64, apiMode bool) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) || errors.Is(err, multipart.ErrMessageTooLarge) {
		writeActionError(w, apiMode, fmt.Sprintf("request body too large: limit is %d bytes", maxRequestBodyBytes), http.StatusRequestEntityTooLarge)
		return
	}

	writeActionError(w, apiMode, err.Error(), http.StatusBadRequest)
}

func uploadedFilePath(tempDir, filename string) (string, error) {
	safeName, err := system.CleanFilename(filename)
	if err != nil {
		return "", fmt.Errorf("invalid uploaded filename: %q", filename)
	}

	fullPath, err := system.PathInDir(tempDir, safeName)
	if err != nil {
		return "", fmt.Errorf("invalid uploaded file path: %q", filename)
	}

	return fullPath, nil
}

// renderParamErrors writes the per-param error message blocks (HTMX OOB).
// Every param gets a block: an empty message clears a previous error in
// the form UI
func (a *Action) renderParamErrors(w io.Writer, paramErrors map[string]any) error {
	errorMsgs := map[string]string{}
	errorKeys := []string{}
	for _, param := range a.params {
		if !strings.HasPrefix(param.Name, OPTIONS_PREFIX) && !strings.HasPrefix(param.Name, OPTIONS_PREFIX_UNDERSCORE) {
			if paramErrors[param.Name] == nil {
				errorMsgs[param.Name] = ""
			} else {
				errorMsgs[param.Name] = fmt.Sprintf("%s", paramErrors[param.Name])
			}
			errorKeys = append(errorKeys, param.Name)
		}
	}

	slices.Sort(errorKeys)
	for _, paramName := range errorKeys {
		tv := struct {
			Name    string
			Message string
		}{
			Name:    paramName,
			Message: errorMsgs[paramName],
		}
		if err := a.actionTemplate.ExecuteTemplate(w, "paramError", tv); err != nil {
			return err
		}
	}
	return nil
}

// errClientGone is the stream outcome when the client disconnected before
// the command finished
var errClientGone = errors.New("client disconnected")

// consumeStream drains a result stream, passing each output chunk (with its
// trailing newline restored) to emit. It returns the command's exit status
// when the stream ended through a process exit (0 for a clean end without
// an exit error), or an error for a client disconnect, a write failure or a
// stream failure that is not an exit status
func consumeStream(ctx context.Context, seq func(yield func(any, error) bool), emit func(chunk string) error) (int, error) {
	for v, streamErr := range seq {
		if streamErr != nil {
			if ctx.Err() != nil {
				return -1, errClientGone
			}
			var exitErr *exec.ExitError
			if errors.As(streamErr, &exitErr) && exitErr.ExitCode() >= 0 {
				return exitErr.ExitCode(), nil
			}
			return -1, streamErr
		}
		var chunk string
		switch val := v.(type) {
		case string:
			chunk = val
		default:
			// Parsed output (jsonlines) arrives as maps: one JSON document
			// per line, as the buffered response would report it
			encoded, err := json.Marshal(val)
			if err != nil {
				return -1, err
			}
			chunk = string(encoded)
		}
		if err := emit(chunk + "\n"); err != nil {
			if ctx.Err() != nil {
				return -1, errClientGone
			}
			return -1, err
		}
	}
	return 0, nil
}

// recordStreamOutcome sets the audit status for a streamed run: success
// only for a clean exit, the failure detail otherwise
func recordStreamOutcome(event *types.AuditEvent, exitStatus int, err error) {
	switch {
	case err != nil:
		event.Status = string(types.EventStatusFailure)
		event.Detail = err.Error()
	case exitStatus != 0:
		event.Status = string(types.EventStatusFailure)
		event.Detail = fmt.Sprintf("exit status %d", exitStatus)
	default:
		event.Status = string(types.EventStatusSuccess)
	}
}

// writeSSEEvent writes one server-sent event. Multi-line data is split into
// data: lines (the client joins them with newlines); a bare CR would end a
// line in the SSE parser, so it is dropped
func writeSSEEvent(w io.Writer, event, data string) error {
	var b strings.Builder
	if event != "" {
		b.WriteString("event: ")
		b.WriteString(event)
		b.WriteString("\n")
	}
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: ")
		b.WriteString(strings.ReplaceAll(line, "\r", ""))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

const (
	sseOutputEvent = "openrun:output"
	sseExitEvent   = "openrun:exit"
)

// writeStreamSSE streams a result to the form UI as server-sent events, the
// transport the hx-sse extension consumes incrementally on the Run button's
// hx-post. The first (unnamed) event carries the HTML the buffered response
// would: the status line for the button's target, the cleared param error
// blocks and the log pane shell (OOB). Then one openrun:output event per
// output chunk feeds the <log-tail> element (JSON string payload, so CR/LF
// and control characters survive the SSE framing), and openrun:exit ends
// the run with the exit status. The request stays open until the command
// exits, so the in-flight indicator matches the command; a client
// disconnect cancels the request context, which kills the command
func (a *Action) writeStreamSSE(w http.ResponseWriter, r *http.Request, outcome *Outcome) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeActionError(w, false, "streaming is not supported by the response writer", http.StatusInternalServerError)
		return
	}

	var initial bytes.Buffer
	if err := a.actionTemplate.ExecuteTemplate(&initial, "status", outcome.Status); err != nil {
		writeActionError(w, false, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.renderParamErrors(&initial, nil); err != nil {
		writeActionError(w, false, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.actionTemplate.ExecuteTemplate(&initial, "result-stream", nil); err != nil {
		writeActionError(w, false, err.Error(), http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("HX-Push-Url", a.pagePath+"?"+outcome.QueryParams.Encode())
	w.WriteHeader(http.StatusOK)

	if err := writeSSEEvent(w, "", initial.String()); err != nil {
		recordStreamOutcome(outcome.event, -1, err)
		return
	}
	flusher.Flush()

	exitStatus, err := outcome.ConsumeStream(r.Context(), func(chunk string) error {
		// The JSON encoder rejects invalid UTF-8 (binary output, other
		// encodings): replace bad bytes for display, as a terminal would
		encoded, encErr := json.Marshal(strings.ToValidUTF8(chunk, "\uFFFD"))
		if encErr != nil {
			return encErr
		}
		if writeErr := writeSSEEvent(w, sseOutputEvent, string(encoded)); writeErr != nil {
			return writeErr
		}
		flusher.Flush()
		return nil
	})
	if errors.Is(err, errClientGone) {
		return
	}

	var exit []byte
	if err != nil {
		a.Error().Err(err).Msg("error producing action stream")
		exit, _ = json.Marshal(map[string]any{"error": err.Error()})
	} else {
		exit, _ = json.Marshal(map[string]any{"status": exitStatus})
	}
	if writeErr := writeSSEEvent(w, sseExitEvent, string(exit)); writeErr != nil {
		return
	}
	flusher.Flush()
}

// Response header carrying the result status text of a streamed API run,
// and the trailer carrying the command's exit status once the stream ends
const (
	streamStatusHeader = types.ACTION_STATUS_HEADER
	streamExitTrailer  = types.ACTION_EXIT_TRAILER
)

// writeStreamText streams a result as chunked plain text: the API mode
// response (curl -N friendly) and the fallback for non-HTMX form posts.
// The result status text travels in the OpenRun-Action-Status header and
// the exit status in the OpenRun-Exit-Status trailer; a missing trailer
// means the stream was cut (a read failure or a client disconnect). No
// synthetic lines are mixed into the output
func (a *Action) WriteStreamText(w http.ResponseWriter, r *http.Request, outcome *Outcome) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeActionError(w, true, "streaming is not supported by the response writer", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set(streamStatusHeader, headerSafe(outcome.Status))
	h.Set("Trailer", streamExitTrailer)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	exitStatus, err := outcome.ConsumeStream(r.Context(), func(chunk string) error {
		if _, writeErr := io.WriteString(w, chunk); writeErr != nil {
			return writeErr
		}
		flusher.Flush()
		return nil
	})
	if err != nil {
		if !errors.Is(err, errClientGone) {
			a.Error().Err(err).Msg("error producing action stream")
		}
		return
	}
	// Announced in the Trailer header, so this is sent as an HTTP trailer
	h.Set(streamExitTrailer, strconv.Itoa(exitStatus))
}

// headerSafe strips the control characters a header value cannot carry
func headerSafe(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

func (a *Action) renderResults(w http.ResponseWriter, report string, valuesMap []map[string]any, valuesStr []string) error {
	if report == apptype.AUTO {
		return a.renderResultsAuto(w, valuesMap, valuesStr)
	}

	switch report {
	case apptype.TABLE:
		return a.renderResultsTable(w, valuesMap)
	case apptype.TEXT:
		return a.renderResultsText(w, valuesStr)
	case apptype.JSON:
		return a.renderResultsJson(w, valuesMap)
	case apptype.DOWNLOAD:
		return a.renderResultsDownload(w, valuesMap)
	case apptype.IMAGE:
		return a.renderResultsImage(w, valuesMap)
	default:
		// Custom template being used for the results
		// Wrap the template output in a div with hx-swap-oob
		_, err := io.WriteString(w, `<div id="action_result" hx-swap-oob="innerHTML"> <output role="alert">`)
		if err != nil {
			return err
		}
		var tmplErr error
		if len(valuesStr) > 0 {
			tmplErr = a.AppTemplate.ExecuteTemplate(w, report, valuesStr)
		} else {
			tmplErr = a.AppTemplate.ExecuteTemplate(w, report, valuesMap)
		}
		_, err = io.WriteString(w, ` </output> </div>`)
		if err != nil {
			return err
		}

		return tmplErr
	}
}

func (a *Action) renderResultsAuto(w http.ResponseWriter, valuesMap []map[string]any, valuesStr []string) error {
	if len(valuesStr) > 0 {
		return a.renderResultsText(w, valuesStr)
	}

	if len(valuesMap) == 0 {
		return a.actionTemplate.ExecuteTemplate(w, "result-empty", nil)
	}

	if len(valuesMap) > 0 {
		firstRow := valuesMap[0]
		hasComplex := false
		for _, v := range firstRow {
			if v == nil {
				continue
			}
			switch v.(type) {
			case int:
			case string:
			case bool:
			default:
				hasComplex = true
			}
			if hasComplex {
				break
			}
		}

		if hasComplex {
			return a.renderResultsJson(w, valuesMap)
		}
		return a.renderResultsTable(w, valuesMap)
	}

	return nil
}

func (a *Action) renderResultsText(w http.ResponseWriter, valuesStr []string) error {
	// Render the result values, using HTMX OOB
	err := a.actionTemplate.ExecuteTemplate(w, "result-textarea", valuesStr)
	return err
}

func (a *Action) renderResultsDownload(w http.ResponseWriter, valuesMap []map[string]any) error {
	// Render the result values, using HTMX OOB
	err := a.actionTemplate.ExecuteTemplate(w, "result-download", valuesMap)
	return err
}

func (a *Action) renderResultsImage(w http.ResponseWriter, valuesMap []map[string]any) error {
	// Render the result values, using HTMX OOB
	err := a.actionTemplate.ExecuteTemplate(w, "result-image", valuesMap)
	return err
}

func (a *Action) renderResultsTable(w http.ResponseWriter, valuesMap []map[string]any) error {
	if len(valuesMap) == 0 {
		return a.actionTemplate.ExecuteTemplate(w, "result-empty", nil)
	}
	firstRow := valuesMap[0]
	keys := make([]string, 0, len(firstRow))
	for k := range firstRow {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	values := make([][]string, 0, len(valuesMap))
	for _, row := range valuesMap {
		rowValues := make([]string, 0, len(keys))
		for _, k := range keys {
			v, ok := row[k]
			if !ok {
				// Missing value
				rowValues = append(rowValues, "")
			} else {
				pv := fmt.Sprintf("%v", v)
				DISPLAY_LIMIT := 100
				if len(pv) > DISPLAY_LIMIT {
					pv = pv[:DISPLAY_LIMIT] + "..."
				}
				rowValues = append(rowValues, pv)
			}
		}
		values = append(values, rowValues)
	}

	input := map[string]any{
		"Keys":   keys,
		"Values": values,
	}

	err := a.actionTemplate.ExecuteTemplate(w, "result-table", input)
	return err
}

func (a *Action) renderResultsJson(w http.ResponseWriter, valuesMap []map[string]any) error {
	err := a.actionTemplate.ExecuteTemplate(w, "result-json", valuesMap)
	return err
}

func RunDeferredCleanup(thread *starlark.Thread) error {
	deferMap := thread.Local(types.TL_DEFER_MAP)
	if deferMap == nil {
		return nil
	}

	strictFailures := []string{}
	for pluginName, pluginMap := range deferMap.(map[string]map[string]apptype.DeferEntry) {
		for key, entry := range pluginMap {
			err := entry.Func()
			if err != nil {
				fmt.Printf("error cleaning up %s %s: %s\n", pluginName, key, err)
			}
			if entry.Strict {
				strictFailures = append(strictFailures, fmt.Sprintf("%s:%s", pluginName, key))
			}
		}
	}

	thread.SetLocal(types.TL_DEFER_MAP, nil) // reset the defer map

	if len(strictFailures) > 0 {
		return fmt.Errorf("resource has not be closed, check handler code: %s", strings.Join(strictFailures, ", "))
	}

	return nil
}

type ParamDef struct {
	Name               string
	Description        string
	Value              any
	InputType          string
	Options            []string
	Strict             bool // dropdown value must be one of the options (default; COMBO display type loosens)
	DisplayType        string
	DisplayTypeOptions string
}

const (
	OPTIONS_PREFIX            = "options-"
	OPTIONS_PREFIX_UNDERSCORE = "options_"
	// Both are allowed, for backward compatibility. Underscore is preferred since it is a valid starlark identifier
)

// paramOptions returns the configured dropdown options: params with an
// options-x/options_x prefix hold the option list (JSON) for param x
func (a *Action) paramOptions() (map[string][]string, error) {
	options := make(map[string][]string)
	for _, p := range a.params {
		if strings.HasPrefix(p.Name, OPTIONS_PREFIX) || strings.HasPrefix(p.Name, OPTIONS_PREFIX_UNDERSCORE) {
			name := p.Name[len(OPTIONS_PREFIX):]
			var vals []string
			err := json.Unmarshal([]byte(a.paramValuesStr[p.Name]), &vals)
			if err != nil {
				return nil, fmt.Errorf("invalid value for %s: %s", p.Name, a.paramValuesStr[p.Name])
			}
			options[name] = vals
		}
	}
	return options, nil
}

func (a *Action) getForm(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}

	queryParams := r.URL.Query()
	params := make([]ParamDef, 0, len(a.params))

	options, err := a.paramOptions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hasFileUpload := false
	for _, p := range a.params {
		if strings.HasPrefix(p.Name, OPTIONS_PREFIX) || strings.HasPrefix(p.Name, OPTIONS_PREFIX_UNDERSCORE) || a.hidden[p.Name] {
			continue
		}

		param := ParamDef{
			Name:        p.Name,
			Description: p.Description,
		}

		value, ok := a.paramValuesStr[p.Name]
		qValue := queryParams.Get(p.Name)
		if !ok && qValue == "" {
			// A param with no default and no app level value (a required
			// action param is supplied per invocation) starts empty
			value = ""
			if p.Type == starlark_type.BOOLEAN {
				value = "false"
			}
		}

		if qValue != "" {
			// Prefer value from query params
			value = qValue
		}

		param.Value = value // Default to string format
		param.InputType = "text"
		if p.Type == starlark_type.BOOLEAN {
			boolValue, err := strconv.ParseBool(value)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid value for %s: %s", p.Name, value), http.StatusInternalServerError)
				return
			}
			if boolValue {
				param.Value = "checked"
			}
			param.InputType = "checkbox"
		} else if options[p.Name] != nil || p.DisplayType == apptype.DisplayTypeCombo {
			// Dropdown: strict (value must be in the list) unless the param
			// display type is COMBO, which allows free text. A COMBO param
			// without a static options list gets its options from suggest
			param.InputType = "select"
			param.Options = options[p.Name]
			param.Strict = p.DisplayType != apptype.DisplayTypeCombo
			param.Value = value
		}

		if p.DisplayType != "" {
			switch p.DisplayType {
			case apptype.DisplayTypePassword:
				param.DisplayType = "password"
			case apptype.DisplayTypeTextArea:
				param.DisplayType = "textarea"
			case apptype.DisplayTypeFileUpload:
				param.DisplayType = "file"
				hasFileUpload = true
			case apptype.DisplayTypeCombo:
				param.DisplayType = "text"
			default:
				http.Error(w, fmt.Sprintf("invalid display type for %s: %s", p.Name, p.DisplayType), http.StatusInternalServerError)
				return
			}
			param.DisplayTypeOptions = p.DisplayTypeOptions
		} else {
			param.DisplayType = "text"
		}

		params = append(params, param)
	}

	input := map[string]any{
		"dev":           a.isDev,
		"name":          a.name,
		"description":   a.description,
		"appName":       a.appName,
		"appPath":       a.appPath,
		"pagePath":      a.pagePath,
		"params":        params,
		"styleType":     string(a.StyleType),
		"lightTheme":    a.LightTheme,
		"darkTheme":     a.DarkTheme,
		"links":         a.getNavLinks(r.Context()),
		"hasFileUpload": hasFileUpload,
		"showSuggest":   a.suggest != nil,
		"showValidate":  a.showValidate,
		"esmLibs":       a.esmLibs,
		"async":         a.IsAsync(),
		"destructive":   a.IsDestructive(),
		"runsPath":      a.runsPath(),
	}
	err = a.actionTemplate.ExecuteTemplate(w, "form.go.html", input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// getNavLinks returns the sidebar navigation links for all actions,
// including the current one (marked Active). The current form param values
// are appended to the link by actions.js at click time, so switching
// actions preserves the entered values
func (a *Action) getNavLinks(ctx context.Context) []ActionLink {
	navLinks := make([]ActionLink, 0, len(a.Links))
	for _, link := range a.Links {
		authorized := true
		if a.rbacApi != nil && len(link.Permits) > 0 {
			var err error
			authorized, err = a.rbacApi.AuthorizeAny(ctx, link.Permits)
			if err != nil {
				a.Error().Msgf("error authorizing link %s: %s", link.Name, err)
			}
		}
		link.Authorized = authorized // whether this user has access to this action
		link.Active = link.Path == a.pagePath
		navLinks = append(navLinks, link)
	}
	return navLinks
}

func (a *Action) handleSuggestResponse(w http.ResponseWriter, retVal starlark.Value) {
	ret, err := starlark_type.ToGo(retVal)
	if err != nil {
		http.Error(w, fmt.Sprintf("error unmarshalling suggest response: %s", err), http.StatusInternalServerError)
		return
	}

	message, retIsString := ret.(string)
	if !retIsString {
		message = "Suggesting values"
	}

	err = a.actionTemplate.ExecuteTemplate(w, "status", message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if retIsString {
		// No suggestions available
		return
	}

	retDict := map[string]any{}
	switch retType := ret.(type) {
	case map[string]any:
		for k, v := range retType {
			retDict[k] = v
		}
	case map[string]string:
		for k, v := range retType {
			retDict[k] = v
		}
	case map[string]int:
		for k, v := range retType {
			retDict[k] = v
		}
	case map[string]bool:
		for k, v := range retType {
			retDict[k] = v
		}
	case map[string][]string:
		for k, v := range retType {
			retDict[k] = v
		}
	default:
		http.Error(w, fmt.Sprintf("invalid suggest response type: %T, expected dict", retType), http.StatusInternalServerError)
		return
	}

	paramMap := map[string]apptype.AppParam{}
	for _, p := range a.params {
		paramMap[p.Name] = p
	}

	keys := slices.Collect(maps.Keys(retDict))
	slices.Sort(keys)
	for _, key := range keys {
		value := retDict[key]
		p, ok := paramMap[key]
		if !ok || strings.HasPrefix(key, OPTIONS_PREFIX) || strings.HasPrefix(key, OPTIONS_PREFIX_UNDERSCORE) {
			a.Info().Msgf("ignoring suggest response for param: %s", key)
			continue
		}
		param := ParamDef{
			Name:        p.Name,
			Description: p.Description,
		}

		param.Value = fmt.Sprintf("%v", value)
		param.InputType = "text"

		valueList, valueIsList := value.([]string)
		if p.DisplayType == apptype.DisplayTypeFileUpload {
			http.Error(w, fmt.Sprintf("suggest not supported for file upload param: %s", p.Name), http.StatusInternalServerError)
			return
		} else if p.Type == starlark_type.STRING && valueIsList {
			param.InputType = "select"
			if len(valueList) == 0 {
				continue
			}
			param.Value = valueList[0]
			param.Options = valueList
			param.Strict = p.DisplayType != apptype.DisplayTypeCombo
		} else if p.Type == starlark_type.BOOLEAN {
			boolValue, err := strconv.ParseBool(fmt.Sprintf("%v", value))
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid value for %s: %s", p.Name, value), http.StatusInternalServerError)
				return
			}
			if boolValue {
				param.Value = "checked"
			}
			param.InputType = "checkbox"
		}

		if p.DisplayType != "" {
			switch p.DisplayType {
			case apptype.DisplayTypePassword:
				param.DisplayType = "password"
			case apptype.DisplayTypeTextArea:
				param.DisplayType = "textarea"
			case apptype.DisplayTypeFileUpload:
				param.DisplayType = "file"
			case apptype.DisplayTypeCombo:
				param.DisplayType = "text"
			default:
				http.Error(w, fmt.Sprintf("invalid display type for %s: %s", p.Name, p.DisplayType), http.StatusInternalServerError)
				return
			}
			param.DisplayTypeOptions = p.DisplayTypeOptions
		} else {
			param.DisplayType = "text"
		}

		err = a.actionTemplate.ExecuteTemplate(w, "param_suggest", param)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
