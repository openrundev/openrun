// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The run pages of an async action in the form UI (arch/docs/async-actions.md
// §6.1): the run card answered to a submission, the runs list, the run page
// with its polled status and output, the result document and cancel. All
// the routes sit under the action path and are gated by the action's permit

const (
	runsPageLimit     = 50
	runStatusPollSecs = 2
)

// ErrRunNotFound is returned by run lookups for an unknown id
var ErrRunNotFound = errors.New("run not found")

// runView is a run as the templates see it
type runView struct {
	types.ActionRun
	Duration  string
	Started   string
	Ended     string
	Active    bool
	PagePath  string
	RunsPath  string
	ArgsList  []runArg
	ArgCells  []string // the run's value of each arg column of the list
	OutputUrl string
}

type runArg struct{ Name, Value string }

func (a *Action) runView(run *types.ActionRun) runView {
	view := runView{ActionRun: *run, Active: run.IsActive(), PagePath: a.RunPagePath(run.Id), RunsPath: a.pagePath + "/runs"}
	view.Started = run.StartedAt.Local().Format("2006-01-02 15:04:05")
	end := time.Now()
	if run.EndedAt != nil {
		end = *run.EndedAt
		view.Ended = run.EndedAt.Local().Format("2006-01-02 15:04:05")
	}
	view.Duration = end.Sub(run.StartedAt).Round(time.Second).String()
	names := make([]string, 0, len(run.Args))
	for name := range run.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		view.ArgsList = append(view.ArgsList, runArg{Name: name, Value: run.Args[name]})
	}
	view.OutputUrl = view.PagePath + "/output"
	return view
}

// pageInput is the template input shared by the run pages and the form
func (a *Action) pageInput(ctx context.Context) map[string]any {
	return map[string]any{
		"name":        a.name,
		"description": a.description,
		"appName":     a.appName,
		"appPath":     a.appPath,
		"pagePath":    a.pagePath,
		"styleType":   string(a.StyleType),
		"lightTheme":  a.LightTheme,
		"darkTheme":   a.DarkTheme,
		"esmLibs":     a.esmLibs,
		"links":       a.getNavLinks(ctx),
		"async":       a.IsAsync(),
		"runsPath":    a.runsPath(),
	}
}

// LoadRun returns a run of this action (a run of another action or app is
// not found here), with the payload when asked
func (a *Action) LoadRun(ctx context.Context, runId string, payload bool) (*types.ActionRun, error) {
	store := a.RunStore()
	if store == nil {
		return nil, ErrRunNotFound
	}
	run, err := store.GetActionRun(ctx, runId, payload)
	if err != nil {
		return nil, ErrRunNotFound
	}
	if run.AppId != a.runHost.AppId || run.ActionPath != a.actionPath {
		return nil, ErrRunNotFound
	}
	return run, nil
}

// WaitRun returns the run, waiting up to wait (capped by the app config)
// for it to end
func (a *Action) WaitRun(ctx context.Context, runId string, wait time.Duration, payload bool) (*types.ActionRun, error) {
	wait = a.MaxWait(wait)
	deadline := time.Now().Add(wait)
	for {
		run, err := a.LoadRun(ctx, runId, payload)
		if err != nil {
			return nil, err
		}
		if !run.IsActive() || time.Now().After(deadline) {
			return run, nil
		}
		select {
		case <-ctx.Done():
			return run, nil
		case <-time.After(time.Second):
		}
	}
}

// ListRuns lists this action's runs, newest first
func (a *Action) ListRuns(ctx context.Context, status string, limit int) ([]types.ActionRun, error) {
	store := a.RunStore()
	if store == nil {
		return []types.ActionRun{}, nil
	}
	if limit <= 0 {
		limit = runsPageLimit
	}
	return store.ListActionRuns(ctx, []types.AppId{a.runHost.AppId}, a.actionPath, status, limit)
}

// CancelRun cancels an active run of this action executing on this node
func (a *Action) CancelRun(ctx context.Context, runId string) (*types.ActionRun, *InvokeError) {
	run, err := a.LoadRun(ctx, runId, false)
	if err != nil {
		return nil, invokeErr(http.StatusNotFound, "run %s not found", runId)
	}
	if !run.IsActive() {
		return nil, invokeErr(http.StatusBadRequest, "run %s is not active (%s)", runId, run.Status)
	}
	if run.NodeId != a.runHost.NodeId {
		return nil, invokeErr(http.StatusConflict, "run %s is executing on node %s, cancel it there", runId, run.NodeId)
	}
	if !a.runHost.Registry.Cancel(runId, system.GetContextUserId(ctx)) {
		return nil, invokeErr(http.StatusConflict, "run %s is not executing on this node", runId)
	}
	return run, nil
}

// writeRunCard answers a submission with a redirect to the started run's
// page: HX-Redirect for the htmx form (the Start button), a plain redirect
// for a form post
func (a *Action) writeRunCard(w http.ResponseWriter, r *http.Request, run *types.ActionRun, isHtmxRequest bool) {
	if isHtmxRequest {
		w.Header().Set("HX-Redirect", a.RunPagePath(run.Id))
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, a.RunPagePath(run.Id), http.StatusSeeOther)
}

// runsPath returns the runs list path of an async action, empty for a sync
// one (the header shows the Run History link when set)
func (a *Action) runsPath() string {
	if !a.IsAsync() {
		return ""
	}
	return a.pagePath + "/runs"
}

// runsListLimit is the number of runs the list reads before the args
// filter is applied; runsPageLimit of them are shown
const runsListLimit = 500

// matchesRunFilter reports whether a run matches the filter text: every
// whitespace separated token must match, a name=value token an arg exactly
// (case insensitive), a bare token a substring of any arg value, of the
// result status or of the run message (a failure, cancel or timeout text)
func matchesRunFilter(run *types.ActionRun, filter string) bool {
	for _, token := range strings.Fields(filter) {
		if name, value, ok := strings.Cut(token, "="); ok && name != "" {
			if !strings.EqualFold(run.Args[name], value) {
				return false
			}
			continue
		}
		found := false
		for _, v := range run.Args {
			if strings.Contains(strings.ToLower(v), strings.ToLower(token)) {
				found = true
				break
			}
		}
		for _, text := range []string{run.ResultStatus, run.Message} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(token)) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// argColumns returns the arg names of the runs, one table column each: the
// action's visible params in their order, then any other name seen
func (a *Action) argColumns(runs []types.ActionRun) []string {
	seen := map[string]bool{}
	columns := []string{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			columns = append(columns, name)
		}
	}
	for _, param := range a.params {
		if a.hidden[param.Name] || param.DisplayType == apptype.DisplayTypePassword ||
			strings.HasPrefix(param.Name, OPTIONS_PREFIX) || strings.HasPrefix(param.Name, OPTIONS_PREFIX_UNDERSCORE) {
			continue
		}
		for _, run := range runs {
			if _, ok := run.Args[param.Name]; ok {
				add(param.Name)
				break
			}
		}
	}
	extra := []string{}
	for _, run := range runs {
		for name := range run.Args {
			if !seen[name] {
				seen[name] = true
				extra = append(extra, name)
			}
		}
	}
	sort.Strings(extra)
	return append(columns, extra...)
}

// getRunsPage renders the runs list of the action
func (a *Action) getRunsPage(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	status := r.URL.Query().Get("status")
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	listed, err := a.ListRuns(r.Context(), status, runsListLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs := make([]types.ActionRun, 0, len(listed))
	for _, run := range listed {
		if matchesRunFilter(&run, filter) {
			runs = append(runs, run)
		}
	}
	more := len(runs) > runsPageLimit
	if more {
		runs = runs[:runsPageLimit]
	}
	columns := a.argColumns(runs)
	views := make([]runView, 0, len(runs))
	hasActive := false
	for i := range runs {
		view := a.runView(&runs[i])
		for _, name := range columns {
			view.ArgCells = append(view.ArgCells, runs[i].Args[name])
		}
		views = append(views, view)
		hasActive = hasActive || runs[i].IsActive()
	}
	input := a.pageInput(r.Context())
	input["runs"] = views
	input["argColumns"] = columns
	input["status"] = status
	input["filter"] = filter
	input["more"] = more
	input["hasActive"] = hasActive
	input["statuses"] = []string{types.ActionRunRunning, types.ActionRunSucceeded, types.ActionRunFailed,
		types.ActionRunTimedOut, types.ActionRunCanceled, types.ActionRunLost}
	if r.Header.Get("HX-Request") == "true" {
		err = a.actionTemplate.ExecuteTemplate(w, "runs-table", input)
	} else {
		err = a.actionTemplate.ExecuteTemplate(w, "runs-page", input)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// getRunPage renders a run: the status header, the args, and the output
// pane or the rendered result
func (a *Action) getRunPage(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	run, err := a.LoadRun(r.Context(), chi.URLParam(r, "runId"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	input := a.pageInput(r.Context())
	input["run"] = a.runView(run)
	input["pollSecs"] = runStatusPollSecs
	input["displayRows"] = a.config.DisplayRows
	if err := a.actionTemplate.ExecuteTemplate(w, "run-page", input); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The stored result of a finished values run; a failed run has no
	// result to show beyond its message
	if run.Status == types.ActionRunSucceeded && !run.IsStream && len(run.ParamErrors) == 0 {
		if err := a.renderStoredResult(w, run); err != nil {
			a.Error().Err(err).Msg("error rendering run result")
		}
	}
	if err := a.actionTemplate.ExecuteTemplate(w, "footer", input); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// DecodeResult decodes a stored result document into the values the result
// renderers take, limited to the first limit rows when limit is positive
func DecodeResult(run *types.ActionRun, limit int) (valuesMap []map[string]any, valuesStr []string, err error) {
	if run.Result == "" {
		return nil, nil, nil
	}
	// Numbers are kept as json.Number: decoding them as float64 would
	// change integer ids beyond 2^53
	var rows []any
	decoder := json.NewDecoder(strings.NewReader(run.Result))
	decoder.UseNumber()
	if err := decoder.Decode(&rows); err != nil {
		return nil, nil, err
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	for _, row := range rows {
		switch v := row.(type) {
		case map[string]any:
			valuesMap = append(valuesMap, v)
		case string:
			valuesStr = append(valuesStr, v)
		default:
			valuesStr = append(valuesStr, fmt.Sprint(v))
		}
	}
	return valuesMap, valuesStr, nil
}

// renderStoredResult renders a finished run's values with the result
// templates of the action page, the first display_rows rows
func (a *Action) renderStoredResult(w io.Writer, run *types.ActionRun) error {
	valuesMap, valuesStr, err := DecodeResult(run, a.config.DisplayRows)
	if err != nil {
		return err
	}
	if run.ResultRows > a.config.DisplayRows || run.ResultTruncated {
		note := fmt.Sprintf("Showing the first %d of %d rows", min(a.config.DisplayRows, run.ResultRows), run.ResultRows)
		if run.ResultTruncated {
			note = fmt.Sprintf("The stored result was truncated to the size limit; showing the first %d of %d rows", len(valuesMap)+len(valuesStr), run.ResultRows)
		}
		if _, err := fmt.Fprintf(w, `<div class="text-sm text-base-content/70 py-1">%s. <a class="link" href="%s/result.json">Download the stored result</a></div>`,
			note, a.RunPagePath(run.Id)); err != nil {
			return err
		}
	}
	report := run.Report
	if report == "" {
		report = apptype.AUTO
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		return a.renderResults(rw, report, valuesMap, valuesStr)
	}
	return nil
}

// getRunStatusFragment renders the polled status header of a run
func (a *Action) getRunStatusFragment(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	run, err := a.LoadRun(r.Context(), chi.URLParam(r, "runId"), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	input := map[string]any{"run": a.runView(run), "pollSecs": runStatusPollSecs}
	if err := a.actionTemplate.ExecuteTemplate(w, "run-status", input); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// getRunOutput returns a run's output from the since offset as text; the
// OpenRun-Output-Bytes header carries the offset to continue from,
// OpenRun-Action-Status the run status, OpenRun-Output-Restart marks a
// window the reader's offset had left
func (a *Action) getRunOutput(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	run, err := a.LoadRun(r.Context(), chi.URLParam(r, "runId"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	WriteRunOutput(w, run, since)
}

// WriteRunOutput writes the output window of a run as plain text with the
// continuation headers
func WriteRunOutput(w http.ResponseWriter, run *types.ActionRun, since int64) {
	window := ReadOutput(run, since)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("OpenRun-Output-Bytes", strconv.FormatInt(window.Total, 10))
	w.Header().Set("OpenRun-Output-Since", strconv.FormatInt(window.Since, 10))
	w.Header().Set(types.ACTION_STATUS_HEADER, headerSafe(run.Status))
	if window.Restart {
		w.Header().Set("OpenRun-Output-Restart", "true")
	}
	if run.ExitCode != nil {
		w.Header().Set("OpenRun-Exit-Code", strconv.Itoa(*run.ExitCode))
	}
	_, _ = io.WriteString(w, window.Output)
}

// getRunResultJSON returns the stored result document of a run
func (a *Action) getRunResultJSON(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	run, err := a.LoadRun(r.Context(), chi.URLParam(r, "runId"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, run.Id))
	result := run.Result
	if result == "" {
		result = "[]"
	}
	_, _ = io.WriteString(w, result)
}

// cancelRunUI cancels a run from the run page and re-renders its status
func (a *Action) cancelRunUI(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeAction(w, r, false) {
		return
	}
	runId := chi.URLParam(r, "runId")
	if _, invErr := a.CancelRun(r.Context(), runId); invErr != nil {
		http.Error(w, invErr.Msg, invErr.Code)
		return
	}
	// The worker records the cancel; give it a moment so the status shows it
	deadline := time.Now().Add(2 * time.Second)
	var run *types.ActionRun
	for {
		var err error
		if run, err = a.LoadRun(r.Context(), runId, false); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if !run.IsActive() || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r.Header.Get("HX-Request") != "true" {
		http.Redirect(w, r, a.RunPagePath(runId), http.StatusSeeOther)
		return
	}
	input := map[string]any{"run": a.runView(run), "pollSecs": runStatusPollSecs}
	if err := a.actionTemplate.ExecuteTemplate(w, "run-status", input); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RunAPIResult is the run document of the REST and management APIs: the run
// without the payload columns, plus the decoded result of a finished values
// run in the ActionResult shape
func (a *Action) RunAPIResult(run *types.ActionRun) map[string]any {
	doc := map[string]any{"run": run.BasicView()}
	if !run.IsActive() && !run.IsStream {
		valuesMap, valuesStr, err := DecodeResult(run, 0)
		result := types.ActionResult{Status: run.ResultStatus, Report: run.Report, ParamErrors: run.ParamErrors}
		if err == nil {
			if valuesMap != nil {
				result.Values = make([]any, 0, len(valuesMap))
				for _, v := range valuesMap {
					result.Values = append(result.Values, v)
				}
			} else {
				result.Values = make([]any, 0, len(valuesStr))
				for _, v := range valuesStr {
					result.Values = append(result.Values, v)
				}
			}
		}
		doc["result"] = result
	}
	return doc
}

// parseWait parses a wait query value (a duration, or seconds)
func parseWait(value string) time.Duration {
	if value == "" {
		return 0
	}
	if d, err := time.ParseDuration(value); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(strings.TrimSuffix(value, "s")); err == nil {
		return time.Duration(secs) * time.Second
	}
	return 0
}
