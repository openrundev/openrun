// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// Async action runs through the management API (arch/docs/async-actions.md
// §6.3): the transport of openrun action runs/output/cancel and of the
// list_action_runs/get_action_run/cancel_action_run MCP tools. A run is
// resolved to its action, and the caller passes the checks of the action
// (provider match, app:access, permit) before seeing the run

// runServices returns the services async action runs need on this node
func (s *Server) runServices() *app.RunServices {
	return &app.RunServices{Store: s.db, Registry: &s.jobRuns, NodeId: s.jobNodeId()}
}

// resolveActionRun resolves a run id to its action, authorizing the caller
// for the action. A caller without the permit gets not found
func (s *Server) resolveActionRun(ctx context.Context, runId string) (*resolvedAction, *types.ActionRun, error) {
	if runId == "" {
		return nil, nil, types.CreateRequestError("run id is required", http.StatusBadRequest)
	}
	run, err := s.db.GetActionRun(ctx, runId, false)
	if err != nil {
		if errors.Is(err, metadata.ErrActionRunNotFound) {
			return nil, nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
		}
		return nil, nil, err
	}
	stage := types.AppStage(run.AppId) == "stage"
	appPath := run.AppPath
	if stage {
		// The stage instance's own path ends in the stage suffix; resolve
		// from the main app path with the stage flag
		if pathDomain, err := parseAppPath(run.AppPath); err == nil {
			pathDomain.Path = strings.TrimSuffix(pathDomain.Path, types.STAGE_SUFFIX)
			appPath = pathDomain.String()
		}
	}
	resolved, err := s.resolveAction(ctx, appPath, run.ActionPath, stage, false)
	if err != nil {
		var reqErr types.RequestError
		if errors.As(err, &reqErr) && reqErr.Code == http.StatusNotFound {
			return nil, nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
		}
		return nil, nil, err
	}
	if !resolved.action.IsAsync() {
		resolved.release()
		return nil, nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	return resolved, run, nil
}

// ListActionRuns lists the async runs of an app's actions the caller may
// run, newest first; action selects one action, status filters
// ListActionRuns lists the runs of async actions the caller may run,
// newest first. appPath is one app path (with stage its staging instance),
// or an app path glob ("all", the default, "/apps/**", ...): the runs of
// every matching app the caller passes the provider match and app:access
// checks on, merged newest first. selector limits the list to one action
// (its tool name or path); an unknown selector is an error for one app and
// matches nothing across a glob. For one app the app must exist and the
// caller must pass its checks; a glob leaves out what the caller cannot
// use, and reports the apps whose actions could not be read as warnings.
// before continues a listing from the cursor a previous page returned
// (NextBefore, set when a page was full): keyset paging in the list order
func (s *Server) ListActionRuns(ctx context.Context, appPath, selector, status string, stage bool, limit int, before string) (*types.ActionRunsResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	cursor, err := types.ParseActionRunCursor(before)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if isAppPathGlob(appPath) {
		return s.listActionRunsAcrossApps(ctx, appPath, selector, status, stage, limit, cursor)
	}
	application, appCtx, release, err := s.actionApp(ctx, appPath, stage, false)
	if err != nil {
		return nil, err
	}
	defer release()
	ret := &types.ActionRunsResponse{Runs: []types.ActionRun{}}
	actions := application.Actions()
	var selected *action.Action
	if selector != "" {
		if selected, err = action.FindAction(actions, selector); err != nil {
			return nil, types.CreateRequestError(err.Error(), http.StatusNotFound)
		}
	}
	for _, act := range actions {
		if !act.IsAsync() || (selected != nil && act != selected) {
			continue
		}
		authorized, err := act.Authorized(appCtx)
		if err != nil {
			return nil, err
		}
		if !authorized {
			continue
		}
		runs, err := act.ListRuns(appCtx, status, cursor, limit)
		if err != nil {
			return nil, err
		}
		mainPath := mainAppPathDomain(application.AppPathDomain(), application.MainApp, application.LinkedAppPath).String()
		for _, run := range runs {
			view := run.BasicView()
			view.MainAppPath = mainPath
			ret.Runs = append(ret.Runs, view)
		}
	}
	sortRunsNewestFirst(ret.Runs)
	if len(ret.Runs) > limit {
		ret.Runs = ret.Runs[:limit]
	}
	setNextBefore(ret, limit)
	return ret, nil
}

// setNextBefore sets the cursor of the next page when the page is full
// (a shorter page is the end of the listing)
func setNextBefore(ret *types.ActionRunsResponse, limit int) {
	if len(ret.Runs) == limit && limit > 0 {
		ret.NextBefore = ret.Runs[len(ret.Runs)-1].RunCursor().String()
	}
}

// isAppPathGlob reports whether an app path argument of the action APIs
// selects apps by glob rather than naming one app: empty or "all" (every
// app), or a pattern with glob metacharacters
func isAppPathGlob(appPath string) bool {
	return appPath == "" || appPath == "all" || strings.ContainsAny(appPath, "*?[{")
}

// listActionRunsAcrossApps is ListActionRuns for an app path glob: the run
// records of each matching app instance are read in one query per app (the
// action definitions come from appActionList: cached, no app is
// initialized), filtered to the async actions the caller holds the permit
// for, and merged newest first up to limit
func (s *Server) listActionRunsAcrossApps(ctx context.Context, appPathGlob, selector, status string, stage bool, limit int, before types.ActionRunCursor) (*types.ActionRunsResponse, error) {
	filteredApps, err := s.FilterApps(cmp.Or(appPathGlob, "all"), false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	// Per app in parallel (as ListActions), collected by app index
	type appResult struct {
		runs    []types.ActionRun
		warning string
	}
	results := make([]appResult, len(filteredApps))
	err = forEachAppParallel(ctx, filteredApps, func(ctx context.Context, i int, appInfo types.AppInfo) error {
		// The instance the caller asked for is resolved FIRST, and the
		// checks run against it: the staging instance may use another
		// login than prod (its own auth setting), a caller the prod checks
		// admit must not see staging runs those checks would refuse
		info := appInfo
		if stage {
			// The staging instance: its own entry (path_cl_stage) holds the
			// staged definition and its runs. An app without one is left
			// out silently: the caller has not been checked on it yet
			entry, err := s.resolveJobInstance(ctx, appInfo.String(), true)
			if err != nil {
				return nil
			}
			info = types.AppInfo{Id: entry.Id, AppPathDomain: entry.AppPathDomain(), MainApp: entry.MainApp, LinkedAppPath: entry.LinkedAppPath,
				Auth: entry.Metadata.AuthnType, UserID: entry.UserID}
		}
		target := actionTargetOfInfo(info)
		if s.rbacManager.APIEnforced(ctx) {
			authorized, err := s.rbacManager.AuthorizeAPI(ctx, types.PermissionAccess, target.grantPath, target.owner)
			if err != nil {
				return err
			}
			if !authorized {
				return nil
			}
		}
		if s.actionProviderMatch(ctx, target) != nil {
			return nil
		}
		listed, err := s.appActionList(ctx, info)
		if err != nil {
			results[i].warning = fmt.Sprintf("%s: %s", info.AppPathDomain, err)
			return nil
		}
		appCtx, err := s.actionAppContext(ctx, target)
		if err != nil {
			return err
		}
		paths := map[string]bool{}
		for _, act := range listed {
			if !act.info.Async || (selector != "" && !selectorMatches(act.info, selector)) {
				continue
			}
			authorized := len(act.permit) == 0
			if !authorized {
				if authorized, err = s.rbacManager.AuthorizeAny(appCtx, act.permit); err != nil {
					return err
				}
			}
			if authorized {
				paths[act.info.Path] = true
			}
		}
		if len(paths) == 0 {
			return nil
		}
		// The permitted actions filter in the query: the limit counts the
		// runs the caller gets, runs of restricted (or removed) actions
		// cannot use it up. limit runs per app, the merge below keeps the
		// newest limit of all
		runs, err := s.db.ListActionRuns(ctx, []types.AppId{info.Id}, slices.Sorted(maps.Keys(paths)), status, before, limit)
		if err != nil {
			return err
		}
		mainPath := target.grantPath.String()
		for _, run := range runs {
			view := run.BasicView()
			view.MainAppPath = mainPath
			results[i].runs = append(results[i].runs, view)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	ret := &types.ActionRunsResponse{Runs: []types.ActionRun{}}
	for _, result := range results {
		ret.Runs = append(ret.Runs, result.runs...)
		if result.warning != "" {
			ret.Warnings = append(ret.Warnings, result.warning)
		}
	}
	sortRunsNewestFirst(ret.Runs)
	if len(ret.Runs) > limit {
		ret.Runs = ret.Runs[:limit]
	}
	setNextBefore(ret, limit)
	return ret, nil
}

// selectorMatches reports whether an action selector (a tool name or an
// action path, as FindAction resolves it) names the listed action
func selectorMatches(info types.ActionInfo, selector string) bool {
	if info.Tool == selector {
		return true
	}
	return strings.HasPrefix(selector, "/") && (info.Path == selector || strings.TrimSuffix(selector, "/") == info.Path)
}

// sortRunsNewestFirst orders runs as the store lists them (started_at desc,
// id desc): the order the before cursor pages by, so a page cut from a
// merged list continues without skipping runs which share a start time
func sortRunsNewestFirst(runs []types.ActionRun) {
	slices.SortStableFunc(runs, func(a, b types.ActionRun) int {
		return cmp.Or(b.StartedAt.Compare(a.StartedAt), strings.Compare(b.Id, a.Id))
	})
}

// GetActionRun returns a run document, waiting up to wait for it to end
func (s *Server) GetActionRun(ctx context.Context, runId string, wait time.Duration) (map[string]any, error) {
	resolved, run, err := s.resolveActionRun(ctx, runId)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	if wait > 0 && run.IsActive() {
		run, err = resolved.action.WaitRun(ctx, runId, wait, true)
	} else {
		run, err = resolved.action.LoadRun(ctx, runId, true)
	}
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	return resolved.action.RunAPIResult(run), nil
}

// GetActionRunMCP returns the run document of the get_action_run MCP tool:
// the bounded MCP rendering (the output tail of a stream run, the values
// under the MCP size limits), not the REST representation
func (s *Server) GetActionRunMCP(ctx context.Context, runId string, wait time.Duration) (map[string]any, error) {
	resolved, run, err := s.resolveActionRun(ctx, runId)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	if wait > 0 && run.IsActive() {
		run, err = resolved.action.WaitRun(ctx, runId, wait, true)
	} else {
		run, err = resolved.action.LoadRun(ctx, runId, true)
	}
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	doc, _, _ := resolved.action.RunDocument(run, string(API_GET_ACTION_RUN))
	return doc, nil
}

// GetActionRunView returns a run for a UI which shows it beside its action
// (the console's run detail page): the run record (basic view), the bounded
// document of the get_action_run MCP tool (the result values or the output
// tail of a stream run, under the MCP size limits) and the url of the run
// page in the app. wait waits up to that long for an active run to end
func (s *Server) GetActionRunView(ctx context.Context, runId string, wait time.Duration) (map[string]any, error) {
	resolved, run, err := s.resolveActionRun(ctx, runId)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	if wait > 0 && run.IsActive() {
		run, err = resolved.action.WaitRun(ctx, runId, wait, true)
	} else {
		run, err = resolved.action.LoadRun(ctx, runId, true)
	}
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	doc, _, _ := resolved.action.RunDocument(run, string(API_GET_ACTION_RUN))
	pathDomain := resolved.app.AppPathDomain()
	origin := strings.TrimSuffix(types.GetAppUrl(pathDomain, s.Config()), pathDomain.Path)
	view := run.BasicView()
	view.MainAppPath = mainAppPathDomain(pathDomain, resolved.app.MainApp, resolved.app.LinkedAppPath).String()
	return map[string]any{
		"run":      view,
		"document": doc,
		"url":      origin + resolved.action.RunPagePath(run.Id),
		"tool":     resolved.tool,
	}, nil
}

// ActionRunOutput returns a run's output from the since offset
func (s *Server) ActionRunOutput(ctx context.Context, runId string, since int64) (*types.ActionRunOutputResponse, error) {
	resolved, _, err := s.resolveActionRun(ctx, runId)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	run, err := resolved.action.LoadRun(ctx, runId, true)
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	window := action.ReadOutput(run, since)
	return &types.ActionRunOutputResponse{Run: run.BasicView(), Output: window.Output, Since: window.Since}, nil
}

// CancelActionRun cancels an active run executing on this node
func (s *Server) CancelActionRun(ctx context.Context, runId string) (*types.ActionRunResponse, error) {
	resolved, _, err := s.resolveActionRun(ctx, runId)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	if _, invErr := resolved.action.CancelRun(ctx, runId); invErr != nil {
		return nil, types.CreateRequestError(invErr.Msg, invErr.Code)
	}
	run, err := resolved.action.WaitRun(ctx, runId, 2*time.Second, false)
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("run %s not found", runId), http.StatusNotFound)
	}
	return &types.ActionRunResponse{Run: run.BasicView()}, nil
}

// reconcileActionRuns finishes as lost the active runs whose liveness stamp
// expired: their node stopped. Runs on the leader with the job reconciler
func (s *Server) reconcileActionRuns(ctx context.Context) {
	expired, err := s.db.ExpiredActionRuns(ctx, time.Now())
	if err != nil {
		s.Error().Err(err).Msg("error listing expired action runs")
		return
	}
	for _, run := range expired {
		if s.jobRuns.Has(run.Id) {
			continue // executing here, the stamp renewal is just late
		}
		s.Warn().Str("run", run.Id).Str("node", run.NodeId).Msg("action run lost: executing node stopped")
		if err := s.db.MarkActionRunLost(ctx, run.Id); err != nil {
			s.Error().Err(err).Msgf("error marking action run %s lost", run.Id)
			continue
		}
		s.InsertAuditEvent(&types.AuditEvent{ //nolint:errcheck
			RequestId:  run.RequestId,
			CreateTime: time.Now(),
			UserId:     run.Actor,
			AppId:      run.AppId,
			EventType:  types.EventTypeAction,
			Operation:  action.AuditOpRunFinish,
			Target:     run.ActionName,
			Detail:     run.Id + " " + types.ActionRunLost,
			Status:     string(types.EventStatusFailure),
		})
	}
}

// removeAppActionRuns deletes the run records of deleted apps; runs still
// executing are canceled
func (s *Server) removeAppActionRuns(ctx context.Context, appIds []types.AppId) {
	runs, err := s.db.ListActionRuns(ctx, appIds, nil, types.ActionRunRunning, types.ActionRunCursor{}, 0)
	if err == nil {
		for _, run := range runs {
			s.jobRuns.Cancel(run.Id, "app delete")
		}
	}
	if err := s.db.DeleteActionRunsForApps(ctx, appIds); err != nil {
		s.Error().Err(err).Msg("error deleting action runs of deleted apps")
	}
}

// Management API handlers

func (h *Handler) listActionRuns(r *http.Request) (any, error) {
	query := r.URL.Query()
	stage, err := parseBoolArg(query.Get("stage"), false)
	if err != nil {
		return nil, err
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	updateTargetInContext(r, query.Get("appPath")+actionSelectorSep+query.Get("action"), false)
	return h.server.ListActionRuns(r.Context(), query.Get("appPath"), query.Get("action"), query.Get("status"), stage, limit, query.Get("before"))
}

func (h *Handler) getActionRun(r *http.Request) (any, error) {
	query := r.URL.Query()
	updateTargetInContext(r, query.Get("runId"), false)
	return h.server.GetActionRun(r.Context(), query.Get("runId"), parseWaitArg(query.Get("wait")))
}

func (h *Handler) actionRunOutput(r *http.Request) (any, error) {
	query := r.URL.Query()
	since, _ := strconv.ParseInt(query.Get("since"), 10, 64)
	updateTargetInContext(r, query.Get("runId"), false)
	return h.server.ActionRunOutput(r.Context(), query.Get("runId"), since)
}

func (h *Handler) cancelActionRun(r *http.Request) (any, error) {
	query := r.URL.Query()
	updateTargetInContext(r, query.Get("runId"), false)
	return h.server.CancelActionRun(r.Context(), query.Get("runId"))
}

// parseWaitArg parses a wait value: a duration or seconds
func parseWaitArg(value string) time.Duration {
	if value == "" {
		return 0
	}
	if d, err := time.ParseDuration(value); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(value); err == nil {
		return time.Duration(secs) * time.Second
	}
	return 0
}
