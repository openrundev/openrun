// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
func (s *Server) ListActionRuns(ctx context.Context, appPath, selector, status string, stage bool, limit int) (*types.ActionRunsResponse, error) {
	if appPath == "" {
		return nil, types.CreateRequestError("app path is required", http.StatusBadRequest)
	}
	application, appCtx, release, err := s.actionApp(ctx, appPath, stage, false)
	if err != nil {
		return nil, err
	}
	defer release()
	if limit <= 0 {
		limit = 50
	}
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
		runs, err := act.ListRuns(appCtx, status, limit)
		if err != nil {
			return nil, err
		}
		for _, run := range runs {
			ret.Runs = append(ret.Runs, run.BasicView())
		}
	}
	sortRunsNewestFirst(ret.Runs)
	if len(ret.Runs) > limit {
		ret.Runs = ret.Runs[:limit]
	}
	return ret, nil
}

func sortRunsNewestFirst(runs []types.ActionRun) {
	for i := 1; i < len(runs); i++ {
		for j := i; j > 0 && runs[j].StartedAt.After(runs[j-1].StartedAt); j-- {
			runs[j], runs[j-1] = runs[j-1], runs[j]
		}
	}
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
	runs, err := s.db.ListActionRuns(ctx, appIds, "", types.ActionRunRunning, 0)
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
	return h.server.ListActionRuns(r.Context(), query.Get("appPath"), query.Get("action"), query.Get("status"), stage, limit)
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
