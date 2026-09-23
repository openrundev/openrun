// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ErrActionRunNotFound is returned when a run id does not exist
var ErrActionRunNotFound = errors.New("action run not found")

// The identity and status columns of a run, read by every query; the payload
// columns (output_head, output_tail, result, param_errors) are read only
// when asked for
const actionRunColumns = `id, app_id, app_path, action_path, action_name, source, actor, request_id, version, args, ` +
	`started_at, ended_at, status, message, node_id, lease_until, is_stream, exit_code, output_bytes, output_omitted_bytes, ` +
	`result_status, report, result_rows, result_truncated`

const actionRunPayloadColumns = `, output_head, output_tail, result, param_errors`

// createActionRunTables creates the async action run table: one row per run
// with its args, status and stored output or result
func (m *Metadata) createActionRunTables(ctx context.Context, tx types.Transaction) error {
	dt := system.MapDataType(m.dbType, "datetime")
	if _, err := tx.ExecContext(ctx, `create table action_runs (id text not null, app_id text not null, app_path text not null, `+
		`action_path text not null, action_name text not null, source text not null, actor text, request_id text, version int, `+
		`args text, started_at `+dt+`, ended_at `+dt+`, status text not null, message text, node_id text, lease_until `+dt+`, `+
		`is_stream bool, exit_code int, output_bytes bigint, output_omitted_bytes bigint, output_head text, output_tail text, `+
		`result_status text, report text, result text, param_errors text, result_rows int, result_truncated bool, `+
		`primary key(id))`); err != nil {
		return fmt.Errorf("error creating action_runs table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `create index idx_action_runs_history on action_runs(app_id, action_path, started_at)`); err != nil {
		return fmt.Errorf("error creating action_runs history index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `create index idx_action_runs_lease on action_runs(status, lease_until)`); err != nil {
		return fmt.Errorf("error creating action_runs lease index: %w", err)
	}
	return nil
}

// CreateActionRun records a new run, in the running state
func (m *Metadata) CreateActionRun(ctx context.Context, run *types.ActionRun) error {
	argsJson, err := json.Marshal(run.Args)
	if err != nil {
		return fmt.Errorf("error marshalling run args: %w", err)
	}
	_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `insert into action_runs(`+actionRunColumns+`) `+
		`values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		run.Id, run.AppId, run.AppPath, run.ActionPath, run.ActionName, run.Source, run.Actor, run.RequestId, run.Version,
		string(argsJson), run.StartedAt.UTC(), toNullTime(run.EndedAt), run.Status, run.Message, run.NodeId, toNullTime(run.LeaseUntil),
		run.IsStream, toNullInt(run.ExitCode), run.OutputBytes, run.OutputOmittedBytes, run.ResultStatus, run.Report,
		run.ResultRows, run.ResultTruncated)
	if err != nil {
		return fmt.Errorf("error inserting action run: %w", err)
	}
	return nil
}

func scanActionRun(row jobRunScanner, payload bool) (*types.ActionRun, error) {
	var run types.ActionRun
	var actor, requestId, args, message, nodeId, resultStatus, report sql.NullString
	var outputHead, outputTail, result, paramErrors sql.NullString
	var version, exitCode, outputBytes, outputOmitted, resultRows sql.NullInt64
	var startedAt, endedAt, leaseUntil sql.NullTime
	var isStream, resultTruncated sql.NullBool
	dest := []any{&run.Id, &run.AppId, &run.AppPath, &run.ActionPath, &run.ActionName, &run.Source, &actor, &requestId, &version, &args,
		&startedAt, &endedAt, &run.Status, &message, &nodeId, &leaseUntil, &isStream, &exitCode, &outputBytes, &outputOmitted,
		&resultStatus, &report, &resultRows, &resultTruncated}
	if payload {
		dest = append(dest, &outputHead, &outputTail, &result, &paramErrors)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	run.Actor = actor.String
	run.RequestId = requestId.String
	run.Message = message.String
	run.NodeId = nodeId.String
	run.Version = int(version.Int64)
	run.IsStream = isStream.Bool
	run.OutputBytes = outputBytes.Int64
	run.OutputOmittedBytes = outputOmitted.Int64
	run.ResultStatus = resultStatus.String
	run.Report = report.String
	run.ResultRows = int(resultRows.Int64)
	run.ResultTruncated = resultTruncated.Bool
	run.OutputHead = outputHead.String
	run.OutputTail = outputTail.String
	run.Result = result.String
	if exitCode.Valid {
		code := int(exitCode.Int64)
		run.ExitCode = &code
	}
	if startedAt.Valid {
		run.StartedAt = startedAt.Time.UTC()
	}
	if endedAt.Valid {
		t := endedAt.Time.UTC()
		run.EndedAt = &t
	}
	if leaseUntil.Valid {
		t := leaseUntil.Time.UTC()
		run.LeaseUntil = &t
	}
	if args.Valid && args.String != "" && args.String != "null" {
		if err := json.Unmarshal([]byte(args.String), &run.Args); err != nil {
			return nil, fmt.Errorf("error unmarshalling run args: %w", err)
		}
	}
	if paramErrors.Valid && paramErrors.String != "" && paramErrors.String != "null" {
		if err := json.Unmarshal([]byte(paramErrors.String), &run.ParamErrors); err != nil {
			return nil, fmt.Errorf("error unmarshalling run param errors: %w", err)
		}
	}
	return &run, nil
}

// GetActionRun returns one run by id, with its stored output and result when
// payload is set
func (m *Metadata) GetActionRun(ctx context.Context, id string, payload bool) (*types.ActionRun, error) {
	columns := actionRunColumns
	if payload {
		columns += actionRunPayloadColumns
	}
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType, `select `+columns+` from action_runs where id = ?`), id)
	run, err := scanActionRun(row, payload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrActionRunNotFound
		}
		return nil, fmt.Errorf("error querying action run: %w", err)
	}
	return run, nil
}

func (m *Metadata) queryActionRuns(ctx context.Context, query string, args ...any) ([]types.ActionRun, error) {
	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, query), args...)
	if err != nil {
		return nil, fmt.Errorf("error querying action runs: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	ret := make([]types.ActionRun, 0)
	for rows.Next() {
		run, err := scanActionRun(rows, false)
		if err != nil {
			return nil, fmt.Errorf("error scanning action run: %w", err)
		}
		ret = append(ret, *run)
	}
	return ret, rows.Err()
}

// ListActionRuns lists the runs of the app instances, newest first, without
// the payload columns; actionPath and status filter when set
func (m *Metadata) ListActionRuns(ctx context.Context, appIds []types.AppId, actionPath, status string, limit int) ([]types.ActionRun, error) {
	if len(appIds) == 0 {
		return []types.ActionRun{}, nil
	}
	args := make([]any, 0, len(appIds)+3)
	for _, id := range appIds {
		args = append(args, id)
	}
	query := `select ` + actionRunColumns + ` from action_runs where app_id in (` + placeholders(len(appIds)) + `)`
	if actionPath != "" {
		query += ` and action_path = ?`
		args = append(args, actionPath)
	}
	if status != "" {
		query += ` and status = ?`
		args = append(args, status)
	}
	query += ` order by started_at desc, id desc`
	if limit > 0 {
		query += ` limit ?`
		args = append(args, limit)
	}
	return m.queryActionRuns(ctx, query, args...)
}

// ExpiredActionRuns returns the active runs whose liveness stamp is older
// than now: their node stopped renewing it
func (m *Metadata) ExpiredActionRuns(ctx context.Context, now time.Time) ([]types.ActionRun, error) {
	runs, err := m.queryActionRuns(ctx, `select `+actionRunColumns+` from action_runs where status = ?`, types.ActionRunRunning)
	if err != nil {
		return nil, err
	}
	ret := make([]types.ActionRun, 0)
	for _, run := range runs {
		if run.LeaseUntil != nil && run.LeaseUntil.Before(now) {
			ret = append(ret, run)
		}
	}
	return ret, nil
}

// UpdateActionRunLease renews the run's liveness stamp
func (m *Metadata) UpdateActionRunLease(ctx context.Context, id string, leaseUntil time.Time) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update action_runs set lease_until = ? where id = ? and status = ?`),
		leaseUntil.UTC(), id, types.ActionRunRunning)
	if err != nil {
		return fmt.Errorf("error updating action run lease: %w", err)
	}
	return nil
}

// UpdateActionRunOutput flushes the output of a running stream run: the
// head (once, when known), the current tail and the byte counts
func (m *Metadata) UpdateActionRunOutput(ctx context.Context, id string, head *string, tail string, outputBytes, omittedBytes int64) error {
	var err error
	if head != nil {
		_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update action_runs set output_head = ?, output_tail = ?, `+
			`output_bytes = ?, output_omitted_bytes = ? where id = ?`), *head, tail, outputBytes, omittedBytes, id)
	} else {
		_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update action_runs set output_tail = ?, `+
			`output_bytes = ?, output_omitted_bytes = ? where id = ?`), tail, outputBytes, omittedBytes, id)
	}
	if err != nil {
		return fmt.Errorf("error updating action run output: %w", err)
	}
	return nil
}

// FinishActionRun records the run's terminal state with its output or
// result. A run already finished (the reconciler marking it lost while the
// owner finishes) is left as is
func (m *Metadata) FinishActionRun(ctx context.Context, run *types.ActionRun) error {
	paramErrorsJson, err := json.Marshal(run.ParamErrors)
	if err != nil {
		return fmt.Errorf("error marshalling run param errors: %w", err)
	}
	_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update action_runs set status = ?, message = ?, ended_at = ?, `+
		`lease_until = null, is_stream = ?, exit_code = ?, output_bytes = ?, output_omitted_bytes = ?, output_head = ?, output_tail = ?, `+
		`result_status = ?, report = ?, result = ?, param_errors = ?, result_rows = ?, result_truncated = ? `+
		`where id = ? and status = ?`),
		run.Status, run.Message, time.Now().UTC(), run.IsStream, toNullInt(run.ExitCode), run.OutputBytes, run.OutputOmittedBytes,
		run.OutputHead, run.OutputTail, run.ResultStatus, run.Report, run.Result, string(paramErrorsJson), run.ResultRows,
		run.ResultTruncated, run.Id, types.ActionRunRunning)
	if err != nil {
		return fmt.Errorf("error finishing action run: %w", err)
	}
	return nil
}

// MarkActionRunLost finishes a run whose node stopped
func (m *Metadata) MarkActionRunLost(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update action_runs set status = ?, message = ?, ended_at = ?, `+
		`lease_until = null where id = ? and status = ?`),
		types.ActionRunLost, "executing node stopped", time.Now().UTC(), id, types.ActionRunRunning)
	if err != nil {
		return fmt.Errorf("error marking action run lost: %w", err)
	}
	return nil
}

// PruneActionRuns deletes the finished runs of an app instance beyond the
// newest keep records, across all its actions
func (m *Metadata) PruneActionRuns(ctx context.Context, appId types.AppId, keep int) (int, error) {
	if keep <= 0 {
		keep = 1
	}
	runs, err := m.queryActionRuns(ctx, `select `+actionRunColumns+` from action_runs where app_id = ? and status != ? `+
		`order by started_at desc, id desc`, appId, types.ActionRunRunning)
	if err != nil {
		return 0, err
	}
	if len(runs) <= keep {
		return 0, nil
	}
	old := runs[keep:]
	for _, run := range old {
		if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from action_runs where id = ?`), run.Id); err != nil {
			return 0, fmt.Errorf("error deleting action run %s: %w", run.Id, err)
		}
	}
	return len(old), nil
}

// DeleteActionRunsForApps deletes every run of the given app instances (app
// delete)
func (m *Metadata) DeleteActionRunsForApps(ctx context.Context, appIds []types.AppId) error {
	if len(appIds) == 0 {
		return nil
	}
	args := make([]any, 0, len(appIds))
	for _, id := range appIds {
		args = append(args, id)
	}
	if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from action_runs where app_id in (`+placeholders(len(appIds))+`)`), args...); err != nil {
		return fmt.Errorf("error deleting action runs: %w", err)
	}
	return nil
}
