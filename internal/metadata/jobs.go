// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ErrJobRunConflict is returned by CreateJobRun when the run cannot be
// claimed: the cron tick is already claimed, or the job already has an
// active run
var ErrJobRunConflict = errors.New("job run conflict")

// ErrJobRunNotFound is returned when a run id does not exist
var ErrJobRunNotFound = errors.New("job run not found")

const jobRunColumns = `id, app_id, app_path, job_name, trigger, actor, request_id, sync_id, version, previous_version, ` +
	`image, definition, args, scheduled_at, started_at, ended_at, status, exit_code, message, node_id, lease_until, ` +
	`container_name, forced`

// createJobTables creates the job run table. Runs are the execution records
// of jobs (arch/docs/jobs-and-deploy-hooks.md §10): one row per execution,
// written in short independent transactions
func (m *Metadata) createJobTables(ctx context.Context, tx types.Transaction) error {
	dt := system.MapDataType(m.dbType, "datetime")
	if _, err := tx.ExecContext(ctx, `create table job_runs (id text not null, app_id text not null, app_path text not null, `+
		`job_name text not null, trigger text not null, actor text, request_id text, sync_id text, version int, previous_version int, `+
		`image text, definition text, args text, scheduled_at `+dt+`, started_at `+dt+`, ended_at `+dt+`, status text not null, `+
		`exit_code int, message text, node_id text, lease_until `+dt+`, container_name text, active_slot int, forced bool, `+
		`primary key(id))`); err != nil {
		return fmt.Errorf("error creating job_runs table: %w", err)
	}
	// One claim per cron tick: the scheduler on each node inserts the tick's
	// run and the index makes a second claim fail
	if _, err := tx.ExecContext(ctx, `create unique index idx_job_runs_claim on job_runs(app_id, job_name, scheduled_at) where trigger = 'cron'`); err != nil {
		return fmt.Errorf("error creating job_runs claim index: %w", err)
	}
	// One active run per job per app instance; active_slot is 1 while a run
	// is active (null for forced runs and once finished)
	if _, err := tx.ExecContext(ctx, `create unique index idx_job_runs_active on job_runs(app_id, job_name, active_slot) where active_slot is not null`); err != nil {
		return fmt.Errorf("error creating job_runs active index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `create index idx_job_runs_history on job_runs(app_id, job_name, started_at)`); err != nil {
		return fmt.Errorf("error creating job_runs history index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `create index idx_job_runs_lease on job_runs(status, lease_until)`); err != nil {
		return fmt.Errorf("error creating job_runs lease index: %w", err)
	}
	return nil
}

// jobExecer returns the caller's transaction when one is open (a deploy
// gate run inside a create transaction) and the pool otherwise: writes from
// another connection would block behind an open sqlite write transaction
type jobExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (m *Metadata) jobExecer(tx types.Transaction) jobExecer {
	if tx.IsInitialized() {
		return tx.Tx
	}
	return m.db
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "duplicate key value violates unique constraint") ||
		strings.Contains(msg, "SQLSTATE 23505")
}

// CreateJobRun claims and records a new run. The run starts as running,
// owned by its node; ErrJobRunConflict when the cron tick was already
// claimed or the job has an active run (unless the run is forced)
func (m *Metadata) CreateJobRun(ctx context.Context, tx types.Transaction, run *types.JobRun) error {
	argsJson, err := json.Marshal(run.Args)
	if err != nil {
		return fmt.Errorf("error marshalling run args: %w", err)
	}
	var activeSlot sql.NullInt64
	if !run.Forced {
		activeSlot = sql.NullInt64{Int64: 1, Valid: true}
	}
	_, err = m.jobExecer(tx).ExecContext(ctx, system.RebindQuery(m.dbType, `insert into job_runs(`+jobRunColumns+`, active_slot) `+
		`values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		run.Id, run.AppId, run.AppPath, run.JobName, run.Trigger, run.Actor, run.RequestId, run.SyncId, run.Version, run.PreviousVersion,
		run.Image, run.Definition, string(argsJson), run.ScheduledAt.UTC(), run.StartedAt.UTC(), toNullTime(run.EndedAt), run.Status,
		toNullInt(run.ExitCode), run.Message, run.NodeId, toNullTime(run.LeaseUntil), run.ContainerName, run.Forced, activeSlot)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrJobRunConflict
		}
		return fmt.Errorf("error inserting job run: %w", err)
	}
	return nil
}

func toNullInt(v *int) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

type jobRunScanner interface {
	Scan(dest ...any) error
}

func scanJobRun(row jobRunScanner) (*types.JobRun, error) {
	var run types.JobRun
	var actor, requestId, syncId, image, definition, args, message, nodeId, containerName sql.NullString
	var version, previousVersion, exitCode sql.NullInt64
	var scheduledAt, startedAt, endedAt, leaseUntil sql.NullTime
	var forced sql.NullBool
	err := row.Scan(&run.Id, &run.AppId, &run.AppPath, &run.JobName, &run.Trigger, &actor, &requestId, &syncId, &version, &previousVersion,
		&image, &definition, &args, &scheduledAt, &startedAt, &endedAt, &run.Status, &exitCode, &message, &nodeId, &leaseUntil,
		&containerName, &forced)
	if err != nil {
		return nil, err
	}
	run.Actor = actor.String
	run.RequestId = requestId.String
	run.SyncId = syncId.String
	run.Image = image.String
	run.Definition = definition.String
	run.Message = message.String
	run.NodeId = nodeId.String
	run.ContainerName = containerName.String
	run.Version = int(version.Int64)
	run.PreviousVersion = int(previousVersion.Int64)
	run.Forced = forced.Bool
	if exitCode.Valid {
		code := int(exitCode.Int64)
		run.ExitCode = &code
	}
	if scheduledAt.Valid {
		run.ScheduledAt = scheduledAt.Time.UTC()
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
	return &run, nil
}

// GetJobRun returns one run by id
func (m *Metadata) GetJobRun(ctx context.Context, id string) (*types.JobRun, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType, `select `+jobRunColumns+` from job_runs where id = ?`), id)
	run, err := scanJobRun(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrJobRunNotFound
		}
		return nil, fmt.Errorf("error querying job run: %w", err)
	}
	return run, nil
}

func (m *Metadata) queryJobRuns(ctx context.Context, query string, args ...any) ([]types.JobRun, error) {
	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, query), args...)
	if err != nil {
		return nil, fmt.Errorf("error querying job runs: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	ret := make([]types.JobRun, 0)
	for rows.Next() {
		run, err := scanJobRun(rows)
		if err != nil {
			return nil, fmt.Errorf("error scanning job run: %w", err)
		}
		ret = append(ret, *run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job runs: %w", err)
	}
	return ret, nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// GetJobApps returns the prod and stage app entries that declare any job,
// for the scheduler. The metadata JSON is filtered in SQL so apps without
// jobs are not decoded every minute
func (m *Metadata) GetJobApps(ctx context.Context) ([]*types.AppEntry, error) {
	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, `select id, path, domain, main_app, linked_app_path, source_url, is_dev, user_id, `+
		`create_time, update_time, settings, metadata from apps where is_dev = ? and (cast(metadata as text) like ? or cast(metadata as text) like ?)`),
		false, `%"definition_jobs":%`, `%"jobs":%`)
	if err != nil {
		return nil, fmt.Errorf("error querying job apps: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	ret := make([]*types.AppEntry, 0)
	for rows.Next() {
		var app types.AppEntry
		var linkedAppPath, settings, metadata sql.NullString
		if err := rows.Scan(&app.Id, &app.Path, &app.Domain, &app.MainApp, &linkedAppPath, &app.SourceUrl, &app.IsDev, &app.UserID,
			&app.CreateTime, &app.UpdateTime, &settings, &metadata); err != nil {
			return nil, fmt.Errorf("error scanning job app: %w", err)
		}
		app.LinkedAppPath = linkedAppPath.String
		if metadata.Valid && metadata.String != "" {
			if err := json.Unmarshal([]byte(metadata.String), &app.Metadata); err != nil {
				return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
			}
		}
		if settings.Valid && settings.String != "" {
			if err := json.Unmarshal([]byte(settings.String), &app.Settings); err != nil {
				return nil, fmt.Errorf("error unmarshalling settings: %w", err)
			}
		}
		ret = append(ret, &app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job apps: %w", err)
	}
	return ret, nil
}

// ListJobRuns returns the runs of the given app instances, newest first,
// optionally filtered by job name and status
func (m *Metadata) ListJobRuns(ctx context.Context, appIds []types.AppId, jobName, status string, limit int) ([]types.JobRun, error) {
	if len(appIds) == 0 {
		return []types.JobRun{}, nil
	}
	args := make([]any, 0, len(appIds)+3)
	for _, id := range appIds {
		args = append(args, id)
	}
	query := `select ` + jobRunColumns + ` from job_runs where app_id in (` + placeholders(len(appIds)) + `)`
	if jobName != "" {
		query += ` and job_name = ?`
		args = append(args, jobName)
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
	return m.queryJobRuns(ctx, query, args...)
}

// ActiveJobRuns returns every run still executing, across all apps
func (m *Metadata) ActiveJobRuns(ctx context.Context) ([]types.JobRun, error) {
	return m.queryJobRuns(ctx, `select `+jobRunColumns+` from job_runs where status = ?`, types.JobRunRunning)
}

// ExpiredJobRuns returns the active runs whose liveness stamp is older than
// now: their node stopped renewing it
func (m *Metadata) ExpiredJobRuns(ctx context.Context, now time.Time) ([]types.JobRun, error) {
	runs, err := m.ActiveJobRuns(ctx)
	if err != nil {
		return nil, err
	}
	ret := make([]types.JobRun, 0)
	for _, run := range runs {
		if run.LeaseUntil != nil && run.LeaseUntil.Before(now) {
			ret = append(ret, run)
		}
	}
	return ret, nil
}

// UpdateJobRunLease renews the run's liveness stamp
func (m *Metadata) UpdateJobRunLease(ctx context.Context, id string, leaseUntil time.Time) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `update job_runs set lease_until = ? where id = ? and status = ?`),
		leaseUntil.UTC(), id, types.JobRunRunning)
	if err != nil {
		return fmt.Errorf("error updating job run lease: %w", err)
	}
	return nil
}

// UpdateJobRunContainer records the container (or Kubernetes Job) name and
// the image the run uses, before the workload starts
func (m *Metadata) UpdateJobRunContainer(ctx context.Context, tx types.Transaction, id, containerName, image string) error {
	_, err := m.jobExecer(tx).ExecContext(ctx, system.RebindQuery(m.dbType, `update job_runs set container_name = ?, image = ? where id = ?`),
		containerName, image, id)
	if err != nil {
		return fmt.Errorf("error updating job run container: %w", err)
	}
	return nil
}

// FinishJobRun records the run's terminal state, releasing its active slot.
// A run already finished (a cancel racing the owner's own finish) is left as
// is
func (m *Metadata) FinishJobRun(ctx context.Context, tx types.Transaction, id, status string, exitCode *int, message string) error {
	_, err := m.jobExecer(tx).ExecContext(ctx, system.RebindQuery(m.dbType, `update job_runs set status = ?, exit_code = ?, message = ?, `+
		`ended_at = ?, active_slot = null, lease_until = null where id = ? and status = ?`),
		status, toNullInt(exitCode), message, time.Now().UTC(), id, types.JobRunRunning)
	if err != nil {
		return fmt.Errorf("error finishing job run: %w", err)
	}
	return nil
}

// PruneJobRuns deletes the finished runs of a job beyond the newest keep
// records and returns the deleted runs, so the caller can remove their
// containers
func (m *Metadata) PruneJobRuns(ctx context.Context, appId types.AppId, jobName string, keep int) ([]types.JobRun, error) {
	if keep <= 0 {
		keep = 1
	}
	runs, err := m.queryJobRuns(ctx, `select `+jobRunColumns+` from job_runs where app_id = ? and job_name = ? and status != ? `+
		`order by started_at desc, id desc`, appId, jobName, types.JobRunRunning)
	if err != nil {
		return nil, err
	}
	if len(runs) <= keep {
		return nil, nil
	}
	old := runs[keep:]
	for _, run := range old {
		if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from job_runs where id = ?`), run.Id); err != nil {
			return nil, fmt.Errorf("error deleting job run %s: %w", run.Id, err)
		}
	}
	return old, nil
}

// DeleteJobRunsForApps deletes every run of the given app instances (app
// delete) and returns them so the caller can remove their containers
func (m *Metadata) DeleteJobRunsForApps(ctx context.Context, appIds []types.AppId) ([]types.JobRun, error) {
	if len(appIds) == 0 {
		return nil, nil
	}
	runs, err := m.ListJobRuns(ctx, appIds, "", "", 0)
	if err != nil {
		return nil, err
	}
	args := make([]any, 0, len(appIds))
	for _, id := range appIds {
		args = append(args, id)
	}
	if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from job_runs where app_id in (`+placeholders(len(appIds))+`)`), args...); err != nil {
		return nil, fmt.Errorf("error deleting job runs: %w", err)
	}
	return runs, nil
}
