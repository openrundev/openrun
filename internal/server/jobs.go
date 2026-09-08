// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	apppkg "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const (
	jobLeaseValidity   = 60 * time.Second
	jobLeaseRenewal    = 20 * time.Second
	jobScheduleWindow  = 2 * time.Minute
	jobMessageMaxBytes = 4096
	jobLogLines        = 1000
	jobLogTailLines    = 50
	jobSchedulerActor  = "scheduler"
)

// jobRunRegistry tracks the runs executing on this node, by run id, so a
// cancel request can stop them
type jobRunRegistry struct {
	mu        sync.Mutex
	active    map[string]context.CancelFunc
	ctx       context.Context
	cancelAll context.CancelFunc
	closed    bool
	wg        sync.WaitGroup
}

// begin registers work before it can touch the database, so shutdown can
// reject new runs and wait for every claimed run to finish cleanup.
func (r *jobRunRegistry) begin() (context.Context, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, errors.New("job runner is stopped")
	}
	if r.ctx == nil {
		r.ctx, r.cancelAll = context.WithCancel(context.Background())
	}
	r.wg.Add(1)
	return r.ctx, r.wg.Done, nil
}
func (r *jobRunRegistry) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.cancelAll != nil {
		r.cancelAll()
	}
}
func (r *jobRunRegistry) wait() { r.wg.Wait() }

func (r *jobRunRegistry) add(id string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[string]context.CancelFunc{}
	}
	r.active[id] = cancel
}

func (r *jobRunRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active, id)
}

func (r *jobRunRegistry) cancel(id string) bool {
	r.mu.Lock()
	cancel, ok := r.active[id]
	r.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func (r *jobRunRegistry) has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[id]
	return ok
}

// jobExecution is one run to execute: the loaded app holding the code, env
// and image, the instance the run targets, and the trigger context
type jobExecution struct {
	app      *apppkg.App
	closeApp func()          // closes a throwaway app once the run ends; nil for the app store's app
	target   *types.AppEntry // the instance the run targets: env identity, bindings account, run app id
	spec     types.JobSpec
	trigger  string
	actor    string
	args     map[string]string
	force    bool
	image    string            // pre-resolved image (deploy gates run the image just built)
	extraEnv map[string]string // CL_DEPLOY_REASON and the like
	version  int
	previous int
	schedule time.Time // the cron tick; zero for other triggers
	request  string
	syncId   string
	tx       types.Transaction // record writes go through the caller's transaction when set (create gates)
}

func (s *Server) jobNodeId() string {
	return string(types.CurrentServerId)
}

// claimJobRun inserts the run record, which is the concurrency and cron
// claim check
func (s *Server) claimJobRun(ctx context.Context, exec *jobExecution) (*types.JobRun, error) {
	id, err := newPrefixedId("run_")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	scheduledAt := exec.schedule
	if scheduledAt.IsZero() {
		scheduledAt = now
	}
	lease := now.Add(jobLeaseValidity)
	run := &types.JobRun{
		Id:              id,
		AppId:           exec.target.Id,
		AppPath:         exec.target.AppPathDomain().String(),
		JobName:         exec.spec.Name,
		Trigger:         exec.trigger,
		Actor:           exec.actor,
		RequestId:       exec.request,
		SyncId:          exec.syncId,
		Version:         exec.version,
		PreviousVersion: exec.previous,
		Image:           exec.image,
		Definition:      exec.spec.String(),
		Args:            exec.args,
		ScheduledAt:     scheduledAt,
		StartedAt:       now,
		Status:          types.JobRunRunning,
		NodeId:          s.jobNodeId(),
		LeaseUntil:      &lease,
		Forced:          exec.force,
	}
	if err := s.db.CreateJobRun(ctx, exec.tx, run); err != nil {
		if errors.Is(err, metadata.ErrJobRunConflict) {
			if exec.trigger == types.JobTriggerCron {
				return nil, err
			}
			return nil, types.CreateRequestError(fmt.Sprintf("job %s of %s already has an active run (use --force to run alongside it)",
				exec.spec.Name, exec.target.AppPathDomain()), http.StatusConflict)
		}
		return nil, err
	}
	return run, nil
}

// startJobRun claims the run and executes it in the background
func (s *Server) startJobRun(ctx context.Context, exec *jobExecution) (*types.JobRun, error) {
	parent, done, err := s.jobRuns.begin()
	if err != nil {
		if exec.closeApp != nil {
			exec.closeApp()
		}
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			done()
		}
	}()
	claimCtx, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(parent, cancel)
	defer stopCancel()
	defer cancel()
	run, err := s.claimJobRun(claimCtx, exec)
	if err != nil {
		if exec.closeApp != nil {
			exec.closeApp()
		}
		return nil, err
	}
	// Background work retains only authorization, never request audit or app state.
	runCtx := newJobAuthorizationContext(parent, ctx)
	// The response and worker must not share mutable status fields.
	workerRun := *run
	handedOff = true
	go func() {
		defer done()
		s.performJobRun(runCtx, exec, &workerRun)
	}()
	return run, nil
}

// valuelessContext keeps a parent's cancellation and deadline but none of
// its values
type valuelessContext struct{ context.Context }

func (valuelessContext) Value(any) any { return nil }

// newJobAuthorizationContext builds the context a job runs under: the
// lifetime of parent, and from caller only the authorization state (user,
// groups, RBAC marker, trusted flag, API invoker, credential scope ceiling
// and sync snapshot). Caller-owned audit state, app values and URL
// permission simulations do not reach the worker
func newJobAuthorizationContext(parent, caller context.Context) context.Context {
	ctx := context.WithValue(valuelessContext{parent}, types.USER_ID, system.GetContextUserId(caller))
	ctx = context.WithValue(ctx, types.GROUPS, slices.Clone(system.GetContextGroups(caller)))
	if invoker := system.GetContextApiInvoker(caller); invoker != "" {
		// The surface policy (checkApiOpEnabled) follows the job: an MCP
		// caller cannot use a job to reach operations disabled for MCP
		ctx = system.WithApiInvoker(ctx, invoker)
	}
	if marker := caller.Value(types.RBAC_ENABLED); marker != nil {
		ctx = context.WithValue(ctx, types.RBAC_ENABLED, marker)
	}
	if system.IsTrustedOperation(caller) {
		ctx = system.WithTrustedOperation(ctx)
	}
	if scopes, present := system.GetContextApiScopes(caller); present {
		ctx = system.WithApiScopes(ctx, slices.Clone(scopes))
	}
	if syncId := system.GetContextValue(caller, types.SYNC_ID); syncId != "" {
		ctx = context.WithValue(ctx, types.SYNC_ID, syncId)
	}
	ctx = rbac.WithSyncAuthorizer(ctx, rbac.GetSyncAuthorizer(caller))
	// Keep credential attenuation too: jobs must not mint longer-lived or
	// broader-resource keys than their caller. Only these constraints are
	// copied, and copied so later caller mutations do not reach the worker
	if cred := system.GetContextApiCredential(caller); cred != nil {
		attenuated := &types.Credential{Scopes: slices.Clone(cred.Scopes), Resources: slices.Clone(cred.Resources)}
		if cred.ExpiresAt != nil {
			expiry := *cred.ExpiresAt
			attenuated.ExpiresAt = &expiry
		}
		ctx = system.WithApiCredential(ctx, attenuated)
	}
	return ctx
}

// executeJobRun claims the run and executes it, returning the finished run
func (s *Server) executeJobRun(ctx context.Context, exec *jobExecution) (*types.JobRun, error) {
	parent, done, err := s.jobRuns.begin()
	if err != nil {
		if exec.closeApp != nil {
			exec.closeApp()
		}
		return nil, err
	}
	defer done()
	claimCtx, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(parent, cancel)
	defer stopCancel()
	defer cancel()
	run, err := s.claimJobRun(claimCtx, exec)
	if err != nil {
		if exec.closeApp != nil {
			exec.closeApp()
		}
		return nil, err
	}
	return s.performJobRun(newJobAuthorizationContext(claimCtx, ctx), exec, run), nil
}

func truncateMessage(msg string) string {
	if len(msg) > jobMessageMaxBytes {
		return msg[len(msg)-jobMessageMaxBytes:]
	}
	return msg
}

// performJobRun executes a claimed run to completion: the Starlark function
// or the job container, under the job timeout, with the liveness stamp
// renewed while it runs. Records the outcome, writes the audit event and
// prunes the job's old runs
func (s *Server) performJobRun(ctx context.Context, exec *jobExecution, run *types.JobRun) *types.JobRun {
	if exec.closeApp != nil {
		defer exec.closeApp()
	}
	spec := exec.spec
	// Preserve the caller's RBAC, scope ceiling and sync snapshot across the
	// asynchronous handoff. A job must not turn a limited caller into admin.
	baseCtx := context.WithValue(ctx, types.REQUEST_ID, exec.request)
	// Plugin permits belong to the job app, even when another app invoked it.
	baseCtx = context.WithValue(baseCtx, types.APP_PATH_DOMAIN,
		mainAppPathDomain(exec.target.AppPathDomain(), exec.target.MainApp, exec.target.LinkedAppPath))
	baseCtx = context.WithValue(baseCtx, types.APP_ID, string(exec.target.Id))
	if system.GetContextUserId(baseCtx) == "" && system.IsTrustedOperation(baseCtx) {
		baseCtx = context.WithValue(baseCtx, types.USER_ID, exec.actor)
	}
	runCtx, cancel := context.WithTimeout(baseCtx, spec.TimeoutDuration())
	defer cancel()
	s.jobRuns.add(run.Id, cancel)
	defer s.jobRuns.remove(run.Id)

	var lease *system.BackgroundTask
	if !exec.tx.IsInitialized() {
		lease = system.StartPeriodicTask(runCtx, jobLeaseRenewal, false, func(ctx context.Context) { s.renewJobLease(ctx, run.Id) })
		defer lease.Stop()
	}

	var status, message string
	var exitCode *int
	if spec.IsRun() {
		result, err := exec.app.RunJobFunction(runCtx, spec, exec.args)
		switch {
		case err != nil:
			status, message = jobErrorStatus(runCtx, err)
		case result.Failed:
			status, message = types.JobRunFailed, result.Message
		default:
			status, message = types.JobRunSucceeded, result.Message
		}
	} else {
		code, err := s.runJobContainer(runCtx, exec, run)
		switch {
		case err != nil:
			status, message = jobErrorStatus(runCtx, err)
		case code == 0:
			status = types.JobRunSucceeded
			exitCode = &code
		default:
			status, message = types.JobRunFailed, fmt.Sprintf("exit code %d", code)
			exitCode = &code
		}
	}
	lease.Stop()
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(baseCtx), 10*time.Second)
	defer finishCancel()
	message = truncateMessage(message)
	if err := s.db.FinishJobRun(finishCtx, exec.tx, run.Id, status, exitCode, message); err != nil {
		s.Error().Err(err).Msgf("error recording job run %s finish", run.Id)
	}
	run.Status = status
	run.Message = message
	run.ExitCode = exitCode
	ended := time.Now().UTC()
	run.EndedAt = &ended
	s.Info().Str("run", run.Id).Str("job", spec.Name).Str("app", run.AppPath).Str("status", status).Msg("job run finished")
	s.insertJobAudit(run)

	if !exec.tx.IsInitialized() {
		s.pruneJobRuns(finishCtx, exec.target, spec.Name, exec.app.AppConfig.Jobs.RetainRuns)
	}
	return run
}

// jobErrorStatus maps an execution error to the run status
func jobErrorStatus(ctx context.Context, err error) (string, string) {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return types.JobRunTimedOut, "timed out"
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		return types.JobRunCanceled, "canceled"
	default:
		return types.JobRunFailed, err.Error()
	}
}

// runJobContainer resolves the image, env and volumes of a command job and
// runs its container, returning the exit code
func (s *Server) runJobContainer(ctx context.Context, exec *jobExecution, run *types.JobRun) (int, error) {
	spec := exec.spec
	if !exec.app.HasContainer() {
		return -1, fmt.Errorf("app %s has no container config, command jobs need one", exec.app.AppPathDomain())
	}
	runner, ok := container.AsJobRunner(exec.app.ContainerManager())
	if !ok {
		return -1, fmt.Errorf("container manager does not support jobs")
	}
	image := exec.image
	if image == "" {
		var err error
		if image, err = exec.app.ResolveJobImage(ctx, spec); err != nil {
			return -1, err
		}
	}
	env, err := exec.app.JobEnv(spec, exec.target)
	if err != nil {
		return -1, err
	}
	env["CL_APP_STAGE"] = types.AppStage(exec.target.Id)
	env["CL_APP_VERSION"] = strconv.Itoa(exec.version)
	env["CL_JOB_NAME"] = spec.Name
	env["CL_JOB_RUN_ID"] = run.Id
	env["CL_JOB_TRIGGER"] = exec.trigger
	if !exec.schedule.IsZero() {
		env["CL_JOB_SCHEDULED_AT"] = exec.schedule.UTC().Format(time.RFC3339)
	}
	for k, v := range exec.extraEnv {
		env[k] = v
	}
	argValues, err := exec.app.JobArgValues(spec, exec.args)
	if err != nil {
		return -1, err
	}
	for k, v := range argValues {
		env["CL_JOB_ARG_"+strings.ToUpper(strings.ReplaceAll(k, "-", "_"))] = v
	}
	volumes, err := exec.app.JobVolumes(ctx, spec)
	if err != nil {
		return -1, err
	}
	options := spec.Options
	if options == nil {
		options = exec.app.Metadata.ContainerOptions
	}
	name := container.JobContainerName(exec.target.Id, spec.Name, run.Id)
	if err := s.db.UpdateJobRunContainer(ctx, exec.tx, run.Id, string(name), image); err != nil {
		return -1, err
	}
	run.ContainerName = string(name)
	run.Image = image
	return runner.RunJob(ctx, container.JobRunRequest{
		AppEntry:         exec.target,
		RunId:            run.Id,
		JobName:          spec.Name,
		ContainerName:    name,
		Image:            image,
		Argv:             spec.Argv(),
		Env:              env,
		Volumes:          volumes,
		ContainerOptions: options,
		ParamMap:         exec.app.JobParamMap(),
		Timeout:          spec.TimeoutDuration(),
	})
}

// renewJobLease renews the run's liveness stamp with a bounded query.
func (s *Server) renewJobLease(parent context.Context, runId string) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if err := s.db.UpdateJobRunLease(ctx, runId, time.Now().Add(jobLeaseValidity)); err != nil && ctx.Err() == nil {
		s.Warn().Err(err).Msgf("error renewing job run %s lease", runId)
	}
}

func (s *Server) insertJobAudit(run *types.JobRun) {
	status := types.EventStatusSuccess
	if run.Status != types.JobRunSucceeded {
		status = types.EventStatusFailure
	}
	event := types.AuditEvent{
		RequestId:  run.RequestId,
		CreateTime: time.Now(),
		UserId:     run.Actor,
		AppId:      run.AppId,
		EventType:  types.EventTypeJob,
		Operation:  run.Trigger,
		Target:     run.AppPath + ":" + run.JobName,
		Status:     string(status),
		Detail:     strings.TrimSpace(run.Id + " " + run.Status + " " + run.Message),
	}
	if err := s.InsertAuditEvent(&event); err != nil {
		s.Error().Err(err).Msgf("error inserting audit event for job run %s", run.Id)
	}
}

// jobRunnerFor builds a job runner for an app instance without loading the
// app: used to read logs and remove the containers of retired runs
func (s *Server) jobRunnerFor(appEntry *types.AppEntry) (container.JobRunner, error) {
	if s.Config().System.ContainerCommand == types.CONTAINER_KUBERNETES {
		merged := s.Config()
		runDir := fmt.Sprintf(os.ExpandEnv("$OPENRUN_HOME/run/app/%s"), appEntry.Id)
		return container.NewKubernetesCM(s.Logger, merged, &merged.AppConfig, runDir, appEntry.Id)
	}
	if s.Config().System.ContainerCommand == "" {
		return nil, fmt.Errorf("container management is not enabled")
	}
	return container.NewCommandCM(s.Logger, s.Config(), appEntry.Id, ""), nil
}

// pruneJobRuns retires the finished runs of a job beyond the retention
// count, removing their containers
func (s *Server) pruneJobRuns(ctx context.Context, target *types.AppEntry, jobName string, retain int) {
	if retain <= 0 {
		retain = s.Config().AppConfig.Jobs.RetainRuns
	}
	if retain <= 0 {
		retain = 50
	}
	old, err := s.db.PruneJobRuns(ctx, target.Id, jobName, retain)
	if err != nil {
		s.Error().Err(err).Msgf("error pruning runs of job %s", jobName)
		return
	}
	s.removeJobContainers(ctx, target, old)
}

// removeJobContainers removes the containers of retired runs
func (s *Server) removeJobContainers(ctx context.Context, appEntry *types.AppEntry, runs []types.JobRun) {
	var runner container.JobRunner
	for _, run := range runs {
		if run.ContainerName == "" {
			continue
		}
		if runner == nil {
			var err error
			if runner, err = s.jobRunnerFor(appEntry); err != nil {
				s.Warn().Err(err).Msg("error building job runner for container cleanup")
				return
			}
		}
		if err := runner.RemoveJob(ctx, container.ContainerName(run.ContainerName)); err != nil {
			s.Warn().Err(err).Msgf("error removing container of retired job run %s", run.Id)
		}
	}
}

// removeAppJobRuns deletes the run records of deleted apps and their
// containers (app delete, after the commit)
func (s *Server) removeAppJobRuns(ctx context.Context, appIds []types.AppId) {
	runs, err := s.db.DeleteJobRunsForApps(ctx, appIds)
	if err != nil {
		s.Error().Err(err).Msg("error deleting job runs of deleted apps")
		return
	}
	for _, run := range runs {
		if run.ContainerName == "" {
			continue
		}
		if s.jobRuns.cancel(run.Id) {
			continue // the run's own cleanup handles a canceled container
		}
		// Docker containers of the app are removed by label with the app's
		// other containers; Kubernetes Jobs are removed with the app
		// resources. Nothing to do per run here
	}
}

// activeJobRunIds returns the ids of the runs executing anywhere, for the
// stale container sweeper
func (s *Server) activeJobRunIds(ctx context.Context) map[string]bool {
	ret := map[string]bool{}
	if s.db == nil {
		return ret
	}
	runs, err := s.db.ActiveJobRuns(ctx)
	if err != nil {
		s.Warn().Err(err).Msg("error listing active job runs")
		return nil
	}
	for _, run := range runs {
		ret[run.Id] = true
	}
	return ret
}

// loadJobApp returns an app object holding the instance's code for a job
// run: the app store's app for dev apps (their container is built by the
// dev reload), a throwaway app loaded without starting containers otherwise
func (s *Server) loadJobApp(ctx context.Context, tx types.Transaction, entry *types.AppEntry) (*apppkg.App, func(), error) {
	if entry.IsDev {
		application, err := s.GetApp(ctx, entry.AppPathDomain(), true)
		if err != nil {
			return nil, nil, err
		}
		return application, nil, nil
	}
	application, err := s.setupApp(ctx, entry, tx)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up app %s: %w", entry, err)
	}
	if _, err := application.Reload(ctx, true, true, types.DryRunFalse, apppkg.ReloadOptions{SkipContainer: true}); err != nil {
		application.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("error loading app %s: %w", entry, err)
	}
	return application, func() { application.Close() }, nil //nolint:errcheck
}

// jobsTick runs the scheduler and the reconciler, once a minute on the leader
func (s *Server) jobsTick(ctx context.Context) {
	s.reconcileJobRuns(ctx)
	s.scheduleCronJobs(ctx)
}

// reconcileJobRuns finishes as lost the active runs whose liveness stamp
// expired: their node stopped
func (s *Server) reconcileJobRuns(ctx context.Context) {
	expired, err := s.db.ExpiredJobRuns(ctx, time.Now())
	if err != nil {
		s.Error().Err(err).Msg("error listing expired job runs")
		return
	}
	for _, run := range expired {
		if s.jobRuns.has(run.Id) {
			continue // executing here, the stamp renewal is just late
		}
		s.Warn().Str("run", run.Id).Str("node", run.NodeId).Msg("job run lost: executing node stopped")
		if err := s.db.FinishJobRun(ctx, types.Transaction{}, run.Id, types.JobRunLost, nil, "executing node stopped"); err != nil {
			s.Error().Err(err).Msgf("error marking job run %s lost", run.Id)
			continue
		}
		run.Status = types.JobRunLost
		run.Message = "executing node stopped"
		s.insertJobAudit(&run)
	}
}

// scheduleCronJobs claims and starts the cron ticks that fell in the last
// window for every enabled cron job of prod and stage instances. A tick is
// claimed by its run row (unique per job and tick), so a leader change
// cannot double claim; ticks older than the window are not replayed
func (s *Server) scheduleCronJobs(ctx context.Context) {
	entries, err := s.db.GetJobApps(ctx)
	if err != nil {
		s.Error().Err(err).Msg("error listing apps with jobs")
		return
	}
	now := time.Now().UTC()
	windowStart := now.Add(-jobScheduleWindow)
	for _, entry := range entries {
		stage := types.AppStage(entry.Id)
		if stage != "prod" && stage != "stage" {
			continue
		}
		jobs, _, err := types.EffectiveJobs(&entry.Metadata)
		if err != nil {
			s.Warn().Err(err).Msgf("skipping app %s jobs", entry.AppPathDomain())
			continue
		}
		for _, spec := range jobs {
			if !spec.IsEnabled() || spec.TriggerType() != types.JobTriggerCron {
				continue
			}
			sched, err := spec.Trigger.CronTrigger().Parse()
			if err != nil {
				s.Warn().Err(err).Msgf("skipping job %s of %s", spec.Name, entry.AppPathDomain())
				continue
			}
			for tick := sched.Next(windowStart); !tick.After(now); tick = sched.Next(tick) {
				s.startCronRun(ctx, entry, spec, tick.UTC())
			}
		}
	}
}

// startCronRun claims one cron tick and starts its run
func (s *Server) startCronRun(ctx context.Context, entry *types.AppEntry, spec types.JobSpec, tick time.Time) {
	parent, done, err := s.jobRuns.begin()
	if err != nil {
		return
	}
	handedOff := false
	defer func() {
		if !handedOff {
			done()
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(parent, cancel)
	defer stopCancel()
	defer cancel()

	exec := &jobExecution{
		target:   entry,
		spec:     spec,
		trigger:  types.JobTriggerCron,
		actor:    jobSchedulerActor,
		version:  entry.Metadata.VersionMetadata.Version,
		schedule: tick,
		request:  system.GetContextRequestId(newBackgroundOperationContext(jobSchedulerActor)),
	}
	run, err := s.claimJobRun(ctx, exec)
	if err != nil {
		if errors.Is(err, metadata.ErrJobRunConflict) {
			s.Debug().Msgf("cron tick %s of job %s %s already claimed or running", tick.Format(time.RFC3339), spec.Name, entry.AppPathDomain())
		} else {
			s.Error().Err(err).Msgf("error claiming cron run of job %s %s", spec.Name, entry.AppPathDomain())
		}
		return
	}
	failRun := func(err error) {
		s.Error().Err(err).Msgf("error preparing job %s", spec.Name)
		if ferr := s.db.FinishJobRun(ctx, types.Transaction{}, run.Id, types.JobRunFailed, nil, truncateMessage(err.Error())); ferr != nil {
			s.Error().Err(ferr).Msgf("error recording job run %s failure", run.Id)
		}
		run.Status = types.JobRunFailed
		run.Message = err.Error()
		s.insertJobAudit(run)
	}
	runCtx, err := s.cronJobContext(parent, entry)
	if err != nil {
		failRun(err)
		return
	}
	application, closeApp, err := s.loadJobApp(ctx, types.Transaction{}, entry)
	if err != nil {
		failRun(err)
		return
	}

	exec.app = application
	exec.closeApp = closeApp
	s.Info().Str("run", run.Id).Str("job", spec.Name).Str("app", run.AppPath).Msg("starting scheduled job run")
	handedOff = true
	go func() { defer done(); s.performJobRun(runCtx, exec, run) }()
}

// cronJobContext attributes scheduled Starlark management API calls to the
// app owner. Scheduling a job must not confer trusted server authority.
// Unattributed, deleted builtin, or disabled owners have no management API
// authority; ordinary app plugin permissions and container execution remain
// independent of RBAC.
func (s *Server) cronJobContext(parent context.Context, entry *types.AppEntry) (context.Context, error) {
	ctx := &managementAPIContext{
		Context: parent, userId: entry.UserID,
		rbacEnabled: s.rbacManager.ConfigEnabled(),
	}
	if !ctx.rbacEnabled {
		ctx.userId = cmp.Or(ctx.userId, jobSchedulerActor)
		return ctx, nil
	}
	if ctx.userId == "" {
		return ctx, nil
	}
	identity, err := s.db.GetIdentityByPrincipal(ctx, ctx.userId)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("error resolving scheduled job owner %q: %w", ctx.userId, err)
	}
	if identity != nil && identity.DisabledAt != nil {
		ctx.userId = ""
		return ctx, nil
	}
	// Builtin groups come from live config even without an API identity row.
	// Deleted builtin users lose authority; this is not a storage failure.
	if username, builtin := strings.CutPrefix(ctx.userId, string(types.AppAuthnBuiltin)+":"); builtin {
		groups, exists := builtinGroups(s.Config(), username)
		if !exists {
			ctx.userId = ""
		} else {
			ctx.groups = groups
		}
		return ctx, nil
	}
	if identity == nil {
		// No federated snapshot exists. Direct principal/config group grants
		// still apply, but there is no stale snapshot to audit.
		return ctx, nil
	}
	ctx.groups, err = s.apiIdentityGroups(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("error resolving scheduled job owner groups for %q: %w", ctx.userId, err)
	}
	return ctx, nil
}

// resolveJobInstance returns the app instance a job command targets: the
// dev app itself, the prod instance, or the stage instance with stage set
func (s *Server) resolveJobInstance(ctx context.Context, appPath string, stage bool) (*types.AppEntry, error) {
	pathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	entry, err := s.db.GetAppEntry(ctx, pathDomain)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusNotFound)
	}
	if stage && !entry.IsDev {
		if strings.HasPrefix(string(entry.Id), types.ID_PREFIX_APP_PROD) {
			return s.getStageAppNoTx(ctx, entry)
		}
	}
	return entry, nil
}

// jobInstanceIds returns the app ids whose runs make up one job history:
// the app and its stage instance
func (s *Server) jobInstanceIds(ctx context.Context, entry *types.AppEntry) []types.AppId {
	ids := []types.AppId{entry.Id}
	if strings.HasPrefix(string(entry.Id), types.ID_PREFIX_APP_PROD) {
		if stageEntry, err := s.getStageAppNoTx(ctx, entry); err == nil {
			ids = append(ids, stageEntry.Id)
		}
	}
	return ids
}

// ListJobs lists the effective jobs of the apps matching the glob, with the
// next scheduled run and the last run of each. Needs app:read on every app;
// without app:read_detail on an app, its jobs are the basic view (identity
// and schedule, last run status) - the execution details, env, run
// definition and args are app:read_detail (see JobSpec.BasicView)
func (s *Server) ListJobs(ctx context.Context, appPathGlob string) (*types.JobListResponse, error) {
	filteredApps, err := s.FilterApps(cmp.Or(appPathGlob, "all"), false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if err := s.enforceAppPermInfos(ctx, types.PermissionRead, filteredApps); err != nil {
		return nil, err
	}
	ret := &types.JobListResponse{Jobs: []types.JobInfo{}}
	now := time.Now()
	for _, appInfo := range filteredApps {
		entry, err := s.db.GetAppEntry(ctx, appInfo.AppPathDomain)
		if err != nil {
			return nil, err
		}
		detail := s.appDetailAllowedEntry(ctx, entry)
		// The prod (or dev) instance's jobs, then the stage instance's jobs
		// that differ from prod's: a staged job change shows before promote
		instances := []*types.AppEntry{entry}
		if stageEntry, err := s.getStageAppNoTx(ctx, entry); err == nil {
			instances = append(instances, stageEntry)
		}
		seen := map[string]string{} // job name -> prod spec JSON
		for _, instance := range instances {
			jobs, origins, err := types.EffectiveJobs(&instance.Metadata)
			if err != nil {
				ret.Jobs = append(ret.Jobs, types.JobInfo{AppPath: entry.AppPathDomain().String(), Stage: types.AppStage(instance.Id),
					Warnings: []string{err.Error()}})
				continue
			}
			for i, spec := range jobs {
				stage := types.AppStage(instance.Id)
				if stage == "stage" {
					if prodSpec, ok := seen[spec.Name]; ok && prodSpec == spec.String() {
						continue
					}
				} else {
					seen[spec.Name] = spec.String()
				}
				info := types.JobInfo{AppPath: entry.AppPathDomain().String(), Stage: stage, Origin: origins[i], Spec: spec}
				if !detail {
					info.Spec = spec.BasicView()
				}
				if spec.IsEnabled() && spec.TriggerType() == types.JobTriggerCron && !entry.IsDev {
					if next, err := spec.Trigger.CronTrigger().NextRun(now); err == nil {
						nextStr := next.UTC().Format(time.RFC3339)
						info.NextRun = &nextStr
					}
				}
				runs, err := s.db.ListJobRuns(ctx, []types.AppId{instance.Id}, spec.Name, "", 1)
				if err != nil {
					return nil, err
				}
				if len(runs) > 0 {
					last := runs[0]
					if !detail {
						last = last.BasicView()
					}
					info.LastRun = &last
				}
				ret.Jobs = append(ret.Jobs, info)
			}
		}
	}
	return ret, nil
}

// RunJob starts a manual run of a job on the app's prod (or stage, or dev)
// instance. wait returns the finished run; force runs a disabled job or
// runs alongside an active run
func (s *Server) RunJob(ctx context.Context, appPath, jobName string, stage, wait, force bool, args map[string]string) (*types.JobRunResponse, error) {
	if jobName == "" {
		return nil, types.CreateRequestError("job name is required", http.StatusBadRequest)
	}
	entry, err := s.resolveJobInstance(ctx, appPath, stage)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionUpdate, entry); err != nil {
		return nil, err
	}
	application, closeApp, err := s.loadJobApp(ctx, types.Transaction{}, entry)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	spec, err := application.FindJob(jobName)
	if err != nil {
		if closeApp != nil {
			closeApp()
		}
		return nil, types.CreateRequestError(err.Error(), http.StatusNotFound)
	}
	if !spec.IsEnabled() && !force {
		if closeApp != nil {
			closeApp()
		}
		return nil, types.CreateRequestError(fmt.Sprintf("job %s is disabled, use --force to run it", jobName), http.StatusBadRequest)
	}
	if _, err := application.JobArgValues(spec, args); err != nil {
		if closeApp != nil {
			closeApp()
		}
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	exec := &jobExecution{
		app:      application,
		closeApp: closeApp,
		target:   entry,
		spec:     spec,
		trigger:  types.JobTriggerManual,
		actor:    cmp.Or(system.GetContextUserId(ctx), "admin"),
		args:     args,
		force:    force,
		version:  entry.Metadata.VersionMetadata.Version,
		request:  system.GetContextRequestId(ctx),
	}
	var run *types.JobRun
	if wait {
		run, err = s.executeJobRun(ctx, exec)
	} else {
		run, err = s.startJobRun(ctx, exec)
	}
	if err != nil {
		return nil, err
	}
	return &types.JobRunResponse{Run: *run}, nil
}

// ListJobRuns lists the runs of an app (prod and stage instances), newest
// first
func (s *Server) ListJobRuns(ctx context.Context, appPath, jobName, status string, limit int) (*types.JobRunsResponse, error) {
	entry, err := s.resolveJobInstance(ctx, appPath, false)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionReadDetail, entry); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	runs, err := s.db.ListJobRuns(ctx, s.jobInstanceIds(ctx, entry), jobName, status, limit)
	if err != nil {
		return nil, err
	}
	return &types.JobRunsResponse{Runs: runs}, nil
}

// jobRunEntry returns a run and the app instance it targets, after the
// permission check
func (s *Server) jobRunEntry(ctx context.Context, runId string, perm types.RBACPermission) (*types.JobRun, *types.AppEntry, error) {
	run, err := s.db.GetJobRun(ctx, runId)
	if err != nil {
		if errors.Is(err, metadata.ErrJobRunNotFound) {
			return nil, nil, types.CreateRequestError(fmt.Sprintf("job run %s not found", runId), http.StatusNotFound)
		}
		return nil, nil, err
	}
	pathDomain, err := parseAppPath(run.AppPath)
	if err != nil {
		return nil, nil, err
	}
	entry, err := s.db.GetAppEntry(ctx, pathDomain)
	if err != nil {
		return nil, nil, types.CreateRequestError(fmt.Sprintf("app %s of run %s not found", run.AppPath, runId), http.StatusNotFound)
	}
	if err := s.enforceAppPermEntry(ctx, perm, entry); err != nil {
		return nil, nil, err
	}
	return run, entry, nil
}

// JobLogs returns a run's container output, read from the container runtime
func (s *Server) JobLogs(ctx context.Context, runId string) (*types.JobLogsResponse, error) {
	run, entry, err := s.jobRunEntry(ctx, runId, types.PermissionReadDetail)
	if err != nil {
		return nil, err
	}
	ret := &types.JobLogsResponse{Run: *run}
	if run.ContainerName == "" {
		ret.Logs = run.Message
		return ret, nil
	}
	runner, err := s.jobRunnerFor(entry)
	if err != nil {
		return nil, err
	}
	logs, err := runner.JobLogs(ctx, container.ContainerName(run.ContainerName), jobLogLines)
	if err != nil {
		return nil, types.CreateRequestError(fmt.Sprintf("logs of run %s are no longer available: %s", runId, err), http.StatusNotFound)
	}
	ret.Logs = logs
	return ret, nil
}

// CancelJobRun stops an active run executing on this node
func (s *Server) CancelJobRun(ctx context.Context, runId string) (*types.JobRunResponse, error) {
	run, _, err := s.jobRunEntry(ctx, runId, types.PermissionUpdate)
	if err != nil {
		return nil, err
	}
	if !run.IsActive() {
		return nil, types.CreateRequestError(fmt.Sprintf("job run %s is not active (%s)", runId, run.Status), http.StatusBadRequest)
	}
	if run.NodeId != s.jobNodeId() {
		return nil, types.CreateRequestError(fmt.Sprintf("job run %s is executing on node %s, cancel it there", runId, run.NodeId), http.StatusConflict)
	}
	if !s.jobRuns.cancel(runId) {
		return nil, types.CreateRequestError(fmt.Sprintf("job run %s is not executing on this node", runId), http.StatusConflict)
	}
	return &types.JobRunResponse{Run: *run}, nil
}

// gateLogTail returns the tail of a failed gate run's output for the error
func (s *Server) gateLogTail(ctx context.Context, application *apppkg.App, run *types.JobRun) string {
	if run.ContainerName == "" || !application.HasContainer() {
		return run.Message
	}
	runner, ok := container.AsJobRunner(application.ContainerManager())
	if !ok {
		return run.Message
	}
	logs, err := runner.JobLogs(ctx, container.ContainerName(run.ContainerName), jobLogTailLines)
	if err != nil {
		return run.Message
	}
	return strings.TrimSpace(run.Message + "\n" + logs)
}

// runDeployGates runs the before_deploy jobs of the loaded (new) code
// against target, sequentially in declaration order. The first failure
// fails the deploy. application holds the new code and, for command jobs,
// its built image; target is the instance being deployed to (its bindings
// account and identity). tx is set when the gate runs inside the caller's
// transaction (create)
func (s *Server) runDeployGates(ctx context.Context, tx types.Transaction, application *apppkg.App, target *types.AppEntry,
	reason string, version, previousVersion int) error {
	if target.IsDev || types.AppStage(target.Id) == "preview" {
		return nil
	}
	gates, err := application.BeforeDeployJobs()
	if err != nil {
		return err
	}
	if len(gates) == 0 {
		return nil
	}
	var image string
	for _, spec := range gates {
		if spec.IsAppImage() && !spec.IsRun() && image == "" {
			if image, err = application.ResolveJobImage(ctx, spec); err != nil {
				return fmt.Errorf("before_deploy job %s of %s: %w", spec.Name, target.AppPathDomain(), err)
			}
		}
		exec := &jobExecution{
			app:      application,
			target:   target,
			spec:     spec,
			trigger:  types.JobTriggerBeforeDeploy,
			actor:    cmp.Or(system.GetContextUserId(ctx), "admin"),
			version:  version,
			previous: previousVersion,
			request:  system.GetContextRequestId(ctx),
			syncId:   system.GetContextValue(ctx, types.SYNC_ID),
			extraEnv: map[string]string{"CL_DEPLOY_REASON": reason, "CL_PREVIOUS_VERSION": strconv.Itoa(previousVersion)},
			tx:       tx,
		}
		if spec.IsAppImage() {
			exec.image = image
		}
		s.Info().Str("job", spec.Name).Str("app", target.AppPathDomain().String()).Str("reason", reason).Msg("running before_deploy job")
		run, err := s.executeJobRun(ctx, exec)
		if err != nil {
			return fmt.Errorf("before_deploy job %s of %s: %w", spec.Name, target.AppPathDomain(), err)
		}
		if run.Status != types.JobRunSucceeded {
			return fmt.Errorf("before_deploy job %s of %s %s (run %s): %s", spec.Name, target.AppPathDomain(), run.Status, run.Id,
				s.gateLogTail(ctx, application, run))
		}
	}
	return nil
}

// runCreateGates runs the before_deploy jobs of a just created app inside
// the create transaction, when the create pre-pass could not run them (see
// prepareCreate): the image is built from the loaded code and the gates run
// against the stage instance. A failure fails the create, which rolls the
// app back
func (s *Server) runCreateGates(ctx context.Context, tx types.Transaction, application *apppkg.App, entry *types.AppEntry) error {
	if entry.IsDev {
		return nil
	}
	gates, err := application.BeforeDeployJobs()
	if err != nil {
		return err
	}
	if len(gates) == 0 {
		return nil
	}
	if err := s.buildGateImage(ctx, application, nil, gates, false); err != nil {
		return err
	}
	return s.runDeployGates(ctx, tx, application, entry, "create", entry.Metadata.VersionMetadata.Version, 0)
}

func (h *Handler) listJobs(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	updateTargetInContext(r, appPathGlob, false)
	updateOperationInContext(r, string(API_LIST_JOBS))
	return h.server.ListJobs(r.Context(), appPathGlob)
}

func (h *Handler) runJob(r *http.Request) (any, error) {
	query := r.URL.Query()
	appPath := query.Get("appPath")
	jobName := query.Get("job")
	if appPath == "" || jobName == "" {
		return nil, types.CreateRequestError("appPath and job are required", http.StatusBadRequest)
	}
	stage, err := parseBoolArg(query.Get("stage"), false)
	if err != nil {
		return nil, err
	}
	wait, err := parseBoolArg(query.Get("wait"), false)
	if err != nil {
		return nil, err
	}
	force, err := parseBoolArg(query.Get("force"), false)
	if err != nil {
		return nil, err
	}
	var req types.JobRunRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.UnmarshalRead(r.Body, &req); err != nil {
			return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
	}
	updateTargetInContext(r, appPath+":"+jobName, false)
	updateOperationInContext(r, string(API_RUN_JOB))
	return h.server.RunJob(r.Context(), appPath, jobName, stage, wait, force, req.Args)
}

func (h *Handler) listJobRuns(r *http.Request) (any, error) {
	query := r.URL.Query()
	appPath := query.Get("appPath")
	if appPath == "" {
		return nil, types.CreateRequestError("appPath is required", http.StatusBadRequest)
	}
	limit := 0
	if limitStr := query.Get("limit"); limitStr != "" {
		var err error
		if limit, err = strconv.Atoi(limitStr); err != nil {
			return nil, types.CreateRequestError("invalid limit", http.StatusBadRequest)
		}
	}
	updateTargetInContext(r, appPath, false)
	updateOperationInContext(r, string(API_LIST_JOB_RUNS))
	return h.server.ListJobRuns(r.Context(), appPath, query.Get("job"), query.Get("status"), limit)
}

func (h *Handler) jobLogs(r *http.Request) (any, error) {
	id := r.URL.Query().Get("id")
	if id == "" {
		return nil, types.CreateRequestError("id is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, id, false)
	updateOperationInContext(r, string(API_JOB_LOGS))
	return h.server.JobLogs(r.Context(), id)
}

func (h *Handler) cancelJobRun(r *http.Request) (any, error) {
	id := r.URL.Query().Get("id")
	if id == "" {
		return nil, types.CreateRequestError("id is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, id, false)
	updateOperationInContext(r, string(API_CANCEL_JOB))
	return h.server.CancelJobRun(r.Context(), id)
}
