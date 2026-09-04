// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Job trigger types
const (
	JobTriggerManual       = "manual"
	JobTriggerCron         = "cron"
	JobTriggerBeforeDeploy = "before_deploy"

	JobDefaultTimeout = "1h"
)

// Job run states
const (
	JobRunRunning   = "running"
	JobRunSucceeded = "succeeded"
	JobRunFailed    = "failed"
	JobRunTimedOut  = "timed_out"
	JobRunCanceled  = "canceled"
	JobRunLost      = "lost"
)

// Job origins, reported by job list
const (
	JobOriginDefinition = "definition"
	JobOriginMetadata   = "metadata"
)

// CronTrigger is the schedule of a cron job: a five field cron expression or
// a descriptor (@daily, @every 4h), evaluated in Timezone (default UTC)
type CronTrigger struct {
	Schedule string
	Timezone string
}

// JobTrigger is the one trigger of a job: {"type": "manual"}, {"type":
// "before_deploy"} or {"type": "cron", "schedule": ..., "timezone": ...}. A
// nil trigger is manual
type JobTrigger struct {
	Type     string `json:"type"`
	Schedule string `json:"schedule,omitempty,omitzero"`
	Timezone string `json:"timezone,omitempty,omitzero"`
}

// CronTrigger returns the cron schedule of a cron trigger
func (t *JobTrigger) CronTrigger() CronTrigger {
	if t == nil {
		return CronTrigger{}
	}
	return CronTrigger{Schedule: t.Schedule, Timezone: t.Timezone}
}

// ManualTrigger, CronJobTrigger and BeforeDeployTrigger build triggers
func ManualTrigger() *JobTrigger { return &JobTrigger{Type: JobTriggerManual} }
func CronJobTrigger(schedule, timezone string) *JobTrigger {
	return &JobTrigger{Type: JobTriggerCron, Schedule: schedule, Timezone: timezone}
}
func BeforeDeployTrigger() *JobTrigger { return &JobTrigger{Type: JobTriggerBeforeDeploy} }

// JobSpec is the declaration of one job of an app: a finite command run in
// an ephemeral container from the app's image (or a foreign image), or a
// Starlark function called in the OpenRun process. The same JSON document is
// accepted from app.star (ace.job), the apps.ace job builtin, the CLI --job
// flag and app update jobs. See arch/docs/jobs-and-deploy-hooks.md
type JobSpec struct {
	// Name identifies the job within the app. Same grammar as sidecar names;
	// jobs and sidecars share the name space
	Name string `json:"name"`
	// Image is "image:<ref>" for a foreign image. Empty runs the app's own
	// image
	Image string `json:"image,omitempty,omitzero"`
	// Command overrides the image entrypoint
	Command []string `json:"command,omitempty,omitzero"`
	// Args are passed to the command
	Args []string `json:"args,omitempty,omitzero"`
	// Shell wraps command and args in "sh -c"
	Shell bool `json:"shell,omitempty,omitzero"`
	// Run is the name of the Starlark function (app.star only) called instead
	// of running a container. Stored for display; the callable lives on the
	// loaded app
	Run string `json:"run,omitempty,omitzero"`
	// Env is the job's own env, overlaid on the inherited app env
	Env map[string]string `json:"env,omitempty,omitzero"`
	// InheritEnv copies the app env (params, bindings, CL_* vars) into the
	// job container. Defaults to true for app image jobs, false for foreign
	// images
	InheritEnv *bool `json:"inherit_env,omitempty,omitzero"`
	// Volumes are named volumes (name:/path) mounted into the job container,
	// docker/podman only
	Volumes []string `json:"volumes,omitempty,omitzero"`
	// Options are container options for the job, same keys as --copt
	Options map[string]string `json:"options,omitempty,omitzero"`
	// Trigger is the job's trigger; nil is manual
	Trigger *JobTrigger `json:"trigger,omitempty,omitzero"`
	// Timeout is a Go duration after which the run is killed (default 1h)
	Timeout string `json:"timeout,omitempty,omitzero"`
	// Enabled false keeps the job listed but never scheduled or gated; a
	// manual run needs --force
	Enabled *bool `json:"enabled,omitempty,omitzero"`
	// Params are the params.star param names a manual run may set
	Params []string `json:"params,omitempty,omitzero"`
	// Description is free text for listings
	Description string `json:"description,omitempty,omitzero"`
}

var jobNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)

// ParseJobSpec parses one job JSON document. Unknown fields are rejected
func ParseJobSpec(data string) (JobSpec, error) {
	var spec JobSpec
	if err := json.Unmarshal([]byte(data), &spec, json.RejectUnknownMembers(true)); err != nil {
		return JobSpec{}, fmt.Errorf("invalid job definition %s: %w", data, err)
	}
	if err := spec.Validate(); err != nil {
		return JobSpec{}, err
	}
	return spec, nil
}

// ParseJobSpecs parses a list of job JSON documents, rejecting duplicate names
func ParseJobSpecs(entries []string) ([]JobSpec, error) {
	ret := make([]JobSpec, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		spec, err := ParseJobSpec(entry)
		if err != nil {
			return nil, err
		}
		if seen[spec.Name] {
			return nil, fmt.Errorf("duplicate job name %q", spec.Name)
		}
		seen[spec.Name] = true
		ret = append(ret, spec)
	}
	return ret, nil
}

// String returns the canonical JSON form of the spec, the form stored in the
// app metadata
func (s JobSpec) String() string {
	data, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return fmt.Sprintf("%+v", struct{ JobSpec }{s})
	}
	return string(data)
}

// Validate checks the definition time constraints of a job spec that do not
// need the app loaded
func (s JobSpec) Validate() error {
	if !jobNameRegex.MatchString(s.Name) {
		return fmt.Errorf("invalid job name %q: use 1-20 lower case letters, digits or dashes, starting with a letter or digit", s.Name)
	}
	if s.Image != "" && !strings.HasPrefix(s.Image, CONTAINER_SOURCE_IMAGE_PREFIX) {
		return fmt.Errorf("job %s: image must be %q followed by the image reference, or empty for the app image", s.Name, CONTAINER_SOURCE_IMAGE_PREFIX)
	}
	if s.Image != "" && s.ImageRef() == "" {
		return fmt.Errorf("job %s: image reference is empty", s.Name)
	}
	hasCommand := len(s.Command) > 0 || len(s.Args) > 0
	if hasCommand && s.Run != "" {
		return fmt.Errorf("job %s: set either command or run, not both", s.Name)
	}
	if !hasCommand && s.Run == "" {
		return fmt.Errorf("job %s: one of command or run is required", s.Name)
	}
	if s.Run != "" && (s.Image != "" || len(s.Volumes) > 0) {
		return fmt.Errorf("job %s: image and volumes do not apply to run jobs", s.Name)
	}
	if s.Timeout != "" {
		d, err := time.ParseDuration(s.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("job %s: invalid timeout %q, expected a positive Go duration like 30m", s.Name, s.Timeout)
		}
	}
	for k := range s.Env {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			return fmt.Errorf("job %s: invalid env name %q", s.Name, k)
		}
	}
	for _, vol := range s.Volumes {
		src, _, _ := strings.Cut(vol, ":")
		if src == "" || strings.ContainsAny(src, "/\\") || strings.HasPrefix(src, ".") {
			return fmt.Errorf("job %s: volume %q must be a named volume (name:/path)", s.Name, vol)
		}
		if strings.HasPrefix(src, "sqlite-") {
			return fmt.Errorf("job %s: the managed sqlite volume %q cannot be mounted by a job", s.Name, src)
		}
	}
	if s.Trigger != nil {
		switch s.Trigger.Type {
		case JobTriggerManual, JobTriggerBeforeDeploy:
			if s.Trigger.Schedule != "" || s.Trigger.Timezone != "" {
				return fmt.Errorf("job %s: schedule and timezone apply to the cron trigger only", s.Name)
			}
		case JobTriggerCron:
			if _, err := s.Trigger.CronTrigger().Parse(); err != nil {
				return fmt.Errorf("job %s: %w", s.Name, err)
			}
		default:
			return fmt.Errorf("job %s: trigger type must be one of manual, cron or before_deploy, got %q", s.Name, s.Trigger.Type)
		}
	}
	return nil
}

// IsAppImage reports whether the job runs the app's own image
func (s JobSpec) IsAppImage() bool {
	return s.Image == ""
}

// ImageRef returns the foreign image reference without the image: prefix,
// empty for app image jobs
func (s JobSpec) ImageRef() string {
	return strings.TrimPrefix(s.Image, CONTAINER_SOURCE_IMAGE_PREFIX)
}

// IsRun reports whether the job calls a Starlark function
func (s JobSpec) IsRun() bool {
	return s.Run != ""
}

// InheritsEnv resolves the inherit_env default: app image jobs inherit the
// app env, foreign images do not
func (s JobSpec) InheritsEnv() bool {
	if s.InheritEnv != nil {
		return *s.InheritEnv
	}
	return s.IsAppImage()
}

// IsEnabled resolves the enabled default (true)
func (s JobSpec) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// TriggerType returns manual, cron or before_deploy
func (s JobSpec) TriggerType() string {
	if s.Trigger == nil || s.Trigger.Type == "" {
		return JobTriggerManual
	}
	return s.Trigger.Type
}

// TimeoutDuration returns the run timeout, applying the default
func (s JobSpec) TimeoutDuration() time.Duration {
	if s.Timeout == "" {
		d, _ := time.ParseDuration(JobDefaultTimeout)
		return d
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		d, _ = time.ParseDuration(JobDefaultTimeout)
	}
	return d
}

// Argv returns the container command line: command followed by args, wrapped
// in sh -c when shell is set
func (s JobSpec) Argv() []string {
	argv := append(append([]string{}, s.Command...), s.Args...)
	if s.Shell {
		return append([]string{"sh", "-c"}, strings.Join(argv, " "))
	}
	return argv
}

// EnvName returns the env var fragment for the job name: upper cased, dashes
// replaced with underscores
func (s JobSpec) EnvName() string {
	return strings.ToUpper(strings.ReplaceAll(s.Name, "-", "_"))
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Parse returns the cron schedule with the trigger's timezone applied
func (c CronTrigger) Parse() (cron.Schedule, error) {
	if strings.TrimSpace(c.Schedule) == "" {
		return nil, fmt.Errorf("cron schedule is empty")
	}
	if strings.HasPrefix(strings.TrimSpace(c.Schedule), "@every") {
		// An interval schedule fires relative to an arbitrary anchor, which
		// the minute scheduler cannot claim as a stable tick
		return nil, fmt.Errorf("cron schedule %q: @every is not supported, use a cron expression like \"*/15 * * * *\"", c.Schedule)
	}
	loc := time.UTC
	if c.Timezone != "" {
		var err error
		if loc, err = time.LoadLocation(c.Timezone); err != nil {
			return nil, fmt.Errorf("unknown timezone %q", c.Timezone)
		}
	}
	// The location goes through the CRON_TZ prefix the standard parser
	// understands, for expressions and @daily style descriptors alike; the
	// parser would otherwise default to the server's local time
	sched, err := cronParser.Parse("CRON_TZ=" + loc.String() + " " + c.Schedule)
	if err != nil {
		return nil, fmt.Errorf("invalid cron schedule %q: %w", c.Schedule, err)
	}
	return sched, nil
}

// NextRun returns the first time the schedule fires after from
func (c CronTrigger) NextRun(from time.Time) (time.Time, error) {
	sched, err := c.Parse()
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(from), nil
}

// MergeJobSpecs combines the app definition jobs with the app metadata jobs:
// a metadata job replaces a same-name definition job entirely (no field
// merge), definition jobs keep their order and metadata-only jobs are
// appended. The returned origins parallel the result: definition or metadata
func MergeJobSpecs(fromApp, fromMetadata []JobSpec) ([]JobSpec, []string, error) {
	byName := make(map[string]JobSpec, len(fromMetadata))
	for _, spec := range fromMetadata {
		byName[spec.Name] = spec
	}
	ret := make([]JobSpec, 0, len(fromApp)+len(fromMetadata))
	origins := make([]string, 0, len(fromApp)+len(fromMetadata))
	seen := map[string]bool{}
	for _, spec := range fromApp {
		if seen[spec.Name] {
			return nil, nil, fmt.Errorf("duplicate job name %q", spec.Name)
		}
		seen[spec.Name] = true
		origin := JobOriginDefinition
		if override, ok := byName[spec.Name]; ok {
			spec = override
			origin = JobOriginMetadata
		}
		ret = append(ret, spec)
		origins = append(origins, origin)
	}
	for _, spec := range fromMetadata {
		if seen[spec.Name] {
			continue
		}
		seen[spec.Name] = true
		ret = append(ret, spec)
		origins = append(origins, JobOriginMetadata)
	}
	for _, spec := range ret {
		if err := spec.Validate(); err != nil {
			return nil, nil, err
		}
	}
	return ret, origins, nil
}

// EffectiveJobs resolves an app instance's jobs from its metadata alone: the
// definition jobs persisted at load with the operator's metadata jobs
// replacing same-name entries. Nothing here needs the app loaded
func EffectiveJobs(metadata *AppMetadata) ([]JobSpec, []string, error) {
	fromApp, err := ParseJobSpecs(metadata.DefinitionJobs)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid app definition jobs: %w", err)
	}
	fromMetadata, err := ParseJobSpecs(metadata.Jobs)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid app metadata jobs: %w", err)
	}
	return MergeJobSpecs(fromApp, fromMetadata)
}

// JobImageAllowed checks a foreign job image reference against the server
// allow list (security.allowed_job_images): "*" allows every image, other
// entries are exact references or regex: patterns. An empty list allows
// nothing but the app image
func JobImageAllowed(allowed []string, imageRef string) (bool, error) {
	for _, entry := range allowed {
		if entry == "*" || entry == imageRef {
			return true, nil
		}
		match, err := RegexMatch(entry, imageRef)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// JobRun is one execution of a job on one app instance
type JobRun struct {
	Id              string            `json:"id"`
	AppId           AppId             `json:"app_id"`
	AppPath         string            `json:"app_path"`
	JobName         string            `json:"job_name"`
	Trigger         string            `json:"trigger"`
	Actor           string            `json:"actor"`
	RequestId       string            `json:"request_id,omitempty"`
	SyncId          string            `json:"sync_id,omitempty"`
	Version         int               `json:"version"`
	PreviousVersion int               `json:"previous_version,omitempty"`
	Image           string            `json:"image,omitempty"`
	Definition      string            `json:"definition"`
	Args            map[string]string `json:"args,omitempty"`
	ScheduledAt     time.Time         `json:"scheduled_at"`
	StartedAt       time.Time         `json:"started_at"`
	EndedAt         *time.Time        `json:"ended_at,omitempty"`
	Status          string            `json:"status"`
	ExitCode        *int              `json:"exit_code,omitempty"`
	Message         string            `json:"message,omitempty"`
	NodeId          string            `json:"node_id"`
	LeaseUntil      *time.Time        `json:"lease_until,omitempty"`
	ContainerName   string            `json:"container_name,omitempty"`
	// Forced runs bypass the one-active-run-per-job rule
	Forced bool `json:"forced,omitempty"`
}

// Stage returns prod, stage, preview or dev from the app id
func (r JobRun) Stage() string {
	return AppStage(r.AppId)
}

// AppStage returns prod, stage, preview or dev from an app id prefix
func AppStage(appId AppId) string {
	id := string(appId)
	switch {
	case strings.HasPrefix(id, ID_PREFIX_APP_STAGE):
		return "stage"
	case strings.HasPrefix(id, ID_PREFIX_APP_PREVIEW):
		return "preview"
	case strings.HasPrefix(id, ID_PREFIX_APP_DEV):
		return "dev"
	default:
		return "prod"
	}
}

// IsActive reports whether the run is still executing
func (r JobRun) IsActive() bool {
	return r.Status == JobRunRunning
}

// JobInfo is one effective job of an app as reported by job list
type JobInfo struct {
	AppPath string `json:"app_path"`
	// Stage is the instance the job belongs to: prod (or dev), or stage
	// when the stage instance's job differs from prod's (a staged change)
	Stage    string   `json:"stage"`
	Origin   string   `json:"origin"`
	Spec     JobSpec  `json:"spec"`
	NextRun  *string  `json:"next_run,omitempty"`
	LastRun  *JobRun  `json:"last_run,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// JobListResponse is the response of the list jobs API
type JobListResponse struct {
	Jobs []JobInfo `json:"jobs"`
}

// JobRunRequest is the body of the run job API
type JobRunRequest struct {
	Args map[string]string `json:"args,omitempty"`
}

// JobRunResponse is the response of the run job API. Status is set when the
// caller waited for the run
type JobRunResponse struct {
	Run JobRun `json:"run"`
}

// JobRunsResponse is the response of the list job runs API
type JobRunsResponse struct {
	Runs []JobRun `json:"runs"`
}

// JobLogsResponse is the response of the job logs API
type JobLogsResponse struct {
	Run  JobRun `json:"run"`
	Logs string `json:"logs"`
}
