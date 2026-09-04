// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// jobDef is one ace.job entry of the loaded app: the spec plus the run
// callable for Starlark jobs
type jobDef struct {
	spec types.JobSpec
	run  starlark.Callable
}

// loadJobs reads the ace.app jobs, validates the effective job list (the
// definition jobs with the metadata jobs replacing same-name entries) and
// persists the definition jobs on the version metadata, so the scheduler and
// the job APIs can work from the app entry alone. Runs after the container
// config is loaded (sidecar names) and the params are known
func (a *App) loadJobs() error {
	jobsAttr, err := a.appDef.Attr("jobs")
	if err != nil {
		return err
	}
	a.jobs = nil
	if jobsAttr != nil && jobsAttr != starlark.None {
		list, ok := jobsAttr.(*starlark.List)
		if !ok {
			return fmt.Errorf("jobs is not a list")
		}
		for i := 0; i < list.Len(); i++ {
			st, ok := list.Index(i).(*starlarkstruct.Struct)
			if !ok {
				return fmt.Errorf("jobs entry %d must be created with ace.job()", i)
			}
			specJson, err := apptype.GetStringAttr(st, apptype.JOB_SPEC_ATTR)
			if err != nil {
				return fmt.Errorf("jobs entry %d must be created with ace.job()", i)
			}
			spec, err := types.ParseJobSpec(specJson)
			if err != nil {
				return err
			}
			def := jobDef{spec: spec}
			if runAttr, _ := st.Attr(apptype.JOB_RUN_ATTR); runAttr != nil && runAttr != starlark.None {
				callable, ok := runAttr.(starlark.Callable)
				if !ok {
					return fmt.Errorf("job %s: run is not a function", spec.Name)
				}
				def.run = callable
			}
			if spec.IsRun() && def.run == nil {
				return fmt.Errorf("job %s: run function is missing", spec.Name)
			}
			a.jobs = append(a.jobs, def)
		}
	}

	definition := make([]string, 0, len(a.jobs))
	for _, def := range a.jobs {
		definition = append(definition, def.spec.String())
	}
	if len(definition) == 0 {
		definition = nil
	}
	a.Metadata.DefinitionJobs = definition

	effective, _, err := a.EffectiveJobs()
	if err != nil {
		return err
	}
	return a.validateJobs(effective)
}

// validateJobs checks the rules that need the loaded app: sidecar name
// collisions, image allow list, param names and executor availability
func (a *App) validateJobs(jobs []types.JobSpec) error {
	sidecarNames := map[string]bool{}
	if a.containerHandler != nil {
		for _, sc := range a.containerHandler.sidecars {
			sidecarNames[sc.spec.Name] = true
		}
	}
	for _, spec := range jobs {
		if sidecarNames[spec.Name] {
			return fmt.Errorf("job %s: name collides with a sidecar", spec.Name)
		}
		if !spec.IsRun() && a.containerHandler == nil {
			return fmt.Errorf("job %s: command jobs need container config; use run= for a Starlark job", spec.Name)
		}
		if !spec.IsAppImage() {
			allowed, err := types.JobImageAllowed(a.serverConfig.Security.AllowedJobImages, spec.ImageRef())
			if err != nil {
				return err
			}
			if !allowed {
				return fmt.Errorf("job %s image %s is not allowed by the server config security.allowed_job_images", spec.Name, spec.ImageRef())
			}
		}
		for _, param := range spec.Params {
			if _, ok := a.paramInfo[param]; !ok {
				return fmt.Errorf("job %s: param %q is not defined in params.star", spec.Name, param)
			}
		}
	}
	return nil
}

// EffectiveJobs returns the app's jobs: the loaded definition jobs with the
// metadata jobs replacing same-name entries, and each job's origin
func (a *App) EffectiveJobs() ([]types.JobSpec, []string, error) {
	fromApp := make([]types.JobSpec, 0, len(a.jobs))
	for _, def := range a.jobs {
		fromApp = append(fromApp, def.spec)
	}
	fromMetadata, err := types.ParseJobSpecs(a.Metadata.Jobs)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid app metadata jobs: %w", err)
	}
	return types.MergeJobSpecs(fromApp, fromMetadata)
}

// FindJob returns the effective job with the given name
func (a *App) FindJob(name string) (types.JobSpec, error) {
	jobs, _, err := a.EffectiveJobs()
	if err != nil {
		return types.JobSpec{}, err
	}
	for _, spec := range jobs {
		if spec.Name == name {
			return spec, nil
		}
	}
	return types.JobSpec{}, fmt.Errorf("job %s not found in app %s", name, a.AppPathDomain())
}

// BeforeDeployJobs returns the enabled before_deploy jobs in declaration
// order
func (a *App) BeforeDeployJobs() ([]types.JobSpec, error) {
	jobs, _, err := a.EffectiveJobs()
	if err != nil {
		return nil, err
	}
	ret := make([]types.JobSpec, 0)
	for _, spec := range jobs {
		if spec.IsEnabled() && spec.TriggerType() == types.JobTriggerBeforeDeploy {
			ret = append(ret, spec)
		}
	}
	return ret, nil
}

// HasContainer reports whether the app has a container config
func (a *App) HasContainer() bool {
	return a.containerHandler != nil
}

// ContainerManager returns the app's container manager, nil for apps
// without a container config
func (a *App) ContainerManager() container.ContainerManager {
	if a.containerHandler == nil {
		return nil
	}
	return a.containerHandler.manager
}

// JobEnv assembles the env of a command job run against target: the app env
// (params, bindings of the target's account, CL_APP_PATH, CL_APP_URL, no
// PORT) when the job inherits it, otherwise the app identity only, with the
// job's own env overlaid
func (a *App) JobEnv(spec types.JobSpec, target *types.AppEntry) (map[string]string, error) {
	if a.containerHandler == nil {
		return nil, fmt.Errorf("job %s: app %s has no container config", spec.Name, a.AppPathDomain())
	}
	base, err := a.containerHandler.jobBaseEnv(target)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if spec.InheritsEnv() {
		for k, v := range base {
			env[k] = v
		}
	} else {
		for _, k := range []string{"CL_APP_PATH", "CL_APP_URL"} {
			if v, ok := base[k]; ok {
				env[k] = v
			}
		}
	}
	for k, v := range spec.Env {
		env[k] = v
	}
	return env, nil
}

// ResolveJobImage returns the image reference a command job of this app runs
// from: the foreign image of the job (pulled and digest pinned), or the app's
// own deployed image. No container is started. Fails when the app image has
// never been built for this version ("deploy the app first")
func (a *App) ResolveJobImage(ctx context.Context, spec types.JobSpec) (string, error) {
	if a.containerHandler == nil {
		return "", fmt.Errorf("job %s: app %s has no container config", spec.Name, a.AppPathDomain())
	}
	if !spec.IsAppImage() {
		image := spec.ImageRef()
		digest, err := a.containerHandler.manager.RefreshImage(ctx, container.ImageName(image))
		if err != nil {
			return "", fmt.Errorf("job %s: error pulling image %s: %w", spec.Name, image, err)
		}
		return container.DigestPinned(image, digest), nil
	}
	return a.containerHandler.resolveAppImage(ctx)
}

// JobVolumes parses a job's named volumes and creates the ones that do not
// exist yet. Docker/podman only
func (a *App) JobVolumes(ctx context.Context, spec types.JobSpec) ([]*container.VolumeInfo, error) {
	if a.containerHandler == nil || len(spec.Volumes) == 0 {
		return nil, nil
	}
	return a.containerHandler.jobVolumes(ctx, spec.Volumes)
}

// JobParamMap returns the app param values, used for volume template
// rendering by the container manager
func (a *App) JobParamMap() map[string]string {
	return a.paramValuesStr
}

// JobRunResult is the outcome of a Starlark run job
type JobRunResult struct {
	Message string
	Failed  bool
}

// RunJobFunction executes a run job's Starlark function with the action
// handler shape fn(dry_run, args): dry_run is False and args carries the
// params.star values with the run arguments (validated by param type)
// applied. The function runs under the app's plugin permissions; ctx
// cancellation cancels the Starlark thread. The result maps as: a handler
// error or ace.output(error=...) fails the run; ace.result with param_errors
// fails the run; otherwise the run succeeds with the result status (or the
// value's string form) as the message
func (a *App) RunJobFunction(ctx context.Context, spec types.JobSpec, runArgs map[string]string) (result JobRunResult, retErr error) {
	var callable starlark.Callable
	for _, def := range a.jobs {
		if def.spec.Name == spec.Name {
			callable = def.run
		}
	}
	if callable == nil {
		return JobRunResult{}, fmt.Errorf("job %s: run function %q not found in the loaded app", spec.Name, spec.Run)
	}

	thread := &starlark.Thread{
		Name:  "job:" + spec.Name,
		Print: func(_ *starlark.Thread, msg string) { a.Info().Str("job", spec.Name).Msg(msg) },
	}
	thread.SetLocal(types.TL_CONTEXT, ctx)
	thread.SetLocal(types.TL_APP_URL, a.appUrl)
	if a.containerHandler != nil {
		if proxyUrl := a.containerHandler.GetProxyUrl(); proxyUrl != "" {
			thread.SetLocal(types.TL_CONTAINER_URL, proxyUrl)
		}
		thread.SetLocal(types.TL_CONTAINER_HANDLER, a.containerHandler)
	}

	args, err := a.jobArgs(spec, runArgs)
	if err != nil {
		return JobRunResult{}, err
	}

	// A canceled context (cancel request or timeout) stops the Starlark
	// thread at its next instruction
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel("job " + spec.Name + " canceled: " + ctx.Err().Error())
		case <-done:
		}
	}()

	defer func() {
		if err := action.RunDeferredCleanup(thread); err != nil {
			a.Error().Err(err).Msgf("job %s: error cleaning up plugins", spec.Name)
			if retErr == nil {
				retErr = err
			}
		}
	}()
	defer func() {
		// ace.audit from the handler records a custom event, like actions
		op := system.GetThreadLocalKey(thread, types.TL_AUDIT_OPERATION)
		if op == "" || a.auditInsert == nil {
			return
		}
		status := types.EventStatusSuccess
		if retErr != nil || result.Failed {
			status = types.EventStatusFailure
		}
		event := types.AuditEvent{
			RequestId:  system.GetContextRequestId(ctx),
			CreateTime: time.Now(),
			UserId:     system.GetContextUserId(ctx),
			AppId:      a.Id,
			EventType:  types.EventTypeCustom,
			Operation:  op,
			Target:     system.GetThreadLocalKey(thread, types.TL_AUDIT_TARGET),
			Detail:     system.GetThreadLocalKey(thread, types.TL_AUDIT_DETAIL),
			Status:     string(status),
		}
		if err := a.auditInsert(&event); err != nil {
			a.Error().Err(err).Msg("error inserting custom audit event")
		}
	}()

	ret, err := starlark.Call(thread, callable, starlark.Tuple{starlark.False, args}, nil)
	if err == nil {
		if pluginErr, ok := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR).(error); ok && pluginErr != nil {
			err = pluginErr
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return JobRunResult{}, ctx.Err()
		}
		var evalErr *starlark.EvalError
		if errors.As(err, &evalErr) {
			return JobRunResult{}, fmt.Errorf("%w\n%s", err, evalErr.Backtrace())
		}
		return JobRunResult{}, err
	}
	return mapJobResult(ret)
}

// JobArgValues validates the run arguments against the job's declared
// params (name and type) and returns the effective value of every declared
// param: the argument when given, the app's configured param value
// otherwise. Command jobs receive them as CL_JOB_ARG_<NAME>
func (a *App) JobArgValues(spec types.JobSpec, runArgs map[string]string) (map[string]string, error) {
	declared := map[string]bool{}
	for _, p := range spec.Params {
		declared[p] = true
	}
	for name, value := range runArgs {
		if !declared[name] {
			return nil, fmt.Errorf("job %s does not accept argument %q (params: %v)", spec.Name, name, spec.Params)
		}
		info, ok := a.paramInfo[name]
		if !ok {
			return nil, fmt.Errorf("job %s: param %q is not defined in params.star", spec.Name, name)
		}
		if _, err := apptype.ParamStringToType(name, info.Type, value); err != nil {
			return nil, err
		}
	}
	ret := make(map[string]string, len(spec.Params))
	for _, p := range spec.Params {
		if value, ok := runArgs[p]; ok {
			ret[p] = value
		} else {
			ret[p] = a.paramValuesStr[p]
		}
	}
	return ret, nil
}

// jobArgs builds the args value for a run job: the param values overlaid
// with the run arguments the job declares
func (a *App) jobArgs(spec types.JobSpec, runArgs map[string]string) (*action.Args, error) {
	members := starlark.StringDict{}
	for k, v := range a.paramDict {
		members[k] = v
	}
	for name, value := range runArgs {
		info, ok := a.paramInfo[name]
		if !ok {
			return nil, fmt.Errorf("job %s: unknown argument %q", spec.Name, name)
		}
		allowed := false
		for _, p := range spec.Params {
			if p == name {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("job %s: argument %q is not in the job's params list", spec.Name, name)
		}
		typed, err := apptype.ParamStringToType(name, info.Type, value)
		if err != nil {
			return nil, err
		}
		members[name] = typed
	}
	return action.NewArgs(members), nil
}

// mapJobResult converts a run job's return value to the run outcome
func mapJobResult(ret starlark.Value) (JobRunResult, error) {
	if ret == nil || ret == starlark.None {
		return JobRunResult{}, nil
	}
	if output, ok := ret.(starlark_type.Output); ok {
		if output.Err != "" {
			return JobRunResult{Message: output.Err, Failed: true}, nil
		}
		return JobRunResult{Message: strings.Trim(output.Value.String(), "\"")}, nil
	}
	if output, ok := ret.(*starlark_type.Output); ok {
		if output.Err != "" {
			return JobRunResult{Message: output.Err, Failed: true}, nil
		}
		return JobRunResult{Message: strings.Trim(output.Value.String(), "\"")}, nil
	}
	st, ok := ret.(*starlarkstruct.Struct)
	if !ok {
		return JobRunResult{Message: strings.Trim(ret.String(), "\"")}, nil
	}
	status, err := apptype.GetOptionalStringAttr(st, "status")
	if err != nil {
		return JobRunResult{}, fmt.Errorf("error getting result status: %w", err)
	}
	paramErrors, err := apptype.GetDictAttr(st, "param_errors", true)
	if err != nil {
		return JobRunResult{}, fmt.Errorf("error getting result param_errors: %w", err)
	}
	if len(paramErrors) > 0 {
		parts := make([]string, 0, len(paramErrors))
		for k, v := range paramErrors {
			parts = append(parts, fmt.Sprintf("%s: %v", k, v))
		}
		return JobRunResult{Message: "param errors: " + strings.Join(parts, "; "), Failed: true}, nil
	}
	return JobRunResult{Message: status}, nil
}

// jobBaseEnv is the app env for a job run against target: the same env the
// app container gets, minus PORT, with the binding account and the app
// identity taken from the target instance (a promote gate runs stage code
// against the prod instance)
func (h *ContainerHandler) jobBaseEnv(target *types.AppEntry) (map[string]string, error) {
	if target == nil {
		target = h.app.AppEntry
	}
	ret := make(map[string]string)
	for paramName, paramVal := range h.paramMap {
		ret[paramName] = paramVal
	}
	pathValue := target.Path
	if pathValue == "/" {
		pathValue = ""
	}
	ret["CL_APP_PATH"] = pathValue
	ret["CL_APP_URL"] = types.GetAppUrl(target.AppPathDomain(), h.app.serverConfig)
	useProdAccount := strings.HasPrefix(string(target.Id), types.ID_PREFIX_APP_PROD)
	for k, v := range h.bindingEnvForAccount(useProdAccount) {
		ret[k] = v
	}
	return ret, nil
}

// resolveAppImage returns the app's own image for the loaded version
// without starting anything: the digest pinned upstream image for image
// spec apps, the built image (which must already exist) otherwise
func (h *ContainerHandler) resolveAppImage(ctx context.Context) (string, error) {
	if h.image != "" {
		// The digest the instance deployed, recorded at its last reload: a
		// moved tag must not change what a job runs. Resolved fresh only
		// for an instance deployed before digests were recorded
		if digest := h.app.Metadata.VersionMetadata.ImageDigest; digest != "" {
			return container.DigestPinned(h.image, digest), nil
		}
		digest, err := h.manager.RefreshImage(ctx, container.ImageName(h.image))
		if err != nil {
			return "", fmt.Errorf("error refreshing image %s: %w", h.image, err)
		}
		return container.DigestPinned(h.image, digest), nil
	}
	if h.GenImageName != "" {
		return string(h.GenImageName), nil
	}
	if h.app.IsDev {
		return "", fmt.Errorf("dev app %s has no built image yet, load the app first", h.app.AppPathDomain())
	}
	if err := h.refreshSidecarImages(ctx); err != nil {
		return "", err
	}
	var err error
	if h.envMap, h.envMapHash, err = h.getEnvMapAndHash(); err != nil {
		return "", fmt.Errorf("error getting env map hash: %w", err)
	}
	fullHash, err := h.getAppHash()
	if err != nil {
		return "", err
	}
	imageName, err := h.buildImageName(fullHash)
	if err != nil {
		return "", err
	}
	exists, err := h.manager.ImageExists(ctx, imageName)
	if err != nil {
		return "", fmt.Errorf("error checking image %s: %w", imageName, err)
	}
	if !exists {
		return "", fmt.Errorf("app %s image %s is not built, deploy the app first", h.app.AppPathDomain(), imageName)
	}
	return string(imageName), nil
}

// jobVolumes parses job volume entries and ensures the named volumes exist
func (h *ContainerHandler) jobVolumes(ctx context.Context, volumes []string) ([]*container.VolumeInfo, error) {
	ret := make([]*container.VolumeInfo, 0, len(volumes))
	for _, vol := range volumes {
		info, err := h.parseVolumeString(vol)
		if err != nil {
			return nil, err
		}
		if info.VolumeName == "" || info.VolumeName == container.UNNAMED_VOLUME {
			return nil, fmt.Errorf("job volume %q must be a named volume", vol)
		}
		genVolumeName := container.GenVolumeName(h.app.Id, info.VolumeName)
		if !h.manager.VolumeExists(ctx, genVolumeName) {
			if err := h.manager.VolumeCreate(ctx, genVolumeName, info.Size); err != nil {
				return nil, fmt.Errorf("error creating volume %s: %w", genVolumeName, err)
			}
		}
		ret = append(ret, info)
	}
	return ret, nil
}
