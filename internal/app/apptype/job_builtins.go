// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"encoding/json/v2"
	"fmt"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	JOB           = "job"
	SIDECAR       = "sidecar"
	CRON          = "cron"
	BEFORE_DEPLOY = "before_deploy"
	MANUAL        = "manual"

	// JOB_SPEC_ATTR holds the canonical JobSpec JSON on a job struct;
	// SIDECAR_SPEC_ATTR the SidecarSpec JSON on a sidecar struct
	JOB_SPEC_ATTR     = "spec"
	SIDECAR_SPEC_ATTR = "spec"
	JOB_RUN_ATTR      = "run"
)

// createJobBuiltin is ace.job in app.star: a job declaration with the
// JobSpec fields plus run, a Starlark callable executed in place of a
// container. The result carries the canonical spec JSON and the callable
func createJobBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	spec, run, err := UnpackJobArgs(JOB, args, kwargs, true)
	if err != nil {
		return nil, err
	}
	return JobStruct(spec, run), nil
}

// JobStruct builds the struct returned by the job builtins
func JobStruct(spec types.JobSpec, run starlark.Callable) *starlarkstruct.Struct {
	fields := starlark.StringDict{
		"name":        starlark.String(spec.Name),
		JOB_SPEC_ATTR: starlark.String(spec.String()),
	}
	if run != nil {
		fields[JOB_RUN_ATTR] = run
	} else {
		fields[JOB_RUN_ATTR] = starlark.None
	}
	return starlarkstruct.FromStringDict(starlark.String(JOB), fields)
}

// UnpackJobArgs parses the job builtin arguments shared by ace.job (app.star)
// and job (apps.ace). allowRun accepts the run callable; the declaration
// surface has no callables
func UnpackJobArgs(fnName string, args starlark.Tuple, kwargs []starlark.Tuple, allowRun bool) (types.JobSpec, starlark.Callable, error) {
	var name, image, timeout, description starlark.String
	var command, cmdArgs, volumes, params *starlark.List
	var env, options *starlark.Dict
	var shell starlark.Bool
	var inheritEnv, enabled, trigger, run starlark.Value
	if err := starlark.UnpackArgs(fnName, args, kwargs, "name", &name, "command?", &command, "args?", &cmdArgs,
		"shell?", &shell, "image?", &image, "run?", &run, "env?", &env, "inherit_env?", &inheritEnv,
		"volumes?", &volumes, "options?", &options, "trigger?", &trigger, "timeout?", &timeout,
		"enabled?", &enabled, "params?", &params, "description?", &description); err != nil {
		return types.JobSpec{}, nil, fmt.Errorf("error unpacking %s args: %w", fnName, err)
	}

	spec := types.JobSpec{
		Name:        name.GoString(),
		Image:       image.GoString(),
		Shell:       bool(shell),
		Timeout:     timeout.GoString(),
		Description: description.GoString(),
	}
	if spec.Image != "" && !hasImagePrefix(spec.Image) {
		// Accept a bare reference too: the prefix is what the spec stores
		spec.Image = types.CONTAINER_SOURCE_IMAGE_PREFIX + spec.Image
	}
	var err error
	if spec.Command, err = optionalStringList("command", command); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Args, err = optionalStringList("args", cmdArgs); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Volumes, err = optionalStringList("volumes", volumes); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Params, err = optionalStringList("params", params); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Env, err = optionalStringDict("env", env); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Options, err = optionalStringDict("options", options); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.InheritEnv, err = optionalBoolValue("inherit_env", inheritEnv); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Enabled, err = optionalBoolValue("enabled", enabled); err != nil {
		return types.JobSpec{}, nil, err
	}
	if spec.Trigger, err = ParseTriggerValue(trigger); err != nil {
		return types.JobSpec{}, nil, fmt.Errorf("job %s: %w", spec.Name, err)
	}

	var runCallable starlark.Callable
	if run != nil && run != starlark.None {
		if !allowRun {
			return types.JobSpec{}, nil, fmt.Errorf("job %s: run is only supported in app.star, use command in the declaration", spec.Name)
		}
		callable, ok := run.(starlark.Callable)
		if !ok {
			return types.JobSpec{}, nil, fmt.Errorf("job %s: run must be a function, got %s", spec.Name, run.Type())
		}
		runCallable = callable
		spec.Run = callable.Name()
	}

	if err := spec.Validate(); err != nil {
		return types.JobSpec{}, nil, err
	}
	return spec, runCallable, nil
}

func hasImagePrefix(image string) bool {
	return len(image) >= len(types.CONTAINER_SOURCE_IMAGE_PREFIX) && image[:len(types.CONTAINER_SOURCE_IMAGE_PREFIX)] == types.CONTAINER_SOURCE_IMAGE_PREFIX
}

func optionalStringList(name string, list *starlark.List) ([]string, error) {
	if list == nil || list.Len() == 0 {
		return nil, nil
	}
	ret, err := GetStringList(list)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return ret, nil
}

func optionalStringDict(name string, dict *starlark.Dict) (map[string]string, error) {
	if dict == nil || dict.Len() == 0 {
		return nil, nil
	}
	ret := make(map[string]string, dict.Len())
	for _, item := range dict.Items() {
		key, ok := item[0].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("%s: keys must be strings, got %s", name, item[0].Type())
		}
		value, ok := item[1].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("%s: value for %s must be a string, got %s", name, key.GoString(), item[1].Type())
		}
		ret[key.GoString()] = value.GoString()
	}
	return ret, nil
}

func optionalBoolValue(name string, v starlark.Value) (*bool, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	b, ok := v.(starlark.Bool)
	if !ok {
		return nil, fmt.Errorf("%s must be a bool, got %s", name, v.Type())
	}
	ret := bool(b)
	return &ret, nil
}

// ParseTriggerValue converts a trigger argument to a JobTrigger: a struct
// from cron()/before_deploy()/manual(), a dict in the JSON form
// ({"type": "cron", "schedule": ...}), or None for manual
func ParseTriggerValue(v starlark.Value) (*types.JobTrigger, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	if st, ok := v.(*starlarkstruct.Struct); ok {
		triggerType, err := GetStringAttr(st, "type")
		if err != nil {
			return nil, fmt.Errorf("trigger must be created with cron(), before_deploy() or manual()")
		}
		switch triggerType {
		case types.JobTriggerCron:
			schedule, err := GetStringAttr(st, "schedule")
			if err != nil {
				return nil, err
			}
			timezone, err := GetOptionalStringAttr(st, "timezone")
			if err != nil {
				return nil, err
			}
			return types.CronJobTrigger(schedule, timezone), nil
		case types.JobTriggerBeforeDeploy:
			return types.BeforeDeployTrigger(), nil
		case types.JobTriggerManual:
			return types.ManualTrigger(), nil
		default:
			return nil, fmt.Errorf("unknown trigger type %q", triggerType)
		}
	}
	goValue, err := starlark_type.ToGo(v)
	if err != nil {
		return nil, fmt.Errorf("invalid trigger: %w", err)
	}
	data, err := json.Marshal(goValue)
	if err != nil {
		return nil, fmt.Errorf("invalid trigger: %w", err)
	}
	var trigger types.JobTrigger
	if err := json.Unmarshal(data, &trigger, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("invalid trigger %s: %w", data, err)
	}
	return &trigger, nil
}

// createCronBuiltin is ace.cron(schedule, timezone="UTC") / cron(...)
func createCronBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var schedule, timezone starlark.String
	if err := starlark.UnpackArgs(CRON, args, kwargs, "schedule", &schedule, "timezone?", &timezone); err != nil {
		return nil, fmt.Errorf("error unpacking cron args: %w", err)
	}
	trigger := types.CronTrigger{Schedule: schedule.GoString(), Timezone: timezone.GoString()}
	if _, err := trigger.Parse(); err != nil {
		return nil, err
	}
	return starlarkstruct.FromStringDict(starlark.String(CRON), starlark.StringDict{
		"type":     starlark.String(types.JobTriggerCron),
		"schedule": schedule,
		"timezone": timezone,
	}), nil
}

// createBeforeDeployBuiltin is ace.before_deploy() / before_deploy()
func createBeforeDeployBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(BEFORE_DEPLOY, args, kwargs); err != nil {
		return nil, fmt.Errorf("error unpacking before_deploy args: %w", err)
	}
	return starlarkstruct.FromStringDict(starlark.String(BEFORE_DEPLOY), starlark.StringDict{
		"type": starlark.String(types.JobTriggerBeforeDeploy),
	}), nil
}

// createManualBuiltin is ace.manual() / manual()
func createManualBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(MANUAL, args, kwargs); err != nil {
		return nil, fmt.Errorf("error unpacking manual args: %w", err)
	}
	return starlarkstruct.FromStringDict(starlark.String(MANUAL), starlark.StringDict{
		"type": starlark.String(types.JobTriggerManual),
	}), nil
}

// TriggerBuiltins returns the trigger builtins shared by app.star (under ace)
// and apps.ace (top level)
func TriggerBuiltins() starlark.StringDict {
	return starlark.StringDict{
		CRON:          starlark.NewBuiltin(CRON, createCronBuiltin),
		BEFORE_DEPLOY: starlark.NewBuiltin(BEFORE_DEPLOY, createBeforeDeployBuiltin),
		MANUAL:        starlark.NewBuiltin(MANUAL, createManualBuiltin),
	}
}

// CreateApplyJobBuiltin returns the apps.ace job builtin: the ace.job fields
// without run
func CreateApplyJobBuiltin() *starlark.Builtin {
	return starlark.NewBuiltin(JOB, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		spec, _, err := UnpackJobArgs(JOB, args, kwargs, false)
		if err != nil {
			return nil, err
		}
		return JobStruct(spec, nil), nil
	})
}

// CreateApplySidecarBuiltin returns the apps.ace sidecar builtin, producing a
// struct carrying the canonical SidecarSpec JSON. The container.sidecar
// plugin call is the app.star counterpart
func CreateApplySidecarBuiltin() *starlark.Builtin {
	return starlark.NewBuiltin(SIDECAR, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name, image, health string
		var port int64
		var command, cmdArgs, volumes *starlark.List
		var env, options *starlark.Dict
		var inheritEnv, alwaysOn starlark.Value
		if err := starlark.UnpackArgs(SIDECAR, args, kwargs, "name", &name, "image?", &image, "command?", &command,
			"args?", &cmdArgs, "env?", &env, "inherit_env?", &inheritEnv, "port?", &port, "health?", &health,
			"volumes?", &volumes, "always_on?", &alwaysOn, "options?", &options); err != nil {
			return nil, fmt.Errorf("error unpacking sidecar args: %w", err)
		}
		spec := types.SidecarSpec{Name: name, Image: image, Port: int32(port), Health: health}
		if port < 0 || port > 65535 {
			return nil, fmt.Errorf("sidecar %s: port must be between 0 and 65535", name)
		}
		if image != "" && !hasImagePrefix(image) {
			spec.Image = types.CONTAINER_SOURCE_IMAGE_PREFIX + image
		}
		var err error
		if spec.Command, err = optionalStringList("command", command); err != nil {
			return nil, err
		}
		if spec.Args, err = optionalStringList("args", cmdArgs); err != nil {
			return nil, err
		}
		if spec.Volumes, err = optionalStringList("volumes", volumes); err != nil {
			return nil, err
		}
		if spec.Env, err = optionalStringDict("env", env); err != nil {
			return nil, err
		}
		if spec.Options, err = optionalStringDict("options", options); err != nil {
			return nil, err
		}
		if spec.InheritEnv, err = optionalBoolValue("inherit_env", inheritEnv); err != nil {
			return nil, err
		}
		if spec.AlwaysOn, err = optionalBoolValue("always_on", alwaysOn); err != nil {
			return nil, err
		}
		if err := spec.Validate(); err != nil {
			return nil, err
		}
		return starlarkstruct.FromStringDict(starlark.String(SIDECAR), starlark.StringDict{
			"name":            starlark.String(spec.Name),
			SIDECAR_SPEC_ATTR: starlark.String(spec.String()),
		}), nil
	})
}

// SpecEntries reads a list attribute holding job or sidecar declarations in
// any accepted form (JSON strings, dicts, or structs from the builtins) and
// returns the canonical JSON of each, validated by parse. nil for an empty
// list, so apply change detection compares equal to a stored nil
func SpecEntries(s starlark.HasAttrs, key, specAttr string, parse func(string) (string, error)) ([]string, error) {
	v, err := s.Attr(key)
	if err != nil {
		return nil, nil
	}
	list, ok := v.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("%s is not a list", key)
	}
	if list.Len() == 0 {
		return nil, nil
	}
	ret := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		var entry string
		switch item := list.Index(i).(type) {
		case starlark.String:
			entry = item.GoString()
		case *starlarkstruct.Struct:
			spec, err := GetStringAttr(item, specAttr)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d: not a %s declaration", key, i, key)
			}
			entry = spec
		default:
			goValue, err := starlark_type.ToGo(item)
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(goValue)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d: %w", key, i, err)
			}
			entry = string(data)
		}
		canonical, err := parse(entry)
		if err != nil {
			return nil, err
		}
		ret = append(ret, canonical)
	}
	return ret, nil
}
