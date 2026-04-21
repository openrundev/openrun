// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const regexAllowedContainerArgPrefix = "regex:"

// CommandOptionArgs converts parsed container options into CLI args.
// Built-in OpenRun options are parsed explicitly. Any remaining Docker/Podman
// flags must be listed in allowedContainerArgs before they are emitted.
func CommandOptionArgs(options CommandOptions, allowedContainerArgs map[string]string) ([]string, error) {
	args := []string{}
	if options.Cpus != "" {
		cpus, err := CPUString(options.Cpus, true)
		if err != nil {
			return nil, fmt.Errorf("error parsing cpus value %q: %w", options.Cpus, err)
		}
		args = append(args, "--cpus", cpus)
	}
	if options.Memory != "" {
		memory, err := BytesString(options.Memory)
		if err != nil {
			return nil, fmt.Errorf("error parsing memory value %q: %w", options.Memory, err)
		}
		args = append(args, "--memory", memory)
	}

	otherArgs, err := commandOtherOptionArgs(options.Other, allowedContainerArgs)
	if err != nil {
		return nil, err
	}
	args = append(args, otherArgs...)
	return args, nil
}

func commandOtherOptionArgs(options map[string]any, allowedContainerArgs map[string]string) ([]string, error) {
	keys := make([]string, 0, len(options))
	for k := range options {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	args := make([]string, 0, len(keys))
	for _, k := range keys {
		v := ""
		if options[k] != nil {
			v = fmt.Sprint(options[k])
		}

		if err := validateAllowedContainerArg(k, v, allowedContainerArgs); err != nil {
			return nil, err
		}

		if v == "" {
			args = append(args, fmt.Sprintf("--%s", k))
		} else {
			args = append(args, fmt.Sprintf("--%s=%s", k, v))
		}
	}
	return args, nil
}

func validateAllowedContainerArg(key, value string, allowedContainerArgs map[string]string) error {
	allowedValue, ok := allowedContainerArgs[key]
	if !ok {
		return fmt.Errorf("container argument %q is not allowed", key)
	}

	if allowedValue == "" {
		if value != "" {
			return fmt.Errorf("container argument %q does not allow a value", key)
		}
		return nil
	}

	if strings.HasPrefix(allowedValue, regexAllowedContainerArgPrefix) {
		pattern := strings.TrimPrefix(allowedValue, regexAllowedContainerArgPrefix)
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid allowed container arg %q regex %q: %w", key, pattern, err)
		}
		if !compiled.MatchString(value) {
			return fmt.Errorf("container argument %q value %q is not allowed", key, value)
		}
		return nil
	}

	if value != allowedValue {
		return fmt.Errorf("container argument %q value %q is not allowed", key, value)
	}
	return nil
}
