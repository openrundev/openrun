// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"fmt"
	"strings"
)

// UnpackArgs binds a call's positional and keyword arguments to Go variables,
// mirroring starlark.UnpackArgs: pairs alternate a parameter name and a
// pointer. A name ending in "?" marks an optional parameter. Supported
// pointer types: *string, *bool, *int64, *[]string, *[]any, *map[string]any,
// **Struct, and *any.
func UnpackArgs(fnName string, call *Call, pairs ...any) error {
	if len(pairs)%2 != 0 {
		return fmt.Errorf("%s: internal error: odd unpack pairs", fnName)
	}
	nparams := len(pairs) / 2

	if len(call.Args) > nparams {
		return fmt.Errorf("%s: got %d arguments, want at most %d", fnName, len(call.Args), nparams)
	}

	assigned := make([]bool, nparams)
	for i, arg := range call.Args {
		if err := assignArg(fnName, paramName(pairs[2*i]), pairs[2*i+1], arg); err != nil {
			return err
		}
		assigned[i] = true
	}

	for _, kwarg := range call.Kwargs {
		found := false
		for i := 0; i < nparams; i++ {
			if paramName(pairs[2*i]) == kwarg.Name {
				if assigned[i] {
					return fmt.Errorf("%s: got multiple values for parameter %q", fnName, kwarg.Name)
				}
				if err := assignArg(fnName, kwarg.Name, pairs[2*i+1], kwarg.Value); err != nil {
					return err
				}
				assigned[i] = true
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: unexpected keyword argument %q", fnName, kwarg.Name)
		}
	}

	for i := 0; i < nparams; i++ {
		name, ok := pairs[2*i].(string)
		if !ok {
			return fmt.Errorf("%s: internal error: parameter name must be a string", fnName)
		}
		if !assigned[i] && !strings.HasSuffix(name, "?") {
			return fmt.Errorf("%s: missing argument for %s", fnName, name)
		}
	}
	return nil
}

func paramName(v any) string {
	name, _ := v.(string)
	return strings.TrimSuffix(name, "?")
}

func assignArg(fnName, name string, ptr any, value any) error {
	switch p := ptr.(type) {
	case *string:
		s, ok := value.(string)
		if !ok {
			return typeErr(fnName, name, "string", value)
		}
		*p = s
	case *bool:
		b, ok := value.(bool)
		if !ok {
			return typeErr(fnName, name, "bool", value)
		}
		*p = b
	case *int64:
		n, ok := value.(int64)
		if !ok {
			return typeErr(fnName, name, "int", value)
		}
		*p = n
	case *[]string:
		items, ok := value.([]any)
		if !ok {
			if value == nil {
				return nil
			}
			return typeErr(fnName, name, "list of strings", value)
		}
		out := make([]string, len(items))
		for i, item := range items {
			s, ok := item.(string)
			if !ok {
				return typeErr(fnName, name, "list of strings", item)
			}
			out[i] = s
		}
		*p = out
	case *[]any:
		items, ok := value.([]any)
		if !ok {
			if value == nil {
				return nil
			}
			return typeErr(fnName, name, "list", value)
		}
		*p = items
	case *map[string]any:
		if value == nil {
			return nil
		}
		m, ok := value.(map[string]any)
		if !ok {
			return typeErr(fnName, name, "dict", value)
		}
		*p = m
	case **Struct:
		s, ok := value.(*Struct)
		if !ok {
			return typeErr(fnName, name, "typed entry", value)
		}
		*p = s
	case *any:
		*p = value
	default:
		return fmt.Errorf("%s: internal error: unsupported unpack target %T for %s", fnName, ptr, name)
	}
	return nil
}

func typeErr(fnName, name, want string, got any) error {
	return fmt.Errorf("%s: for parameter %s: got %T, want %s", fnName, name, got, want)
}
