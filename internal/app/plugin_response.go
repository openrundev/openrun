// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// PluginResponse is a starlark.Value that represents the response to a plugin request
type PluginResponse struct {
	errorCode int
	err       error
	value     any
	isStream  bool
	thread    *starlark.Thread
}

func NewErrorResponse(err error, thread *starlark.Thread) *PluginResponse {
	return &PluginResponse{
		errorCode: 1,
		err:       err,
		value:     nil,
		thread:    thread,
	}
}

func NewErrorCodeResponse(errorCode int, err error, value any) *PluginResponse {
	return &PluginResponse{
		errorCode: errorCode,
		err:       err,
		value:     value,
	}
}

// NewErrorCodeResponseThread is NewErrorCodeResponse with the thread
// attached, so an explicit error check by the app (accessing .error or
// truth-testing the response) clears the thread-local failure state, the way
// NewErrorResponse does. Without the thread, a handled coded error would
// still fail the next plugin call or the handler return.
func NewErrorCodeResponseThread(errorCode int, err error, value any, thread *starlark.Thread) *PluginResponse {
	return &PluginResponse{
		errorCode: errorCode,
		err:       err,
		value:     value,
		thread:    thread,
	}
}

func NewResponse(value any) *PluginResponse {
	return &PluginResponse{
		value: value,
	}
}

// ToPluginValue returns the response value for passing into another plugin
// call. A failed response fails the call; a handled error is not possible
// through this path.
func (r *PluginResponse) ToPluginValue(depth int) (any, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.isStream {
		return nil, errors.New("stream value cannot be passed to a plugin call")
	}
	if v, ok := r.value.(starlark.Value); ok {
		return starlark_type.ToPlugin(v, depth)
	}
	return r.value, nil
}

func NewStreamResponse(value any) *PluginResponse {
	return &PluginResponse{
		value:    value,
		isStream: true,
	}
}

func (r *PluginResponse) Attr(name string) (starlark.Value, error) {
	switch name {
	case "error_code":
		return starlark.MakeInt(r.errorCode), nil
	case "is_stream":
		return starlark.Bool(r.isStream), nil
	case "error":
		// Error value is being checked in the handler code, clear the thread local state
		if r.thread != nil {
			r.thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, nil)
		}

		if r.err == nil {
			return starlark.None, nil
		}
		return starlark.String(r.err.Error()), nil
	case "value":
		if r.err != nil {
			// Value is being accessed when there was an error, abort
			return nil, r.err
		}

		if r.value == nil {
			return starlark.None, nil
		}

		if r.isStream {
			return starlark.None, errors.New("stream value cannot be accessed in Starlark, return the response object instead")
		}

		if v, ok := r.value.(starlark.Value); ok {
			return v, nil
		}
		return starlark_type.FromGo(r.value)

	default:
		return starlark.None, fmt.Errorf("response has no attribute '%s'", name)
	}
}

func (r *PluginResponse) AttrNames() []string {
	return []string{"error_code", "error", "value", "is_stream"}
}

func (r *PluginResponse) String() string {
	return fmt.Sprintf("%d:%s:%s:%t", r.errorCode, r.err, r.value, r.isStream)
}

func (r *PluginResponse) Type() string {
	return "Response"
}

func (r *PluginResponse) Freeze() {
}

func (r *PluginResponse) Truth() starlark.Bool {
	// Error value is being checked in the handler code, clear the thread local state
	if r.thread != nil {
		r.thread.SetLocal(types.TL_PLUGIN_API_FAILED_ERROR, nil)
	}
	return r.err == nil
}

func (r *PluginResponse) Hash() (uint32, error) {
	var err error
	var errValue starlark.Value
	errValue, err = r.Attr("error")
	if err != nil {
		return 0, err
	}

	var value starlark.Value
	value, err = r.Attr("value")
	if err != nil {
		return 0, err
	}
	return starlark.Tuple{starlark.MakeInt(r.errorCode), errValue, value}.Hash()
}

func (r *PluginResponse) ToGoValue() (any, error) {
	return map[string]any{
		"error_code": r.errorCode,
		"error":      r.err,
		"value":      r.value,
		"is_stream":  r.isStream,
	}, nil
}

var _ starlark.Value = (*PluginResponse)(nil)
var _ starlark_type.GoValuer = (*PluginResponse)(nil)
