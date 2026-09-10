// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

// StreamValue is implemented by the response of a plugin call made with
// stream=True (exec.run, container.run, container_logs_stream). The value
// is opaque in Starlark; the framework consumes it as a range function
// yielding output chunks (plain strings, or maps for parsed output) and a
// terminal error. StartStream detaches the stream from the request's plugin
// cleanup and must be called before that cleanup runs; CloseStream releases
// the producer (killing a still running command) and is safe to call more
// than once
type StreamValue interface {
	StartStream() (func(yield func(any, error) bool), error)
	CloseStream()
}
