// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxLineChunkBytes bounds the partial-line buffer of a line stream; a line
// longer than this is force-broken so memory stays bounded
const MaxLineChunkBytes = 1024 * 1024

// StreamLines converts a reader of line-oriented output (a process pipe, a
// container log stream) into a range func yielding chunks of complete lines
// as plain Go strings (not starlark values, so the stream writer sends them
// verbatim without quoting). Each yielded value holds one or more complete
// lines without the trailing newline (the consumer adds one per value). One
// yield per read keeps the per-line overhead minimal for large outputs while
// still delivering each line promptly when the producer is slow. Reads use
// a 64KB buffer; a newline-less run is force-broken at MaxLineChunkBytes.
// The reader is closed and cleanup runs when the stream ends or the consumer
// stops iterating. A read failure (other than EOF, a canceled context or a
// closed pipe, which are normal endings) is yielded as the terminal error
// after the buffered output, so a consumer can tell a cut stream from a
// complete one. Shared by the container log stream and the exec plugin
func StreamLines(reader io.ReadCloser, cleanup func()) func(yield func(any, error) bool) {
	return func(yield func(any, error) bool) {
		defer func() {
			_ = reader.Close()
			if cleanup != nil {
				cleanup()
			}
		}()

		buf := make([]byte, 64*1024)
		partial := make([]byte, 0, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				data := buf[:n]
				if nl := bytes.LastIndexByte(data, '\n'); nl == -1 {
					partial = append(partial, data...)
					if len(partial) >= MaxLineChunkBytes {
						// Force a break on newline-less output so the partial
						// buffer stays bounded
						if !yield(string(partial), nil) {
							return
						}
						partial = partial[:0]
					}
				} else {
					var out string
					if len(partial) > 0 {
						out = string(partial) + string(data[:nl])
						partial = partial[:0]
					} else {
						out = string(data[:nl])
					}
					partial = append(partial, data[nl+1:]...)
					if !yield(out, nil) {
						return
					}
				}
			}
			if err != nil {
				if len(partial) > 0 {
					if !yield(string(partial), nil) {
						return
					}
				}
				// Normal endings: EOF, the client went away (ctx cancel kills
				// the producing process and closes the pipe). Anything else is
				// the stream's terminal error
				if err != io.EOF && !errors.Is(err, context.Canceled) && !errors.Is(err, os.ErrClosed) {
					yield(nil, fmt.Errorf("error reading output: %w", err))
				}
				return
			}
		}
	}
}
