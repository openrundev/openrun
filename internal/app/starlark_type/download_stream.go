// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"fmt"
	"io"

	"go.starlark.net/starlark"
)

// DownloadStream is an opaque starlark value carrying a lazily produced
// download body. Only plugin Go code can construct one; app starlark code
// can just pass it through into ace.response(data=..., download=...) - it
// exposes no attributes, so a handler cannot fabricate or inspect one. The
// producer is invoked by the download response handler at response-write
// time, writing the body into the response buffer: the payload is never
// fully materialized in memory or staged to disk, and once the buffer fills
// a stalled client blocks the producer (TCP backpressure). Single use: a
// second Produce errors instead of silently sending an empty body.
type DownloadStream struct {
	name     string
	producer func(w io.Writer) error
	consumed bool
}

func NewDownloadStream(name string, producer func(w io.Writer) error) *DownloadStream {
	return &DownloadStream{name: name, producer: producer}
}

// Name is the download attachment file name
func (d *DownloadStream) Name() string {
	return d.name
}

// Produce writes the body to w. It may block on w (the response writer) when
// the client is slow to read
func (d *DownloadStream) Produce(w io.Writer) error {
	if d.consumed {
		return fmt.Errorf("download stream %s was already consumed", d.name)
	}
	d.consumed = true
	return d.producer(w)
}

func (d *DownloadStream) String() string {
	return fmt.Sprintf("download_stream(%s)", d.name)
}

func (d *DownloadStream) Type() string {
	return "download_stream"
}

// Freeze is a no-op: the value is consumed by the single request thread that
// created it, never shared across starlark threads
func (d *DownloadStream) Freeze() {
}

func (d *DownloadStream) Truth() starlark.Bool {
	return starlark.True
}

func (d *DownloadStream) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: download_stream")
}

var _ starlark.Value = (*DownloadStream)(nil)
