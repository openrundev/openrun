// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"io"
	"strings"
	"testing"
)

// A download stream is single use: the second Produce must error instead of
// silently sending an empty body, and must not invoke the producer again.
func TestDownloadStreamSingleUse(t *testing.T) {
	calls := 0
	stream := NewDownloadStream("test.zip", func(w io.Writer) error {
		calls++
		_, err := w.Write([]byte("payload"))
		return err
	})

	var sb strings.Builder
	if err := stream.Produce(&sb); err != nil {
		t.Fatalf("first produce failed: %v", err)
	}
	if sb.String() != "payload" || calls != 1 {
		t.Fatalf("unexpected first produce: body %q calls %d", sb.String(), calls)
	}

	if err := stream.Produce(&sb); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("second produce must fail with already consumed, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("producer ran again on second produce")
	}
}
