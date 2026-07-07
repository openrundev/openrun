// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

// chunkedReader returns its chunks one Read call at a time, simulating a
// pipe delivering partial writes
type chunkedReader struct {
	chunks []string
	pos    int
	closed bool
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.pos])
	c.chunks[c.pos] = c.chunks[c.pos][n:]
	if c.chunks[c.pos] == "" {
		c.pos++
	}
	return n, nil
}

func (c *chunkedReader) Close() error {
	c.closed = true
	return nil
}

func collectStream(t *testing.T, reader *chunkedReader) []string {
	t.Helper()
	cleaned := false
	stream := streamLogLines(reader, func() { cleaned = true })
	values := []string{}
	stream(func(v any, err error) bool {
		testutil.AssertNoError(t, err)
		values = append(values, v.(string))
		return true
	})
	testutil.AssertEqualsBool(t, "reader closed", true, reader.closed)
	testutil.AssertEqualsBool(t, "cleanup ran", true, cleaned)
	return values
}

func TestStreamLogLinesChunking(t *testing.T) {
	// Complete lines per read are yielded as one chunk without the trailing
	// newline; a partial line is held until its newline arrives
	reader := &chunkedReader{chunks: []string{
		"line1\nline2\npar", "tial\n", "tail no newline"}}
	values := collectStream(t, reader)

	expected := []string{"line1\nline2", "partial", "tail no newline"}
	testutil.AssertEqualsInt(t, "chunk count", len(expected), len(values))
	for i, want := range expected {
		testutil.AssertEqualsString(t, "chunk", want, values[i])
	}
}

func TestStreamLogLinesEmptyAndBlank(t *testing.T) {
	// Blank lines survive the round trip: each yielded value is terminated
	// with one newline by the response writer
	reader := &chunkedReader{chunks: []string{"\n", "a\n\nb\n"}}
	values := collectStream(t, reader)

	expected := []string{"", "a\n\nb"}
	testutil.AssertEqualsInt(t, "chunk count", len(expected), len(values))
	for i, want := range expected {
		testutil.AssertEqualsString(t, "chunk", want, values[i])
	}
}

func TestStreamLogLinesLongLineBounded(t *testing.T) {
	// A newline-less line longer than the cap is force-broken so the partial
	// buffer stays bounded
	long := strings.Repeat("x", maxLogChunkBytes+1000)
	reader := &chunkedReader{chunks: []string{long}}
	values := collectStream(t, reader)

	total := 0
	for _, v := range values {
		if len(v) > maxLogChunkBytes+64*1024 {
			t.Fatalf("chunk exceeds bound: %d bytes", len(v))
		}
		total += len(v)
	}
	testutil.AssertEqualsInt(t, "total bytes", len(long), total)
	if len(values) < 2 {
		t.Fatalf("expected a forced break, got %d chunks", len(values))
	}
}

func TestStreamLogLinesEarlyStop(t *testing.T) {
	// The consumer stopping early (client disconnect) still runs cleanup
	reader := &chunkedReader{chunks: []string{"a\n", "b\n", "c\n"}}
	cleaned := false
	stream := streamLogLines(reader, func() { cleaned = true })
	count := 0
	stream(func(v any, err error) bool {
		count++
		return false
	})
	testutil.AssertEqualsInt(t, "yields", 1, count)
	testutil.AssertEqualsBool(t, "reader closed", true, reader.closed)
	testutil.AssertEqualsBool(t, "cleanup ran", true, cleaned)
}
