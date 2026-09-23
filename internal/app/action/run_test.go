// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestOutputRecorderHeadAndTail(t *testing.T) {
	r := newOutputRecorder(10, 10)
	r.write("0123456789") // fills the head
	r.write("abcdefghij") // the tail
	r.write("KLMNO")      // pushes the tail

	head, tail, total, omitted := r.snapshot()
	testutil.AssertEqualsString(t, "head", "0123456789", head)
	testutil.AssertEqualsString(t, "tail", "fghijKLMNO", tail)
	testutil.AssertEqualsInt(t, "total", 25, int(total))
	testutil.AssertEqualsInt(t, "omitted", 5, int(omitted))

	// The running view is the last tailMax bytes of everything
	recent, flushedTotal, flushedOmitted, changed := r.tailForFlush(true)
	testutil.AssertEqualsBool(t, "changed", true, changed)
	testutil.AssertEqualsString(t, "recent", "fghijKLMNO", recent)
	testutil.AssertEqualsInt(t, "flushed total", 25, int(flushedTotal))
	testutil.AssertEqualsInt(t, "flushed omitted", 15, int(flushedOmitted))
	_, _, _, changed = r.tailForFlush(true)
	testutil.AssertEqualsBool(t, "unchanged", false, changed)
}

func TestOutputRecorderSmallOutput(t *testing.T) {
	r := newOutputRecorder(100, 100)
	r.write("hello\n")
	head, tail, total, omitted := r.snapshot()
	testutil.AssertEqualsString(t, "head", "hello\n", head)
	testutil.AssertEqualsString(t, "tail", "", tail)
	testutil.AssertEqualsInt(t, "total", 6, int(total))
	testutil.AssertEqualsInt(t, "omitted", 0, int(omitted))
}

func TestOutputRecorderLargeChunk(t *testing.T) {
	r := newOutputRecorder(4, 4)
	r.write(strings.Repeat("x", 3) + strings.Repeat("y", 20) + "zz")
	head, tail, total, omitted := r.snapshot()
	testutil.AssertEqualsString(t, "head", "xxxy", head)
	testutil.AssertEqualsString(t, "tail", "yyzz", tail)
	testutil.AssertEqualsInt(t, "total", 25, int(total))
	testutil.AssertEqualsInt(t, "omitted", 17, int(omitted))
}

func TestReadOutput(t *testing.T) {
	// A finished run: head [0,10), tail [15,25), 5 bytes omitted
	run := &types.ActionRun{OutputHead: "0123456789", OutputTail: "fghijKLMNO", OutputBytes: 25, OutputOmittedBytes: 5}

	w := ReadOutput(run, 0)
	testutil.AssertEqualsString(t, "from zero", "0123456789\n... 5 bytes omitted ...\nfghijKLMNO", w.Output)
	testutil.AssertEqualsInt(t, "total", 25, int(w.Total))
	testutil.AssertEqualsBool(t, "restart", false, w.Restart)

	w = ReadOutput(run, 20)
	testutil.AssertEqualsString(t, "from tail", "KLMNO", w.Output)
	w = ReadOutput(run, 25)
	testutil.AssertEqualsString(t, "at end", "", w.Output)
	w = ReadOutput(run, 5)
	testutil.AssertEqualsString(t, "from head", "56789\n... 5 bytes omitted ...\nfghijKLMNO", w.Output)

	// An offset in the gap restarts from the beginning
	w = ReadOutput(run, 12)
	testutil.AssertEqualsBool(t, "restart", true, w.Restart)
	testutil.AssertEqualsInt(t, "since", 0, int(w.Since))

	// A running run: no head yet, the tail is the recent window
	running := &types.ActionRun{OutputTail: "fghijKLMNO", OutputBytes: 25}
	w = ReadOutput(running, 0)
	testutil.AssertEqualsString(t, "running from zero", "... 15 bytes omitted ...\nfghijKLMNO", w.Output)
	w = ReadOutput(running, 22)
	testutil.AssertEqualsString(t, "running from offset", "MNO", w.Output)

	// All the output fits in the head
	small := &types.ActionRun{OutputHead: "hello\n", OutputBytes: 6}
	w = ReadOutput(small, 0)
	testutil.AssertEqualsString(t, "small", "hello\n", w.Output)
	w = ReadOutput(small, 3)
	testutil.AssertEqualsString(t, "small offset", "lo\n", w.Output)
}

func TestEncodeResult(t *testing.T) {
	rows := []map[string]any{{"id": 1}, {"id": 2}, {"id": 3}}
	doc, count, truncated, err := encodeResult(rows, nil, 1000)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "rows", 3, count)
	testutil.AssertEqualsBool(t, "truncated", false, truncated)
	var decoded []map[string]any
	testutil.AssertNoError(t, json.Unmarshal([]byte(doc), &decoded))
	testutil.AssertEqualsInt(t, "decoded", 3, len(decoded))

	// Rows beyond the limit are dropped whole
	doc, count, truncated, err = encodeResult(rows, nil, 20)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "rows", 3, count)
	testutil.AssertEqualsBool(t, "truncated", true, truncated)
	testutil.AssertNoError(t, json.Unmarshal([]byte(doc), &decoded))
	testutil.AssertEqualsInt(t, "kept", 2, len(decoded))

	doc, count, truncated, err = encodeResult(nil, []string{"a", "b"}, 1000)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "strings", `["a","b"]`, doc)
	testutil.AssertEqualsInt(t, "rows", 2, count)
	testutil.AssertEqualsBool(t, "truncated", false, truncated)

	doc, _, _, err = encodeResult(nil, nil, 1000)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "empty", "[]", doc)
}

func TestRunTimeoutOf(t *testing.T) {
	d, err := runTimeoutOf("", types.ActionConfig{})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "default", "1h0m0s", d.String())

	d, err = runTimeoutOf("", types.ActionConfig{RunTimeout: "30m"})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "config", "30m0s", d.String())

	d, err = runTimeoutOf("2h", types.ActionConfig{RunTimeout: "30m"})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "action", "2h0m0s", d.String())

	_, err = runTimeoutOf("soon", types.ActionConfig{})
	testutil.AssertErrorContains(t, err, "invalid action run timeout")
}

func TestRunErrorStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	status, msg := runErrorStatus(ctx, context.DeadlineExceeded)
	testutil.AssertEqualsString(t, "status", types.ActionRunTimedOut, status)
	testutil.AssertEqualsString(t, "message", "timed out", msg)

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	status, _ = runErrorStatus(ctx2, context.Canceled)
	testutil.AssertEqualsString(t, "canceled", types.ActionRunCanceled, status)

	status, msg = runErrorStatus(context.Background(), errClientGone)
	testutil.AssertEqualsString(t, "client gone", types.ActionRunCanceled, status)
	testutil.AssertEqualsString(t, "client gone message", "canceled", msg)
}

func TestDecodeStoredResult(t *testing.T) {
	run := &types.ActionRun{Result: `[{"id":1},{"id":2},{"id":3}]`}
	valuesMap, valuesStr, err := DecodeResult(run, 2)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "limited", 2, len(valuesMap))
	testutil.AssertEqualsInt(t, "strings", 0, len(valuesStr))

	run = &types.ActionRun{Result: `["a","b"]`}
	valuesMap, valuesStr, err = DecodeResult(run, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "maps", 0, len(valuesMap))
	testutil.AssertEqualsInt(t, "strings", 2, len(valuesStr))

	// Large integers keep their precision
	run = &types.ActionRun{Result: `[{"id":9007199254740993}]`}
	valuesMap, _, err = DecodeResult(run, 0)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "big int", "9007199254740993", fmt.Sprint(valuesMap[0]["id"]))
	encoded, err := json.Marshal(valuesMap[0])
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "big int json", `{"id":9007199254740993}`, string(encoded))
}

func TestOutputRecorderUTF8Boundaries(t *testing.T) {
	// Windows of 4 bytes over two byte runes: the cuts land on rune
	// boundaries, the offsets count every byte, nothing is dropped between
	// the head and the tail of a short output
	r := newOutputRecorder(4, 4)
	r.write("ééé\n") // 7 bytes: é é é \n
	head, tail, total, omitted := r.snapshot()
	testutil.AssertEqualsString(t, "head", "éé", head)
	testutil.AssertEqualsString(t, "tail", "é\n", tail)
	testutil.AssertEqualsInt(t, "total", 7, int(total))
	testutil.AssertEqualsInt(t, "omitted", 0, int(omitted))
	if !utf8.ValidString(head) || !utf8.ValidString(tail) {
		t.Fatal("invalid utf-8 in the windows")
	}

	r = newOutputRecorder(4, 4)
	r.write("ééééé\n") // 11 bytes
	head, tail, total, omitted = r.snapshot()
	testutil.AssertEqualsString(t, "head", "éé", head)
	testutil.AssertEqualsString(t, "tail", "é\n", tail)
	testutil.AssertEqualsInt(t, "total", 11, int(total))
	testutil.AssertEqualsInt(t, "omitted", 4, int(omitted))
	recent, _, _, _ := r.tailForFlush(true)
	if !utf8.ValidString(recent) {
		t.Fatalf("invalid utf-8 in the running view %q", recent)
	}

	// Invalid input bytes are replaced before they are counted
	r = newOutputRecorder(100, 100)
	r.write("a\xffb\n")
	head, _, total, _ = r.snapshot()
	testutil.AssertEqualsString(t, "sanitized", "a\uFFFDb\n", head)
	testutil.AssertEqualsInt(t, "sanitized total", 6, int(total))
}

func TestReadOutputRuneAlignedOffsets(t *testing.T) {
	// An offset inside a rune moves forward to the rune's end, in the head
	// and in the tail; Since reports the offset used
	small := &types.ActionRun{OutputHead: "é\n", OutputBytes: 3}
	w := ReadOutput(small, 1)
	testutil.AssertEqualsString(t, "head mid rune", "\n", w.Output)
	testutil.AssertEqualsInt(t, "head since", 2, int(w.Since))

	run := &types.ActionRun{OutputHead: "ab", OutputTail: "éx\n", OutputBytes: 10, OutputOmittedBytes: 4}
	w = ReadOutput(run, 7) // the tail starts at 6, é is bytes 6-7
	testutil.AssertEqualsString(t, "tail mid rune", "x\n", w.Output)
	testutil.AssertEqualsInt(t, "tail since", 8, int(w.Since))
	if !utf8.ValidString(w.Output) {
		t.Fatal("invalid utf-8")
	}
}

func TestTruncateRunMessageUTF8(t *testing.T) {
	msg := strings.Repeat("é", runMessageMaxBytes) + "x"
	got := truncateRunMessage(msg)
	if len(got) > runMessageMaxBytes || !utf8.ValidString(got) {
		t.Fatalf("truncated message len %d valid %v", len(got), utf8.ValidString(got))
	}
	testutil.AssertEqualsBool(t, "keeps the end", true, strings.HasSuffix(got, "x"))
}
