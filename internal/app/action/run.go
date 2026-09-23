// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// Async action runs (arch/docs/async-actions.md): an action declared with
// is_async=True executes its handler in a goroutine on the node which
// accepted the submission, records the run in the action_runs table with
// its output (stream results) or result values, and can be listed, watched
// and canceled while the app keeps serving

const (
	runLeaseValidity   = 60 * time.Second
	runLeaseRenewal    = 20 * time.Second
	runOutputFlush     = time.Second
	runFlushBytes      = 64 * 1024
	runMessageMaxBytes = 4096
	runFinishTimeout   = 10 * time.Second

	defaultRunTimeout     = time.Hour
	defaultMaxAsyncRuns   = 20
	defaultRetainRuns     = 100
	defaultOutputBytes    = 10 * 1024 * 1024
	defaultResultMaxBytes = 100 * 1024 * 1024
	defaultDisplayRows    = 1000
	defaultMaxWaitSecs    = 120

	// AuditOpRunFinish is the audit operation of the completion event of an
	// async run
	AuditOpRunFinish = "run_finish"
)

// RunStore persists async runs; the metadata database implements it
type RunStore interface {
	CreateActionRun(ctx context.Context, run *types.ActionRun) error
	GetActionRun(ctx context.Context, id string, payload bool) (*types.ActionRun, error)
	ListActionRuns(ctx context.Context, appIds []types.AppId, actionPath, status string, limit int) ([]types.ActionRun, error)
	UpdateActionRunLease(ctx context.Context, id string, leaseUntil time.Time) error
	UpdateActionRunOutput(ctx context.Context, id string, head *string, tail string, outputBytes, omittedBytes int64) error
	FinishActionRun(ctx context.Context, run *types.ActionRun) error
	PruneActionRuns(ctx context.Context, appId types.AppId, keep int) (int, error)
}

// RunHost is what an action needs from its app and the server to execute
// async runs: the store, the node's run registry, the identity of the app
// instance, and the app pin (Acquire keeps the app open for the run's
// lifetime: a reload or delete which closes the app defers the close until
// the run releases it)
type RunHost struct {
	Store          RunStore
	Registry       *system.RunRegistry
	NodeId         string
	AppId          types.AppId
	AppPath        string // the app path domain
	Version        int
	Acquire        func() (release func(), err error)
	RecordActivity func()
}

// SetRunHost sets the run services; async actions cannot start runs
// without them
func (a *Action) SetRunHost(host *RunHost) {
	a.runHost = host
}

// withRunDefaults fills the zero async run settings with their defaults
func withRunDefaults(config types.ActionConfig) types.ActionConfig {
	if config.MaxAsyncRuns <= 0 {
		config.MaxAsyncRuns = defaultMaxAsyncRuns
	}
	if config.RetainRuns <= 0 {
		config.RetainRuns = defaultRetainRuns
	}
	if config.OutputHeadBytes <= 0 {
		config.OutputHeadBytes = defaultOutputBytes
	}
	if config.OutputTailBytes <= 0 {
		config.OutputTailBytes = defaultOutputBytes
	}
	if config.ResultMaxBytes <= 0 {
		config.ResultMaxBytes = defaultResultMaxBytes
	}
	if config.DisplayRows <= 0 {
		config.DisplayRows = defaultDisplayRows
	}
	if config.MaxWaitSecs <= 0 {
		config.MaxWaitSecs = defaultMaxWaitSecs
	}
	return config
}

// runTimeoutOf returns the action's async timeout: its own, else the app
// config's run_timeout, else an hour
func runTimeoutOf(timeout string, config types.ActionConfig) (time.Duration, error) {
	if timeout == "" {
		timeout = config.RunTimeout
	}
	if timeout == "" {
		return defaultRunTimeout, nil
	}
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, fmt.Errorf("invalid action run timeout %q: %w", timeout, err)
	}
	if d <= 0 {
		return defaultRunTimeout, nil
	}
	return d, nil
}

// MaxWait caps a wait requested by a run read API
func (a *Action) MaxWait(wait time.Duration) time.Duration {
	limit := time.Duration(a.config.MaxWaitSecs) * time.Second
	if wait > limit {
		return limit
	}
	return wait
}

// RunStore returns the store async runs are recorded in, nil when the
// action has no run host
func (a *Action) RunStore() RunStore {
	if a.runHost == nil {
		return nil
	}
	return a.runHost.Store
}

// RunPagePath returns the path of a run's page in the action UI
func (a *Action) RunPagePath(runId string) string {
	return a.pagePath + "/runs/" + runId
}

// RunStarted is the API response for a started run
func (a *Action) RunStarted(run *types.ActionRun) types.ActionRunStarted {
	return types.ActionRunStarted{RunId: run.Id, Status: run.Status, Url: a.RunPagePath(run.Id)}
}

// redactedArgs returns the run's args for the record: the visible params as
// strings, without password params, file params as the uploaded file name
func (a *Action) redactedArgs(args starlark.StringDict) map[string]string {
	ret := make(map[string]string)
	for _, param := range a.params {
		if a.hidden[param.Name] || param.DisplayType == apptype.DisplayTypePassword ||
			strings.HasPrefix(param.Name, OPTIONS_PREFIX) || strings.HasPrefix(param.Name, OPTIONS_PREFIX_UNDERSCORE) {
			continue
		}
		value, ok := args[param.Name]
		if !ok {
			continue
		}
		str := value.String()
		if s, isStr := value.(starlark.String); isStr {
			str = string(s)
		}
		if param.DisplayType == apptype.DisplayTypeFileUpload && str != "" {
			str = filepath.Base(str)
		}
		ret[param.Name] = str
	}
	return ret
}

// startRun admits and records an async run and starts its worker. The
// caller has authorized the submission and built the args
func (a *Action) startRun(ctx context.Context, inv Invocation, args starlark.StringDict, tempDir string) (*types.ActionRun, *InvokeError) {
	host := a.runHost
	if host == nil || host.Store == nil || host.Registry == nil {
		return nil, invokeErr(http.StatusInternalServerError, "async action %s: the app has no run services", a.name)
	}
	group := string(host.AppId)
	// The admission is atomic with the slot count: the reservation holds
	// the slot until the run is registered (or the submission fails)
	unreserve, admitted := host.Registry.Reserve(group, a.config.MaxAsyncRuns)
	if !admitted {
		return nil, invokeErr(http.StatusTooManyRequests, "app %s has %d active async runs, the limit (action.max_async_runs); retry later",
			host.AppPath, a.config.MaxAsyncRuns)
	}
	parent, done, err := host.Registry.Begin()
	if err != nil {
		unreserve()
		return nil, invokeErr(http.StatusServiceUnavailable, "%s", err)
	}
	release := func() {}
	if host.Acquire != nil {
		if release, err = host.Acquire(); err != nil {
			unreserve()
			done()
			return nil, invokeErr(http.StatusServiceUnavailable, "app %s is closing: %s", host.AppPath, err)
		}
	}

	id, err := system.NewPrefixedId("")
	if err != nil {
		unreserve()
		release()
		done()
		return nil, invokeErr(http.StatusInternalServerError, "%s", err)
	}
	now := time.Now().UTC()
	lease := now.Add(runLeaseValidity)
	source := strings.TrimSuffix(inv.AuditOp, "_execute")
	if source == "execute" {
		source = "ui"
	}
	run := &types.ActionRun{
		Id:         id,
		AppId:      host.AppId,
		AppPath:    host.AppPath,
		ActionPath: a.actionPath,
		ActionName: a.name,
		Source:     source,
		Actor:      system.GetContextUserId(ctx),
		RequestId:  system.GetContextRequestId(ctx),
		Version:    host.Version,
		Args:       a.redactedArgs(args),
		StartedAt:  now,
		Status:     types.ActionRunRunning,
		NodeId:     host.NodeId,
		LeaseUntil: &lease,
	}
	if err := host.Store.CreateActionRun(ctx, run); err != nil {
		unreserve()
		release()
		done()
		return nil, invokeErr(http.StatusInternalServerError, "error recording run: %s", err)
	}

	// The worker keeps only the caller's identity, for the run's lifetime
	runCtx, cancel := context.WithTimeout(rbac.DetachedAppContext(parent, ctx), a.timeout)
	host.Registry.Add(run.Id, group, cancel)
	unreserve() // the run counts as active now
	workerRun := *run
	go func() {
		defer done()
		defer release()
		defer host.Registry.Remove(run.Id)
		defer cancel()
		a.performRun(runCtx, &workerRun, args, tempDir)
	}()
	return run, nil
}

// performRun executes a claimed run to completion: the handler call, the
// consumption of a stream result into the output recorder or the encoding
// of a values result, then the finish record, the audit events and the
// retention pruning
func (a *Action) performRun(ctx context.Context, run *types.ActionRun, args starlark.StringDict, tempDir string) {
	host := a.runHost
	recorder := newOutputRecorder(a.config.OutputHeadBytes, a.config.OutputTailBytes)
	thread := &starlark.Thread{
		Name:  a.name + ":" + run.Id,
		Print: func(_ *starlark.Thread, msg string) { recorder.write(msg + "\n") },
	}
	thread.SetLocal(types.TL_CONTEXT, ctx)
	if a.containerProxyUrl != "" {
		thread.SetLocal(types.TL_CONTAINER_URL, a.containerProxyUrl)
	}
	if a.containerHandler != nil {
		thread.SetLocal(types.TL_CONTAINER_HANDLER, a.containerHandler)
	}
	thread.SetLocal(types.TL_APP_URL, types.GetAppUrl(a.appPathDomain, a.serverConfig))

	// A canceled context (cancel request or timeout) stops the Starlark
	// thread at its next instruction
	threadDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel("run " + run.Id + " canceled: " + ctx.Err().Error())
		case <-threadDone:
		}
	}()

	// The liveness stamp, renewed while the run executes; the renewal counts
	// as app activity so the idle shutdown keeps the app container up
	lease := system.StartPeriodicTask(ctx, runLeaseRenewal, false, func(ctx context.Context) {
		leaseCtx, cancel := context.WithTimeout(ctx, runFinishTimeout)
		defer cancel()
		if err := host.Store.UpdateActionRunLease(leaseCtx, run.Id, time.Now().Add(runLeaseValidity)); err != nil && ctx.Err() == nil {
			a.Warn().Err(err).Msgf("error renewing run %s lease", run.Id)
		}
		if host.RecordActivity != nil {
			host.RecordActivity()
		}
	})
	// The running output, flushed so any node can serve the recent output
	flusher := system.StartPeriodicTask(ctx, runOutputFlush, false, func(ctx context.Context) {
		a.flushOutput(ctx, run.Id, recorder, false)
	})

	customEvent := types.AuditEvent{
		RequestId: run.RequestId,
		UserId:    run.Actor,
		AppId:     run.AppId,
		EventType: types.EventTypeCustom,
	}

	argsValue := Args{members: args}
	ret, callErr := a.callHandler(thread, a.run, starlark.Tuple{starlark.False, &argsValue})
	close(threadDone)
	var status, message string
	switch {
	case callErr != nil:
		status, message = runErrorStatus(ctx, callErr)
	default:
		status, message = a.recordResult(ctx, run, ret, recorder)
	}
	if status == types.ActionRunCanceled {
		// Record who asked for the cancel (a user, the app delete, the
		// server shutdown)
		if by := host.Registry.CanceledBy(run.Id); by != "" {
			message = "canceled by " + by
		}
	}
	if cleanupErr := RunDeferredCleanup(thread); cleanupErr != nil {
		a.Error().Err(cleanupErr).Msgf("run %s: error cleaning up plugins", run.Id)
		if status == types.ActionRunSucceeded {
			status, message = types.ActionRunFailed, cleanupErr.Error()
		}
	}
	lease.Stop()
	flusher.Stop()
	if tempDir != "" {
		if remErr := os.RemoveAll(tempDir); remErr != nil {
			a.Error().Err(remErr).Msg("error removing run temp dir")
		}
	}

	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), runFinishTimeout)
	defer finishCancel()
	run.Status = status
	run.Message = truncateRunMessage(message)
	ended := time.Now().UTC()
	run.EndedAt = &ended
	run.OutputHead, run.OutputTail, run.OutputBytes, run.OutputOmittedBytes = recorder.snapshot()
	if err := host.Store.FinishActionRun(finishCtx, run); err != nil {
		a.Error().Err(err).Msgf("error recording run %s finish", run.Id)
	}
	a.Info().Str("run", run.Id).Str("status", status).Msg("action run finished")

	if a.auditInsert != nil {
		eventStatus := types.EventStatusFailure
		if status == types.ActionRunSucceeded {
			eventStatus = types.EventStatusSuccess
		}
		event := types.AuditEvent{
			RequestId:  run.RequestId,
			CreateTime: time.Now(),
			UserId:     run.Actor,
			AppId:      run.AppId,
			EventType:  types.EventTypeAction,
			Operation:  AuditOpRunFinish,
			Target:     a.name,
			Detail:     run.Id + " " + status,
			Status:     string(eventStatus),
		}
		if err := a.auditInsert(&event); err != nil {
			a.Error().Err(err).Msg("error inserting audit event")
		}
		customEvent.CreateTime = time.Now()
		customEvent.Status = string(eventStatus)
		customEvent.Operation = system.GetThreadLocalKey(thread, types.TL_AUDIT_OPERATION)
		customEvent.Target = system.GetThreadLocalKey(thread, types.TL_AUDIT_TARGET)
		customEvent.Detail = system.GetThreadLocalKey(thread, types.TL_AUDIT_DETAIL)
		if customEvent.Operation != "" {
			if err := a.auditInsert(&customEvent); err != nil {
				a.Error().Err(err).Msg("error inserting custom audit event")
			}
		}
	}

	if _, err := host.Store.PruneActionRuns(finishCtx, run.AppId, a.config.RetainRuns); err != nil {
		a.Warn().Err(err).Msgf("error pruning runs of app %s", run.AppPath)
	}
}

// recordResult decodes the handler's return value into the run: a stream
// is consumed into the recorder, values are encoded into the result
// document. Returns the run status and message
func (a *Action) recordResult(ctx context.Context, run *types.ActionRun, ret starlark.Value, recorder *outputRecorder) (string, string) {
	decoded, decodeErr := decodeResult(ret)
	if decodeErr != nil {
		return types.ActionRunFailed, decodeErr.Msg
	}
	run.ResultStatus = decoded.status
	if decoded.stream != nil {
		run.IsStream = true
		run.Report = reportStream
		seq, err := decoded.stream.StartStream()
		if err != nil {
			return types.ActionRunFailed, fmt.Sprintf("error starting result stream: %s", err)
		}
		defer decoded.stream.CloseStream()
		exitStatus, streamErr := consumeStream(ctx, seq, func(chunk string) error {
			recorder.write(chunk)
			return nil
		})
		if streamErr != nil {
			return runErrorStatus(ctx, streamErr)
		}
		run.ExitCode = &exitStatus
		if exitStatus != 0 {
			return types.ActionRunFailed, fmt.Sprintf("exit code %d", exitStatus)
		}
		return types.ActionRunSucceeded, ""
	}

	run.Report = effectiveReport(decoded.report, decoded.valuesMap, decoded.valuesStr)
	if len(decoded.paramErrors) > 0 {
		run.ParamErrors = make(map[string]string, len(decoded.paramErrors))
		for k, v := range decoded.paramErrors {
			run.ParamErrors[k] = fmt.Sprint(v)
		}
	}
	var err error
	run.Result, run.ResultRows, run.ResultTruncated, err = encodeResult(decoded.valuesMap, decoded.valuesStr, a.config.ResultMaxBytes)
	if err != nil {
		return types.ActionRunFailed, fmt.Sprintf("error encoding result: %s", err)
	}
	if len(run.ParamErrors) > 0 {
		return types.ActionRunFailed, "param errors"
	}
	return types.ActionRunSucceeded, ""
}

// encodeResult encodes the result values as a JSON list, row by row up to
// maxBytes: rows which do not fit are dropped and the result is flagged as
// truncated. Returns the document, the total row count and the flag
func encodeResult(valuesMap []map[string]any, valuesStr []string, maxBytes int64) (string, int, bool, error) {
	var rows []any
	if valuesMap != nil {
		rows = make([]any, 0, len(valuesMap))
		for _, v := range valuesMap {
			rows = append(rows, v)
		}
	} else {
		rows = make([]any, 0, len(valuesStr))
		for _, v := range valuesStr {
			rows = append(rows, v)
		}
	}
	var b strings.Builder
	b.WriteByte('[')
	kept := 0
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return "", 0, false, err
		}
		if int64(b.Len()+len(encoded)+2) > maxBytes {
			break
		}
		if kept > 0 {
			b.WriteByte(',')
		}
		b.Write(encoded)
		kept++
	}
	b.WriteByte(']')
	return b.String(), len(rows), kept < len(rows), nil
}

// runErrorStatus maps an execution error to the run status
func runErrorStatus(ctx context.Context, err error) (string, string) {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return types.ActionRunTimedOut, "timed out"
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) || errors.Is(err, errClientGone):
		return types.ActionRunCanceled, "canceled"
	default:
		return types.ActionRunFailed, err.Error()
	}
}

// truncateRunMessage keeps the last runMessageMaxBytes of a message, cut on
// a rune boundary so the stored text stays valid UTF-8
func truncateRunMessage(msg string) string {
	if len(msg) > runMessageMaxBytes {
		return string(lastBytes([]byte(msg), runMessageMaxBytes))
	}
	return msg
}

// flushOutput writes the recorder's recent output to the run record when it
// changed since the last flush
func (a *Action) flushOutput(ctx context.Context, runId string, recorder *outputRecorder, force bool) {
	tail, total, omitted, changed := recorder.tailForFlush(force)
	if !changed {
		return
	}
	flushCtx, cancel := context.WithTimeout(ctx, runFinishTimeout)
	defer cancel()
	if err := a.runHost.Store.UpdateActionRunOutput(flushCtx, runId, nil, tail, total, omitted); err != nil && ctx.Err() == nil {
		a.Warn().Err(err).Msgf("error flushing run %s output", runId)
	}
}

// outputRecorder keeps the first headMax bytes of a run's output and a ring
// of the last tailMax bytes. Until the head is stored (at the finish), the
// tail is what any node can show of a running run: the last tailMax bytes of
// everything produced. The flushed tail is therefore the last tailMax bytes
// of the whole output while running, and the last tailMax bytes after the
// head once finished, so a reader's offsets stay valid across the finish
type outputRecorder struct {
	mu          sync.Mutex
	headMax     int64
	tailMax     int64
	head        []byte
	tail        []byte // the last bytes after the head (finished view)
	recent      []byte // the last bytes of everything (running view)
	total       int64
	unflushed   int64
	dirty       bool
	lastFlushed time.Time
}

func newOutputRecorder(headMax, tailMax int64) *outputRecorder {
	return &outputRecorder{headMax: headMax, tailMax: tailMax}
}

// write records a chunk of output. The chunk is made valid UTF-8 first
// (invalid sequences become U+FFFD): the stored text goes into text
// columns and JSON documents, and every offset (total, the windows) counts
// the stored bytes, so readers and writers agree. The head and the tail
// are cut on rune boundaries, so the windows are valid text as well
func (r *outputRecorder) write(chunk string) {
	if chunk == "" {
		return
	}
	chunk = strings.ToValidUTF8(chunk, "\uFFFD")
	r.mu.Lock()
	defer r.mu.Unlock()
	data := []byte(chunk)
	r.total += int64(len(data))
	r.unflushed += int64(len(data))
	r.dirty = true
	if room := r.headMax - int64(len(r.head)); room > 0 {
		want := min(room, int64(len(data)))
		n := runeBoundaryBefore(data, want)
		r.head = append(r.head, data[:n]...)
		data = data[n:]
		if n < want {
			// A rune did not fit: the head is complete, its bytes go to
			// the tail (nothing is lost between the two)
			r.headMax = int64(len(r.head))
		}
	}
	r.recent = appendRing(r.recent, []byte(chunk), r.tailMax)
	if len(data) > 0 {
		r.tail = appendRing(r.tail, data, r.tailMax)
	}
}

// runeBoundaryBefore returns the largest n' <= n such that data[:n'] does
// not end inside a multi byte rune
func runeBoundaryBefore(data []byte, n int64) int64 {
	if n >= int64(len(data)) {
		return int64(len(data))
	}
	for n > 0 && !utf8.RuneStart(data[n]) {
		n--
	}
	return n
}

// runeBoundaryAt returns the smallest i >= start such that data[i:] starts
// on a rune boundary
func runeBoundaryAt(data []byte, start int) int {
	for start < len(data) && !utf8.RuneStart(data[start]) {
		start++
	}
	return start
}

// appendRing appends data to buf keeping at most limit trailing bytes (cut
// on a rune boundary); the buffer is compacted when it grows past twice the
// limit, so appends are amortized copies rather than a copy per write
func appendRing(buf, data []byte, limit int64) []byte {
	if int64(len(data)) >= limit {
		return append(buf[:0], lastBytes(data, limit)...)
	}
	buf = append(buf, data...)
	if int64(len(buf)) > 2*limit {
		buf = append(buf[:0], lastBytes(buf, limit)...)
	}
	return buf
}

// lastBytes returns at most the last limit bytes of buf, starting on a rune
// boundary
func lastBytes(buf []byte, limit int64) []byte {
	if int64(len(buf)) <= limit {
		return buf
	}
	return buf[runeBoundaryAt(buf, len(buf)-int(limit)):]
}

// tailForFlush returns the running view (the last tailMax bytes of
// everything), the total and the omitted count, and whether anything
// changed since the last flush; a flush happens when the output changed and
// the flush interval or the byte threshold is reached (force skips the
// interval)
func (r *outputRecorder) tailForFlush(force bool) (string, int64, int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty {
		return "", 0, 0, false
	}
	if !force && r.unflushed < runFlushBytes && time.Since(r.lastFlushed) < runOutputFlush {
		return "", 0, 0, false
	}
	recent := lastBytes(r.recent, r.tailMax)
	r.dirty = false
	r.unflushed = 0
	r.lastFlushed = time.Now()
	return string(recent), r.total, r.total - int64(len(recent)), true
}

// snapshot returns the finished view: the head, the tail after the head,
// the total and the bytes omitted between them
func (r *outputRecorder) snapshot() (string, string, int64, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tail := lastBytes(r.tail, r.tailMax)
	omitted := r.total - int64(len(r.head)) - int64(len(tail))
	if omitted < 0 {
		omitted = 0
	}
	return string(r.head), string(tail), r.total, omitted
}

// OutputWindow is the readable output of a run from an offset
type OutputWindow struct {
	Output  string // the bytes, starting at Since
	Since   int64  // the offset the bytes start at
	Total   int64  // the bytes produced so far, the offset to continue from
	Omitted int64  // bytes not available between the head and the tail
	Restart bool   // the reader's offset was no longer available, the output restarts from the head
}

// ReadOutput returns the output of a run from offset since: the head covers
// [0, len(head)), the tail covers [total-len(tail), total). An offset in
// the tail returns the tail from there; an offset in the head (or zero)
// returns the head, an omitted marker when bytes are missing, then the tail;
// an offset in the gap restarts from the head. An offset inside a multi
// byte rune is moved forward to the rune's end, so the window is valid
// text; Since reports the offset used
func ReadOutput(run *types.ActionRun, since int64) OutputWindow {
	total := run.OutputBytes
	head, tail := run.OutputHead, run.OutputTail
	tailStart := total - int64(len(tail))
	if since < 0 {
		since = 0
	}
	if since >= tailStart && since <= total {
		offset := runeBoundaryAt([]byte(tail), int(since-tailStart))
		return OutputWindow{Output: tail[offset:], Since: tailStart + int64(offset), Total: total}
	}
	restart := since > int64(len(head))
	var b strings.Builder
	start := since
	if restart {
		start = 0
	}
	if start < int64(len(head)) {
		start = int64(runeBoundaryAt([]byte(head), int(start)))
		b.WriteString(head[start:])
	}
	omitted := tailStart - int64(len(head))
	if omitted > 0 {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "... %d bytes omitted ...\n", omitted)
	}
	b.WriteString(tail)
	return OutputWindow{Output: b.String(), Since: start, Total: total, Omitted: max(omitted, 0), Restart: restart}
}
