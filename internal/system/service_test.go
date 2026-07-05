// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"testing"
	"time"
)

const testWait = 5 * time.Second

// startManager runs the manager loop with updates captured on a channel.
// Returns the updates channel and a channel with the run loop's exit code.
func startManager(mgr *serviceManager) (<-chan serviceUpdate, <-chan uint32) {
	updates := make(chan serviceUpdate, 100)
	exitCode := make(chan uint32, 1)
	go func() {
		exitCode <- mgr.run(func(u serviceUpdate) {
			updates <- u
		})
	}()
	return updates, exitCode
}

func nextUpdate(t *testing.T, updates <-chan serviceUpdate) serviceUpdate {
	t.Helper()
	select {
	case u := <-updates:
		return u
	case <-time.After(testWait):
		t.Fatal("timed out waiting for service status update")
		return serviceUpdate{}
	}
}

func expectState(t *testing.T, updates <-chan serviceUpdate, state serviceState) serviceUpdate {
	t.Helper()
	u := nextUpdate(t, updates)
	if u.state != state {
		t.Fatalf("expected service state %d, got %d", state, u.state)
	}
	return u
}

func expectNoUpdate(t *testing.T, updates <-chan serviceUpdate) {
	t.Helper()
	select {
	case u := <-updates:
		t.Fatalf("expected no service status update, got state %d", u.state)
	case <-time.After(50 * time.Millisecond):
	}
}

func expectClosed(t *testing.T, name string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testWait):
		t.Fatalf("timed out waiting for %s channel to close", name)
	}
}

func TestServiceLifecycle(t *testing.T) {
	mgr := newServiceManager()
	updates, exitCode := startManager(mgr)

	u := expectState(t, updates, svcStartPending)
	if u.checkpoint != 1 {
		t.Errorf("expected initial checkpoint 1, got %d", u.checkpoint)
	}
	if u.waitHint != serviceStartWaitHint {
		t.Errorf("expected start wait hint %v, got %v", serviceStartWaitHint, u.waitHint)
	}

	mgr.post(eventReady, 0)
	expectState(t, updates, svcRunning)

	select {
	case <-mgr.stopRequested:
		t.Fatal("stopRequested closed before any stop request")
	default:
	}

	mgr.post(eventStopRequest, 0)
	u = expectState(t, updates, svcStopPending)
	if u.waitHint != serviceStopWaitHint {
		t.Errorf("expected stop wait hint %v, got %v", serviceStopWaitHint, u.waitHint)
	}
	expectClosed(t, "stopRequested", mgr.stopRequested)

	mgr.post(eventStopped, 0)
	expectState(t, updates, svcStopped)
	select {
	case code := <-exitCode:
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	case <-time.After(testWait):
		t.Fatal("timed out waiting for run loop to return")
	}
}

func TestServiceReadyAfterStopIgnored(t *testing.T) {
	// A stop requested during startup must not be followed by a Running
	// report when startup later completes
	mgr := newServiceManager()
	updates, _ := startManager(mgr)
	expectState(t, updates, svcStartPending)

	mgr.post(eventStopRequest, 0)
	expectState(t, updates, svcStopPending)

	mgr.post(eventReady, 0)
	expectNoUpdate(t, updates)

	mgr.post(eventStopped, 0)
	expectState(t, updates, svcStopped)
}

func TestServiceDuplicateStopRequest(t *testing.T) {
	// SCM stop and the self-initiated NotifyServiceStopping can both fire;
	// only one StopPending report should go out
	mgr := newServiceManager()
	updates, _ := startManager(mgr)
	expectState(t, updates, svcStartPending)

	mgr.post(eventStopRequest, 0)
	expectState(t, updates, svcStopPending)
	mgr.post(eventStopRequest, 0)
	expectNoUpdate(t, updates)

	mgr.post(eventStopped, 0)
	expectState(t, updates, svcStopped)
}

func TestServiceFailureExitCode(t *testing.T) {
	mgr := newServiceManager()
	updates, exitCode := startManager(mgr)
	expectState(t, updates, svcStartPending)

	mgr.post(eventStopped, 7)
	u := expectState(t, updates, svcStopped)
	if u.exitCode != 7 {
		t.Errorf("expected exit code 7 in update, got %d", u.exitCode)
	}
	select {
	case code := <-exitCode:
		if code != 7 {
			t.Errorf("expected run to return exit code 7, got %d", code)
		}
	case <-time.After(testWait):
		t.Fatal("timed out waiting for run loop to return")
	}
}

func TestServiceInterrogate(t *testing.T) {
	mgr := newServiceManager()
	updates, _ := startManager(mgr)
	first := expectState(t, updates, svcStartPending)

	mgr.post(eventInterrogate, 0)
	u := expectState(t, updates, svcStartPending)
	if u != first {
		t.Errorf("expected interrogate to repeat current status %+v, got %+v", first, u)
	}

	mgr.post(eventReady, 0)
	expectState(t, updates, svcRunning)
	mgr.post(eventInterrogate, 0)
	expectState(t, updates, svcRunning)

	mgr.post(eventStopped, 0)
	expectState(t, updates, svcStopped)
}

func TestServicePendingHeartbeat(t *testing.T) {
	mgr := newServiceManager()
	mgr.pingInterval = 5 * time.Millisecond
	updates, _ := startManager(mgr)

	u := expectState(t, updates, svcStartPending)
	last := u.checkpoint
	for range 3 {
		u = expectState(t, updates, svcStartPending)
		if u.checkpoint <= last {
			t.Errorf("expected checkpoint to increase, got %d after %d", u.checkpoint, last)
		}
		last = u.checkpoint
	}

	// After Running is reported, no StartPending heartbeat may follow: the
	// state regression race in the old implementation
	mgr.post(eventReady, 0)
	for {
		u = nextUpdate(t, updates)
		if u.state == svcRunning {
			break
		}
		if u.state != svcStartPending {
			t.Fatalf("unexpected state %d before Running", u.state)
		}
	}
	deadline := time.After(50 * time.Millisecond)
drain:
	for {
		select {
		case u = <-updates:
			t.Fatalf("expected no updates while running, got state %d", u.state)
		case <-deadline:
			break drain
		}
	}

	// Heartbeat resumes with increasing checkpoints during StopPending
	mgr.post(eventStopRequest, 0)
	u = expectState(t, updates, svcStopPending)
	last = u.checkpoint
	u = expectState(t, updates, svcStopPending)
	if u.checkpoint <= last {
		t.Errorf("expected stop pending checkpoint to increase, got %d after %d", u.checkpoint, last)
	}

	mgr.post(eventStopped, 0)
}

func TestServicePostDoesNotBlock(t *testing.T) {
	// Posting must never block, even with no run loop draining events
	mgr := newServiceManager()
	done := make(chan struct{})
	go func() {
		for range 100 {
			mgr.post(eventInterrogate, 0)
		}
		close(done)
	}()
	expectClosed(t, "post", done)
}

func TestServiceNotifyWithoutService(t *testing.T) {
	if serviceMgr != nil {
		t.Fatal("expected serviceMgr to be nil in tests")
	}
	// All public entry points must be no-ops when not running as a service
	NotifyServiceReady()
	NotifyServiceStopping()
	NotifyServiceStopped()
	NotifyServiceFailed(1)
	if ServiceStopNotify() != nil {
		t.Error("expected nil stop notify channel when not running as a service")
	}
}

func TestServiceNotifyExitWaitsForRunner(t *testing.T) {
	mgr := newServiceManager()
	serviceMgr = mgr
	defer func() { serviceMgr = nil }()

	// With the control handler already done, exit notification must return
	// promptly instead of waiting out the full report timeout
	close(mgr.runnerDone)
	start := time.Now()
	NotifyServiceFailed(3)
	if elapsed := time.Since(start); elapsed > testWait {
		t.Fatalf("notify exit took too long: %v", elapsed)
	}

	select {
	case msg := <-mgr.events:
		if msg.event != eventStopped || msg.exitCode != 3 {
			t.Errorf("expected stopped event with exit code 3, got event %d code %d", msg.event, msg.exitCode)
		}
	default:
		t.Error("expected a stopped event to be posted")
	}
}
