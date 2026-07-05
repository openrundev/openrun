// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"sync"
	"time"
)

// This file implements the platform independent part of the OS service
// integration (Windows service control manager). All status reporting is
// serialized through the serviceManager run loop, which is the only writer
// to the status sink. That guarantees the control manager sees state
// transitions in order (a pending-state heartbeat can never overwrite a
// later Running/Stopped report). The platform glue lives in
// service_windows.go; on other platforms serviceMgr stays nil and the
// Notify* functions are no-ops.

type serviceState int

const (
	svcStartPending serviceState = iota
	svcRunning
	svcStopPending
	svcStopped
)

const (
	serviceStartWaitHint = 120 * time.Second
	serviceStopWaitHint  = 60 * time.Second
	// serviceStopWaitHint has to cover the server shutdown timeout used in
	// startServer plus the pending heartbeat keeps the checkpoint moving
	servicePendingPingInterval = 10 * time.Second
	// serviceReportWait bounds how long process exit waits for the control
	// handler to finish reporting the final Stopped state
	serviceReportWait = 10 * time.Second
)

// serviceUpdate is one status report for the service control manager
type serviceUpdate struct {
	state      serviceState
	checkpoint uint32
	waitHint   time.Duration
	exitCode   uint32
}

type serviceEvent int

const (
	eventReady serviceEvent = iota
	eventStopRequest
	eventStopped
	eventInterrogate
)

type serviceEventMsg struct {
	event    serviceEvent
	exitCode uint32
}

// serviceManager serializes service status reporting through its run loop
type serviceManager struct {
	events        chan serviceEventMsg
	stopRequested chan struct{}
	stopOnce      sync.Once
	runnerDone    chan struct{} // closed by the platform glue when the control handler exits
	pingInterval  time.Duration
}

// serviceMgr is set by MaybeRunAsService when the process is running as an
// OS service, nil otherwise
var serviceMgr *serviceManager

func newServiceManager() *serviceManager {
	return &serviceManager{
		events:        make(chan serviceEventMsg, 16),
		stopRequested: make(chan struct{}),
		runnerDone:    make(chan struct{}),
		pingInterval:  servicePendingPingInterval,
	}
}

// post delivers an event without blocking. The run loop drains promptly
// while alive; after it returns the process is exiting and events are moot,
// so dropping on a full buffer is safe and avoids deadlocks.
func (m *serviceManager) post(event serviceEvent, exitCode uint32) {
	select {
	case m.events <- serviceEventMsg{event: event, exitCode: exitCode}:
	default:
	}
}

// run processes events and reports status updates via send until the
// Stopped state is reported. It returns the service exit code. run is the
// only caller of send, so updates reach the control manager in order.
func (m *serviceManager) run(send func(serviceUpdate)) uint32 {
	ticker := time.NewTicker(m.pingInterval)
	defer ticker.Stop()

	checkpoint := uint32(1)
	current := serviceUpdate{state: svcStartPending, checkpoint: checkpoint, waitHint: serviceStartWaitHint}
	send(current)

	for {
		select {
		case msg := <-m.events:
			switch msg.event {
			case eventReady:
				if current.state != svcStartPending {
					continue // stop already requested, do not regress to Running
				}
				current = serviceUpdate{state: svcRunning}
				send(current)
			case eventStopRequest:
				if current.state == svcStopPending {
					continue
				}
				checkpoint++
				current = serviceUpdate{state: svcStopPending, checkpoint: checkpoint, waitHint: serviceStopWaitHint}
				send(current)
				m.stopOnce.Do(func() { close(m.stopRequested) })
			case eventStopped:
				current = serviceUpdate{state: svcStopped, exitCode: msg.exitCode}
				send(current)
				return msg.exitCode
			case eventInterrogate:
				send(current)
			}
		case <-ticker.C:
			if current.state == svcStartPending || current.state == svcStopPending {
				checkpoint++
				current.checkpoint = checkpoint
				send(current)
			}
		}
	}
}

// NotifyServiceReady reports the Running state to the service control
// manager. No-op when not running as a service.
func NotifyServiceReady() {
	if serviceMgr != nil {
		serviceMgr.post(eventReady, 0)
	}
}

// NotifyServiceStopping reports that a graceful shutdown has started
func NotifyServiceStopping() {
	if serviceMgr != nil {
		serviceMgr.post(eventStopRequest, 0)
	}
}

// NotifyServiceStopped reports a clean shutdown to the service control
// manager and waits for the report to be delivered before returning
func NotifyServiceStopped() {
	notifyServiceExit(0)
}

// NotifyServiceFailed reports a failed startup or shutdown with a service
// specific exit code. Call before exiting the process on a fatal error so
// the control manager does not log an unexpected termination.
func NotifyServiceFailed(exitCode uint32) {
	if exitCode == 0 {
		exitCode = 1
	}
	notifyServiceExit(exitCode)
}

func notifyServiceExit(exitCode uint32) {
	if serviceMgr == nil {
		return
	}
	serviceMgr.post(eventStopped, exitCode)
	// Wait for the control handler to exit so the process does not die
	// while the final Stopped report is still in flight
	select {
	case <-serviceMgr.runnerDone:
	case <-time.After(serviceReportWait):
	}
}

// ServiceStopNotify returns a channel that is closed when the OS requests a
// service stop or shutdown. Returns nil when not running as a service.
func ServiceStopNotify() <-chan struct{} {
	if serviceMgr == nil {
		return nil
	}
	return serviceMgr.stopRequested
}
