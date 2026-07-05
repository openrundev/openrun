// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package system

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
)

// windowsServiceName is the name used in the service table entry. The
// service control manager ignores it for SERVICE_WIN32_OWN_PROCESS
// services, so it does not have to match the registered service name.
const windowsServiceName = "openrun"

// MaybeRunAsService detects whether the process was started by the Windows
// service control manager and, if so, starts the control handler that
// reports service status. Must be called early in main, before the server
// starts. No-op when the process was started interactively.
func MaybeRunAsService() {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return
	}

	// Windows services start in System32. Use the executable directory so
	// relative paths behave like they do when openrun is run interactively.
	if execPath, err := os.Executable(); err == nil {
		if err := os.Chdir(filepath.Dir(execPath)); err != nil {
			log.Warn().Err(err).Msg("unable to change to executable directory")
		}
	}

	serviceMgr = newServiceManager()
	go func() {
		defer close(serviceMgr.runnerDone)
		if err := svc.Run(windowsServiceName, serviceRunner{}); err != nil {
			log.Error().Err(err).Msg("windows service control handler failed")
		}
	}()
}

type serviceRunner struct{}

func (serviceRunner) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	runDone := make(chan uint32, 1)
	go func() {
		runDone <- serviceMgr.run(func(update serviceUpdate) {
			if update.state == svcStopped {
				// Reported by svc.Run from Execute's return values, which
				// also carry the exit code
				return
			}
			status <- toSvcStatus(update)
		})
	}()

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				requests = nil // block; wait for the run loop to report Stopped
				continue
			}
			switch req.Cmd {
			case svc.Interrogate:
				serviceMgr.post(eventInterrogate, 0)
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				serviceMgr.post(eventStopRequest, 0)
			default:
				log.Warn().Int("control", int(req.Cmd)).Msg("unsupported windows service control request")
			}
		case exitCode := <-runDone:
			return exitCode != 0, exitCode
		}
	}
}

func toSvcStatus(update serviceUpdate) svc.Status {
	result := svc.Status{
		CheckPoint: update.checkpoint,
		WaitHint:   uint32(update.waitHint / time.Millisecond),
	}
	switch update.state {
	case svcStartPending:
		result.State = svc.StartPending
	case svcRunning:
		result.State = svc.Running
		result.Accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	case svcStopPending:
		result.State = svc.StopPending
	case svcStopped:
		result.State = svc.Stopped
	}
	return result
}
