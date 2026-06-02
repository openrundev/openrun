// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package system

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceStartWaitHintMillis uint32 = 120000
	serviceStopWaitHintMillis  uint32 = 60000

	serviceStartCheckpointInterval = 10 * time.Second
	serviceStatusRegistrationWait  = 30 * time.Second
)

var (
	serviceMode           bool
	serviceStatus         chan<- svc.Status
	serviceStatusMu       sync.RWMutex
	serviceStatusReady    = make(chan struct{})
	serviceDispatcherDone = make(chan struct{})
	serviceStarted        = make(chan struct{})
	serviceStop           = make(chan struct{})
	serviceDone           = make(chan struct{})
	serviceStatusReadyMu  sync.Once
	serviceStartedMu      sync.Once
	serviceStopMu         sync.Once
	serviceDoneMu         sync.Once
)

func init() {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return
	}
	serviceMode = true

	// Windows services start in System32. Use the executable directory so
	// relative paths behave like they do when openrun is run interactively.
	if execPath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(execPath))
	}

	go func() {
		defer close(serviceDispatcherDone)
		if err := svc.Run("", serviceRunner{}); err != nil {
			log.Error().Err(err).Msg("windows service control handler failed")
		}
	}()
}

type serviceRunner struct{}

func (serviceRunner) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	setServiceStatus(status)
	status <- startPendingStatus(1)
	go serviceStartPendingHeartbeat(status)

	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending, WaitHint: serviceStopWaitHintMillis}
			serviceStopMu.Do(func() {
				close(serviceStop)
			})
			<-serviceDone
			return false, 0
		default:
			log.Warn().Str("control", serviceCmdString(req.Cmd)).Msg("unsupported windows service control request")
		}
	}

	return false, 0
}

func NotifyServiceReady() {
	status := waitForServiceStatus()
	if status == nil {
		return
	}
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	serviceStartedMu.Do(func() {
		close(serviceStarted)
	})
}

func NotifyServiceStopping() {
	status := waitForServiceStatus()
	if status == nil {
		return
	}
	status <- svc.Status{State: svc.StopPending, WaitHint: serviceStopWaitHintMillis}
}

func NotifyServiceStopped() {
	status := waitForServiceStatus()
	if status == nil {
		return
	}
	status <- svc.Status{State: svc.Stopped}
	serviceDoneMu.Do(func() {
		close(serviceDone)
	})
}

func ServiceStopNotify() <-chan struct{} {
	return serviceStop
}

func setServiceStatus(status chan<- svc.Status) {
	serviceStatusMu.Lock()
	defer serviceStatusMu.Unlock()
	serviceStatus = status
	serviceStatusReadyMu.Do(func() {
		close(serviceStatusReady)
	})
}

func getServiceStatus() chan<- svc.Status {
	serviceStatusMu.RLock()
	defer serviceStatusMu.RUnlock()
	return serviceStatus
}

func waitForServiceStatus() chan<- svc.Status {
	if !serviceMode {
		return nil
	}

	select {
	case <-serviceStatusReady:
	case <-serviceDispatcherDone:
		return nil
	case <-time.After(serviceStatusRegistrationWait):
		log.Warn().Dur("timeout", serviceStatusRegistrationWait).Msg("timed out waiting for windows service status channel")
		return nil
	}
	return getServiceStatus()
}

func serviceStartPendingHeartbeat(status chan<- svc.Status) {
	ticker := time.NewTicker(serviceStartCheckpointInterval)
	defer ticker.Stop()

	checkpoint := uint32(2)
	for {
		select {
		case <-serviceStarted:
			return
		case <-serviceStop:
			return
		case <-ticker.C:
			status <- startPendingStatus(checkpoint)
			checkpoint++
		}
	}
}

func startPendingStatus(checkpoint uint32) svc.Status {
	return svc.Status{
		State:      svc.StartPending,
		CheckPoint: checkpoint,
		WaitHint:   serviceStartWaitHintMillis,
	}
}

func serviceCmdString(c svc.Cmd) string {
	switch c {
	case svc.Stop:
		return "stop"
	case svc.Pause:
		return "pause"
	case svc.Continue:
		return "continue"
	case svc.Interrogate:
		return "interrogate"
	case svc.Shutdown:
		return "shutdown"
	case svc.ParamChange:
		return "param_change"
	case svc.NetBindAdd:
		return "net_bind_add"
	case svc.NetBindRemove:
		return "net_bind_remove"
	case svc.NetBindEnable:
		return "net_bind_enable"
	case svc.NetBindDisable:
		return "net_bind_disable"
	case svc.DeviceEvent:
		return "device_event"
	case svc.HardwareProfileChange:
		return "hardware_profile_change"
	case svc.PowerEvent:
		return "power_event"
	case svc.SessionChange:
		return "session_change"
	case svc.PreShutdown:
		return "pre_shutdown"
	default:
		return "unknown"
	}
}
