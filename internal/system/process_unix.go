// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package system

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// SetProcessGroup sets the process group flag for the command
func SetProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// KillGroup kills the process group
func KillGroup(process *os.Process) error {
	return syscall.Kill(-process.Pid, syscall.SIGKILL)
}

// ProcessExists reports whether a process with the given pid is running.
// EPERM means the process exists but is owned by another user
func ProcessExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
