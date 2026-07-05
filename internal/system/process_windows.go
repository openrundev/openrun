// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package system

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// SetProcessGroup sets the process group flag for the command
func SetProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// KillGroup kills the process and its descendants. Process.Kill only
// terminates the direct child on Windows, so use taskkill to kill the tree.
func KillGroup(process *os.Process) error {
	err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(process.Pid)).Run()
	if err != nil {
		return process.Kill()
	}
	return nil
}
