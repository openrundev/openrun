// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

// enableVirtualTerminal is a no-op on non-Windows platforms, the terminal
// handles ANSI escape sequences when the output is a tty
func enableVirtualTerminal() bool {
	return true
}
