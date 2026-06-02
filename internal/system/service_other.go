// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package system

func NotifyServiceReady() {}

func NotifyServiceStopping() {}

func NotifyServiceStopped() {}

func ServiceStopNotify() <-chan struct{} {
	return nil
}
