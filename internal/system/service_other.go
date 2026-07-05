// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package system

// MaybeRunAsService is a no-op on platforms without OS service integration
func MaybeRunAsService() {}
