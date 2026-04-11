// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestAdminBasicAuth_ShortHeader(t *testing.T) {
	t.Parallel()

	handler := NewAdminBasicAuth(testutil.TestLogger(), &types.ServerConfig{})
	user, pass, ok := handler.BasicAuth("Basic")

	testutil.AssertEqualsBool(t, "basic auth result", false, ok)
	testutil.AssertEqualsString(t, "username", "", user)
	testutil.AssertEqualsString(t, "password", "", pass)
}
