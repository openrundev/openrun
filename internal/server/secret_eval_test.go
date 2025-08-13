// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func evalFunc(input string) (string, error) {
	if len(input) < 4 {
		return input, nil
	}
	if !strings.Contains(input, "{{") || !strings.Contains(input, "}}") {
		return input, nil
	}

	return "aXXXmysecretXXXb", nil
}

func TestUpdateAuth(t *testing.T) {
	serverConfig := &types.ServerConfig{
		Auth: map[string]types.AuthConfig{
			"auth0": {
				Key:    "myclientID",
				Secret: `a{{ secret_from ("asm", "mysecret")}}b`,
			},
			"auth2": {
				Key:    "myclientID2",
				Secret: `{{ secret_from "env" "TEST"} }}`,
			},
		},
	}

	err := updateConfigSecrets(serverConfig, evalFunc)
	testutil.AssertEqualsError(t, "error", err, nil)
	testutil.AssertEqualsString(t, "clientID", "myclientID", serverConfig.Auth["auth0"].Key)
	testutil.AssertEqualsString(t, "secret", "aXXXmysecretXXXb", serverConfig.Auth["auth0"].Secret)
	testutil.AssertEqualsString(t, "clientID", "myclientID2", serverConfig.Auth["auth2"].Key)
	testutil.AssertEqualsString(t, "secret", "aXXXmysecretXXXb", serverConfig.Auth["auth2"].Secret)
}
