// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// asUserContext carries the identity for a management API call made with the
// CLI --as flag over the unix domain socket: the call runs as the given user
// with RBAC enforcement instead of as the trusted administrator. Answering
// USER_ID, GROUPS and RBAC_ENABLED from one context node mirrors authContext;
// RBAC_ENABLED is always true since the context is only built when RBAC is
// enabled (enforcement state is computed once per request, like app requests)
type asUserContext struct {
	context.Context
	userId string
	groups []string
}

func (c *asUserContext) Value(key any) any {
	switch key {
	case types.USER_ID:
		return c.userId
	case types.GROUPS:
		return c.groups
	case types.RBAC_ENABLED:
		return true
	}
	return c.Context.Value(key)
}

// asUserRequestContext builds the request context for a management API call
// made as another user (the CLI --as flag). asUser is <provider>:<username>,
// like builtin:user1. For builtin users the entry must exist and its groups
// feed RBAC group: matching; any other provider id is taken literally with no
// groups, so grants for SSO identities can be tested without creating them.
// Fails when RBAC is not enabled: without enforcement the call would silently
// run with full admin authority
func (s *Server) asUserRequestContext(ctx context.Context, asUser string) (context.Context, error) {
	if !s.rbacManager.ConfigEnabled() {
		return nil, types.CreateRequestError(
			fmt.Sprintf("as user %q: RBAC is not enabled, the --as option requires RBAC enforcement", asUser),
			http.StatusBadRequest)
	}

	provider, username, ok := strings.Cut(asUser, ":")
	if !ok || provider == "" || username == "" {
		return nil, types.CreateRequestError(
			fmt.Sprintf("invalid as user %q: the format is <provider>:<username>, like builtin:user1", asUser),
			http.StatusBadRequest)
	}

	groups := []string{}
	if provider == string(types.AppAuthnBuiltin) {
		entry, exists := s.Config().BuiltinAuth[username]
		if !exists {
			return nil, types.CreateRequestError(
				fmt.Sprintf("as user %q: builtin user %s is not configured", asUser, username),
				http.StatusBadRequest)
		}
		if entry.Groups != nil {
			groups = entry.Groups
		}
	}

	return &asUserContext{Context: ctx, userId: asUser, groups: groups}, nil
}
