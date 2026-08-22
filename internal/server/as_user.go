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

// managementAPIContext carries the identity and frozen RBAC enforcement state
// for an attributed management API request. It is used by CLI --as calls over
// the unix socket and by authenticated admin-over-TCP calls. Answering USER_ID,
// GROUPS and RBAC_ENABLED from one context node mirrors authContext.
type managementAPIContext struct {
	context.Context
	userId      string
	groups      []string
	rbacEnabled bool
}

func (c *managementAPIContext) Value(key any) any {
	switch key {
	case types.USER_ID:
		return c.userId
	case types.GROUPS:
		return c.groups
	case types.RBAC_ENABLED:
		return c.rbacEnabled
	}
	return c.Context.Value(key)
}

// adminTCPRequestContext attributes an authenticated admin-over-TCP request
// instead of marking it trusted. Only the unix-socket CLI is outside management
// API RBAC enforcement. The built-in admin principal still passes authorization
// as the RBAC super-user, but every TCP operation now traverses the same checks
// as Starlark management calls and cannot become an unattributed bypass.
func (s *Server) adminTCPRequestContext(ctx context.Context) context.Context {
	return &managementAPIContext{
		Context:     ctx,
		userId:      types.ADMIN_USER,
		groups:      []string{},
		rbacEnabled: s.rbacManager.ConfigEnabled(),
	}
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

	return &managementAPIContext{Context: ctx, userId: asUser, groups: groups, rbacEnabled: true}, nil
}
