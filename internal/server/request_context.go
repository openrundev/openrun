// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/openrundev/openrun/internal/types"
)

// authContext carries the per-request identity and authorization values as a
// single context node. authenticateAndServeApp would otherwise chain nine
// context.WithValue calls, each allocating a heap valueCtx; this answers those
// keys directly from struct fields and defers everything else to the parent
// context, so the request path allocates one struct instead of nine nodes.
//
// The customPerms and rbacEnabled fields are filled in after construction (they
// depend on the other values being readable through the context first). That is
// safe because the context is not shared across goroutines until it is attached
// to the request with r.WithContext further down the same handler.
type authContext struct {
	context.Context
	userId      string
	userSubject string
	userEmail   string
	appId       string
	pathDomain  types.AppPathDomain
	appAuth     types.AppAuthnType
	groups      []string
	customPerms []string
	rbacEnabled bool
}

func (c *authContext) Value(key any) any {
	switch key {
	case types.USER_ID:
		return c.userId
	case types.USER_SUBJECT:
		return c.userSubject
	case types.USER_EMAIL:
		return c.userEmail
	case types.APP_ID:
		return c.appId
	case types.APP_PATH_DOMAIN:
		return c.pathDomain
	case types.APP_AUTH:
		return c.appAuth
	case types.GROUPS:
		return c.groups
	case types.CUSTOM_PERMS:
		return c.customPerms
	case types.RBAC_ENABLED:
		return c.rbacEnabled
	}
	return c.Context.Value(key)
}

// statusContext carries the request id, default user and shared audit state that
// the handleStatus middleware adds on every request, as one context node
// instead of three chained context.WithValue calls. The shared pointer stays
// mutable (app auth fills in the resolved user/app id on it), and the userId
// here is the default, later shadowed by authContext for app requests.
type statusContext struct {
	context.Context
	requestId string
	userId    string
	shared    *ContextShared
}

func (c *statusContext) Value(key any) any {
	switch key {
	case types.REQUEST_ID:
		return c.requestId
	case types.USER_ID:
		return c.userId
	case types.SHARED:
		return c.shared
	}
	return c.Context.Value(key)
}
