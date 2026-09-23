// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"slices"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// valuelessContext keeps a parent's cancellation and deadline but none of
// its values
type valuelessContext struct{ context.Context }

func (valuelessContext) Value(any) any { return nil }

// DetachedAuthContext builds the context a background run (a job run, an
// async action run) executes under: the lifetime of parent, and from caller
// only the authorization state (user, groups, RBAC marker, trusted flag, API
// invoker, credential scope ceiling and sync snapshot). Caller-owned audit
// state, app values, request objects and URL permission simulations do not
// reach the worker; a run must not turn a limited caller into admin, and
// must not retain the request it was submitted from
func DetachedAuthContext(parent, caller context.Context) context.Context {
	ctx := context.WithValue(valuelessContext{parent}, types.USER_ID, system.GetContextUserId(caller))
	ctx = context.WithValue(ctx, types.GROUPS, slices.Clone(system.GetContextGroups(caller)))
	if invoker := system.GetContextApiInvoker(caller); invoker != "" {
		// The surface policy (checkApiOpEnabled) follows the run: an MCP
		// caller cannot use a run to reach operations disabled for MCP
		ctx = system.WithApiInvoker(ctx, invoker)
	}
	if marker := caller.Value(types.RBAC_ENABLED); marker != nil {
		ctx = context.WithValue(ctx, types.RBAC_ENABLED, marker)
	}
	if system.IsTrustedOperation(caller) {
		ctx = system.WithTrustedOperation(ctx)
	}
	if scopes, present := system.GetContextApiScopes(caller); present {
		ctx = system.WithApiScopes(ctx, slices.Clone(scopes))
	}
	if syncId := system.GetContextValue(caller, types.SYNC_ID); syncId != "" {
		ctx = context.WithValue(ctx, types.SYNC_ID, syncId)
	}
	ctx = WithSyncAuthorizer(ctx, GetSyncAuthorizer(caller))
	// Keep credential attenuation too: runs must not mint longer-lived or
	// broader-resource keys than their caller. Only these constraints are
	// copied, and copied so later caller mutations do not reach the worker
	if cred := system.GetContextApiCredential(caller); cred != nil {
		attenuated := &types.Credential{Scopes: slices.Clone(cred.Scopes), Resources: slices.Clone(cred.Resources)}
		if cred.ExpiresAt != nil {
			expiry := *cred.ExpiresAt
			attenuated.ExpiresAt = &expiry
		}
		ctx = system.WithApiCredential(ctx, attenuated)
	}
	return ctx
}

// DetachedAppContext is DetachedAuthContext plus the app identity of the
// caller's app request context: the app id and path domain the plugin permit
// checks and the audit events read, the custom permissions the permit
// checks read, the federated subject and email plugins pass on, and the
// request id which ties the run's audit events to the submitting request.
// This is the context of an async action run, which executes the app's code
// as the submitting user, in the app it was submitted to
func DetachedAppContext(parent, caller context.Context) context.Context {
	ctx := DetachedAuthContext(parent, caller)
	for _, key := range []types.ContextKey{types.APP_ID, types.APP_PATH_DOMAIN, types.APP_AUTH,
		types.USER_SUBJECT, types.USER_EMAIL, types.REQUEST_ID} {
		if value := caller.Value(key); value != nil {
			ctx = context.WithValue(ctx, key, value)
		}
	}
	if perms := system.GetCustomPerms(caller); perms != nil {
		ctx = context.WithValue(ctx, types.CUSTOM_PERMS, slices.Clone(perms))
	}
	return ctx
}
