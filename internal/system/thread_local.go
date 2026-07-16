// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"

	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

func GetThreadLocalKey(thread *starlark.Thread, key string) string {
	value := thread.Local(key)
	if value == nil {
		return ""
	}

	valueStr, ok := value.(string)
	if !ok {
		return ""
	}
	return valueStr
}

func GetRequestUserId(thread *starlark.Thread) string {
	ctxVal := thread.Local(types.TL_CONTEXT)
	if ctxVal == nil {
		return ""
	}

	ctx, ok := ctxVal.(context.Context)
	if !ok {
		return ""
	}

	return GetContextUserId(ctx)
}

// GetRequestContext returns the request context stored on the Starlark
// thread. A missing thread context yields context.Background(), which carries
// no enforcement or trust marker: RBAC fails closed for it when enabled, so a
// propagation bug denies instead of silently running as a trusted internal call
func GetRequestContext(thread *starlark.Thread) context.Context {
	ctxVal := thread.Local(types.TL_CONTEXT)
	if ctxVal == nil {
		return context.Background()
	}

	ctx, ok := ctxVal.(context.Context)
	if !ok {
		return context.Background()
	}

	return ctx
}

func GetRequestGroups(thread *starlark.Thread) []string {
	ctxVal := thread.Local(types.TL_CONTEXT)
	if ctxVal == nil {
		return []string{}
	}

	ctx, ok := ctxVal.(context.Context)
	if !ok {
		return []string{}
	}

	return GetContextGroups(ctx)
}

// Context keys pre-boxed as any values. ctx.Value takes an interface, so
// passing a ContextKey variable boxes it and allocates on every lookup; these
// getters run several times per request, so the keys are boxed once here.
var (
	userIdKey        any = types.USER_ID
	userSubjectKey   any = types.USER_SUBJECT
	userEmailKey     any = types.USER_EMAIL
	requestIdKey     any = types.REQUEST_ID
	appIdKey         any = types.APP_ID
	groupsKey        any = types.GROUPS
	customPermsKey   any = types.CUSTOM_PERMS
	rbacEnabledKey   any = types.RBAC_ENABLED
	trustedOpKey     any = types.TRUSTED_OPERATION
	appPathDomainKey any = types.APP_PATH_DOMAIN
)

// GetContextAppPathDomain returns the path domain of the app serving the
// request, the zero value when not present
func GetContextAppPathDomain(ctx context.Context) types.AppPathDomain {
	value := ctx.Value(appPathDomainKey)
	if value == nil {
		return types.AppPathDomain{}
	}
	pathDomain, ok := value.(types.AppPathDomain)
	if !ok {
		return types.AppPathDomain{}
	}
	return pathDomain
}

func GetContextGroups(ctx context.Context) []string {
	value := ctx.Value(groupsKey)
	if value == nil {
		return []string{}
	}
	valueStr, ok := value.([]string)
	if !ok {
		return []string{}
	}
	return valueStr
}

func GetContextValue(ctx context.Context, key types.ContextKey) string {
	return getContextString(ctx, key)
}

func getContextString(ctx context.Context, key any) string {
	value := ctx.Value(key)
	if value == nil {
		return ""
	}
	valueStr, ok := value.(string)
	if !ok {
		return ""
	}
	return valueStr
}

func GetContextUserId(ctx context.Context) string {
	return getContextString(ctx, userIdKey)
}

func GetContextUserSubject(ctx context.Context) string {
	return getContextString(ctx, userSubjectKey)
}

func GetContextUserEmail(ctx context.Context) string {
	return getContextString(ctx, userEmailKey)
}

func GetContextRequestId(ctx context.Context) string {
	return getContextString(ctx, requestIdKey)
}

func GetContextAppId(ctx context.Context) types.AppId {
	return types.AppId(getContextString(ctx, appIdKey))
}

func GetCustomPerms(ctx context.Context) []string {
	customPerms := make([]string, 0)
	if customPermsCtx := ctx.Value(customPermsKey); customPermsCtx != nil {
		if customPermsSlice, ok := customPermsCtx.([]string); ok {
			customPerms = customPermsSlice
		}
	}
	return customPerms
}

func IsAppRBACEnabled(ctx context.Context) bool {
	appRBACEnabled := false
	if rbacEnabledCtx := ctx.Value(rbacEnabledKey); rbacEnabledCtx != nil {
		if rbacEnabledBool, ok := rbacEnabledCtx.(bool); ok {
			appRBACEnabled = rbacEnabledBool
		}
	}
	return appRBACEnabled
}

// AppRBACMarkerPresent reports whether the per-request RBAC enforcement bool
// is present in the context, regardless of its value. It is set for every app
// request during authentication, so presence identifies an attributed app
// request: enforcement state is computed once per request and stays stable for
// its lifetime (enabling RBAC mid-request applies from the next request on)
func AppRBACMarkerPresent(ctx context.Context) bool {
	return ctx.Value(rbacEnabledKey) != nil
}

// WithTrustedOperation marks the context as a trusted administrative path.
// Set ONLY where the caller's authority is established by other means: the
// admin/UDS management API after authentication, token authenticated
// webhooks, and internal background operations (newBackgroundOperationContext).
// RBAC enforcement fails closed for contexts with neither this nor an
// enforcement marker, so an unmarked context (a propagation bug, e.g. a
// missing Starlark thread context) is denied instead of running as admin
func WithTrustedOperation(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustedOpKey, true)
}

// IsTrustedOperation reports whether the context is a trusted administrative
// path, see WithTrustedOperation
func IsTrustedOperation(ctx context.Context) bool {
	value := ctx.Value(trustedOpKey)
	if value == nil {
		return false
	}
	trusted, ok := value.(bool)
	return ok && trusted
}
