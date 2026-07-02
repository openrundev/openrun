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
	userIdKey      any = types.USER_ID
	userSubjectKey any = types.USER_SUBJECT
	userEmailKey   any = types.USER_EMAIL
	requestIdKey   any = types.REQUEST_ID
	appIdKey       any = types.APP_ID
	groupsKey      any = types.GROUPS
	customPermsKey any = types.CUSTOM_PERMS
	rbacEnabledKey any = types.RBAC_ENABLED
)

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
