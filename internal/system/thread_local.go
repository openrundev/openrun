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

func GetContextGroups(ctx context.Context) []string {
	value := ctx.Value(types.GROUPS)
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
	return GetContextValue(ctx, types.USER_ID)
}

func GetContextRequestId(ctx context.Context) string {
	return GetContextValue(ctx, types.REQUEST_ID)
}

func GetContextAppId(ctx context.Context) types.AppId {
	return types.AppId(GetContextValue(ctx, types.APP_ID))
}
