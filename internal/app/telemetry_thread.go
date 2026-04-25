// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"

	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// pushThreadContext stores ctx in the Starlark thread-local TL_CONTEXT slot
// and returns a function that restores the previous value. It centralizes the
// save/swap/restore dance used around plugin and handler spans so behavior
// stays consistent across call sites. The fallback is used when the previous
// value was unset (typically the originating http.Request context).
func pushThreadContext(thread *starlark.Thread, ctx context.Context, fallback context.Context) func() {
	prev := thread.Local(types.TL_CONTEXT)
	thread.SetLocal(types.TL_CONTEXT, ctx)
	return func() {
		switch {
		case prev != nil:
			thread.SetLocal(types.TL_CONTEXT, prev)
		case fallback != nil:
			thread.SetLocal(types.TL_CONTEXT, fallback)
		default:
			thread.SetLocal(types.TL_CONTEXT, nil)
		}
	}
}
