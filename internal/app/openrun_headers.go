// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func deleteOpenRunHeaders(header http.Header) {
	prefixLen := len(types.OPENRUN_HEADER_PREFIX)
	for key := range header {
		// Case-insensitive prefix check without allocating a lowercased copy
		// per header (strings.EqualFold allocates nothing). Keys ranged from
		// the map are already in canonical form, so delete directly rather than
		// header.Del, which would re-canonicalize.
		if len(key) >= prefixLen && strings.EqualFold(key[:prefixLen], types.OPENRUN_HEADER_PREFIX) {
			delete(header, key)
		}
	}
}

func setOpenRunHeaders(header http.Header, ctx context.Context) {
	customPerms := system.GetCustomPerms(ctx)
	header.Set(types.OPENRUN_HEADER_PERMS, strings.Join(customPerms, ","))
	header.Set(types.OPENRUN_HEADER_USER, system.GetContextUserId(ctx))
	if userSubject := system.GetContextUserSubject(ctx); userSubject != "" {
		header.Set(types.OPENRUN_HEADER_USER_ID, userSubject)
	}
	if userEmail := system.GetContextUserEmail(ctx); userEmail != "" {
		header.Set(types.OPENRUN_HEADER_USER_EMAIL, userEmail)
	}
	header.Set(types.OPENRUN_HEADER_APP_RBAC_ENABLED, strconv.FormatBool(rbac.AppRBACActive(ctx)))
}
