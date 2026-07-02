// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

var openrunHeaderPrefixLower = strings.ToLower(types.OPENRUN_HEADER_PREFIX)

func deleteOpenRunHeaders(header http.Header) {
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), openrunHeaderPrefixLower) {
			header.Del(key)
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
	appRBACEnabled := system.IsAppRBACEnabled(ctx)
	header.Set(types.OPENRUN_HEADER_APP_RBAC_ENABLED, strconv.FormatBool(appRBACEnabled))
}
