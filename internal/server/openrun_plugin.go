// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

func initOpenRunPlugin(server *Server) {
	app.RegisterLocalProvider("openrun", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"openrun": {
				Builder: func() sdk.Module { return &openrunPlugin{server: server} },
				Functions: []sdk.FuncDef{
					{Name: "list_apps", Type: sdk.READ, Method: "ListApps"},
					{Name: "list_all_apps", Type: sdk.READ, Method: "ListAllApps"},
					{Name: "list_audit_events", Type: sdk.READ, Method: "ListAuditEvents"},
					{Name: "analytics_summary", Type: sdk.READ, Method: "AnalyticsSummary"},
					{Name: "list_operations", Type: sdk.READ, Method: "ListOperations"},
					{Name: "list_sync", Type: sdk.READ, Method: "ListSync"},
					{Name: "list_bindings", Type: sdk.READ, Method: "ListBindings"},
					{Name: "replication_status", Type: sdk.READ, Method: "ReplicationStatus"},
					{Name: "get_app", Type: sdk.READ, Method: "GetApp"},
					{Name: "list_specs", Type: sdk.READ, Method: "ListSpecs"},
					{Name: "list_versions", Type: sdk.READ, Method: "ListVersions"},
					{Name: "list_version_files", Type: sdk.READ, Method: "ListVersionFiles"},
					{Name: "get_version_zip", Type: sdk.READ, Method: "GetVersionZip"},
					{Name: "get_version_file", Type: sdk.READ, Method: "GetVersionFile"},
					{Name: "export_app", Type: sdk.READ, Method: "ExportApp"},
					{Name: "export_app_diff", Type: sdk.READ, Method: "ExportAppDiff"},
					{Name: "audit_app", Type: sdk.READ, Method: "AuditApp"},
					{Name: "list_services", Type: sdk.READ, Method: "ListServices"},
					{Name: "service_health", Type: sdk.READ, Method: "ServiceHealth"},
					{Name: "binding_health", Type: sdk.READ, Method: "BindingHealth"},
					{Name: "get_rbac_config", Type: sdk.READ, Method: "GetRBACConfig"},
					{Name: "get_config_entries", Type: sdk.READ, Method: "GetConfigEntries"},
					{Name: "get_config_values", Type: sdk.READ, Method: "GetConfigValues"},
					{Name: "list_config_history", Type: sdk.READ, Method: "ListConfigHistory"},
					{Name: "get_config_version", Type: sdk.READ, Method: "GetConfigVersion"},
					{Name: "list_containers", Type: sdk.READ, Method: "ListContainers"},
					{Name: "get_container", Type: sdk.READ, Method: "GetContainer"},
					{Name: "kubernetes_stats", Type: sdk.READ, Method: "KubernetesStats"},
					{Name: "container_kubernetes_status", Type: sdk.READ, Method: "ContainerKubernetesStatus"},
					{Name: "container_logs", Type: sdk.READ, Method: "GetContainerLogs"},
					{Name: "container_logs_stream", Type: sdk.READ, Method: "GetContainerLogsStream"},
					{Name: "get_permissions", Type: sdk.READ, Method: "GetPermissions"},
					{Name: "system_plugins_allowed", Type: sdk.READ, Method: "SystemPluginsAllowed"},
					{Name: "server_info", Type: sdk.READ, Method: "ServerInfo"},
					{Name: "list_rbac_permissions", Type: sdk.READ, Method: "ListRBACPermissions"},
					{Name: "list_auths", Type: sdk.READ, Method: "ListAuths"},
					{Name: "list_git_auths", Type: sdk.READ, Method: "ListGitAuths"},
				},
			},
		},
	}, app.LocalProviderOptions{})
}

type openrunPlugin struct {
	server *Server
}

func (c *openrunPlugin) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (c *openrunPlugin) Close(ctx context.Context) error {
	return nil
}

func (c *openrunPlugin) ListAllApps(ctx context.Context, call *sdk.Call) (any, error) {
	return c.listAppsImpl(ctx, call, false, "list_all_apps")
}

func (c *openrunPlugin) ListApps(ctx context.Context, call *sdk.Call) (any, error) {
	return c.listAppsImpl(ctx, call, true, "list_apps")
}

func (c *openrunPlugin) listAppsImpl(ctx context.Context, call *sdk.Call, permCheck bool, apiName string) (any, error) {
	var query, path, syncId string
	var includeInternal, checkApproval bool
	if err := sdk.UnpackArgs(apiName, call, "query?", &query, "path?", &path,
		"include_internal?", &includeInternal, "sync_id?", &syncId,
		"check_approval?", &checkApproval); err != nil {
		return nil, err
	}

	apps, err := c.server.apps.GetAllAppsInfo()
	if err != nil {
		return nil, err
	}

	appMap := map[types.AppId]types.AppInfo{}
	for _, app := range apps {
		appMap[app.Id] = app
	}
	versionMismatchMap := map[types.AppId]bool{}
	for _, app := range apps {
		if app.MainApp != "" {
			mainApp, ok := appMap[types.AppId(app.MainApp)]
			if !ok || !strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE) {
				continue
			}

			if mainApp.Version != app.Version {
				versionMismatchMap[app.Id] = true
				versionMismatchMap[mainApp.Id] = true
			}
		}
	}

	// sync_id filters to the apps last applied by that sync entry. The
	// staging app carries the most recent sync state (prod picks it up on
	// promote); a match on either selects the main app and its linked apps
	syncIdStr := strings.TrimSpace(syncId)
	var syncApps map[types.AppId]bool
	if syncIdStr != "" {
		syncApps = map[types.AppId]bool{}
		for _, app := range apps {
			if app.AppliedSyncId != syncIdStr {
				continue
			}
			if app.MainApp == "" {
				syncApps[app.Id] = true
			} else if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE) {
				syncApps[app.MainApp] = true
			}
		}
	}

	// The user of each app's active version, for update attribution
	var versionUsers map[types.AppId]map[int]string
	if c.server.db != nil {
		if versionUsers, err = c.server.db.GetVersionUsers(); err != nil {
			return nil, err
		}
	}

	userId := call.Thread.UserId
	groups := call.Thread.Groups

	// check_approval audits each listed app for unapproved plugin loads and
	// permissions. For prod apps the staging app is audited, since approvals
	// apply to staging first. Results are cached, see appNeedsApproval
	var stageByMain map[types.AppId]types.AppInfo
	var approvalTx types.Transaction
	if checkApproval {
		stageByMain = map[types.AppId]types.AppInfo{}
		for _, app := range apps {
			if app.MainApp != "" && strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE) {
				stageByMain[app.MainApp] = app
			}
		}
		approvalTx, err = c.server.db.BeginTransaction(ctx)
		if err != nil {
			return nil, err
		}
		defer approvalTx.Rollback() //nolint:errcheck
	}

	if c.server.rbacManager.APIEnforced(ctx) {
		// Under RBAC enforcement, list_all_apps also filters by app:read; otherwise
		// it would be a filtering bypass
		permCheck = true
	}
	ret := []any{}
	for _, app := range apps {
		// Filter out internal apps
		if app.MainApp != "" && !includeInternal {
			continue
		}

		if syncApps != nil {
			mainId := app.Id
			if app.MainApp != "" {
				mainId = app.MainApp
			}
			if !syncApps[mainId] {
				continue
			}
		}

		// For stage/preview apps, glob matching is done against the main app path
		mainPathDomain := mainAppPathDomain(app.AppPathDomain, app.MainApp, app.LinkedAppPath)

		// Check query filter
		if query != "" {
			queryStr := strings.ToLower(query)
			if !strings.Contains(strings.ToLower(app.Name), queryStr) &&
				!strings.Contains(strings.ToLower(app.String()), queryStr) &&
				!strings.Contains(strings.ToLower(app.SourceUrl), queryStr) &&
				!strings.Contains(strings.ToLower(app.UserID), queryStr) {
				continue
			}
		}

		if path != "" {
			// If path glob is specified, check if the app (or its main app) matches
			match, err := rbac.MatchGlob(path, mainPathDomain)
			if err != nil {
				return nil, err
			}
			if !match {
				continue
			}
		}

		if permCheck {
			hasAccess, err := c.server.AuthorizeList(ctx, userId, &app, groups)
			if err != nil {
				return nil, err
			}
			if !hasAccess {
				continue
			}
		}

		v := map[string]any{}
		v["name"] = app.Name
		v["url"] = types.GetAppUrl(app.AppPathDomain, c.server.Config())
		v["path"] = app.String()
		pathSplit := []string{}
		pathSplitGlob := []string{}
		if app.Domain != "" {
			pathSplit = append(pathSplit, app.Domain)
		}
		for _, path := range strings.Split(app.Path, "/") {
			if path != "" {
				pathSplit = append(pathSplit, "/"+path)
			}
		}

		globDomain := mainPathDomain.Domain
		globPath := mainPathDomain.Path
		globDomainPrefix := ""
		if globDomain != "" {
			pathSplitGlob = append(pathSplitGlob, globDomain+":**")
			globDomainPrefix = globDomain + ":"
		}
		appPath := ""
		splitPath := strings.Split(globPath, "/")
		for i, path := range splitPath {
			if path != "" {
				appPath += "/" + path
				if i == len(splitPath)-1 {
					// Last path, no glob
					pathSplitGlob = append(pathSplitGlob, globDomainPrefix+appPath)
				} else {
					pathSplitGlob = append(pathSplitGlob, globDomainPrefix+appPath+"/**")
				}
			}
		}
		// Stage/preview apps can display internal path breadcrumbs like
		// /_cl_stage while filtering still targets the linked main app path.
		if len(pathSplitGlob) < len(pathSplit) {
			filterPath := mainPathDomain.String()
			if filterPath == "" {
				filterPath = "/"
			}
			for len(pathSplitGlob) < len(pathSplit) {
				pathSplitGlob = append(pathSplitGlob, filterPath)
			}
		}
		v["path_split"] = pathSplit
		v["path_split_glob"] = pathSplitGlob
		v["id"] = string(app.Id)
		v["is_dev"] = app.IsDev
		v["is_stage"] = strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE)
		v["main_app"] = string(app.MainApp)
		v["created_by"] = app.UserID
		if app.Auth == types.AppAuthnDefault {
			v["auth"] = c.server.Config().Security.AppDefaultAuthType
			v["auth_uses_default"] = true
		} else {
			v["auth"] = string(app.Auth)
			v["auth_uses_default"] = false
		}
		v["source"] = app.SourceUrl
		v["source_url"] = getSourceUrl(app.SourceUrl, app.Branch)
		v["applied_sync_id"] = app.AppliedSyncId
		v["star_base"] = app.StarBase
		v["spec"] = string(app.Spec)
		v["version"] = app.Version
		v["version_mismatch"] = versionMismatchMap[app.Id]
		if checkApproval {
			needsApproval := false
			target := app
			haveTarget := true
			if app.MainApp != "" {
				// Linked apps: only the staging app is audited; previews are skipped
				haveTarget = strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE)
			} else if !app.IsDev {
				// Prod app: approvals apply to its staging app
				target, haveTarget = stageByMain[app.Id]
			}
			if haveTarget {
				var approvalErr error
				needsApproval, approvalErr = c.server.appNeedsApproval(ctx, approvalTx, target)
				if approvalErr != nil {
					// One unauditable app (broken source) must not fail the listing
					c.server.Warn().Err(approvalErr).Msgf("approval check failed for %s", target.AppPathDomain)
					needsApproval = false
				}
			}
			v["needs_approval"] = needsApproval
		}
		v["git_sha"] = app.GitSha
		v["git_message"] = app.GitMessage
		v["git_branch"] = app.Branch
		v["update_age"] = system.HumanDuration(time.Since(app.UpdateTime), 0)
		v["update_time"] = app.UpdateTime.UTC()
		// Who performed the last update: the active version's creator, with
		// the app creator as the fallback (dev apps have no versions)
		updateUser := versionUsers[app.Id][app.Version]
		if updateUser == "" {
			updateUser = app.UserID
		}
		v["update_user"] = updateUser

		ret = append(ret, v)
	}

	return ret, nil
}

func getSourceUrl(sourceUrl, branch string) string {
	if branch == "" {
		return ""
	}
	if !system.IsGit(sourceUrl) || strings.HasPrefix(sourceUrl, "git@") {
		return ""
	}
	repo, folder, err := parseGitUrl(sourceUrl, false)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%s/tree/%s/%s", repo, branch, folder)
}

func (c *openrunPlugin) ListAuditEvents(ctx context.Context, call *sdk.Call) (any, error) {
	var appGlob, userId, eventType, operation, target, status, rid, detail string
	var startDate, endDate, beforeTimestamp string
	limit := int64(50)
	if err := sdk.UnpackArgs("list_audit_events", call, "app_glob?", &appGlob, "user_id?", &userId, "event_type?",
		&eventType, "operation?", &operation, "target?", &target, "status?", &status, "start_date?", &startDate, "end_date?", &endDate,
		"rid?", &rid, "detail?", &detail, "limit?", &limit, "before_timestamp?", &beforeTimestamp); err != nil {
		return nil, err
	}

	// audit:read grants access to the audit log across all apps
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionAuditRead, ""); err != nil {
		return nil, err
	}

	var query strings.Builder
	query.WriteString("select rid, app_id, create_time, user_id, event_type, operation, target, status, detail from audit ")

	filterConditions := []string{}
	appGlobStr := strings.TrimSpace(appGlob)
	if appGlobStr != "" {
		appInfo, err := c.server.ParseGlob(appGlobStr)
		if err != nil {
			return nil, err
		}
		appIds := []string{}
		for _, app := range appInfo {
			appIds = append(appIds, "'"+string(app.Id)+"'")
		}

		filterConditions = append(filterConditions, fmt.Sprintf("app_id in (%s)", strings.Join(appIds, ",")))
	}

	queryParams := []any{}
	userIdStr := strings.TrimSpace(userId)
	if userIdStr != "" {
		filterConditions = append(filterConditions, "user_id = ?")
		queryParams = append(queryParams, userIdStr)
	}

	eventTypeStr := strings.TrimSpace(eventType)
	if eventTypeStr != "" {
		filterConditions = append(filterConditions, "event_type = ?")
		queryParams = append(queryParams, eventTypeStr)
	}

	operationStr := strings.TrimSpace(operation)
	if operationStr != "" {
		opList, opQuery := getOpList(operationStr)
		filterConditions = append(filterConditions, "operation in ("+opQuery+")")
		queryParams = append(queryParams, opList...)
	}

	targetStr := strings.TrimSpace(target)
	if targetStr != "" {
		filterConditions = append(filterConditions, "target = ?")
		queryParams = append(queryParams, targetStr)
	}

	statusStr := strings.TrimSpace(status)
	if statusStr != "" {
		filterConditions = append(filterConditions, "status = ?")
		queryParams = append(queryParams, statusStr)
	}

	startDateStr := strings.TrimSpace(startDate)
	if startDateStr != "" {
		if c.server.auditDbType == system.DB_TYPE_SQLITE {
			filterConditions = append(filterConditions, `create_time >= strftime('%s', ?) * 1000000000`)
		} else {
			// Postgres
			filterConditions = append(filterConditions, `create_time >= EXTRACT(EPOCH FROM  ?::timestamp)::bigint * 1000000000`)
		}
		queryParams = append(queryParams, startDateStr)
	}

	endDateStr := strings.TrimSpace(endDate)
	if endDateStr != "" {
		if c.server.auditDbType == system.DB_TYPE_SQLITE {
			filterConditions = append(filterConditions, `create_time <= (strftime('%s', ?) + 86400) * 1000000000`)
		} else {
			// Postgres
			filterConditions = append(filterConditions, `create_time <= (EXTRACT(EPOCH FROM  ?::timestamp)::bigint + 86400) * 1000000000`)
		}
		queryParams = append(queryParams, endDateStr)
	}

	ridStr := strings.TrimSpace(rid)
	if ridStr != "" {
		filterConditions = append(filterConditions, "rid = ?")
		queryParams = append(queryParams, ridStr)
	}

	detailStr := strings.TrimSpace(detail)
	if detailStr != "" {
		filterConditions = append(filterConditions, "detail like ?")
		queryParams = append(queryParams, detailStr)
	}

	beforeTimestampStr := strings.TrimSpace(beforeTimestamp)
	if beforeTimestampStr != "" {
		filterConditions = append(filterConditions, " create_time < ?")
		bt, err := strconv.ParseInt(beforeTimestampStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("before_timestamp has to be a valid in value in milliseconds")
		}
		queryParams = append(queryParams, bt)
	}

	if len(filterConditions) > 0 {
		query.WriteString(" where ")
		query.WriteString(strings.Join(filterConditions, " and "))
	}

	query.WriteString(" order by create_time desc")

	if limit <= 0 || limit > 10_000 {
		return nil, fmt.Errorf("limit has to be between 1 and 10000")
	}
	query.WriteString(" limit ?")
	queryParams = append(queryParams, limit)

	// Ensure previously queued audit events are visible to the query
	c.server.FlushAuditEvents()
	rows, err := c.server.auditDB.Query(system.RebindQuery(c.server.auditDbType, query.String()), queryParams...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	apps, err := c.server.apps.GetAllAppsInfo()
	if err != nil {
		return nil, err
	}
	appIdMap := map[types.AppId]types.AppInfo{}
	for _, app := range apps {
		appIdMap[app.Id] = app
	}

	ret := []any{}
	for rows.Next() {
		var rid, appId, userId, eventType, operation, target, status, detail string
		var createTime int64
		err := rows.Scan(&rid, &appId, &createTime, &userId, &eventType, &operation, &target, &status, &detail)
		if err != nil {
			return nil, err
		}

		utcTime := time.Unix(0, createTime).UTC()

		v := map[string]any{}
		v["rid"] = rid
		v["app_id"] = appId
		appEnv := ""
		switch {
		case strings.HasPrefix(appId, types.ID_PREFIX_APP_PROD):
			appEnv = "prod"
		case strings.HasPrefix(appId, types.ID_PREFIX_APP_STAGE):
			appEnv = "stage"
		case strings.HasPrefix(appId, types.ID_PREFIX_APP_PREVIEW):
			appEnv = "preview"
		case strings.HasPrefix(appId, types.ID_PREFIX_APP_DEV):
			appEnv = "dev"
		}
		if appInfo, ok := appIdMap[types.AppId(appId)]; ok {
			// Staging events resolve to the main app, so links go to the
			// prod app's detail page
			if appEnv == "stage" && appInfo.MainApp != "" {
				if mainInfo, ok := appIdMap[appInfo.MainApp]; ok {
					appInfo = mainInfo
				}
			}
			v["app_name"] = appInfo.Name
			v["app_path"] = appInfo.String()
		} else {
			v["app_name"] = appId
			v["app_path"] = ""
		}
		v["app_env"] = appEnv
		v["create_time_epoch"] = strconv.FormatInt(createTime, 10)
		v["create_time"] = utcTime
		v["user_id"] = userId
		v["event_type"] = eventType
		v["operation"] = operation
		v["target"] = target
		v["status"] = status
		v["detail"] = detail

		ret = append(ret, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return ret, nil
}

func (c *openrunPlugin) ListOperations(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_operations", call); err != nil {
		return nil, err
	}

	// The distinct operation list is read from the audit log, gated by audit:read
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionAuditRead, ""); err != nil {
		return nil, err
	}

	// Ensure previously queued audit events are visible to the query
	c.server.FlushAuditEvents()
	rows, err := c.server.auditDB.Query("select distinct operation from audit where event_type = 'custom'")
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	ret := []string{}
	for rows.Next() {
		var operation string
		err := rows.Scan(&operation)
		if err != nil {
			return nil, err
		}

		ret = append(ret, operation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	ret = append(ret, "reload_apps")
	ret = append(ret, "list_apps")
	ret = append(ret, "get_app")
	ret = append(ret, "create_app")
	ret = append(ret, "create_preview")
	ret = append(ret, "delete_apps")
	ret = append(ret, "approve_apps")
	ret = append(ret, "promote_apps")
	ret = append(ret, "update_settings")
	ret = append(ret, "update_metadata")
	ret = append(ret, "update_links")
	ret = append(ret, "update_params")
	ret = append(ret, "list_versions")
	ret = append(ret, "list_files")
	ret = append(ret, "version_switch")
	ret = append(ret, "list_webhooks")
	ret = append(ret, "token_create")
	ret = append(ret, "token_delete")
	ret = append(ret, "stop_server")
	ret = append(ret, "POST")
	ret = append(ret, "PUT")
	ret = append(ret, "DELETE")
	ret = append(ret, "PATCH")
	ret = append(ret, "suggest")
	ret = append(ret, "validate")
	ret = append(ret, "execute")

	return ret, nil
}

func getOpList(op string) ([]any, string) {
	opList := []any{op}
	switch op {
	case "reload_apps":
		opList = []any{"reload_apps", "reload_apps_promote_approve", "reload_apps_approve", "reload_apps_promote"}
	case "approve_apps":
		opList = []any{"approve_apps", "approve_apps_promote", "reload_apps_promote_approve", "reload_apps_approve"}
	case "promote_apps":
		opList = []any{"promote_apps", "reload_apps_promote_approve", "reload_apps_promote", "approve_apps_promote", "param_update_promote"}
	case "update_metadata":
		opList = []any{"update_metadata", "update_metadata_promote"}
	case "param_update":
		opList = []any{"param_update", "param_update_promote"}
		// Some infrequent operations like account link are not included in the list for now
	}

	queryParams := []string{}
	for range opList {
		queryParams = append(queryParams, "?")
	}
	return opList, strings.Join(queryParams, ",")
}

func (c *openrunPlugin) ListSync(ctx context.Context, call *sdk.Call) (any, error) {
	sync, err := c.server.ListSyncEntries(ctx)
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, entry := range sync.Entries {
		entryMap, err := structValue(entry)
		if err != nil {
			return nil, err
		}
		ret = append(ret, entryMap)
	}

	return ret, nil
}

// GetApp returns the app entry for an exact app path, with the fields needed
// for displaying/updating the app. Settings (webhook tokens) are not included.
func (c *openrunPlugin) GetApp(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	var includeInternal bool
	if err := sdk.UnpackArgs("get_app", call, "path", &path, "include_internal?", &includeInternal); err != nil {
		return nil, err
	}

	var entry types.AppResponse
	if includeInternal {
		// Internal (staging/preview) app paths need the exact-path lookup
		found, err := c.server.GetInternalApp(ctx, path)
		if err != nil {
			return nil, err
		}
		entry = *found
	} else {
		apps, err := c.server.GetApps(ctx, path, false)
		if err != nil {
			return nil, err
		}
		if len(apps) != 1 {
			return nil, fmt.Errorf("app %s not found", path)
		}
		entry = apps[0]
	}
	params := map[string]any{}
	for k, val := range entry.Metadata.ParamValues {
		params[k] = val
	}
	bindings := []string{}
	bindings = append(bindings, entry.Metadata.Bindings...)

	v := map[string]any{}
	v["path"] = entry.AppPathDomain().String()
	v["name"] = entry.Metadata.Name
	v["id"] = string(entry.Id)
	v["url"] = types.GetAppUrl(entry.AppPathDomain(), c.server.Config())
	v["source_url"] = entry.SourceUrl
	// Browsable web url for git sources (empty otherwise), same as the
	// source_url field in the list_apps response
	v["browse_url"] = getSourceUrl(entry.SourceUrl, entry.Metadata.VersionMetadata.GitBranch)
	v["is_dev"] = entry.IsDev
	v["auth"] = string(entry.Metadata.AuthnType)
	v["spec"] = string(entry.Metadata.Spec)
	v["git_branch"] = entry.Metadata.VersionMetadata.GitBranch
	v["git_commit"] = entry.Metadata.VersionMetadata.GitCommit
	v["git_message"] = entry.Metadata.VersionMetadata.GitMessage
	v["git_auth"] = entry.Metadata.GitAuthName
	v["version"] = entry.Metadata.VersionMetadata.Version
	v["applied_sync_id"] = entry.Metadata.AppliedSyncId
	v["builder_published"] = c.server.isBuilderManaged(&entry.AppEntry)
	v["params"] = params
	v["bindings"] = bindings
	v["staged_changes"] = entry.StagedChanges
	if entry.UpdateTime != nil {
		v["update_time"] = *entry.UpdateTime
	} else {
		v["update_time"] = ""
	}

	stagePath := ""
	stageUrl := ""
	if !entry.IsDev {
		// The path of the linked staging app, for version/file lookups, and
		// its serving url (staging apps are served like any other app)
		stagePathDomain, err := parseLinkedAppPathDomain(entry.LinkedAppPath)
		if err != nil {
			stagePathDomain = pathBasedStageApp(&entry.AppEntry)
		}
		stagePath = stagePathDomain.String()
		stageUrl = types.GetAppUrl(stagePathDomain, c.server.Config())
	}
	v["stage_path"] = stagePath
	v["stage_url"] = stageUrl
	return v, nil
}

// ListVersions returns the versions for the app at the given path. Use the
// _cl_stage path suffix for the staging app's versions
func (c *openrunPlugin) ListVersions(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	if err := sdk.UnpackArgs("list_versions", call, "path", &path); err != nil {
		return nil, err
	}

	result, err := c.server.VersionList(ctx, path)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// ListVersionFiles returns the files in a version of the app at the given
// path. version defaults to the active version
func (c *openrunPlugin) ListVersionFiles(ctx context.Context, call *sdk.Call) (any, error) {
	var path, version string
	if err := sdk.UnpackArgs("list_version_files", call, "path", &path, "version?", &version); err != nil {
		return nil, err
	}

	result, err := c.server.VersionFiles(ctx, path, version)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// ExportApp returns the declarative config for one app as a formatted app()
// call. env selects prod (default) or stage; version a specific version of
// that environment (empty = active). Param values are masked without
// app:update on the app
func (c *openrunPlugin) ExportApp(ctx context.Context, call *sdk.Call) (any, error) {
	var path, env, version string
	if err := sdk.UnpackArgs("export_app", call, "path", &path, "env?", &env, "version?", &version); err != nil {
		return nil, err
	}

	exported, err := c.server.ExportAppVersion(ctx, path, env, version)
	if err != nil {
		return nil, err
	}
	return exported, nil
}

// ExportAppDiff compares two versions of an app as their export outputs,
// aligned line by line. from/to are "env:version" specs ("prod:14",
// "stage:" = staging active)
func (c *openrunPlugin) ExportAppDiff(ctx context.Context, call *sdk.Call) (any, error) {
	var path, from, to string
	if err := sdk.UnpackArgs("export_app_diff", call, "path", &path, "from", &from, "to", &to); err != nil {
		return nil, err
	}

	diff, err := c.server.ExportAppDiff(ctx, path, from, to)
	if err != nil {
		return nil, err
	}
	return structValue(diff)
}

// GetVersionFile returns one file's content from an app version, for the
// version files viewer. Use the stage path for staging versions. Binary and
// over-1MB files error with a message pointing at the zip download
func (c *openrunPlugin) GetVersionFile(ctx context.Context, call *sdk.Call) (any, error) {
	var path, version, name string
	if err := sdk.UnpackArgs("get_version_file", call, "path", &path, "version?", &version, "name?", &name); err != nil {
		return nil, err
	}

	content, err := c.server.VersionFileContent(ctx, path, version, name)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// GetVersionZip returns a download value whose content is a lazily produced
// zip of one app version's files. The zip is built at response-write time by
// the download handler, streaming to the client (chunked) with backpressure,
// so the archive is never fully held in memory or staged to disk. Use the
// stage path for staging versions
func (c *openrunPlugin) GetVersionZip(ctx context.Context, call *sdk.Call) (any, error) {
	var path, version string
	if err := sdk.UnpackArgs("get_version_zip", call, "path", &path, "version?", &version); err != nil {
		return nil, err
	}

	producer, fileName, err := c.server.VersionFilesZip(ctx, path, version)
	if err != nil {
		return nil, err
	}
	return zipDownloadValue(&sdk.Download{Name: fileName, Producer: producer}), nil
}

// ListSpecs returns the available app spec names
func (c *openrunPlugin) ListSpecs(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_specs", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	names := make(map[string]bool)
	for name := range appTypes {
		names[name] = true
	}
	customSpecsDir := path.Clean(path.Join(os.ExpandEnv("$OPENRUN_HOME/config"), APPSPECS))
	if entries, err := os.ReadDir(customSpecsDir); err == nil {
		for _, entry := range entries {
			// The appspec checkout may live directly in this directory. Its
			// repository metadata is not an appspec and must not be offered to
			// callers of list_specs.
			if entry.IsDir() && entry.Name() != ".git" {
				names[entry.Name()] = true
			}
		}
	}

	sorted := slices.Collect(maps.Keys(names))
	slices.Sort(sorted)
	return sorted, nil
}

// approvalCacheEntry is one cached needs-approval audit result, see the
// approvalCache field on Server for the validity rules
type approvalCacheEntry struct {
	version       int
	gen           int64
	needsApproval bool
}

// appNeedsApproval reports whether the app's current source requests plugin
// loads or permissions that are not approved yet. Results for non-dev apps
// are cached per (app version, binding generation): every approval-affecting
// app change (reload, approve, update-metadata, version switch) bumps the
// app version, and binding edits bump the generation. Dev apps serve from
// local disk which can change without a server operation, so they are
// audited on every call
func (s *Server) appNeedsApproval(ctx context.Context, tx types.Transaction, appInfo types.AppInfo) (bool, error) {
	gen := s.approvalCacheGen.Load()
	if !appInfo.IsDev {
		if cached, ok := s.approvalCache.Load(appInfo.Id); ok {
			entry := cached.(approvalCacheEntry)
			if entry.version == appInfo.Version && entry.gen == gen {
				return entry.needsApproval, nil
			}
		}
	}

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appInfo.AppPathDomain)
	if err != nil {
		return false, err
	}
	auditApp, err := s.setupApp(ctx, appEntry, tx)
	if err != nil {
		return false, err
	}
	result, err := auditApp.Audit()
	if err != nil {
		return false, err
	}
	if !appInfo.IsDev {
		s.approvalCache.Store(appInfo.Id, approvalCacheEntry{
			version:       appEntry.Metadata.VersionMetadata.Version,
			gen:           gen,
			needsApproval: result.NeedsApproval,
		})
	}
	return result.NeedsApproval, nil
}

// AuditApp audits the app's code and returns the requested plugin loads and
// permissions with the approval status. For prod apps the staging app is
// audited, since approvals apply to staging first. Nothing is persisted
func (c *openrunPlugin) AuditApp(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	if err := sdk.UnpackArgs("audit_app", call, "path", &path); err != nil {
		return nil, err
	}

	appPathDomain, err := parseAppPath(path)
	if err != nil {
		return nil, err
	}

	tx, err := c.server.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := c.server.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}
	if err := c.server.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return nil, err
	}
	if !appEntry.IsDev {
		appEntry, err = c.server.getStageApp(ctx, tx, appEntry)
		if err != nil {
			return nil, err
		}
	}

	auditApp, err := c.server.setupApp(ctx, appEntry, tx)
	if err != nil {
		return nil, err
	}
	result, err := auditApp.Audit()
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// ListServices lists the service entries. Config values are redacted, only
// the config keys are returned
func (c *openrunPlugin) ListServices(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_services", call); err != nil {
		return nil, err
	}

	services, err := c.server.ListServices(ctx, "", "")
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, service := range services {
		configKeys := make([]string, 0, len(service.Config))
		for key := range service.Config {
			configKeys = append(configKeys, key)
		}
		sort.Strings(configKeys)

		entry, err := structValue(map[string]any{
			"id":           service.Id,
			"name":         service.Name,
			"service_type": service.ServiceType,
			"is_default":   service.IsDefault,
			"staging":      service.Staging,
			"config_keys":  configKeys,
			"create_time":  service.CreateTime,
			"update_time":  service.UpdateTime,
		})
		if err != nil {
			return nil, err
		}
		ret = append(ret, entry)
	}
	return ret, nil
}

// ServiceHealth checks the health of every service the caller can read (one
// aggregate call, checks run concurrently server-side with a short result
// cache) and reports per-service status
func (c *openrunPlugin) ServiceHealth(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("service_health", call); err != nil {
		return nil, err
	}

	results, err := c.server.ServicesHealth(ctx)
	if err != nil {
		return nil, err
	}

	unhealthy := 0
	entries := make([]map[string]any, 0, len(results))
	for _, result := range results {
		if !result.Healthy {
			unhealthy++
		}
		entries = append(entries, map[string]any{
			"id":      result.Id,
			"healthy": result.Healthy,
			"error":   result.Error,
		})
	}
	return structValue(map[string]any{
		"total":     len(results),
		"unhealthy": unhealthy,
		"results":   entries,
	})
}

// BindingHealth checks the health of every binding the caller can read,
// filtered by kind ("base", "derived", "auto" or "" for all), and reports
// per-binding status for both the prod and the staging account. A binding
// counts as unhealthy when either account fails its check.
func (c *openrunPlugin) BindingHealth(ctx context.Context, call *sdk.Call) (any, error) {
	var kind string
	if err := sdk.UnpackArgs("binding_health", call, "kind?", &kind); err != nil {
		return nil, err
	}

	results, err := c.server.BindingsHealth(ctx, kind)
	if err != nil {
		return nil, err
	}

	unhealthy := 0
	entries := make([]map[string]any, 0, len(results))
	for _, result := range results {
		if !result.Healthy || !result.StagingHealthy {
			unhealthy++
		}
		entries = append(entries, map[string]any{
			"path":            result.Path,
			"healthy":         result.Healthy,
			"error":           result.Error,
			"staging_healthy": result.StagingHealthy,
			"staging_error":   result.StagingError,
		})
	}
	return structValue(map[string]any{
		"total":     len(results),
		"unhealthy": unhealthy,
		"results":   entries,
	})
}

// ListContainers lists the containers (or Kubernetes pods) managed by OpenRun
func (c *openrunPlugin) ListContainers(ctx context.Context, call *sdk.Call) (any, error) {
	var ctype string
	if err := sdk.UnpackArgs("list_containers", call, "type?", &ctype); err != nil {
		return nil, err
	}

	var containers []ContainerInfo
	var err error
	switch ctype {
	case "":
		containers, err = c.server.ListManagedContainers(ctx)
	case "agent":
		containers, err = c.server.ListAgentContainers(ctx)
	case "kaniko":
		containers, err = c.server.ListKanikoBuildContainers(ctx)
	default:
		return nil, fmt.Errorf("invalid list_containers type %q, expected agent or kaniko", ctype)
	}
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, info := range containers {
		entry, err := structValue(info)
		if err != nil {
			return nil, err
		}
		ret = append(ret, entry)
	}
	return ret, nil
}

// GetContainer returns the details of one OpenRun managed container,
// including mounts, disk usage and live resource stats
func (c *openrunPlugin) GetContainer(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	stats := true
	if err := sdk.UnpackArgs("get_container", call, "id", &id, "stats?", &stats); err != nil {
		return nil, err
	}

	detail, err := c.server.GetManagedContainer(ctx, id, stats)
	if err != nil {
		return nil, err
	}
	return structValue(detail)
}

// KubernetesStats returns pod stats for the OpenRun kubernetes namespaces
// (system and apps); enabled is false when the runtime is not kubernetes
func (c *openrunPlugin) KubernetesStats(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("kubernetes_stats", call); err != nil {
		return nil, err
	}

	stats, err := c.server.GetKubernetesStats(ctx)
	if err != nil {
		return nil, err
	}
	return structValue(stats)
}

// ContainerKubernetesStatus returns the kubernetes specific status of one
// managed pod: conditions, container states and recent events
func (c *openrunPlugin) ContainerKubernetesStatus(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("container_kubernetes_status", call, "id", &id); err != nil {
		return nil, err
	}

	status, err := c.server.GetKubernetesPodStatus(ctx, id)
	if err != nil {
		return nil, err
	}
	return structValue(status)
}

// GetContainerLogs returns the last tail lines of a container's logs
func (c *openrunPlugin) GetContainerLogs(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	tail := int64(100)
	if err := sdk.UnpackArgs("container_logs", call, "id", &id, "tail?", &tail); err != nil {
		return nil, err
	}

	logs, err := c.server.GetManagedContainerLogs(ctx, id, int(tail))
	if err != nil {
		return nil, err
	}
	return logs, nil
}

// GetContainerLogsStream returns a container's logs as a streaming response:
// the last tail lines, optionally following new output until the client
// disconnects. The handler must return the response object as is (the value
// is not accessible in Starlark)
func (c *openrunPlugin) GetContainerLogsStream(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	var follow bool
	tail := int64(500)
	if err := sdk.UnpackArgs("container_logs_stream", call, "id", &id, "tail?", &tail, "follow?", &follow); err != nil {
		return nil, err
	}

	stream, err := c.server.GetManagedContainerLogsStream(ctx, id, int(tail), follow)
	if err != nil {
		return nil, err
	}
	return sdk.PushCursor("container_logs", fmt.Sprintf("container_logs_%p", &stream), true, stream), nil
}

// GetPermissions returns the management API permissions the current user holds.
// With a path argument, app permissions are evaluated against that app (with the
// owner rule); global permissions are always included. When RBAC enforcement is
// not active for the calling app, all permissions are returned
func (c *openrunPlugin) GetPermissions(ctx context.Context, call *sdk.Call) (any, error) {
	var path string
	if err := sdk.UnpackArgs("get_permissions", call, "path?", &path); err != nil {
		return nil, err
	}

	var target types.AppPathDomain
	owner := ""
	if path != "" {
		pathDomain, err := parseAppPath(path)
		if err != nil {
			return nil, err
		}
		apps, err := c.server.apps.GetAllAppsInfo()
		if err != nil {
			return nil, err
		}
		target = pathDomain
		// Resolve the input to its main app path so the reported permissions
		// match what enforcement uses (enforceAppPerm resolves stage/preview
		// apps to the main path). Match the input against the app's own path or
		// its main path, then take the main path as target and its creator as
		// owner for the owner rule.
		for _, appInfo := range apps {
			mainPD := mainAppPathDomain(appInfo.AppPathDomain, appInfo.MainApp, appInfo.LinkedAppPath)
			if appInfo.AppPathDomain == pathDomain || mainPD == pathDomain {
				target = mainPD
				owner = appInfo.UserID
				break
			}
		}
	}

	perms, err := c.server.rbacManager.GetAPIPermissions(ctx, target, owner)
	if err != nil {
		return nil, err
	}

	ret := []string{}
	ret = append(ret, perms...)
	return ret, nil
}

// SystemPluginsAllowed reports whether the current caller may invoke the
// privileged system plugins (openrun_admin, build), using the same
// app.SystemPluginsAllowed predicate as the pluginHook gate. This read-only
// call is on the ungated openrun plugin so the console can detect the blocked
// state and show a clear message instead of failing on the first
// admin/builder call.
func (c *openrunPlugin) SystemPluginsAllowed(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("system_plugins_allowed", call); err != nil {
		return nil, err
	}

	userId := call.Thread.UserId
	return app.SystemPluginsAllowed(c.server.Config(), userId), nil
}

// ServerInfo reports identity and runtime facts about this server: version,
// commit, uptime, database types, container runtime, leader flag and the
// metadata replication state. Everything is read from memory (the metadata
// replication entries come from the in-process litestream manager), so the
// API is safe to call on every page render. Per-binding replication state
// needs the full replication_status API
func (c *openrunPlugin) ServerInfo(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("server_info", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	s := c.server
	runtime := s.containerRuntime()
	if runtime != "" && runtime != types.CONTAINER_KUBERNETES {
		// FindExec resolution can return a full executable path
		runtime = path.Base(runtime)
	}
	mdRepl := s.metadataReplicationStatus(ctx)
	if mdRepl == nil {
		mdRepl = []types.ReplicationStatusEntry{}
	}
	info := types.ServerInfo{
		Version:             types.GetVersion(),
		Commit:              types.GetCommit(),
		StartTime:           s.startTime,
		UptimeSecs:          int64(time.Since(s.startTime).Seconds()),
		MetadataDBType:      string(s.db.DBType()),
		AuditDBType:         string(s.auditDbType),
		ContainerCommand:    strings.TrimSpace(s.Config().System.ContainerCommand),
		ContainerRuntime:    runtime,
		IsLeader:            s.db.IsLeader(),
		MetadataReplication: mdRepl,
	}
	return structValue(&info)
}

// ListAuths returns the auth types an app can be configured with: the
// built-ins (default/system/none) plus the oauth, saml and client cert auth
// entries configured on this server
func (c *openrunPlugin) ListAuths(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_auths", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	ret := []string{}
	for _, auth := range c.server.ListAppAuths() {
		ret = append(ret, string(auth))
	}
	return ret, nil
}

// ListGitAuths returns the git_auth entry names configured on this server
// plus the security.default_git_auth entry name (the auth used when an app
// or sync does not name one), usable in app create and sync setup
func (c *openrunPlugin) ListGitAuths(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("list_git_auths", call); err != nil {
		return nil, err
	}

	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigBasicRead, ""); err != nil {
		return nil, err
	}

	names := slices.Collect(maps.Keys(c.server.Config().GitAuth))
	slices.Sort(names)
	if names == nil {
		names = []string{}
	}
	return structValue(map[string]any{
		"entries": names,
		"default": c.server.Config().Security.DefaultGitAuth,
	})
}

// ReplicationStatus reports litestream replication state for the server's
// metadata databases and litestream-enabled sqlite bindings. Read-only, no
// credentials in the response (paths, timestamps and sizes only).
func (c *openrunPlugin) ReplicationStatus(ctx context.Context, call *sdk.Call) (any, error) {
	if err := sdk.UnpackArgs("replication_status", call); err != nil {
		return nil, err
	}

	// Visibility is filtered per caller inside ReplicationStatus: metadata
	// rows need config:basic_read, app rows are trimmed to the apps the
	// caller holds app:read on
	entries, err := c.server.ReplicationStatus(ctx, false)
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, entry := range entries {
		entryMap, err := structValue(&entry)
		if err != nil {
			return nil, err
		}
		ret = append(ret, entryMap)
	}
	return ret, nil
}

func (c *openrunPlugin) ListBindings(ctx context.Context, call *sdk.Call) (any, error) {
	var source string
	if err := sdk.UnpackArgs("list_bindings", call, "source?", &source); err != nil {
		return nil, err
	}

	// ListBindings filters to the bindings the user holds binding:read on
	// (through grants or the owner rule) and redacts account credentials
	bindings, err := c.server.ListBindings(ctx, source)
	if err != nil {
		return nil, err
	}

	ret := []any{}
	for _, binding := range bindings {
		// The raw apply info is dropped
		redacted := *binding
		redacted.Metadata.ApplyInfo = nil
		redacted.StagedMetadata.ApplyInfo = nil
		entryMap, err := structValue(&redacted)
		if err != nil {
			return nil, err
		}
		ret = append(ret, entryMap)
	}

	return ret, nil
}
