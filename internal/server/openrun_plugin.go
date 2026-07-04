// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sort"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

func initOpenRunPlugin(server *Server) {
	c := &openrunPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApiName(c.ListApps, app.READ, "list_apps"),
		app.CreatePluginApiName(c.ListAllApps, app.READ, "list_all_apps"),
		app.CreatePluginApiName(c.ListAuditEvents, app.READ, "list_audit_events"),
		app.CreatePluginApiName(c.ListOperations, app.READ, "list_operations"),
		app.CreatePluginApiName(c.ListSync, app.READ, "list_sync"),
		app.CreatePluginApiName(c.ListBindings, app.READ, "list_bindings"),
		app.CreatePluginApiName(c.GetApp, app.READ, "get_app"),
		app.CreatePluginApiName(c.ListSpecs, app.READ, "list_specs"),
		app.CreatePluginApiName(c.ListVersions, app.READ, "list_versions"),
		app.CreatePluginApiName(c.ListVersionFiles, app.READ, "list_version_files"),
		app.CreatePluginApiName(c.AuditApp, app.READ, "audit_app"),
		app.CreatePluginApiName(c.ListServices, app.READ, "list_services"),
		app.CreatePluginApiName(c.GetRBACConfig, app.READ, "get_rbac_config"),
		app.CreatePluginApiName(c.ListConfigHistory, app.READ, "list_config_history"),
		app.CreatePluginApiName(c.GetConfigVersion, app.READ, "get_config_version"),
		app.CreatePluginApiName(c.ListContainers, app.READ, "list_containers"),
		app.CreatePluginApiName(c.GetContainer, app.READ, "get_container"),
		app.CreatePluginApiName(c.GetContainerLogs, app.READ, "container_logs"),
		app.CreatePluginApiName(c.GetPermissions, app.READ, "get_permissions"),
		app.CreatePluginApiName(c.ListRBACPermissions, app.READ, "list_rbac_permissions"),
		app.CreatePluginApiName(c.ListAuths, app.READ, "list_auths"),
		app.CreatePluginApiName(c.ListGitAuths, app.READ, "list_git_auths"),
	}

	newOpenRunPlugin := func(pluginContext *types.PluginContext) (any, error) {
		return &openrunPlugin{server: server}, nil
	}

	app.RegisterPlugin("openrun", newOpenRunPlugin, pluginFuncs)
}

type openrunPlugin struct {
	server *Server
}

func (c *openrunPlugin) ListAllApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return c.listAppsImpl(thread, builtin, args, kwargs, false, "list_all_apps")
}

func (c *openrunPlugin) ListApps(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return c.listAppsImpl(thread, builtin, args, kwargs, true, "list_apps")
}

func (c *openrunPlugin) listAppsImpl(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, permCheck bool, apiName string) (starlark.Value, error) {
	var query, path starlark.String
	var include_internal starlark.Bool
	if err := starlark.UnpackArgs(apiName, args, kwargs, "query?", &query, "path?", &path, "include_internal?", &include_internal); err != nil {
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

	userId := system.GetRequestUserId(thread)
	groups := system.GetRequestGroups(thread)
	ctx := system.GetRequestContext(thread)
	if c.server.rbacManager.APIEnforced(ctx) {
		// Under RBAC enforcement, list_all_apps also filters by app:read; otherwise
		// it would be a filtering bypass
		permCheck = true
	}
	ret := starlark.List{}
	//nolint:errcheck
	for _, app := range apps {
		// Filter out internal apps
		if app.MainApp != "" && !bool(include_internal) {
			continue
		}

		// For stage/preview apps, glob matching is done against the main app path
		mainPathDomain := mainAppPathDomain(app.AppPathDomain, app.MainApp, app.LinkedAppPath)

		// Check query filter
		if query != "" {
			queryStr := strings.ToLower(query.GoString())
			if !strings.Contains(strings.ToLower(app.Name), queryStr) &&
				!strings.Contains(strings.ToLower(app.String()), queryStr) &&
				!strings.Contains(strings.ToLower(app.SourceUrl), queryStr) &&
				!strings.Contains(strings.ToLower(app.UserID), queryStr) {
				continue
			}
		}

		if path != "" {
			// If path glob is specified, check if the app (or its main app) matches
			match, err := rbac.MatchGlob(path.GoString(), mainPathDomain)
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

		v := starlark.Dict{}
		v.SetKey(starlark.String("name"), starlark.String(app.Name))
		v.SetKey(starlark.String("url"), starlark.String(types.GetAppUrl(app.AppPathDomain, c.server.config)))
		v.SetKey(starlark.String("path"), starlark.String(app.String()))
		pathSplit := starlark.List{}
		pathSplitGlob := starlark.List{}
		if app.Domain != "" {
			pathSplit.Append(starlark.String(app.Domain))
		}
		for _, path := range strings.Split(app.Path, "/") {
			if path != "" {
				pathSplit.Append(starlark.String("/" + path)) //nolint:errcheck
			}
		}

		globDomain := mainPathDomain.Domain
		globPath := mainPathDomain.Path
		globDomainPrefix := ""
		if globDomain != "" {
			pathSplitGlob.Append(starlark.String(globDomain + ":**"))
			globDomainPrefix = globDomain + ":"
		}
		appPath := ""
		splitPath := strings.Split(globPath, "/")
		for i, path := range splitPath {
			if path != "" {
				appPath += "/" + path
				if i == len(splitPath)-1 {
					// Last path, no glob
					pathSplitGlob.Append(starlark.String(globDomainPrefix + appPath)) //nolint:errcheck
				} else {
					pathSplitGlob.Append(starlark.String(globDomainPrefix + appPath + "/**")) //nolint:errcheck
				}
			}
		}
		// Stage/preview apps can display internal path breadcrumbs like
		// /_cl_stage while filtering still targets the linked main app path.
		if pathSplitGlob.Len() < pathSplit.Len() {
			filterPath := mainPathDomain.String()
			if filterPath == "" {
				filterPath = "/"
			}
			for pathSplitGlob.Len() < pathSplit.Len() {
				pathSplitGlob.Append(starlark.String(filterPath)) //nolint:errcheck
			}
		}
		v.SetKey(starlark.String("path_split"), &pathSplit)
		v.SetKey(starlark.String("path_split_glob"), &pathSplitGlob)
		v.SetKey(starlark.String("id"), starlark.String(app.Id))
		v.SetKey(starlark.String("is_dev"), starlark.Bool(app.IsDev))
		v.SetKey(starlark.String("is_stage"), starlark.Bool(strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE)))
		v.SetKey(starlark.String("main_app"), starlark.String(app.MainApp))
		v.SetKey(starlark.String("created_by"), starlark.String(app.UserID))
		if app.Auth == types.AppAuthnDefault {
			v.SetKey(starlark.String("auth"), starlark.String(c.server.config.Security.AppDefaultAuthType))
			v.SetKey(starlark.String("auth_uses_default"), starlark.Bool(true))
		} else {
			v.SetKey(starlark.String("auth"), starlark.String(app.Auth))
			v.SetKey(starlark.String("auth_uses_default"), starlark.Bool(false))
		}
		v.SetKey(starlark.String("source"), starlark.String(app.SourceUrl))
		v.SetKey(starlark.String("source_url"), starlark.String(getSourceUrl(app.SourceUrl, app.Branch)))
		v.SetKey(starlark.String("applied_sync_id"), starlark.String(app.AppliedSyncId))
		v.SetKey(starlark.String("star_base"), starlark.String(app.StarBase))
		v.SetKey(starlark.String("spec"), starlark.String(app.Spec))
		v.SetKey(starlark.String("version"), starlark.MakeInt(app.Version))
		v.SetKey(starlark.String("version_mismatch"), starlark.Bool(versionMismatchMap[app.Id]))
		v.SetKey(starlark.String("git_sha"), starlark.String(app.GitSha))
		v.SetKey(starlark.String("git_message"), starlark.String(app.GitMessage))
		v.SetKey(starlark.String("git_branch"), starlark.String(app.Branch))
		v.SetKey(starlark.String("update_age"), starlark.String(system.HumanDuration(time.Since(app.UpdateTime))))
		v.SetKey(starlark.String("update_time"), starlark.String(app.UpdateTime.Format(time.RFC3339)))

		ret.Append(&v)
	}

	return &ret, nil
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

func (c *openrunPlugin) ListAuditEvents(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var appGlob, userId, eventType, operation, target, status, rid, detail starlark.String
	var startDate, endDate, beforeTimestamp starlark.String
	limit := starlark.MakeInt(50)
	if err := starlark.UnpackArgs("list_audit_events", args, kwargs, "app_glob?", &appGlob, "user_id?", &userId, "event_type?",
		&eventType, "operation?", &operation, "target?", &target, "status?", &status, "start_date", &startDate, "end_date?", &endDate,
		"rid?", &rid, "detail?", &detail, "limit?", &limit, "before_timestamp?", &beforeTimestamp); err != nil {
		return nil, err
	}

	var query strings.Builder
	query.WriteString("select rid, app_id, create_time, user_id, event_type, operation, target, status, detail from audit ")

	filterConditions := []string{}
	appGlobStr := strings.TrimSpace(appGlob.GoString())
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
	userIdStr := strings.TrimSpace(userId.GoString())
	if userIdStr != "" {
		filterConditions = append(filterConditions, "user_id = ?")
		queryParams = append(queryParams, userIdStr)
	}

	eventTypeStr := strings.TrimSpace(eventType.GoString())
	if eventTypeStr != "" {
		filterConditions = append(filterConditions, "event_type = ?")
		queryParams = append(queryParams, eventTypeStr)
	}

	operationStr := strings.TrimSpace(operation.GoString())
	if operationStr != "" {
		opList, opQuery := getOpList(operationStr)
		filterConditions = append(filterConditions, "operation in ("+opQuery+")")
		queryParams = append(queryParams, opList...)
	}

	targetStr := strings.TrimSpace(target.GoString())
	if targetStr != "" {
		filterConditions = append(filterConditions, "target = ?")
		queryParams = append(queryParams, targetStr)
	}

	statusStr := strings.TrimSpace(status.GoString())
	if statusStr != "" {
		filterConditions = append(filterConditions, "status = ?")
		queryParams = append(queryParams, statusStr)
	}

	startDateStr := strings.TrimSpace(startDate.GoString())
	if startDateStr != "" {
		if c.server.auditDbType == system.DB_TYPE_SQLITE {
			filterConditions = append(filterConditions, `create_time >= strftime('%s', ?) * 1000000000`)
		} else {
			// Postgres
			filterConditions = append(filterConditions, `create_time >= EXTRACT(EPOCH FROM  ?::timestamp)::bigint * 1000000000`)
		}
		queryParams = append(queryParams, startDateStr)
	}

	endDateStr := strings.TrimSpace(endDate.GoString())
	if endDateStr != "" {
		if c.server.auditDbType == system.DB_TYPE_SQLITE {
			filterConditions = append(filterConditions, `create_time <= (strftime('%s', ?) + 86400) * 1000000000`)
		} else {
			// Postgres
			filterConditions = append(filterConditions, `create_time <= (EXTRACT(EPOCH FROM  ?::timestamp)::bigint + 86400) * 1000000000`)
		}
		queryParams = append(queryParams, endDateStr)
	}

	ridStr := strings.TrimSpace(rid.GoString())
	if ridStr != "" {
		filterConditions = append(filterConditions, "rid = ?")
		queryParams = append(queryParams, ridStr)
	}

	detailStr := strings.TrimSpace(detail.GoString())
	if detailStr != "" {
		filterConditions = append(filterConditions, "detail like ?")
		queryParams = append(queryParams, detailStr)
	}

	beforeTimestampStr := strings.TrimSpace(beforeTimestamp.GoString())
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

	limitVal, _ := limit.Int64()
	if limitVal <= 0 || limitVal > 10_000 {
		return nil, fmt.Errorf("limit has to be between 1 and 10000")
	}
	query.WriteString(" limit ?")
	queryParams = append(queryParams, limitVal)

	// Ensure previously queued audit events are visible to the query
	c.server.FlushAuditEvents()
	rows, err := c.server.auditDB.Query(system.RebindQuery(c.server.auditDbType, query.String()), queryParams...)
	if err != nil {
		return nil, err
	}

	apps, err := c.server.apps.GetAllAppsInfo()
	if err != nil {
		return nil, err
	}
	appIdMap := map[types.AppId]types.AppInfo{}
	for _, app := range apps {
		appIdMap[app.Id] = app
	}

	ret := starlark.List{}
	//nolint:errcheck
	for rows.Next() {
		var rid, appId, userId, eventType, operation, target, status, detail string
		var createTime int64
		err := rows.Scan(&rid, &appId, &createTime, &userId, &eventType, &operation, &target, &status, &detail)
		if err != nil {
			return nil, err
		}

		utcTime := time.Unix(0, createTime).UTC()

		v := starlark.Dict{}
		v.SetKey(starlark.String("rid"), starlark.String(rid))
		v.SetKey(starlark.String("app_id"), starlark.String(appId))
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
			v.SetKey(starlark.String("app_name"), starlark.String(appInfo.Name))
			v.SetKey(starlark.String("app_path"), starlark.String(appInfo.String()))
		} else {
			v.SetKey(starlark.String("app_name"), starlark.String(appId))
			v.SetKey(starlark.String("app_path"), starlark.String(""))
		}
		v.SetKey(starlark.String("app_env"), starlark.String(appEnv))
		v.SetKey(starlark.String("create_time_epoch"), starlark.String(strconv.FormatInt(createTime, 10)))
		v.SetKey(starlark.String("create_time"), starlark.String(utcTime.Format("2006-01-02T15:04:05.999Z")))
		v.SetKey(starlark.String("user_id"), starlark.String(userId))
		v.SetKey(starlark.String("event_type"), starlark.String(eventType))
		v.SetKey(starlark.String("operation"), starlark.String(operation))
		v.SetKey(starlark.String("target"), starlark.String(target))
		v.SetKey(starlark.String("status"), starlark.String(status))
		v.SetKey(starlark.String("detail"), starlark.String(detail))

		ret.Append(&v)
	}

	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return &ret, nil
}

//nolint:errcheck
func (c *openrunPlugin) ListOperations(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_operations", args, kwargs); err != nil {
		return nil, err
	}

	// Ensure previously queued audit events are visible to the query
	c.server.FlushAuditEvents()
	rows, err := c.server.auditDB.Query("select distinct operation from audit where event_type = 'custom'")
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for rows.Next() {
		var operation string
		err := rows.Scan(&operation)
		if err != nil {
			return nil, err
		}

		ret.Append(starlark.String(operation))
	}

	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	ret.Append(starlark.String("reload_apps"))
	ret.Append(starlark.String("list_apps"))
	ret.Append(starlark.String("get_app"))
	ret.Append(starlark.String("create_app"))
	ret.Append(starlark.String("create_preview"))
	ret.Append(starlark.String("delete_apps"))
	ret.Append(starlark.String("approve_apps"))
	ret.Append(starlark.String("promote_apps"))
	ret.Append(starlark.String("update_settings"))
	ret.Append(starlark.String("update_metadata"))
	ret.Append(starlark.String("update_links"))
	ret.Append(starlark.String("update_params"))
	ret.Append(starlark.String("list_versions"))
	ret.Append(starlark.String("list_files"))
	ret.Append(starlark.String("version_switch"))
	ret.Append(starlark.String("list_webhooks"))
	ret.Append(starlark.String("token_create"))
	ret.Append(starlark.String("token_delete"))
	ret.Append(starlark.String("stop_server"))
	ret.Append(starlark.String("POST"))
	ret.Append(starlark.String("PUT"))
	ret.Append(starlark.String("DELETE"))
	ret.Append(starlark.String("PATCH"))
	ret.Append(starlark.String("suggest"))
	ret.Append(starlark.String("validate"))
	ret.Append(starlark.String("execute"))

	return &ret, nil
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

func (c *openrunPlugin) ListSync(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ctx := system.GetRequestContext(thread)
	sync, err := c.server.ListSyncEntries(ctx)
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, entry := range sync.Entries {
		entryMap, err := starlark_type.ConvertToStarlark(entry)
		if err != nil {
			return nil, err
		}
		ret.Append(entryMap) //nolint:errcheck
	}

	return &ret, nil
}

// GetApp returns the app entry for an exact app path, with the fields needed
// for displaying/updating the app. Settings (webhook tokens) are not included.
func (c *openrunPlugin) GetApp(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	if err := starlark.UnpackArgs("get_app", args, kwargs, "path", &path); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	apps, err := c.server.GetApps(ctx, path.GoString(), false)
	if err != nil {
		return nil, err
	}
	if len(apps) != 1 {
		return nil, fmt.Errorf("app %s not found", path.GoString())
	}

	entry := apps[0]
	params := starlark.Dict{}
	for k, val := range entry.Metadata.ParamValues {
		params.SetKey(starlark.String(k), starlark.String(val)) //nolint:errcheck
	}

	v := starlark.Dict{}
	v.SetKey(starlark.String("path"), starlark.String(entry.AppPathDomain().String()))                 //nolint:errcheck
	v.SetKey(starlark.String("name"), starlark.String(entry.Metadata.Name))                            //nolint:errcheck
	v.SetKey(starlark.String("id"), starlark.String(entry.Id))                                         //nolint:errcheck
	v.SetKey(starlark.String("url"), starlark.String(types.GetAppUrl(entry.AppPathDomain(), c.server.config))) //nolint:errcheck
	v.SetKey(starlark.String("source_url"), starlark.String(entry.SourceUrl))                          //nolint:errcheck
	v.SetKey(starlark.String("is_dev"), starlark.Bool(entry.IsDev))                                    //nolint:errcheck
	v.SetKey(starlark.String("auth"), starlark.String(entry.Metadata.AuthnType))                       //nolint:errcheck
	v.SetKey(starlark.String("spec"), starlark.String(entry.Metadata.Spec))                            //nolint:errcheck
	v.SetKey(starlark.String("git_branch"), starlark.String(entry.Metadata.VersionMetadata.GitBranch)) //nolint:errcheck
	v.SetKey(starlark.String("git_commit"), starlark.String(entry.Metadata.VersionMetadata.GitCommit)) //nolint:errcheck
	v.SetKey(starlark.String("git_message"), starlark.String(entry.Metadata.VersionMetadata.GitMessage)) //nolint:errcheck
	v.SetKey(starlark.String("git_auth"), starlark.String(entry.Metadata.GitAuthName))                 //nolint:errcheck
	v.SetKey(starlark.String("version"), starlark.MakeInt(entry.Metadata.VersionMetadata.Version))     //nolint:errcheck
	v.SetKey(starlark.String("applied_sync_id"), starlark.String(entry.Metadata.AppliedSyncId))        //nolint:errcheck
	v.SetKey(starlark.String("params"), &params)                                                       //nolint:errcheck
	v.SetKey(starlark.String("staged_changes"), starlark.Bool(apps[0].StagedChanges))                  //nolint:errcheck
	if entry.UpdateTime != nil {
		v.SetKey(starlark.String("update_time"), starlark.String(entry.UpdateTime.Format(time.RFC3339))) //nolint:errcheck
	} else {
		v.SetKey(starlark.String("update_time"), starlark.String("")) //nolint:errcheck
	}

	stagePath := ""
	if !entry.IsDev {
		// The path of the linked staging app, for version/file lookups
		stagePathDomain, err := parseLinkedAppPathDomain(entry.LinkedAppPath)
		if err != nil {
			stagePathDomain = pathBasedStageApp(&entry.AppEntry)
		}
		stagePath = stagePathDomain.String()
	}
	v.SetKey(starlark.String("stage_path"), starlark.String(stagePath)) //nolint:errcheck
	return &v, nil
}

// ListVersions returns the versions for the app at the given path. Use the
// _cl_stage path suffix for the staging app's versions
func (c *openrunPlugin) ListVersions(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	if err := starlark.UnpackArgs("list_versions", args, kwargs, "path", &path); err != nil {
		return nil, err
	}

	result, err := c.server.VersionList(system.GetRequestContext(thread), path.GoString())
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// ListVersionFiles returns the files in a version of the app at the given
// path. version defaults to the active version
func (c *openrunPlugin) ListVersionFiles(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, version starlark.String
	if err := starlark.UnpackArgs("list_version_files", args, kwargs, "path", &path, "version?", &version); err != nil {
		return nil, err
	}

	result, err := c.server.VersionFiles(system.GetRequestContext(thread), path.GoString(), version.GoString())
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// ListSpecs returns the available app spec names
func (c *openrunPlugin) ListSpecs(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_specs", args, kwargs); err != nil {
		return nil, err
	}

	names := make(map[string]bool)
	for name := range appTypes {
		names[name] = true
	}
	customSpecsDir := path.Clean(path.Join(os.ExpandEnv("$OPENRUN_HOME/config"), APPSPECS))
	if entries, err := os.ReadDir(customSpecsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				names[entry.Name()] = true
			}
		}
	}

	sorted := slices.Collect(maps.Keys(names))
	slices.Sort(sorted)
	ret := starlark.List{}
	for _, name := range sorted {
		ret.Append(starlark.String(name)) //nolint:errcheck
	}
	return &ret, nil
}

// AuditApp audits the app's code and returns the requested plugin loads and
// permissions with the approval status. For prod apps the staging app is
// audited, since approvals apply to staging first. Nothing is persisted
func (c *openrunPlugin) AuditApp(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	if err := starlark.UnpackArgs("audit_app", args, kwargs, "path", &path); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	appPathDomain, err := parseAppPath(path.GoString())
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
	return starlark_type.ConvertToStarlark(result)
}

// ListServices lists the service entries. Config values are redacted, only
// the config keys are returned
func (c *openrunPlugin) ListServices(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_services", args, kwargs); err != nil {
		return nil, err
	}

	services, err := c.server.ListServices(system.GetRequestContext(thread), "", "")
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, service := range services {
		configKeys := make([]string, 0, len(service.Config))
		for key := range service.Config {
			configKeys = append(configKeys, key)
		}
		sort.Strings(configKeys)

		entry, err := starlark_type.ConvertToStarlark(map[string]any{
			"id":           service.Id,
			"name":         service.Name,
			"service_type": service.ServiceType,
			"is_default":   service.IsDefault,
			"staging":      service.Staging,
			"config_keys":  configKeys,
			"create_time":  service.CreateTime.Format(time.RFC3339),
			"update_time":  service.UpdateTime.Format(time.RFC3339),
		})
		if err != nil {
			return nil, err
		}
		ret.Append(entry) //nolint:errcheck
	}
	return &ret, nil
}

// ListContainers lists the containers (or Kubernetes pods) managed by OpenRun
func (c *openrunPlugin) ListContainers(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_containers", args, kwargs); err != nil {
		return nil, err
	}

	containers, err := c.server.ListManagedContainers(system.GetRequestContext(thread))
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, info := range containers {
		entry, err := starlark_type.ConvertToStarlark(info)
		if err != nil {
			return nil, err
		}
		ret.Append(entry) //nolint:errcheck
	}
	return &ret, nil
}

// GetContainer returns the details of one OpenRun managed container,
// including mounts, disk usage and live resource stats
func (c *openrunPlugin) GetContainer(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	stats := starlark.Bool(true)
	if err := starlark.UnpackArgs("get_container", args, kwargs, "id", &id, "stats?", &stats); err != nil {
		return nil, err
	}

	detail, err := c.server.GetManagedContainer(system.GetRequestContext(thread), id.GoString(), bool(stats))
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(detail)
}

// GetContainerLogs returns the last tail lines of a container's logs
func (c *openrunPlugin) GetContainerLogs(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	tail := starlark.MakeInt(100)
	if err := starlark.UnpackArgs("container_logs", args, kwargs, "id", &id, "tail?", &tail); err != nil {
		return nil, err
	}

	tailInt, _ := tail.Int64()
	logs, err := c.server.GetManagedContainerLogs(system.GetRequestContext(thread), id.GoString(), int(tailInt))
	if err != nil {
		return nil, err
	}
	return starlark.String(logs), nil
}

// GetPermissions returns the management API permissions the current user holds.
// With a path argument, app permissions are evaluated against that app (with the
// owner rule); global permissions are always included. When RBAC enforcement is
// not active for the calling app, all permissions are returned
func (c *openrunPlugin) GetPermissions(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path starlark.String
	if err := starlark.UnpackArgs("get_permissions", args, kwargs, "path?", &path); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	var target types.AppPathDomain
	owner := ""
	if path != "" {
		pathDomain, err := parseAppPath(path.GoString())
		if err != nil {
			return nil, err
		}
		apps, err := c.server.apps.GetAllAppsInfo()
		if err != nil {
			return nil, err
		}
		target = pathDomain
		for _, appInfo := range apps {
			if mainAppPathDomain(appInfo.AppPathDomain, appInfo.MainApp, appInfo.LinkedAppPath) == pathDomain {
				owner = appInfo.UserID
				break
			}
		}
	}

	perms, err := c.server.rbacManager.GetAPIPermissions(ctx, target, owner)
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, perm := range perms {
		ret.Append(starlark.String(perm)) //nolint:errcheck
	}
	return &ret, nil
}

// ListAuths returns the auth types an app can be configured with: the
// built-ins (default/system/none) plus the oauth, saml and client cert auth
// entries configured on this server
func (c *openrunPlugin) ListAuths(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_auths", args, kwargs); err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, auth := range c.server.ListAppAuths() {
		ret.Append(starlark.String(auth)) //nolint:errcheck
	}
	return &ret, nil
}

// ListGitAuths returns the git_auth entry names configured on this server,
// usable for private repo access in app create and sync setup
func (c *openrunPlugin) ListGitAuths(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_git_auths", args, kwargs); err != nil {
		return nil, err
	}

	names := slices.Collect(maps.Keys(c.server.config.GitAuth))
	slices.Sort(names)
	ret := starlark.List{}
	for _, name := range names {
		ret.Append(starlark.String(name)) //nolint:errcheck
	}
	return &ret, nil
}

func (c *openrunPlugin) ListBindings(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.String
	if err := starlark.UnpackArgs("list_bindings", args, kwargs, "source?", &source); err != nil {
		return nil, err
	}

	ctx := system.GetRequestContext(thread)
	// The ListBindings server method is not gated (apply uses it internally), so
	// the plugin entry point enforces binding:read
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBindingRead, ""); err != nil {
		return nil, err
	}
	bindings, err := c.server.ListBindings(ctx, source.GoString())
	if err != nil {
		return nil, err
	}

	ret := starlark.List{}
	for _, binding := range bindings {
		// Account info (credentials) is redacted, the raw apply info is dropped
		redacted := redactBindingAccount(binding)
		redacted.Metadata.ApplyInfo = nil
		redacted.StagedMetadata.ApplyInfo = nil
		entryMap, err := starlark_type.ConvertToStarlark(redacted)
		if err != nil {
			return nil, err
		}
		ret.Append(entryMap) //nolint:errcheck
	}

	return &ret, nil
}
