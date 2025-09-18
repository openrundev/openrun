// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/plugin"
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
	ret := starlark.List{}
	for _, app := range apps {
		// Filter out internal apps
		if app.MainApp != "" && !bool(include_internal) {
			continue
		}

		// Check query filter
		if query != "" {
			queryStr := strings.ToLower(query.GoString())
			if !strings.Contains(strings.ToLower(app.Name), queryStr) &&
				!strings.Contains(strings.ToLower(app.AppPathDomain.String()), queryStr) &&
				!strings.Contains(strings.ToLower(app.SourceUrl), queryStr) {
				continue
			}
		}

		if path != "" {
			// If path glob is specified, check if app matches. If internal apps are to be included,
			// check if main app matches
			appPath := app.Path
			if include_internal && app.MainApp != "" {
				appPath = strings.TrimSuffix(appPath, types.STAGE_SUFFIX)
				appPath = strings.TrimSuffix(appPath, types.PREVIEW_SUFFIX)
			}
			tmpPath := types.AppPathDomain{
				Domain: app.Domain,
				Path:   appPath,
			}

			match, err := MatchGlob(path.GoString(), tmpPath)
			if err != nil {
				return nil, err
			}
			if !match {
				continue
			}
		}

		if permCheck {
			hasAccess, err := c.server.AuthorizeList(userId, &app)
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
		v.SetKey(starlark.String("path"), starlark.String(app.AppPathDomain.String()))
		pathSplit := starlark.List{}
		pathSplitGlob := starlark.List{}
		appDomain := ""
		if app.Domain != "" {
			pathSplit.Append(starlark.String(app.Domain))
			pathSplitGlob.Append(starlark.String(app.Domain + ":**"))
			appDomain = app.Domain + ":"
		}
		appPath := ""
		splitPath := strings.Split(app.Path, "/")
		for i, path := range splitPath {
			if path != "" {
				pathSplit.Append(starlark.String("/" + path))
				appPath += "/" + path
				if i == len(splitPath)-1 {
					appPath = strings.TrimSuffix(appPath, types.STAGE_SUFFIX)
					appPath = strings.TrimSuffix(appPath, types.PREVIEW_SUFFIX)
					// Last path, no glob
					pathSplitGlob.Append(starlark.String(appDomain + appPath))
				} else {
					pathSplitGlob.Append(starlark.String(appDomain + appPath + "/**"))
				}
			}
		}
		v.SetKey(starlark.String("path_split"), &pathSplit)
		v.SetKey(starlark.String("path_split_glob"), &pathSplitGlob)
		v.SetKey(starlark.String("id"), starlark.String(app.Id))
		v.SetKey(starlark.String("is_dev"), starlark.Bool(app.IsDev))
		v.SetKey(starlark.String("is_stage"), starlark.Bool(strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE)))
		v.SetKey(starlark.String("main_app"), starlark.String(app.MainApp))
		if app.Auth == types.AppAuthnDefault {
			v.SetKey(starlark.String("auth"), starlark.String(c.server.config.Security.AppDefaultAuthType))
			v.SetKey(starlark.String("auth_uses_default"), starlark.Bool(true))
		} else {
			v.SetKey(starlark.String("auth"), starlark.String(app.Auth))
			v.SetKey(starlark.String("auth_uses_default"), starlark.Bool(false))
		}
		v.SetKey(starlark.String("source"), starlark.String(app.SourceUrl))
		v.SetKey(starlark.String("source_url"), starlark.String(getSourceUrl(app.SourceUrl, app.Branch)))
		v.SetKey(starlark.String("star_base"), starlark.String(app.StarBase))
		v.SetKey(starlark.String("spec"), starlark.String(app.Spec))
		v.SetKey(starlark.String("version"), starlark.MakeInt(app.Version))
		v.SetKey(starlark.String("version_mismatch"), starlark.Bool(versionMismatchMap[app.Id]))
		v.SetKey(starlark.String("git_sha"), starlark.String(app.GitSha))
		v.SetKey(starlark.String("git_message"), starlark.String(app.GitMessage))

		ret.Append(&v)
	}

	return &ret, nil
}

func getSourceUrl(sourceUrl, branch string) string {
	if branch == "" {
		return ""
	}
	url := sourceUrl
	if strings.HasPrefix(sourceUrl, "http://") {
		url = strings.TrimPrefix(sourceUrl, "http://")
	} else if strings.HasPrefix(sourceUrl, "https://") {
		url = strings.TrimPrefix(sourceUrl, "https://")
	}

	isGitUrl := false
	if strings.HasPrefix(url, "github.com/") {
		url = strings.TrimPrefix(url, "github.com/")
	} else if strings.HasPrefix(url, "git@github.com:") {
		url = strings.TrimPrefix(url, "git@github.com:")
		isGitUrl = true
	} else {
		return "" // cannot get full url
	}

	splitPath := strings.Split(url, "/")
	if len(splitPath) < 2 {
		return "" // cannot get full url
	}
	folder := ""
	if len(splitPath) > 2 {
		folder = strings.Join(splitPath[2:], "/")
	}

	repo := splitPath[1]
	if isGitUrl {
		repo = strings.TrimSuffix(splitPath[1], ".git")
	}
	return fmt.Sprintf("https://github.com/%s/%s/tree/%s/%s", splitPath[0], repo, branch, folder)
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
		if appInfo, ok := appIdMap[types.AppId(appId)]; ok {
			v.SetKey(starlark.String("app_name"), starlark.String(appInfo.Name))
			v.SetKey(starlark.String("app_path"), starlark.String(appInfo.AppPathDomain.String()))
		} else {
			v.SetKey(starlark.String("app_name"), starlark.String(appId))
			v.SetKey(starlark.String("app_path"), starlark.String(""))
		}
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

func (c *openrunPlugin) ListOperations(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list_operations", args, kwargs); err != nil {
		return nil, err
	}

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
