// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	sdk "github.com/openrundev/openrun/pkg/plugin"
)

// initBuilderPlugin registers the build.in plugin: the app builder APIs used
// by the console Builder tab
func initBuilderPlugin(server *Server) {
	app.RegisterLocalProvider("build", &sdk.ServeConfig{
		ProviderVersion: "builtin",
		Modules: map[string]sdk.ModuleDef{
			"build": {
				Builder: func() sdk.Module { return &builderPlugin{server: server} },
				Functions: []sdk.FuncDef{
					{Name: "list_sessions", Type: sdk.READ, Method: "ListSessions"},
					{Name: "get_session", Type: sdk.READ, Method: "GetSession"},
					{Name: "get_messages", Type: sdk.READ, Method: "GetMessages"},
					{Name: "session_events", Type: sdk.READ, Method: "SessionEvents"},
					{Name: "list_files", Type: sdk.READ, Method: "ListFiles"},
					{Name: "read_file", Type: sdk.READ, Method: "ReadFile"},
					{Name: "get_source_zip", Type: sdk.READ, Method: "GetSourceZip"},
					{Name: "get_publish_config", Type: sdk.READ, Method: "GetPublishConfig"},
					{Name: "list_activity", Type: sdk.READ, Method: "ListActivity"},
					{Name: "create_session", Type: sdk.WRITE, Method: "CreateSession"},
					{Name: "send_message", Type: sdk.WRITE, Method: "SendMessage"},
					{Name: "cancel_turn", Type: sdk.WRITE, Method: "CancelTurn"},
					{Name: "stop_session", Type: sdk.WRITE, Method: "StopSession"},
					{Name: "resume_session", Type: sdk.WRITE, Method: "ResumeSession"},
					{Name: "delete_session", Type: sdk.WRITE, Method: "DeleteSession"},
					{Name: "check_publish_path", Type: sdk.READ, Method: "CheckPublishPath"},
					{Name: "publish_app", Type: sdk.WRITE, Method: "PublishApp"},
					{Name: "unpublish_app", Type: sdk.WRITE, Method: "UnpublishApp"},
					{Name: "verify_config", Type: sdk.WRITE, Method: "VerifyConfig"},
				},
			},
		},
	}, app.LocalProviderOptions{SystemModules: []string{"build"}})
}

type builderPlugin struct {
	server *Server
}

func (c *builderPlugin) InitModule(ctx context.Context, init sdk.ModuleInit) error {
	return nil
}

func (c *builderPlugin) Close(ctx context.Context) error {
	return nil
}

// requireSession loads a session and authorizes read access: users reach
// only their own sessions (with the base permission); any other user's
// session requires the admin permission
func (c *builderPlugin) requireSession(ctx context.Context, id string, perm types.RBACPermission) (*types.BuilderSession, error) {
	session, err := c.server.builderManager.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if session.UserID != system.GetContextUserId(ctx) {
		if err := c.server.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		return session, nil
	}
	if err := c.server.enforceGlobalPerm(ctx, perm, session.UserID); err != nil {
		return nil, err
	}
	return session, nil
}

func (c *builderPlugin) sessionToValue(session *types.BuilderSession) map[string]any {
	// The stored publish path may carry a relative (trailing ".") domain;
	// app operations in the console need the path resolved on this instance
	resolved := session.PublishPath
	if session.PublishPath != "" {
		if r, _, err := c.server.builderResolvePath(session.PublishPath); err == nil {
			resolved = r
		}
	}
	sessionServices := session.Services
	if sessionServices == nil {
		sessionServices = []string{}
	}
	return map[string]any{
		"publish_path_resolved": resolved,
		"services":              sessionServices,
		"id":                    session.Id,
		"user_id":               session.UserID,
		"name":                  session.Name,
		"spec":                  session.Spec,
		"agent":                 session.Agent,
		"profile":               session.Profile,
		"edit_app":              session.EditApp,
		"status":                string(session.Status),
		"preview_path":          session.PreviewPath,
		"publish_path":          session.PublishPath,
		"create_time":           session.CreateTime.UTC(),
		"update_time":           session.UpdateTime.UTC(),
		"workspace_dir":         session.WorkspaceDir,
	}
}

// ListSessions lists builder sessions: one's own with builder:list, everyone's
// with all_users (requires the admin permission)
func (c *builderPlugin) ListSessions(ctx context.Context, call *sdk.Call) (any, error) {
	var allUsers bool
	if err := sdk.UnpackArgs("list_sessions", call, "all_users?", &allUsers); err != nil {
		return nil, err
	}
	userID := call.Thread.UserId
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderList, userID); err != nil {
		return nil, err
	}
	filterUser := userID
	if allUsers {
		if err := c.server.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		filterUser = ""
	}
	sessions, err := c.server.builderManager.ListSessions(ctx, filterUser)
	if err != nil {
		return nil, err
	}
	ret := make([]any, 0, len(sessions))
	for _, session := range sessions {
		ret = append(ret, c.sessionToValue(session))
	}
	return ret, nil
}

func (c *builderPlugin) GetSession(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("get_session", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	return c.sessionToValue(session), nil
}

// GetMessages returns the transcript: activity rows plus the live in-flight
// turn state (partial agent message)
func (c *builderPlugin) GetMessages(ctx context.Context, call *sdk.Call) (any, error) {
	var id, afterId string
	if err := sdk.UnpackArgs("get_messages", call, "id", &id, "after_id?", &afterId); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}

	entries, err := c.server.builderManager.ListActivity(ctx, session.Id, afterId, 0)
	if err != nil {
		return nil, err
	}
	messages := make([]any, 0, len(entries))
	for _, entry := range entries {
		messages = append(messages, map[string]any{
			"id":          entry.Id,
			"kind":        entry.Kind,
			"content":     entry.Content,
			"metadata":    entry.Metadata,
			"create_time": entry.CreateTime.UTC(),
		})
	}
	isLive, turnActive, partial := c.server.builderManager.LiveState(session.Id)
	return map[string]any{
		"messages":    messages,
		"is_live":     isLive,
		"turn_active": turnActive,
		"partial":     partial,
		"status":      string(session.Status),
	}, nil
}

// SessionEvents streams session events (message chunks, tool calls, status)
// as JSON lines until the client disconnects
func (c *builderPlugin) SessionEvents(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("session_events", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	events, cancel, err := c.server.builderManager.Subscribe(session.Id)
	if err != nil {
		return nil, err
	}

	stream := func(yield func(any, error) bool) {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					continue
				}
				if !yield(string(data), nil) {
					return
				}
			}
		}
	}
	return sdk.PushCursor("session_events", fmt.Sprintf("session_events_%p", &stream), true, stream), nil
}

func (c *builderPlugin) ListFiles(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("list_files", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	files, err := c.server.builderManager.ListFiles(ctx, session.Id)
	if err != nil {
		return nil, err
	}
	ret := make([]any, 0, len(files))
	for _, file := range files {
		ret = append(ret, file)
	}
	return ret, nil
}

func (c *builderPlugin) ReadFile(ctx context.Context, call *sdk.Call) (any, error) {
	var id, path string
	if err := sdk.UnpackArgs("read_file", call, "id", &id, "path", &path); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	content, err := c.server.builderManager.ReadFile(ctx, session.Id, path)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// GetSourceZip returns a download value whose content is a lazily produced
// zip of the session workspace. The zip is built at response-write time by
// the download handler, streaming to the client (chunked) with backpressure,
// so the archive is never fully held in memory or staged to disk or the db
func (c *builderPlugin) GetSourceZip(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("get_source_zip", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}

	workspaceDir := session.WorkspaceDir
	stream := &sdk.Download{Name: builderZipName(session.Name), Producer: func(w io.Writer) error {
		return writeBuilderSourceZip(workspaceDir, w)
	}}
	return zipDownloadValue(stream), nil
}

// zipDownloadValue builds the {content, name} value returned by the zip
// download plugin APIs. content is an opaque download stream (constructible
// only from plugin Go code) that the download response handler drains at
// response-write time; name is the attachment file name
func zipDownloadValue(stream *sdk.Download) map[string]any {
	return map[string]any{
		"content": stream,
		"name":    stream.Name,
	}
}

var zipNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// builderZipName derives the download file name from the session name
func builderZipName(sessionName string) string {
	name := strings.Trim(zipNameSanitizer.ReplaceAllString(sessionName, "-"), "-.")
	if name == "" {
		name = "builder-app"
	}
	return name + "-source.zip"
}

// GetPublishConfig returns the builder publish setup for the UI. With
// session_id the mode and git fields reflect that session's resolved git
// destination (its prompt preset may pick a [builder_git.*] entry)
func (c *builderPlugin) GetPublishConfig(ctx context.Context, call *sdk.Call) (any, error) {
	var sessionId string
	if err := sdk.UnpackArgs("get_publish_config", call, "session_id?", &sessionId); err != nil {
		return nil, err
	}
	config := c.server.Config()

	sessionProfile := ""
	editApp := ""
	if sessionId != "" {
		session, err := c.requireSession(ctx, sessionId, types.PermissionBuilderList)
		if err != nil {
			return nil, err
		}
		sessionProfile = session.Profile
		editApp = session.EditApp
	} else if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderList, ""); err != nil {
		// Without a session the result still exposes the configured git
		// destinations, profiles and agent names, so require builder:list
		return nil, err
	}
	var gitCfg types.BuilderGitConfig
	var err error
	inPlaceEdit := false
	if editApp != "" {
		// In-place edit sessions publish to the app's own destination,
		// derived from its source url. Fork sessions (original not builder
		// managed) publish as a new app with the normal resolution
		if apps, appsErr := c.server.GetApps(ctx, editApp, false); appsErr == nil && len(apps) == 1 &&
			c.server.isBuilderManaged(&apps[0].AppEntry) {
			inPlaceEdit = true
			if matched, _, matchErr := c.server.matchBuilderGitBySource(apps[0].SourceUrl); matchErr == nil {
				gitCfg = matched
			}
		}
	}
	if !inPlaceEdit {
		gitCfg, err = config.ResolveBuilderGit(sessionProfile)
		if err != nil {
			return nil, err
		}
	}
	mode := "local"
	if gitCfg.Repo != "" {
		mode = "git"
	}
	agents := make([]string, 0, len(config.BuilderAgent))
	for name := range config.BuilderAgent {
		agents = append(agents, name)
	}
	sort.Strings(agents)
	// The session's publish restriction: its profile's publish mode/target
	// (empty mode = anywhere). The subdomain target stays RAW - a trailing
	// "." keeps the apps.star declaration relative so other instances can
	// sync it under their own default_domain; the resolved form is returned
	// separately for the dialog hint
	sessionPublishMode := ""
	sessionPublishTarget := ""
	sessionPublishResolved := ""
	sessionPublishDesc := ""
	if _, profile, err := config.ResolveBuilderProfile(sessionProfile); err == nil && profile != nil {
		sessionPublishMode = profile.PublishMode
		sessionPublishTarget = profile.PublishTarget
		sessionPublishDesc = profile.Description
		if sessionPublishMode == "subdomain" {
			if base, err := c.server.builderPublishBaseDomain(sessionPublishTarget); err == nil {
				sessionPublishResolved = base
			}
		}
	}
	profiles := make([]any, 0, len(config.BuilderProfile))
	for _, name := range slices.Sorted(maps.Keys(config.BuilderProfile)) {
		entry := config.BuilderProfile[name]
		profileServices := entry.Services
		if profileServices == nil {
			profileServices = []string{}
		}
		profiles = append(profiles, map[string]any{
			"name":           name,
			"description":    entry.Description,
			"agent":          entry.Agent,
			"git_config":     entry.GitConfig,
			"publish_mode":   entry.PublishMode,
			"publish_target": entry.PublishTarget,
			"spec":           entry.Spec,
			"replace":        entry.Replace,
			"services":       profileServices,
		})
	}
	// Live services for the new-app Services checklist (offer computation
	// happens in the console per selected profile)
	allServices := []any{}
	if serviceRows, err := c.server.ListServices(ctx, "", ""); err == nil {
		for _, service := range serviceRows {
			allServices = append(allServices, map[string]any{
				"id":         service.ServiceType + "/" + service.Name,
				"type":       service.ServiceType,
				"name":       service.Name,
				"is_default": service.IsDefault,
			})
		}
	}
	gitConfigs := make([]any, 0, len(config.BuilderGit))
	for _, name := range slices.Sorted(maps.Keys(config.BuilderGit)) {
		entry := config.BuilderGit[name]
		gitConfigs = append(gitConfigs, map[string]any{
			"name":   name,
			"repo":   entry.Repo,
			"branch": entry.Branch,
		})
	}
	return map[string]any{
		"enabled":                 config.AppBuilder.Enabled,
		"mode":                    mode,
		"git_repo":                gitCfg.Repo,
		"git_branch":              gitCfg.Branch,
		"apps_file":               gitCfg.AppsFile,
		"source_dir":              gitCfg.SourceDir,
		"publish_mode":            sessionPublishMode,
		"publish_target":          sessionPublishTarget,
		"publish_target_resolved": sessionPublishResolved,
		"publish_desc":            sessionPublishDesc,
		"preview_path":            config.AppBuilder.PreviewPath,
		"default_builder_profile": config.AppBuilder.DefaultBuilderProfile,
		"git_configs":             gitConfigs,
		"all_services":            allServices,
		"agents":                  agents,
		"profiles":                profiles,
	}, nil
}

func (c *builderPlugin) ListActivity(ctx context.Context, call *sdk.Call) (any, error) {
	var id, afterId string
	limit := int64(200)
	if err := sdk.UnpackArgs("list_activity", call, "id", &id, "after_id?", &afterId, "limit?", &limit); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	entries, err := c.server.builderManager.ListActivity(ctx, session.Id, afterId, int(limit))
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(entries))
	for _, entry := range entries {
		result = append(result, map[string]any{
			"id":          entry.Id,
			"user_id":     entry.UserID,
			"kind":        entry.Kind,
			"content":     entry.Content,
			"metadata":    entry.Metadata,
			"create_time": entry.CreateTime.UTC(),
		})
	}
	return result, nil
}

func (c *builderPlugin) CreateSession(ctx context.Context, call *sdk.Call) (any, error) {
	var name, prompt, profile, editApp string
	var services []string
	if err := sdk.UnpackArgs("create_session", call, "name", &name, "prompt", &prompt,
		"profile?", &profile, "edit_app?", &editApp, "services?", &services); err != nil {
		return nil, err
	}
	if services == nil {
		services = []string{}
	}
	userID := call.Thread.UserId
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderCreate, userID); err != nil {
		return nil, err
	}
	session, err := c.server.builderCreateSession(ctx, userID, name, prompt,
		profile, editApp, services)
	if err != nil {
		return nil, err
	}
	return c.sessionToValue(session), nil
}

func (c *builderPlugin) SendMessage(ctx context.Context, call *sdk.Call) (any, error) {
	var id, message string
	if err := sdk.UnpackArgs("send_message", call, "id", &id, "message", &message); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.SendMessage(ctx, session.Id, call.Thread.UserId, message); err != nil {
		return nil, err
	}
	return nil, nil
}

// requireWriteSession authorizes session mutation: the owner needs
// builder:create; any other user's session requires the admin permission
func (c *builderPlugin) requireWriteSession(ctx context.Context, id string) (*types.BuilderSession, error) {
	session, err := c.server.builderManager.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if session.UserID != system.GetContextUserId(ctx) {
		if err := c.server.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		return session, nil
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderCreate, session.UserID); err != nil {
		return nil, err
	}
	return session, nil
}

func (c *builderPlugin) CancelTurn(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("cancel_turn", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.CancelTurn(session.Id); err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *builderPlugin) StopSession(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("stop_session", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.StopSession(session.Id, call.Thread.UserId); err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *builderPlugin) ResumeSession(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("resume_session", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.ResumeSession(ctx, session.Id, call.Thread.UserId); err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *builderPlugin) DeleteSession(ctx context.Context, call *sdk.Call) (any, error) {
	var id string
	if err := sdk.UnpackArgs("delete_session", call, "id", &id); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.builderDeleteSession(ctx, session.Id, call.Thread.UserId); err != nil {
		return nil, err
	}
	return nil, nil
}

// CheckPublishPath validates a publish target for a session without
// publishing: normalization, the profile's publish restriction and the app
// RBAC permissions all run exactly as a real publish would. Returns the
// normalized path and whether an app already exists there (a republish)
func (c *builderPlugin) CheckPublishPath(ctx context.Context, call *sdk.Call) (any, error) {
	var id, path string
	if err := sdk.UnpackArgs("check_publish_path", call, "id", &id, "path", &path); err != nil {
		return nil, err
	}
	session, err := c.requireSession(ctx, id, types.PermissionBuilderPublish)
	if err != nil {
		return nil, err
	}
	publishPath, _, err := c.server.builderCheckPublishPath(ctx, path, session)
	if err != nil {
		return nil, err
	}
	resolvedPath, resolvedPathDomain, err := c.server.builderResolvePath(publishPath)
	if err != nil {
		return nil, err
	}
	_, exists, err := c.server.findAppInfo(resolvedPathDomain)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"path":     publishPath,
		"resolved": resolvedPath,
		"exists":   exists,
	}, nil
}

func (c *builderPlugin) PublishApp(ctx context.Context, call *sdk.Call) (any, error) {
	var id, path, commitMsg string
	if err := sdk.UnpackArgs("publish_app", call, "id", &id, "path", &path,
		"commit_msg?", &commitMsg); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderPublish, session.UserID); err != nil {
		return nil, err
	}
	message := commitMsg
	if message == "" {
		message = fmt.Sprintf("Add app %s (built with OpenRun Builder)", path)
	}
	result, err := c.server.builderPublish(ctx, session.Id, path, message)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

func (c *builderPlugin) UnpublishApp(ctx context.Context, call *sdk.Call) (any, error) {
	var id, commitMsg string
	if err := sdk.UnpackArgs("unpublish_app", call, "id", &id, "commit_msg?", &commitMsg); err != nil {
		return nil, err
	}
	session, err := c.requireWriteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderPublish, session.UserID); err != nil {
		return nil, err
	}
	result, err := c.server.builderUnpublish(ctx, session.Id, commitMsg)
	if err != nil {
		return nil, err
	}
	return structValue(result)
}

// VerifyConfig runs the builder config checklist. With test_prompt, each
// profile check also round-trips one real prompt (costs a model call)
func (c *builderPlugin) VerifyConfig(ctx context.Context, call *sdk.Call) (any, error) {
	var testPrompt bool
	if err := sdk.UnpackArgs("verify_config", call, "test_prompt?", &testPrompt); err != nil {
		return nil, err
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	checks := c.server.builderVerify(ctx, testPrompt)
	result := make([]any, 0, len(checks))
	for _, check := range checks {
		result = append(result, map[string]any{"name": check.Name, "ok": check.Ok, "detail": check.Detail})
	}
	return result, nil
}
