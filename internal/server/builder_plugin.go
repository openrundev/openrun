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
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// initBuilderPlugin registers the build.in plugin: the app builder APIs used
// by the console Builder tab
func initBuilderPlugin(server *Server) {
	c := &builderPlugin{}
	pluginFuncs := []plugin.PluginFunc{
		app.CreatePluginApiName(c.ListSessions, app.READ, "list_sessions"),
		app.CreatePluginApiName(c.GetSession, app.READ, "get_session"),
		app.CreatePluginApiName(c.GetMessages, app.READ, "get_messages"),
		app.CreatePluginApiName(c.SessionEvents, app.READ, "session_events"),
		app.CreatePluginApiName(c.ListFiles, app.READ, "list_files"),
		app.CreatePluginApiName(c.ReadFile, app.READ, "read_file"),
		app.CreatePluginApiName(c.GetSourceZip, app.READ, "get_source_zip"),
		app.CreatePluginApiName(c.GetPublishConfig, app.READ, "get_publish_config"),
		app.CreatePluginApiName(c.ListActivity, app.READ, "list_activity"),
		app.CreatePluginApiName(c.CreateSession, app.WRITE, "create_session"),
		app.CreatePluginApiName(c.SendMessage, app.WRITE, "send_message"),
		app.CreatePluginApiName(c.CancelTurn, app.WRITE, "cancel_turn"),
		app.CreatePluginApiName(c.StopSession, app.WRITE, "stop_session"),
		app.CreatePluginApiName(c.ResumeSession, app.WRITE, "resume_session"),
		app.CreatePluginApiName(c.DeleteSession, app.WRITE, "delete_session"),
		app.CreatePluginApiName(c.CheckPublishPath, app.READ, "check_publish_path"),
		app.CreatePluginApiName(c.PublishApp, app.WRITE, "publish_app"),
		app.CreatePluginApiName(c.UnpublishApp, app.WRITE, "unpublish_app"),
		app.CreatePluginApiName(c.VerifyConfig, app.WRITE, "verify_config"),
	}

	newBuilderPlugin := func(pluginContext *types.PluginContext) (any, error) {
		return &builderPlugin{server: server, pluginContext: pluginContext}, nil
	}
	app.RegisterSystemPlugin("build", newBuilderPlugin, pluginFuncs)
}

type builderPlugin struct {
	server        *Server
	pluginContext *types.PluginContext
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

func (c *builderPlugin) sessionToStarlark(session *types.BuilderSession) (starlark.Value, error) {
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
	return starlark_type.ConvertToStarlark(map[string]any{
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
		"create_time":           session.CreateTime.UTC().Format("2006-01-02T15:04:05Z"),
		"update_time":           session.UpdateTime.UTC().Format("2006-01-02T15:04:05Z"),
		"workspace_dir":         session.WorkspaceDir,
	})
}

// ListSessions lists builder sessions: one's own with builder:list, everyone's
// with all_users (requires the admin permission)
func (c *builderPlugin) ListSessions(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var allUsers starlark.Bool
	if err := starlark.UnpackArgs("list_sessions", args, kwargs, "all_users?", &allUsers); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	userID := system.GetContextUserId(ctx)
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderList, userID); err != nil {
		return nil, err
	}
	filterUser := userID
	if bool(allUsers) {
		if err := c.server.enforceGlobalPerm(ctx, types.PermissionAdmin, ""); err != nil {
			return nil, err
		}
		filterUser = ""
	}
	sessions, err := c.server.builderManager.ListSessions(ctx, filterUser)
	if err != nil {
		return nil, err
	}
	ret := starlark.List{}
	for _, session := range sessions {
		value, err := c.sessionToStarlark(session)
		if err != nil {
			return nil, err
		}
		ret.Append(value) //nolint:errcheck
	}
	return &ret, nil
}

func (c *builderPlugin) GetSession(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("get_session", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	return c.sessionToStarlark(session)
}

// GetMessages returns the transcript: activity rows plus the live in-flight
// turn state (partial agent message)
func (c *builderPlugin) GetMessages(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, afterId starlark.String
	if err := starlark.UnpackArgs("get_messages", args, kwargs, "id", &id, "after_id?", &afterId); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}

	entries, err := c.server.builderManager.ListActivity(ctx, session.Id, afterId.GoString(), 0)
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
			"create_time": entry.CreateTime.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	isLive, turnActive, partial := c.server.builderManager.LiveState(session.Id)
	return starlark_type.ConvertToStarlark(map[string]any{
		"messages":    messages,
		"is_live":     isLive,
		"turn_active": turnActive,
		"partial":     partial,
		"status":      string(session.Status),
	})
}

// SessionEvents streams session events (message chunks, tool calls, status)
// as JSON lines until the client disconnects
func (c *builderPlugin) SessionEvents(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("session_events", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
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
	return app.NewStreamResponse(stream), nil
}

func (c *builderPlugin) ListFiles(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("list_files", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	files, err := c.server.builderManager.ListFiles(ctx, session.Id)
	if err != nil {
		return nil, err
	}
	ret := starlark.List{}
	for _, file := range files {
		ret.Append(starlark.String(file)) //nolint:errcheck
	}
	return &ret, nil
}

func (c *builderPlugin) ReadFile(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, path starlark.String
	if err := starlark.UnpackArgs("read_file", args, kwargs, "id", &id, "path", &path); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	content, err := c.server.builderManager.ReadFile(ctx, session.Id, path.GoString())
	if err != nil {
		return nil, err
	}
	return starlark.String(content), nil
}

// GetSourceZip returns a download value whose content is a lazily produced
// zip of the session workspace. The zip is built at response-write time by
// the download handler, streaming to the client (chunked) with backpressure,
// so the archive is never fully held in memory or staged to disk or the db
func (c *builderPlugin) GetSourceZip(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("get_source_zip", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}

	workspaceDir := session.WorkspaceDir
	stream := starlark_type.NewDownloadStream(builderZipName(session.Name), func(w io.Writer) error {
		return writeBuilderSourceZip(workspaceDir, w)
	})
	return zipDownloadValue(stream), nil
}

// zipDownloadValue builds the {content, name} value returned by the zip
// download plugin APIs. content is an opaque download stream (constructible
// only from plugin Go code) that the download response handler drains at
// response-write time; name is the attachment file name
func zipDownloadValue(stream *starlark_type.DownloadStream) starlark.Value {
	dict := starlark.NewDict(2)
	dict.SetKey(starlark.String("content"), stream)                      //nolint:errcheck
	dict.SetKey(starlark.String("name"), starlark.String(stream.Name())) //nolint:errcheck
	return dict
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
func (c *builderPlugin) GetPublishConfig(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sessionId starlark.String
	if err := starlark.UnpackArgs("get_publish_config", args, kwargs, "session_id?", &sessionId); err != nil {
		return nil, err
	}
	config := c.server.Config()
	ctx := system.GetRequestContext(thread)

	sessionProfile := ""
	editApp := ""
	if sessionId.GoString() != "" {
		session, err := c.requireSession(ctx, sessionId.GoString(), types.PermissionBuilderList)
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
		if apps, appsErr := c.server.GetApps(system.GetRequestContext(thread), editApp, false); appsErr == nil && len(apps) == 1 &&
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
	return starlark_type.ConvertToStarlark(map[string]any{
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
	})
}

func (c *builderPlugin) ListActivity(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, afterId starlark.String
	limit := starlark.MakeInt(200)
	if err := starlark.UnpackArgs("list_activity", args, kwargs, "id", &id, "after_id?", &afterId, "limit?", &limit); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderList)
	if err != nil {
		return nil, err
	}
	limitInt, _ := limit.Int64()
	entries, err := c.server.builderManager.ListActivity(ctx, session.Id, afterId.GoString(), int(limitInt))
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
			"create_time": entry.CreateTime.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return starlark_type.ConvertToStarlark(result)
}

func (c *builderPlugin) CreateSession(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, prompt, profile, editApp starlark.String
	var servicesList *starlark.List
	if err := starlark.UnpackArgs("create_session", args, kwargs, "name", &name, "prompt", &prompt,
		"profile?", &profile, "edit_app?", &editApp, "services?", &servicesList); err != nil {
		return nil, err
	}
	services := []string{}
	if servicesList != nil {
		for entry := range servicesList.Elements() {
			if str, ok := starlark.AsString(entry); ok {
				services = append(services, str)
			}
		}
	}
	ctx := system.GetRequestContext(thread)
	userID := system.GetContextUserId(ctx)
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderCreate, userID); err != nil {
		return nil, err
	}
	session, err := c.server.builderCreateSession(ctx, userID, name.GoString(), prompt.GoString(),
		profile.GoString(), editApp.GoString(), services)
	if err != nil {
		return nil, err
	}
	return c.sessionToStarlark(session)
}

func (c *builderPlugin) SendMessage(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, message starlark.String
	if err := starlark.UnpackArgs("send_message", args, kwargs, "id", &id, "message", &message); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.SendMessage(ctx, session.Id, system.GetContextUserId(ctx), message.GoString()); err != nil {
		return nil, err
	}
	return starlark.None, nil
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

func (c *builderPlugin) CancelTurn(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("cancel_turn", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.CancelTurn(session.Id); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (c *builderPlugin) StopSession(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("stop_session", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.StopSession(session.Id, system.GetContextUserId(ctx)); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (c *builderPlugin) ResumeSession(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("resume_session", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.builderManager.ResumeSession(ctx, session.Id, system.GetContextUserId(ctx)); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (c *builderPlugin) DeleteSession(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id starlark.String
	if err := starlark.UnpackArgs("delete_session", args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.builderDeleteSession(ctx, session.Id, system.GetContextUserId(ctx)); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// CheckPublishPath validates a publish target for a session without
// publishing: normalization, the profile's publish restriction and the app
// RBAC permissions all run exactly as a real publish would. Returns the
// normalized path and whether an app already exists there (a republish)
func (c *builderPlugin) CheckPublishPath(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, path starlark.String
	if err := starlark.UnpackArgs("check_publish_path", args, kwargs, "id", &id, "path", &path); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireSession(ctx, id.GoString(), types.PermissionBuilderPublish)
	if err != nil {
		return nil, err
	}
	publishPath, _, err := c.server.builderCheckPublishPath(ctx, path.GoString(), session)
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
	return starlark_type.ConvertToStarlark(map[string]any{
		"path":     publishPath,
		"resolved": resolvedPath,
		"exists":   exists,
	})
}

func (c *builderPlugin) PublishApp(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, path, commitMsg starlark.String
	if err := starlark.UnpackArgs("publish_app", args, kwargs, "id", &id, "path", &path,
		"commit_msg?", &commitMsg); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderPublish, session.UserID); err != nil {
		return nil, err
	}
	message := commitMsg.GoString()
	if message == "" {
		message = fmt.Sprintf("Add app %s (built with OpenRun Builder)", path.GoString())
	}
	result, err := c.server.builderPublish(ctx, session.Id, path.GoString(), message)
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

func (c *builderPlugin) UnpublishApp(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, commitMsg starlark.String
	if err := starlark.UnpackArgs("unpublish_app", args, kwargs, "id", &id, "commit_msg?", &commitMsg); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	session, err := c.requireWriteSession(ctx, id.GoString())
	if err != nil {
		return nil, err
	}
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionBuilderPublish, session.UserID); err != nil {
		return nil, err
	}
	result, err := c.server.builderUnpublish(ctx, session.Id, commitMsg.GoString())
	if err != nil {
		return nil, err
	}
	return starlark_type.ConvertToStarlark(result)
}

// VerifyConfig runs the builder config checklist. With test_prompt, each
// profile check also round-trips one real prompt (costs a model call)
func (c *builderPlugin) VerifyConfig(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var testPrompt starlark.Bool
	if err := starlark.UnpackArgs("verify_config", args, kwargs, "test_prompt?", &testPrompt); err != nil {
		return nil, err
	}
	ctx := system.GetRequestContext(thread)
	if err := c.server.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	checks := c.server.builderVerify(ctx, bool(testPrompt))
	result := make([]any, 0, len(checks))
	for _, check := range checks {
		result = append(result, map[string]any{"name": check.Name, "ok": check.Ok, "detail": check.Detail})
	}
	return starlark_type.ConvertToStarlark(result)
}
