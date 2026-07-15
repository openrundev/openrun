// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitobject "github.com/go-git/go-git/v5/plumbing/object"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"time"
)

const (
	builderMarkerBegin = "# openrun-builder: begin "
	builderMarkerEnd   = "# openrun-builder: end "
	appSrcDir          = "app_src" // local publish root, relative to $OPENRUN_HOME
)

// initBuilder constructs the builder manager. Config validation runs here so
// an enabled-but-misconfigured builder fails server startup with a clear error
func (s *Server) initBuilder() error {
	s.builderManager = builder.NewManager(s.Logger, s.Config, s.db, func(input string) (string, error) {
		return s.secretsMgr().EvalTemplate(input)
	})
	s.builderManager.OnTurnDone = s.builderTurnDone
	return s.builderManager.ValidateConfig()
}

// BuilderManager returns the builder manager (used by the build.in plugin)
func (s *Server) BuilderManager() *builder.Manager {
	return s.builderManager
}

// builderCreateSession creates a session, seeding the workspace with the
// spec's scaffold files (create) or the app's current source (edit).
// editApp names a builder-published app this session modifies
func (s *Server) builderCreateSession(ctx context.Context, userID, name, prompt, spec, agent, promptPreset, editApp string) (*types.BuilderSession, error) {
	var editEntry *types.AppEntry
	if editApp != "" {
		entry, err := s.builderEditableApp(ctx, editApp)
		if err != nil {
			return nil, err
		}
		editEntry = entry
		editApp = entry.AppPathDomain().String()
		// The session inherits the app's spec; the workspace is seeded from
		// the app source, not the spec scaffold
		spec = string(entry.Metadata.Spec)
	}
	if editApp == "" && spec != "" {
		if _, ok := appTypes[spec]; !ok {
			return nil, fmt.Errorf("unknown spec %q", spec)
		}
	}
	// The seed callback runs inside CreateSession, after the workspace is
	// created and BEFORE the agent launches: the first prompt must never
	// race an empty or half-copied workspace, and a seed failure aborts the
	// create without leaving a session behind
	seed := func(session *types.BuilderSession) error {
		if editEntry != nil {
			// Seed from the app's current deployed version (the metadata file
			// store); generated *_gen files are included - non-dev installs
			// need them present in the source
			liveApp, err := s.GetApp(ctx, editEntry.AppPathDomain(), true)
			if err != nil {
				return fmt.Errorf("error loading app %s for editing: %w", editApp, err)
			}
			srcDir, err := liveApp.MaterializeSource()
			if err != nil {
				return fmt.Errorf("error materializing source of %s: %w", editApp, err)
			}
			defer os.RemoveAll(srcDir) //nolint:errcheck
			if err := copyAppSource(srcDir, session.WorkspaceDir); err != nil {
				return fmt.Errorf("error seeding workspace from %s: %w", editApp, err)
			}
			session.EditVersion = editEntry.Metadata.VersionMetadata.Version
			if s.isBuilderManaged(editEntry) {
				// In-place edit: the publish dialog targets the app being
				// edited. Fork sessions (unmanaged original) leave PublishPath
				// empty so the dialog offers the normal new-app destinations
				session.PublishPath = editApp
			}
			return nil
		}
		for fileName, content := range appTypes[spec] {
			target := filepath.Join(session.WorkspaceDir, filepath.FromSlash(fileName))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(target, []byte(content), 0644); err != nil {
				return fmt.Errorf("seeding spec file %s: %w", fileName, err)
			}
		}
		return nil
	}
	return s.builderManager.CreateSession(ctx, userID, name, prompt, spec, agent, promptPreset, editApp, seed)
}

// isBuilderManaged reports whether the builder can republish an app in
// place: flagged builder-published (set on local publishes), or sourced
// from a configured [builder_git.*] destination. Git publishes reach prod
// through sync applies of the apps.star declaration, which cannot carry
// the metadata flag - the source url match identifies them instead
func (s *Server) isBuilderManaged(entry *types.AppEntry) bool {
	if entry.Metadata.BuilderPublished {
		return true
	}
	_, _, err := s.matchBuilderGitBySource(entry.SourceUrl)
	return err == nil
}

// builderSourceName derives the published source directory name from the
// full publish target (domain + path): distinct targets like /teams/a and
// /other/a (or the same path on two domains) must never share a source
// directory - the second publish would overwrite the first app's source and
// unpublishing either would remove the shared directory
func builderSourceName(appPathDomain types.AppPathDomain) string {
	name := strings.Trim(appPathDomain.Path, "/")
	if appPathDomain.Domain != "" {
		name = appPathDomain.Domain + "_" + name
	}
	name = strings.ReplaceAll(name, "/", "_")
	return builderNameSanitizer.ReplaceAllString(strings.ToLower(name), "_")
}

var builderNameSanitizer = regexp.MustCompile(`[^a-z0-9._-]`)

// builderEditableApp validates that editApp names an app builder edit
// sessions support. Builder-managed apps (see isBuilderManaged) are edited
// in place; other apps can be edited too - read and write access to the
// original required - but publish then creates a NEW app (fork), the
// original is never updated
func (s *Server) builderEditableApp(ctx context.Context, editApp string) (*types.AppEntry, error) {
	appPathDomain, err := parseAppPath(editApp)
	if err != nil {
		return nil, err
	}
	apps, err := s.GetApps(ctx, appPathDomain.String(), false)
	if err != nil || len(apps) != 1 {
		return nil, fmt.Errorf("app %s not found", editApp)
	}
	entry := &apps[0].AppEntry
	if entry.IsDev {
		return nil, fmt.Errorf("app %s is a dev app; edit its source directory directly", editApp)
	}
	if s.rbacManager.APIEnforced(ctx) {
		// The app owner is passed so the owner rule applies: the creator of an
		// app can start an edit session on it without an explicit grant
		if err := s.enforceAppPerm(ctx, types.PermissionRead, appPathDomain, entry.UserID); err != nil {
			return nil, err
		}
		if err := s.enforceAppPerm(ctx, types.PermissionUpdate, appPathDomain, entry.UserID); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

// builderTurnDone runs after each completed prompt turn: once the workspace
// contains a loadable app definition, the preview dev app is created. Dev
// apps re-read disk source on every request, so later turns need no action
func (s *Server) builderTurnDone(sessionId string) {
	ctx := context.Background()
	session, err := s.builderManager.GetSession(ctx, sessionId)
	if err != nil || session.PreviewPath != "" {
		return
	}
	if _, err := os.Stat(filepath.Join(session.WorkspaceDir, "app.star")); err != nil {
		// no app definition yet; the agent may still be scaffolding
		return
	}

	// This callback is a system continuation of the RBAC checked builder calls
	// that ran the turn (create_session/send_message/resume_session all require
	// builder:create): creating the preview app under the configured preview
	// path is authorized by builder:create, not by app permissions (grant
	// targets rarely cover the preview mount). The context carries the session
	// creator so the preview app is OWNED by them - the owner rule then gives
	// them preview access and lets session deletion remove the app - and the
	// audit events are attributed
	ctx = newBackgroundOperationContext(cmp.Or(session.UserID, "builder"))

	previewPath := path.Join(s.Config().AppBuilder.PreviewPath, strings.TrimPrefix(sessionId, types.ID_PREFIX_BUILDER_SES)[:12])
	appRequest := &types.CreateAppRequest{
		Path:      previewPath,
		SourceUrl: session.WorkspaceDir,
		IsDev:     true,
		AppAuthn:  types.AppAuthnDefault,
		Spec:      types.AppSpec(session.Spec),
	}
	if _, err := s.CreateApp(ctx, previewPath, false, false, appRequest); err != nil {
		s.Warn().Err(err).Str("session", sessionId).Msg("Builder preview app creation failed")
		s.builderManager.LogActivity(sessionId, session.UserID, "error", "preview app creation failed: "+err.Error(), nil)
		return
	}

	session.PreviewPath = previewPath
	if err := s.builderManager.UpdateSessionInfo(ctx, session); err != nil {
		s.Warn().Err(err).Str("session", sessionId).Msg("Error saving preview path")
	}
	s.builderManager.LogActivity(sessionId, session.UserID, "lifecycle", "preview app created at "+previewPath,
		map[string]any{"preview_path": previewPath})
}

// builderDeleteSession deletes the preview app (if any) and then the session
func (s *Server) builderDeleteSession(ctx context.Context, sessionId, userID string) error {
	session, err := s.builderManager.GetSession(ctx, sessionId)
	if err != nil {
		return err
	}
	if session.PreviewPath != "" {
		if _, err := s.DeleteApps(ctx, session.PreviewPath, false); err != nil {
			// keep going: a manually deleted preview app must not wedge the session
			s.Warn().Err(err).Str("session", sessionId).Msg("Error deleting preview app")
		}
	}
	return s.builderManager.DeleteSession(ctx, sessionId, userID)
}

// BuilderPublishResponse is the publish/unpublish result
type BuilderPublishResponse struct {
	Mode        string `json:"mode"` // git or local
	PublishPath string `json:"publish_path"`
	Source      string `json:"source"`
	CommitSha   string `json:"commit_sha,omitempty"`
	Repo        string `json:"repo,omitempty"`
	Stanza      string `json:"stanza"`
}

// builderPublish publishes a session's app: source copy + an app() stanza in
// apps.star, committed to the configured git repo, or (local mode, no
// git_repo) applied immediately on this instance
func (s *Server) builderPublish(ctx context.Context, sessionId, publishPath, commitMsg string) (*BuilderPublishResponse, error) {
	config := s.Config()
	session, err := s.builderManager.GetSession(ctx, sessionId)
	if err != nil {
		return nil, err
	}
	if session.PreviewPath == "" {
		return nil, fmt.Errorf("session has no preview app yet, the app must load before publishing")
	}
	var forkFrom *types.AppEntry
	if session.EditApp != "" {
		origEntry, err := s.builderEditableApp(ctx, session.EditApp)
		if err != nil {
			return nil, err
		}
		if s.isBuilderManaged(origEntry) {
			// In-place edit: source changes push to the app's own
			// destination; the apps.star declaration is never touched
			return s.builderRepublishEdit(ctx, session, publishPath, commitMsg)
		}
		// Fork: the session edits an app not published by the builder. It
		// publishes as a NEW app with the normal destination options; the
		// stanza copies the original app's settings and the original app
		// is never updated
		forkFrom = origEntry
	}

	publishPath, appPathDomain, err := s.builderCheckPublishPath(ctx, publishPath)
	if err != nil {
		return nil, err
	}
	if forkFrom != nil && publishPath == session.EditApp {
		return nil, fmt.Errorf("app %s was not published by the app builder and cannot be updated directly; publish to a new app path instead", session.EditApp)
	}

	appName := builderSourceName(appPathDomain)
	gitCfg, err := config.ResolveBuilderGit(session.Preset)
	if err != nil {
		return nil, err
	}
	gitMode := gitCfg.Repo != ""

	var sourceUrl string
	if gitMode {
		sourceUrl = strings.TrimSuffix(gitCfg.Repo, "/") + "/" + path.Join(gitCfg.SourceDir, appName)
	} else {
		sourceUrl = filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), appSrcDir, appName)
	}

	// Create sessions export the preview app; fork sessions export the
	// ORIGINAL app so its settings (auth, params, container options,
	// bindings) carry over. Auto bindings export as service references,
	// which the apply re-materializes as fresh auto bindings for the new app
	exportPath := session.PreviewPath
	if forkFrom != nil {
		exportPath = forkFrom.AppPathDomain().String()
	}
	stanza, err := s.builderExportStanza(ctx, exportPath, publishPath, sourceUrl, gitCfg)
	if err != nil {
		return nil, err
	}

	response := &BuilderPublishResponse{PublishPath: publishPath, Source: sourceUrl, Stanza: stanza}
	if gitMode {
		response.Mode = "git"
		response.Repo = gitCfg.Repo
		sha, err := s.builderPublishGit(ctx, session, gitCfg, appName, publishPath, stanza, commitMsg, true, false)
		if err != nil {
			return nil, err
		}
		response.CommitSha = sha
	} else {
		response.Mode = "local"
		// A local publish creates and approves the app in one step
		if err := s.enforceAppPerm(ctx, types.PermissionApprove, appPathDomain, ""); err != nil {
			return nil, err
		}
		if err := s.builderPublishLocal(ctx, session, gitCfg, appName, publishPath, stanza); err != nil {
			return nil, err
		}
		// Mark the created app as builder-published: the flag gates edit
		// sessions. Apply updates merge metadata, so the flag sticks
		if err := s.setBuilderPublished(ctx, appPathDomain); err != nil {
			s.Warn().Err(err).Msgf("Error setting builder-published flag on %s", publishPath)
		}
	}

	session.PublishPath = publishPath
	session.Status = types.BuilderSessionPublished
	if err := s.builderManager.UpdateSessionInfo(ctx, session); err != nil {
		return nil, err
	}
	s.builderManager.LogActivity(sessionId, system.GetContextUserId(ctx), "publish",
		fmt.Sprintf("published to %s (%s mode)", publishPath, response.Mode),
		map[string]any{"publish_path": publishPath, "commit_sha": response.CommitSha, "source": sourceUrl})
	return response, nil
}

// builderRepublishEdit publishes an edit session: the workspace source
// replaces the app's source at its existing destination (the local app_src
// copy, or the repo directory matched from the app's source url). The
// apps.star declaration is never modified
func (s *Server) builderRepublishEdit(ctx context.Context, session *types.BuilderSession,
	publishPath, commitMsg string) (*BuilderPublishResponse, error) {
	if publishPath != "" && publishPath != session.EditApp {
		return nil, fmt.Errorf("edit sessions publish to the app being edited (%s); publishing to a different path is not supported", session.EditApp)
	}
	publishPath = session.EditApp
	appPathDomain, err := parseAppPath(publishPath)
	if err != nil {
		return nil, err
	}
	apps, err := s.GetApps(ctx, appPathDomain.String(), false)
	if err != nil || len(apps) != 1 {
		return nil, fmt.Errorf("app %s not found", publishPath)
	}
	entry := &apps[0].AppEntry
	if s.rbacManager.APIEnforced(ctx) {
		if err := s.enforceAppPerm(ctx, types.PermissionUpdate, appPathDomain, entry.UserID); err != nil {
			return nil, err
		}
	}
	// Concurrent-change guard: the version the publish builds on (staging
	// for prod apps - publishes land on staging first) must still be the one
	// this session was seeded from (a later republish from this session
	// advances the recorded version)
	baseVersion, err := s.builderPublishBaseVersion(ctx, entry)
	if err != nil {
		return nil, err
	}
	if baseVersion != session.EditVersion {
		return nil, fmt.Errorf("app %s changed since this edit session started (version %d, session is based on %d); start a new edit session",
			publishPath, baseVersion, session.EditVersion)
	}

	appName := builderSourceName(appPathDomain)
	if commitMsg == "" {
		commitMsg = "Update app source for " + publishPath
	}
	response := &BuilderPublishResponse{PublishPath: publishPath, Source: entry.SourceUrl}

	localRoot := filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), appSrcDir)
	if strings.HasPrefix(entry.SourceUrl, localRoot+string(filepath.Separator)) {
		// Local mode: replace the app's source directory and reload. The
		// approve check runs BEFORE the live source directory is replaced: a
		// denial afterwards would leave staged source that a later privileged
		// reload would deploy. The reload applies to STAGING only (staging
		// first, like the console app actions); promotion is a separate step
		// offered by the console when the caller holds app:promote
		response.Mode = "local"
		if err := s.enforceAppPerm(ctx, types.PermissionApprove, appPathDomain, entry.UserID); err != nil {
			return nil, err
		}
		if err := copyAppSource(session.WorkspaceDir, entry.SourceUrl); err != nil {
			return nil, fmt.Errorf("copying app source: %w", err)
		}
		if _, err := s.ReloadApps(ctx, appPathDomain.String(), true /*approve*/, false, /*dryRun*/
			false /*promote*/, "", "", "", false /*forceReload*/, false /*verify*/); err != nil {
			return nil, fmt.Errorf("reloading app: %w", err)
		}
		// Track the reloaded staging version so this session can republish again
		if apps, err := s.GetApps(ctx, appPathDomain.String(), false); err == nil && len(apps) == 1 {
			if version, err := s.builderPublishBaseVersion(ctx, &apps[0].AppEntry); err == nil {
				session.EditVersion = version
			}
		}
	} else {
		gitCfg, gitName, err := s.matchBuilderGitBySource(entry.SourceUrl)
		if err != nil {
			return nil, err
		}
		response.Mode = "git"
		response.Repo = gitCfg.Repo
		sha, err := s.builderPublishGit(ctx, session, gitCfg, appName, publishPath, "", commitMsg, false /*updateAppsFile*/, false)
		if err != nil {
			return nil, err
		}
		response.CommitSha = sha
		s.Info().Msgf("Builder edit republish of %s pushed to builder_git.%s", publishPath, gitName)
	}

	session.PublishPath = publishPath
	session.Status = types.BuilderSessionPublished
	if err := s.builderManager.UpdateSessionInfo(ctx, session); err != nil {
		return nil, err
	}
	s.builderManager.LogActivity(session.Id, system.GetContextUserId(ctx), "publish",
		fmt.Sprintf("updated source of %s (%s mode)", publishPath, response.Mode),
		map[string]any{"publish_path": publishPath, "commit_sha": response.CommitSha, "source": response.Source})
	return response, nil
}

// matchBuilderGitBySource finds the [builder_git.*] entry whose repo the
// app's source url points into (publish builds the url as repo/source_dir/
// name), with the entry field defaults applied
func (s *Server) matchBuilderGitBySource(sourceUrl string) (types.BuilderGitConfig, string, error) {
	config := s.Config()
	for name, entry := range config.BuilderGit {
		repo := strings.TrimSuffix(entry.Repo, "/")
		if repo == "" || !strings.HasPrefix(sourceUrl, repo+"/") {
			continue
		}
		if entry.Branch == "" {
			entry.Branch = types.BuilderGitDefaultBranch
		}
		if entry.AppsFile == "" {
			entry.AppsFile = types.BuilderGitDefaultAppsFile
		}
		if entry.SourceDir == "" {
			entry.SourceDir = types.BuilderGitDefaultSourceDir
		}
		return entry, name, nil
	}
	return types.BuilderGitConfig{}, "", fmt.Errorf("the app source %q does not match any [builder_git.*] repo; cannot determine the publish destination", sourceUrl)
}

// setBuilderPublished marks the app (and its linked stage app, so the flag
// survives promotes) as published by the builder, enabling edit sessions
func (s *Server) setBuilderPublished(ctx context.Context, appPathDomain types.AppPathDomain) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	entry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return err
	}
	targets := []*types.AppEntry{entry}
	if stagePathDomain, err := parseLinkedAppPathDomain(entry.LinkedAppPath); err == nil {
		if stageEntry, err := s.db.GetAppEntryTx(ctx, tx, stagePathDomain); err == nil {
			targets = append(targets, stageEntry)
		}
	}
	for _, target := range targets {
		if target.Metadata.BuilderPublished {
			continue
		}
		target.Metadata.BuilderPublished = true
		if err := s.db.UpdateAppMetadata(ctx, tx, target); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// builderCheckPublishPath validates the target path against the configured
// publish_paths globs and the caller's app:create authorization
func (s *Server) builderCheckPublishPath(ctx context.Context, publishPath string) (string, types.AppPathDomain, error) {
	// Normalize only the path component: targets may be domain qualified
	// (example.com:/teams/app), and the domain must survive normalization
	target := strings.TrimSpace(publishPath)
	domain := ""
	if idx := strings.Index(target, ":"); idx >= 0 {
		domain, target = target[:idx], target[idx+1:]
	}
	target = "/" + strings.Trim(target, "/")
	if target == "/" {
		return "", types.AppPathDomain{}, fmt.Errorf("publish path is required")
	}
	if domain != "" {
		target = domain + ":" + target
	}
	appPathDomain, err := parseAppPath(target)
	if err != nil {
		return "", types.AppPathDomain{}, err
	}
	publishPath = appPathDomain.String()

	// No configured [builder_publish.*] entries means any path is allowed
	// (RBAC still gates); with entries, the path must match one of them
	publishEntries := s.Config().BuilderPublish
	allowed := len(publishEntries) == 0
	for entryName, entry := range publishEntries {
		match, err := rbac.MatchGlob(entry.Path, appPathDomain)
		if err != nil {
			return "", types.AppPathDomain{}, fmt.Errorf("invalid builder_publish.%s path %q: %w", entryName, entry.Path, err)
		}
		if match {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", types.AppPathDomain{}, fmt.Errorf("path %s does not match any [builder_publish.*] entry", publishPath)
	}

	// The publish mutates the app at the target path (directly in local mode,
	// via the repo's sync in git mode): the same app permissions the direct app
	// APIs require apply, app:create for a new path and app:update (with the
	// owner rule) for a republish to an existing app
	if s.rbacManager.APIEnforced(ctx) {
		perm, owner := types.PermissionCreate, ""
		if appInfo, ok, err := s.findAppInfo(appPathDomain); err != nil {
			return "", types.AppPathDomain{}, err
		} else if ok {
			perm, owner = types.PermissionUpdate, appInfo.UserID
		}
		if err := s.enforceAppPerm(ctx, perm, appPathDomain, owner); err != nil {
			return "", types.AppPathDomain{}, err
		}
	}
	return publishPath, appPathDomain, nil
}

// findAppInfo looks up an app by path without any authorization check, for
// callers that only need existence and ownership
func (s *Server) findAppInfo(appPathDomain types.AppPathDomain) (types.AppInfo, bool, error) {
	allApps, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return types.AppInfo{}, false, err
	}
	for _, appInfo := range allApps {
		if appInfo.AppPathDomain == appPathDomain {
			return appInfo, true, nil
		}
	}
	return types.AppInfo{}, false, nil
}

// builderExportStanza renders the app() stanza for the published app: the
// exported definition of exportPath (the preview app for create sessions,
// the original app for forks) with path, source and dev mode rewritten to
// the publish destination
func (s *Server) builderExportStanza(ctx context.Context, exportPath,
	publishPath, sourceUrl string, gitCfg types.BuilderGitConfig) (string, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck

	exportPathDomain, err := parseAppPath(exportPath)
	if err != nil {
		return "", err
	}
	appEntry, err := s.db.GetAppEntryTx(ctx, tx, exportPathDomain)
	if err != nil {
		return "", fmt.Errorf("error reading app %s: %w", exportPath, err)
	}

	allBindings, err := s.db.ListBindings(ctx, tx, "")
	if err != nil {
		return "", err
	}
	bindingsByPath := make(map[string]*types.Binding, len(allBindings))
	for _, binding := range allBindings {
		bindingsByPath[binding.Path] = binding
	}

	exporter := newExportBuilder(types.ExportOptions{ServiceRef: types.ExportRefDefault, GitAuthRef: types.ExportRefDefault})
	req := s.exportApp(ctx, tx, appEntry, bindingsByPath, exporter)
	req.Path = publishPath
	req.SourceUrl = sourceUrl
	req.IsDev = false
	req.GitBranch = ""
	req.GitCommit = ""
	req.GitAuthName = ""
	if gitCfg.Repo != "" {
		req.GitBranch = gitCfg.Branch
		req.GitAuthName = gitCfg.Auth
	}

	stanza, warnings := formatApp(req)
	for _, warning := range warnings {
		stanza = "# WARNING: " + warning + "\n" + stanza
	}
	return stanza, nil
}

// builderPublishBaseVersion returns the version an edit session republish
// builds on: the staging app's version for prod apps (publishes land on
// staging first), the app's own version for dev apps
func (s *Server) builderPublishBaseVersion(ctx context.Context, entry *types.AppEntry) (int, error) {
	if entry.IsDev {
		return entry.Metadata.VersionMetadata.Version, nil
	}
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	stageEntry, err := s.getStageApp(ctx, tx, entry)
	if err != nil {
		return 0, err
	}
	return stageEntry.Metadata.VersionMetadata.Version, nil
}

// builderPublishLocal copies the workspace to $OPENRUN_HOME/app_src/<name>,
// updates the local apps.star and applies the entry immediately. The apply
// runs staging first: an update to an existing app lands on its staging app,
// promotion is a separate step offered by the console (a first publish
// creates the app, whose initial version is live on create)
func (s *Server) builderPublishLocal(ctx context.Context, session *types.BuilderSession,
	gitCfg types.BuilderGitConfig, appName, publishPath, stanza string) error {
	// Preflight everything the apply and reload below will enforce BEFORE the
	// shared apps file or source directory is touched: a denial after the copy
	// would leave staged changes that a later privileged apply would deploy.
	// The apply runs with approve set, so app:apply and app:approve are
	// needed (the caller checks app:approve too; app:reload for the
	// unchanged-stanza republish fallback is implied by app:update)
	if s.rbacManager.APIEnforced(ctx) {
		appPathDomain, err := parseAppPath(publishPath)
		if err != nil {
			return err
		}
		owner := ""
		if appInfo, ok, err := s.findAppInfo(appPathDomain); err != nil {
			return err
		} else if ok {
			owner = appInfo.UserID
		}
		if err := s.enforceAppPerm(ctx, types.PermissionApply, appPathDomain, owner); err != nil {
			return err
		}
		if err := s.enforceAppPerm(ctx, types.PermissionApprove, appPathDomain, owner); err != nil {
			return err
		}
	}

	root := filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), appSrcDir)
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	destDir := filepath.Join(root, appName)
	if err := copyAppSource(session.WorkspaceDir, destDir); err != nil {
		return fmt.Errorf("copying app source: %w", err)
	}

	appsFile := filepath.Join(root, gitCfg.AppsFile)
	if err := upsertMarkerBlockFile(appsFile, publishPath, stanza); err != nil {
		return err
	}

	resp, _, err := s.Apply(ctx, types.Transaction{}, appsFile, publishPath, true /*approve*/, false, /*dryRun*/
		false /*promote*/, types.AppReloadOptionUpdated, "", "", "", false /*clobber*/, false, /*forceReload*/
		false /*verify*/, "", nil, false)
	if err != nil {
		return err
	}
	// Apply is declarative: it reloads the app only when the app.star stanza
	// changed. A republish that changes only source files leaves the stanza
	// identical, so Apply skips the reload - the running app would keep
	// serving the old source and record no new version. When Apply neither
	// created nor reloaded the app, force a reload to load the updated source
	// and record a version (the edit-session republish does the same)
	if len(resp.CreateResults) == 0 && len(resp.ReloadResults) == 0 {
		_, err = s.ReloadApps(ctx, publishPath, true /*approve*/, false /*dryRun*/, false, /*promote*/
			"", "", "", true /*forceReload*/, false /*verify*/)
	}
	return err
}

// builderPublishGit clones the publish repo, copies the source, updates
// apps.star and pushes. One retry on push rejection (concurrent publish)
func (s *Server) builderPublishGit(ctx context.Context, session *types.BuilderSession,
	gitCfg types.BuilderGitConfig, appName, publishPath, stanza, commitMsg string, updateAppsFile, isRetry bool) (string, error) {
	repoCache, err := NewRepoCache(s)
	if err != nil {
		return "", err
	}
	auth, err := repoCache.createAuthMethod(gitCfg.Auth)
	if err != nil {
		return "", err
	}

	cloneDir, err := os.MkdirTemp("", "openrun-builder-publish")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(cloneDir) //nolint:errcheck

	repoUrl := gitCfg.Repo
	if !strings.Contains(repoUrl, "://") && !strings.HasPrefix(repoUrl, "git@") {
		repoUrl = "https://" + repoUrl
	}
	branch := gitCfg.Branch
	repo, err := git.PlainCloneContext(ctx, cloneDir, false, &git.CloneOptions{
		URL:           repoUrl,
		Auth:          auth,
		ReferenceName: gitBranchRef(branch),
		SingleBranch:  true,
		Depth:         1,
	})
	if err != nil {
		return "", fmt.Errorf("cloning %s: %w", repoUrl, err)
	}

	var updateErr error
	if session != nil {
		// publish: copy the source and (create sessions only) upsert the
		// stanza; edit sessions leave the apps file untouched
		destDir := filepath.Join(cloneDir, filepath.FromSlash(gitCfg.SourceDir), appName)
		if err := copyAppSource(session.WorkspaceDir, destDir); err != nil {
			return "", fmt.Errorf("copying app source: %w", err)
		}
		if updateAppsFile {
			updateErr = upsertMarkerBlockFile(filepath.Join(cloneDir, gitCfg.AppsFile), publishPath, stanza)
		}
	} else {
		// unpublish: remove the block and the source copy
		if err := removeMarkerBlockFile(filepath.Join(cloneDir, gitCfg.AppsFile), publishPath); err != nil {
			return "", err
		}
		updateErr = os.RemoveAll(filepath.Join(cloneDir, filepath.FromSlash(gitCfg.SourceDir), appName))
	}
	if updateErr != nil {
		return "", updateErr
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	if err := worktree.AddGlob("."); err != nil {
		return "", err
	}
	userId := system.GetContextUserId(ctx)
	commit, err := worktree.Commit(commitMsg, &git.CommitOptions{
		Author: &gitobject.Signature{Name: userId, Email: userId + "@openrun-builder", When: time.Now()},
	})
	if err != nil {
		if err == git.ErrEmptyCommit {
			return "", fmt.Errorf("nothing to publish: no changes since the last publish")
		}
		return "", err
	}

	if err := repo.PushContext(ctx, &git.PushOptions{Auth: auth}); err != nil {
		if !isRetry {
			// the remote may have moved (concurrent publish); retry once from a fresh clone
			s.Warn().Err(err).Msg("Builder publish push rejected, retrying once")
			return s.builderPublishGit(ctx, session, gitCfg, appName, publishPath, stanza, commitMsg, updateAppsFile, true)
		}
		return "", fmt.Errorf("pushing to %s: %w (retry also failed; publish again to retry)", repoUrl, err)
	}
	return commit.String(), nil
}

// builderUnpublish removes the app's marker block (and source copy). Git
// mode commits the removal; whether prod deletes the app is the sync
// entry's policy. Local mode also deletes the local app
func (s *Server) builderUnpublish(ctx context.Context, sessionId, commitMsg string) (*BuilderPublishResponse, error) {
	config := s.Config()
	session, err := s.builderManager.GetSession(ctx, sessionId)
	if err != nil {
		return nil, err
	}
	if session.EditApp != "" {
		return nil, fmt.Errorf("edit sessions cannot unpublish: the app declaration is not managed by this session")
	}
	if session.PublishPath == "" {
		return nil, fmt.Errorf("session %s is not published", sessionId)
	}
	publishPath := session.PublishPath
	unpubPathDomain, err := parseAppPath(publishPath)
	if err != nil {
		return nil, err
	}
	appName := builderSourceName(unpubPathDomain)
	response := &BuilderPublishResponse{PublishPath: publishPath}

	// Removing the published app needs app:delete on its path, same as the
	// direct delete API. Checked up front (before the apps file or repo is
	// touched) and for both modes: git mode removes the declaration the repo's
	// sync applies, without any direct app mutation on this server
	if s.rbacManager.APIEnforced(ctx) {
		owner := ""
		if appInfo, ok, err := s.findAppInfo(unpubPathDomain); err != nil {
			return nil, err
		} else if ok {
			owner = appInfo.UserID
		}
		if err := s.enforceAppPerm(ctx, types.PermissionDelete, unpubPathDomain, owner); err != nil {
			return nil, err
		}
	}

	gitCfg, err := config.ResolveBuilderGit(session.Preset)
	if err != nil {
		return nil, err
	}
	if gitCfg.Repo != "" {
		response.Mode = "git"
		if commitMsg == "" {
			commitMsg = "Unpublish app " + publishPath
		}
		sha, err := s.builderPublishGit(ctx, nil, gitCfg, appName, publishPath, "", commitMsg, true, false)
		if err != nil {
			return nil, err
		}
		response.CommitSha = sha
	} else {
		response.Mode = "local"
		root := filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), appSrcDir)
		if err := removeMarkerBlockFile(filepath.Join(root, gitCfg.AppsFile), publishPath); err != nil {
			return nil, err
		}
		if _, err := s.DeleteApps(ctx, publishPath, false); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(filepath.Join(root, appName)); err != nil {
			return nil, err
		}
	}

	session.PublishPath = ""
	session.Status = types.BuilderSessionReady
	if err := s.builderManager.UpdateSessionInfo(ctx, session); err != nil {
		return nil, err
	}
	s.builderManager.LogActivity(sessionId, system.GetContextUserId(ctx), "unpublish",
		"unpublished "+publishPath, map[string]any{"publish_path": publishPath, "commit_sha": response.CommitSha})
	return response, nil
}

// builderSkipDirs are the VCS and agent artifact directories excluded when
// the workspace source is copied for publish or bundled for download
var builderSkipDirs = map[string]bool{".git": true, "node_modules": true, "__pycache__": true,
	".venv": true, ".claude": true, ".codex": true, ".opencode": true, ".pi": true}

// copyAppSource copies the workspace source tree, excluding VCS and agent
// artifacts. The destination is replaced
func copyAppSource(srcDir, destDir string) error {
	skipDirs := builderSkipDirs
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	return filepath.WalkDir(srcDir, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, current)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(destDir, rel), 0755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destDir, rel), data, 0644)
	})
}

// writeBuilderSourceZip bundles the session workspace (minus VCS/agent
// artifacts, same exclusions as publish) into a zip written to w. It runs as
// a download stream producer at response-write time: the archive flows
// through the response buffer to the client (chunked) with backpressure, so
// it is never fully held in memory or staged to disk or the db
func writeBuilderSourceZip(workspaceDir string, w io.Writer) error {
	writer := zip.NewWriter(w)

	err := filepath.WalkDir(workspaceDir, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if builderSkipDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(workspaceDir, current)
		if err != nil {
			return err
		}
		dest, err := writer.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		src, err := os.Open(current)
		if err != nil {
			return err
		}
		defer src.Close() //nolint:errcheck
		_, err = io.Copy(dest, src)
		return err
	})
	if err != nil {
		writer.Close() //nolint:errcheck
		return err
	}
	return writer.Close()
}

// upsertMarkerBlockFile inserts or replaces the app's marker block in the
// apps file, creating the file (with a header) if missing
func upsertMarkerBlockFile(appsFile, appPath, stanza string) error {
	content := "# Declarative app definitions published by the OpenRun app builder.\n" +
		"# Blocks between openrun-builder markers are managed by publish/unpublish;\n" +
		"# content outside the markers is never modified.\n"
	if data, err := os.ReadFile(appsFile); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return err
	}

	updated, err := upsertMarkerBlock(content, appPath, stanza)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(appsFile), 0755); err != nil {
		return err
	}
	return os.WriteFile(appsFile, []byte(updated), 0644)
}

func removeMarkerBlockFile(appsFile, appPath string) error {
	data, err := os.ReadFile(appsFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", appsFile, err)
	}
	updated, found, err := removeMarkerBlock(string(data), appPath)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no builder block for %s in %s", appPath, appsFile)
	}
	return os.WriteFile(appsFile, []byte(updated), 0644)
}

// upsertMarkerBlock replaces the marker block for appPath, or appends one.
// Content outside marker blocks is preserved byte for byte
func upsertMarkerBlock(content, appPath, stanza string) (string, error) {
	block := builderMarkerBegin + appPath + "\n" + strings.TrimRight(stanza, "\n") + "\n" + builderMarkerEnd + appPath + "\n"
	begin, end, err := findMarkerBlock(content, appPath)
	if err != nil {
		return "", err
	}
	if begin < 0 {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + "\n" + block, nil
	}
	return content[:begin] + block + content[end:], nil
}

func removeMarkerBlock(content, appPath string) (string, bool, error) {
	begin, end, err := findMarkerBlock(content, appPath)
	if err != nil {
		return "", false, err
	}
	if begin < 0 {
		return content, false, nil
	}
	updated := content[:begin] + content[end:]
	return strings.TrimLeft(updated, "\n"), true, nil
}

// findMarkerBlock locates the block for appPath, matching marker lines
// exactly (so /teams/pto never matches /teams/pto2's markers). Returns
// begin=-1 when absent; errors on broken markers rather than guessing
func findMarkerBlock(content, appPath string) (int, int, error) {
	beginLine := builderMarkerBegin + appPath
	endLine := builderMarkerEnd + appPath

	begin, end := -1, -1
	offset := 0
	for _, line := range strings.SplitAfter(content, "\n") {
		trimmed := strings.TrimRight(line, "\n")
		switch trimmed {
		case beginLine:
			if begin >= 0 {
				return -1, -1, fmt.Errorf("duplicate begin marker for %s", appPath)
			}
			begin = offset
		case endLine:
			if begin < 0 {
				return -1, -1, fmt.Errorf("end marker without begin marker for %s", appPath)
			}
			if end < 0 {
				end = offset + len(line)
			}
		}
		offset += len(line)
	}
	if begin >= 0 && end < 0 {
		return -1, -1, fmt.Errorf("begin marker without end marker for %s", appPath)
	}
	return begin, end, nil
}

func gitBranchRef(branch string) plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(branch)
}

// ListAgentContainers lists the app builder's agent containers
// (docker/podman label filter). Empty on the Kubernetes backend, where the
// builder is not supported. "Agent" is the app builder's AI container;
// "builder" containers elsewhere (kaniko) are image builds
func (s *Server) ListAgentContainers(ctx context.Context) ([]ContainerInfo, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionContainerRead, ""); err != nil {
		return nil, err
	}
	runtime := s.containerRuntime()
	if runtime == "" || runtime == types.CONTAINER_KUBERNETES {
		return []ContainerInfo{}, nil
	}
	out, err := runContainerCmd(ctx, runtime, "ps", "--all",
		"--filter", "label="+builder.SandboxLabelFilter, "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("error listing agent containers: %s : %s", out, err)
	}
	entries, err := parseJSONObjects(out)
	if err != nil {
		return nil, err
	}
	infos := make([]ContainerInfo, 0, len(entries))
	for _, entry := range entries {
		labels := entryLabels(entry)
		infos = append(infos, ContainerInfo{
			Id:      entryString(entry, "ID", "Id"),
			Name:    entryNames(entry),
			AppPath: labels[builder.SandboxSessionLabel],
			Image:   entryString(entry, "Image"),
			State:   entryString(entry, "State"),
			Status:  entryString(entry, "Status"),
			Runtime: runtime,
		})
	}
	return infos, nil
}

// ListKanikoBuildContainers lists the kaniko image build pods (Kubernetes
// backend only; docker/podman builds run in-process)
func (s *Server) ListKanikoBuildContainers(ctx context.Context) ([]ContainerInfo, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionContainerRead, ""); err != nil {
		return nil, err
	}
	if s.containerRuntime() != types.CONTAINER_KUBERNETES {
		return []ContainerInfo{}, nil
	}
	pods, err := container.ListWorkloadPodsSelector(ctx, s.Config(), "app=kaniko")
	if err != nil {
		return nil, err
	}
	infos := make([]ContainerInfo, 0, len(pods))
	for _, pod := range pods {
		infos = append(infos, kubernetesPodInfo(&pod))
	}
	return infos, nil
}

// BuilderCheck is one row of the builder config verification checklist
type BuilderCheck struct {
	Name   string `json:"name"`
	Ok     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// builderVerify runs the builder config checklist: base config (runtime
// reachable, not Kubernetes, profiles valid), a full sandbox check per
// profile (image build + ACP handshake, optionally a test prompt) and the
// publish configuration
func (s *Server) builderVerify(ctx context.Context, testPrompt bool) []BuilderCheck {
	config := s.Config()
	checks := []BuilderCheck{}
	appendCheck := func(name string, err error, okDetail string) bool {
		check := BuilderCheck{Name: name, Ok: err == nil, Detail: okDetail}
		if err != nil {
			check.Detail = err.Error()
		}
		checks = append(checks, check)
		return err == nil
	}

	if !config.AppBuilder.Enabled {
		return append(checks, BuilderCheck{Name: "enabled", Ok: false, Detail: "app_builder.enabled is false"})
	}
	if !appendCheck("config", s.builderManager.ValidateConfig(), "container runtime found, agent profiles valid") {
		return checks
	}

	for name := range config.BuilderAgent {
		detail := "image built, ACP handshake ok"
		if testPrompt {
			detail += ", test prompt ok"
		}
		appendCheck("agent "+name, s.builderManager.VerifyProfile(ctx, name, testPrompt), detail)
	}

	for entryName, entry := range config.BuilderPublish {
		if _, err := rbac.MatchGlob(entry.Path, types.AppPathDomain{Domain: "localhost", Path: "/probe"}); err != nil {
			appendCheck("builder_publish."+entryName, fmt.Errorf("invalid path glob %q: %w", entry.Path, err), "")
		}
	}

	// Every [builder_git.*] destination is checked for reachability
	for _, name := range slices.Sorted(maps.Keys(config.BuilderGit)) {
		gitCfg := config.BuilderGit[name]
		if gitCfg.Branch == "" {
			gitCfg.Branch = types.BuilderGitDefaultBranch
		}
		checkErr := func() error {
			repoCache, err := NewRepoCache(s)
			if err != nil {
				return err
			}
			auth, err := repoCache.createAuthMethod(gitCfg.Auth)
			if err != nil {
				return err
			}
			repoUrl := gitCfg.Repo
			if !strings.Contains(repoUrl, "://") && !strings.HasPrefix(repoUrl, "git@") {
				repoUrl = "https://" + repoUrl
			}
			_, err = latestCommitSHA(repoUrl, gitCfg.Branch, auth)
			return err
		}()
		appendCheck("publish (git "+name+")", checkErr,
			fmt.Sprintf("%s branch %s reachable", gitCfg.Repo, gitCfg.Branch))
	}
	// Local mode applies whenever a session's preset and the builder default
	// pick no git destination, so its writability is always checked
	root := filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), appSrcDir)
	checkErr := func() error {
		if err := os.MkdirAll(root, 0755); err != nil {
			return err
		}
		probe := filepath.Join(root, ".openrun-verify")
		if err := os.WriteFile(probe, []byte("ok"), 0600); err != nil {
			return err
		}
		return os.Remove(probe)
	}()
	appendCheck("publish (local)", checkErr, root+" is writable")
	return checks
}
