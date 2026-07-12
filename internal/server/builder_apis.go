// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
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
// spec's scaffold files first
func (s *Server) builderCreateSession(ctx context.Context, userID, name, prompt, spec, agent, promptPreset string) (*types.BuilderSession, error) {
	if spec != "" {
		if _, ok := appTypes[spec]; !ok {
			return nil, fmt.Errorf("unknown spec %q", spec)
		}
	}
	session, err := s.builderManager.CreateSession(ctx, userID, name, prompt, spec, agent, promptPreset)
	if err != nil {
		return nil, err
	}
	if spec != "" {
		for fileName, content := range appTypes[spec] {
			target := filepath.Join(session.WorkspaceDir, filepath.FromSlash(fileName))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(target, []byte(content), 0644); err != nil {
				return nil, fmt.Errorf("seeding spec file %s: %w", fileName, err)
			}
		}
	}
	return session, nil
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

	publishPath, appPathDomain, err := s.builderCheckPublishPath(ctx, publishPath)
	if err != nil {
		return nil, err
	}

	appName := path.Base(publishPath)
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

	stanza, err := s.builderExportStanza(ctx, session, publishPath, sourceUrl, gitCfg)
	if err != nil {
		return nil, err
	}

	response := &BuilderPublishResponse{PublishPath: publishPath, Source: sourceUrl, Stanza: stanza}
	if gitMode {
		response.Mode = "git"
		response.Repo = gitCfg.Repo
		sha, err := s.builderPublishGit(ctx, session, gitCfg, appName, publishPath, stanza, commitMsg, false)
		if err != nil {
			return nil, err
		}
		response.CommitSha = sha
	} else {
		response.Mode = "local"
		if err := s.enforceAppPerm(ctx, types.PermissionApprove, appPathDomain, ""); err != nil {
			return nil, err
		}
		if err := s.builderPublishLocal(ctx, session, gitCfg, appName, publishPath, stanza); err != nil {
			return nil, err
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

// builderCheckPublishPath validates the target path against the configured
// publish_paths globs and the caller's app:create authorization
func (s *Server) builderCheckPublishPath(ctx context.Context, publishPath string) (string, types.AppPathDomain, error) {
	publishPath = "/" + strings.Trim(strings.TrimSpace(publishPath), "/")
	if publishPath == "/" {
		return "", types.AppPathDomain{}, fmt.Errorf("publish path is required")
	}
	appPathDomain, err := parseAppPath(publishPath)
	if err != nil {
		return "", types.AppPathDomain{}, err
	}

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

	if s.rbacManager.APIEnforced(ctx) {
		if err := s.enforceAppPerm(ctx, types.PermissionCreate, appPathDomain, ""); err != nil {
			return "", types.AppPathDomain{}, err
		}
	}
	return publishPath, appPathDomain, nil
}

// builderExportStanza renders the app() stanza for the published app: the
// preview app's exported definition with path, source and dev mode rewritten
// to the publish destination
func (s *Server) builderExportStanza(ctx context.Context, session *types.BuilderSession,
	publishPath, sourceUrl string, gitCfg types.BuilderGitConfig) (string, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck

	previewPathDomain, err := parseAppPath(session.PreviewPath)
	if err != nil {
		return "", err
	}
	appEntry, err := s.db.GetAppEntryTx(ctx, tx, previewPathDomain)
	if err != nil {
		return "", fmt.Errorf("error reading preview app %s: %w", session.PreviewPath, err)
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

// builderPublishLocal copies the workspace to $OPENRUN_HOME/app_src/<name>,
// updates the local apps.star and applies the entry immediately
func (s *Server) builderPublishLocal(ctx context.Context, session *types.BuilderSession,
	gitCfg types.BuilderGitConfig, appName, publishPath, stanza string) error {
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

	_, _, err := s.Apply(ctx, types.Transaction{}, appsFile, publishPath, true /*approve*/, false, /*dryRun*/
		true /*promote*/, types.AppReloadOptionUpdated, "", "", "", false /*clobber*/, false, /*forceReload*/
		false /*verify*/, "", nil, false)
	return err
}

// builderPublishGit clones the publish repo, copies the source, updates
// apps.star and pushes. One retry on push rejection (concurrent publish)
func (s *Server) builderPublishGit(ctx context.Context, session *types.BuilderSession,
	gitCfg types.BuilderGitConfig, appName, publishPath, stanza, commitMsg string, isRetry bool) (string, error) {
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
		// publish: copy the source and upsert the stanza
		destDir := filepath.Join(cloneDir, filepath.FromSlash(gitCfg.SourceDir), appName)
		if err := copyAppSource(session.WorkspaceDir, destDir); err != nil {
			return "", fmt.Errorf("copying app source: %w", err)
		}
		updateErr = upsertMarkerBlockFile(filepath.Join(cloneDir, gitCfg.AppsFile), publishPath, stanza)
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
			return s.builderPublishGit(ctx, session, gitCfg, appName, publishPath, stanza, commitMsg, true)
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
	if session.PublishPath == "" {
		return nil, fmt.Errorf("session %s is not published", sessionId)
	}
	publishPath := session.PublishPath
	appName := path.Base(publishPath)
	response := &BuilderPublishResponse{PublishPath: publishPath}

	gitCfg, err := config.ResolveBuilderGit(session.Preset)
	if err != nil {
		return nil, err
	}
	if gitCfg.Repo != "" {
		response.Mode = "git"
		if commitMsg == "" {
			commitMsg = "Unpublish app " + publishPath
		}
		sha, err := s.builderPublishGit(ctx, nil, gitCfg, appName, publishPath, "", commitMsg, false)
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

// copyAppSource copies the workspace source tree, excluding VCS and agent
// artifacts. The destination is replaced
func copyAppSource(srcDir, destDir string) error {
	skipDirs := map[string]bool{".git": true, "node_modules": true, "__pycache__": true,
		".venv": true, ".claude": true, ".codex": true, ".opencode": true, ".pi": true}
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
