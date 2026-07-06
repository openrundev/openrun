// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/BurntSushi/toml"
	apppkg "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const (
	APP     = "app"
	BINDING = "binding"
)

func (s *Server) loadApplyInfo(fileName string, data []byte, branch string, applyDev bool) ([]*types.CreateAppRequest, []*types.CreateBindingRequest, error) {
	applyBuiltins, err := s.builtinsForApply(applyDev)
	if err != nil {
		return nil, nil, err
	}

	builtins := starlark.StringDict{
		APP:            applyBuiltins.createAppBuiltin,
		BINDING:        applyBuiltins.createBindingBuiltin,
		apptype.CONFIG: starlark.NewBuiltin(apptype.CONFIG, apptype.CreateConfigBuiltin(s.config.NodeConfig, s.config.System.AllowedEnv)),
	}

	thread := &starlark.Thread{
		Name:  fileName,
		Print: func(_ *starlark.Thread, msg string) { s.Info().Msg(msg) },
	}

	thread.SetLocal(types.TL_BRANCH, branch)
	thread.SetLocal(types.TL_DEV, applyDev)

	options := syntax.FileOptions{}
	_, err = starlark.ExecFileOptions(&options, thread, fileName, data, builtins)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			s.Error().Err(evalErr).Msgf("Error loading app definitions: %s", evalErr.Backtrace())
		}
		return nil, nil, fmt.Errorf("error loading app definitions: %w", err)
	}

	retApp := make([]*types.CreateAppRequest, 0, len(applyBuiltins.appDefs))
	retBinding := make([]*types.CreateBindingRequest, 0, len(applyBuiltins.bindingDefs))
	for _, appDef := range applyBuiltins.appDefs {
		appInfo, err := appDefToApplyInfo(appDef)
		if err != nil {
			return nil, nil, err
		}
		retApp = append(retApp, appInfo)
	}
	for _, bindingDef := range applyBuiltins.bindingDefs {
		bindingInfo, err := bindingDefToApplyInfo(bindingDef)
		if err != nil {
			return nil, nil, err
		}
		retBinding = append(retBinding, bindingInfo)
	}

	return retApp, retBinding, nil
}

func appDefToApplyInfo(appDef *starlarkstruct.Struct) (*types.CreateAppRequest, error) {
	path, err := apptype.GetStringAttr(appDef, "path")
	if err != nil {
		return nil, err
	}

	source, err := apptype.GetStringAttr(appDef, "source")
	if err != nil {
		return nil, err
	}

	dev, err := apptype.GetOptionalBoolAttr(appDef, "dev")
	if err != nil {
		return nil, err
	}
	verify, err := apptype.GetOptionalBoolAttr(appDef, "verify")
	if err != nil {
		return nil, err
	}

	auth, err := apptype.GetStringAttr(appDef, "auth")
	if err != nil {
		return nil, err
	}

	gitAuth, err := apptype.GetStringAttr(appDef, "git_auth")
	if err != nil {
		return nil, err
	}
	gitBranch, err := apptype.GetStringAttr(appDef, "git_branch")
	if err != nil {
		return nil, err
	}
	gitCommit, err := apptype.GetStringAttr(appDef, "git_commit")
	if err != nil {
		return nil, err
	}
	params, err := apptype.GetDictAttr(appDef, "params", true)
	if err != nil {
		return nil, err
	}
	spec, err := apptype.GetStringAttr(appDef, "spec")
	if err != nil {
		return nil, err
	}
	stageAt, err := apptype.GetStringAttr(appDef, "stage_at")
	if err != nil {
		return nil, err
	}

	appConfig, err := apptype.GetDictAttr(appDef, "app_config", true)
	if err != nil {
		return nil, err
	}
	containerArgs, err := apptype.GetDictAttr(appDef, "container_args", true)
	if err != nil {
		return nil, err
	}
	containerOpts, err := apptype.GetDictAttr(appDef, "container_opts", true)
	if err != nil {
		return nil, err
	}
	containerVols, err := apptype.GetListStringAttr(appDef, "container_vols", true)
	if err != nil {
		return nil, err
	}
	bindings, err := apptype.GetListStringAttr(appDef, "bindings", true)
	if err != nil {
		return nil, err
	}
	bindingSourcePerms, err := apptype.GetListStringAttr(appDef, "bind_perm", true)
	if err != nil {
		return nil, err
	}

	paramStr, err := convertToMapString(params, false)
	if err != nil {
		return nil, err
	}
	appConfigStr, err := convertToMapString(appConfig, true)
	if err != nil {
		return nil, err
	}
	containerArgsStr, err := convertToMapString(containerArgs, false)
	if err != nil {
		return nil, err
	}
	containerOptsStr, err := convertToMapString(containerOpts, false)
	if err != nil {
		return nil, err
	}

	return &types.CreateAppRequest{
		Path:               path,
		SourceUrl:          source,
		IsDev:              dev,
		ParamValues:        paramStr,
		AppAuthn:           types.AppAuthnType(auth),
		GitAuthName:        gitAuth,
		GitBranch:          gitBranch,
		GitCommit:          gitCommit,
		Spec:               types.AppSpec(spec),
		AppConfig:          appConfigStr,
		ContainerOptions:   containerOptsStr,
		ContainerArgs:      containerArgsStr,
		ContainerVolumes:   containerVols,
		Bindings:           bindings,
		BindingSourcePerms: bindingSourcePerms,
		StageAt:            stageAt,
		Verify:             verify,
	}, nil
}

func (s *Server) setupSource(applyPath, branch, commit, gitAuth string, repoCache *RepoCache, isDev bool) (string, string, error) {
	if !system.IsGit(applyPath) {
		return filepath.Dir(applyPath), filepath.Base(applyPath), nil
	}

	branch = cmp.Or(branch, "main")
	repo, applyFile, _, _, err := repoCache.CheckoutRepo(applyPath, branch, commit, gitAuth, isDev)
	if err != nil {
		return "", "", err
	}
	if applyFile == "" {
		return "", "", fmt.Errorf("apply file name has to be specified within source repo")
	}
	if applyFile[len(applyFile)-1] == '/' {
		applyFile = applyFile[:len(applyFile)-1]
	}
	s.Trace().Msgf("Applying %s files from repo %s", applyFile, repo)
	return repo, applyFile, nil
}

func (s *Server) Apply(ctx context.Context, inputTx types.Transaction, applyPath string, appPathGlob string, approve, dryRun, promote bool,
	reload types.AppReloadOption, branch, commit, gitAuth string, clobber,
	forceReload, verify bool, lastRunCommitId string, repoCache *RepoCache, isDev bool) (_ *types.AppApplyResponse, _ []types.AppPathDomain, retErr error) {
	var tx types.Transaction
	var err error
	verify = verify && !dryRun
	if inputTx.Tx == nil {
		tx, err = s.db.BeginTransaction(ctx)
		if err != nil {
			return nil, nil, err
		}
		defer tx.Rollback() //nolint:errcheck
	} else {
		tx = inputTx
		// No rollback here if transaction is passed in
	}

	// Operation-level rollback scope: apps that mutate their Kubernetes
	// deployments in-place register on its stack and binding changes record the
	// accounts and grants they create, so a failure anywhere reverts both the
	// cluster and the external services along with the DB transaction. We own
	// the scope only when we own the DB transaction; when a transaction is
	// passed in, the caller owns the commit (and therefore the rollback) and we
	// just register into its scope.
	ctx, deployScope := s.beginDeployScope(ctx, inputTx.Tx == nil, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()
	bindingAccounts := deployScope.accounts

	if reload == "" {
		reload = types.AppReloadOptionUpdated
	}

	if repoCache == nil {
		repoCache, err = NewRepoCache(s)
		if err != nil {
			return nil, nil, err
		}
		defer repoCache.Cleanup()
	}

	newSha := ""
	if system.IsGit(applyPath) {
		branch = cmp.Or(branch, "main")
		newSha, err = repoCache.GetSha(applyPath, branch, gitAuth)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting git commit sha for %s: %w", applyPath, err)
		}
		if !forceReload && (reload != types.AppReloadOptionMatched) &&
			lastRunCommitId != "" && newSha == lastRunCommitId && (commit == "" || commit == lastRunCommitId) {
			// If no commit is specified, and the current version is the same as the latest commit, skip apply
			// Only schedule sync passes in the lastRunCommitId, so this does not happen for normal apply
			s.Debug().Msgf("Already applied commit for %s, skipping apply", applyPath)
			return &types.AppApplyResponse{
				DryRun:       dryRun,
				SkippedApply: true,
				CommitId:     newSha,
			}, nil, nil
		}
	}

	dir, file, err := s.setupSource(applyPath, branch, commit, gitAuth, repoCache, isDev)
	if err != nil {
		return nil, nil, err
	}
	sourceFS, err := appfs.NewSourceFs(dir, appfs.NewDiskReadFS(s.Logger, dir, nil), false)
	if err != nil {
		return nil, nil, err
	}
	defer sourceFS.Close() //nolint:errcheck

	applyConfig := map[types.AppPathDomain]*types.CreateAppRequest{}
	bindingConfig := map[string]*types.CreateBindingRequest{}
	globFiles, err := sourceFS.Glob(file)
	if err != nil {
		return nil, nil, err
	}

	if !system.IsGit(applyPath) {
		branch = ""
	}

	if len(globFiles) == 0 {
		return nil, nil, fmt.Errorf("no matching files found in %s", applyPath)
	}
	bindingList := make([]string, 0)
	for _, f := range globFiles {
		s.Trace().Msgf("Applying file %s", f)
		fileBytes, err := sourceFS.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading file %s: %w", f, err)
		}

		appDefs, bindingDefs, err := s.loadApplyInfo(f, fileBytes, branch, isDev)
		if err != nil {
			return nil, nil, err
		}

		for _, appDef := range appDefs {
			appPathDomain, err := parseAppPath(appDef.Path)
			if err != nil {
				return nil, nil, err
			}
			if appPathDomain.Domain != "" && appPathDomain.Domain[len(appPathDomain.Domain)-1] == '.' {
				// If domain ends with a dot, append the default domain
				if s.config.System.DefaultDomain == "" {
					return nil, nil, types.CreateRequestError("Domain cannot end with a dot since default_domain is not configured", http.StatusBadRequest)
				}
				appPathDomain.Domain += s.config.System.DefaultDomain
			}
			if _, ok := applyConfig[appPathDomain]; ok {
				return nil, nil, fmt.Errorf("duplicate app %s defined in file %s", appPathDomain, f)
			}
			applyConfig[appPathDomain] = appDef
		}

		for _, bindingDef := range bindingDefs {
			bindingPathDomain, err := parseAppPath(bindingDef.Path)
			if err != nil {
				return nil, nil, err
			}
			if bindingPathDomain.Domain != "" {
				return nil, nil, fmt.Errorf("binding %s cannot include a domain", bindingDef.Path)
			}
			bindingDef.Path = bindingPathDomain.Path
			if _, ok := bindingConfig[bindingDef.Path]; ok {
				return nil, nil, fmt.Errorf("duplicate binding %s defined in file %s", bindingDef.Path, f)
			}
			bindingConfig[bindingDef.Path] = bindingDef
			bindingList = append(bindingList, bindingDef.Path)
		}
	}
	s.Trace().Msgf("Applying %d apps and %d bindings", len(applyConfig), len(bindingList))

	filteredApps := make([]types.AppPathDomain, 0, len(applyConfig))
	verifyRequested := verify
	for appPathDomain := range applyConfig {
		match, err := rbac.MatchGlob(appPathGlob, appPathDomain)
		if err != nil {
			return nil, nil, err
		}
		if !match {
			continue
		}
		verifyRequested = verifyRequested || applyConfig[appPathDomain].Verify
		filteredApps = append(filteredApps, appPathDomain)
	}

	updateResults := make([]types.AppPathDomain, 0, len(filteredApps))
	approveResults := make([]types.ApproveResult, 0, len(filteredApps))
	promoteResults := make([]types.AppPathDomain, 0, len(filteredApps))
	reloadResults := make([]types.AppPathDomain, 0, len(filteredApps))
	skippedResults := make([]types.AppPathDomain, 0, len(filteredApps))

	allApps, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return nil, nil, err
	}
	allAppsMap := make(map[types.AppPathDomain]types.AppInfo)
	for _, appInfo := range allApps {
		allAppsMap[appInfo.AppPathDomain] = appInfo
	}

	// app:apply gates the whole declarative apply, for every affected app path,
	// including apps the plan would create. approve additionally needs app:approve
	// and promote additionally needs app:promote
	if s.rbacManager.APIEnforced(ctx) {
		for _, appPath := range filteredApps {
			owner := ""
			if appInfo, ok := allAppsMap[appPath]; ok {
				owner = appInfo.UserID
			}
			if err := s.enforceAppPerm(ctx, types.PermissionApply, appPath, owner); err != nil {
				return nil, nil, err
			}
			if approve {
				if err := s.enforceAppPerm(ctx, types.PermissionApprove, appPath, owner); err != nil {
					return nil, nil, err
				}
			}
			if promote {
				if err := s.enforceAppPerm(ctx, types.PermissionPromote, appPath, owner); err != nil {
					return nil, nil, err
				}
			}
		}
	}

	newApps := make([]types.AppPathDomain, 0, len(filteredApps))
	updatedApps := make([]types.AppPathDomain, 0, len(filteredApps))

	for _, appPath := range filteredApps {
		appInfo, ok := allAppsMap[appPath]
		if !ok {
			// New app being created
			newApps = append(newApps, appPath)
		} else {
			applyInfo := applyConfig[appPath]
			if appInfo.SourceUrl != applyInfo.SourceUrl {
				return nil, nil, fmt.Errorf("app %s already exists with different source url: %s", appPath, appInfo.SourceUrl)
			}
			if appInfo.IsDev != applyInfo.IsDev {
				return nil, nil, fmt.Errorf("app %s already exists with different dev status: %t", appPath, appInfo.IsDev)
			}

			updatedApps = append(updatedApps, appPath)
		}
	}

	// Get list of all bindings in the database
	allBindings, err := s.ListBindings(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	allBindingsMap := make(map[string]*types.Binding)
	for _, binding := range allBindings {
		allBindingsMap[binding.Path] = binding
	}

	newBindings := make([]string, 0, len(bindingList))
	updatedBindings := make([]string, 0, len(bindingList))
	for _, bindingPath := range bindingList {
		bindingDef := bindingConfig[bindingPath]
		if bindingInfo, ok := allBindingsMap[bindingPath]; !ok {
			newBindings = append(newBindings, bindingPath)
		} else {
			if bindingInfo.Source != bindingDef.Source {
				return nil, nil, fmt.Errorf("binding %s already exists with different source: %s", bindingPath, bindingInfo.Source)
			}
			updatedBindings = append(updatedBindings, bindingPath)
		}
	}

	createBindingResults := make([]string, 0, len(newBindings))
	for _, newBinding := range newBindings {
		s.Trace().Msgf("Applying create binding %s", newBinding)
		applyInfo := bindingConfig[newBinding]
		if err := prepareBindingApplyInfo(applyInfo); err != nil {
			return nil, nil, err
		}
		if _, err := s.createBindingTx(ctx, tx, applyInfo, bindingAccounts, false); err != nil {
			return nil, nil, err
		}
		createBindingResults = append(createBindingResults, newBinding)
	}

	updateBindingResults := make([]string, 0, len(updatedBindings))
	promoteBindingResults := make([]string, 0, len(updatedBindings))
	for _, updateBinding := range updatedBindings {
		s.Trace().Msgf("Applying update binding %s", updateBinding)
		applyInfo := bindingConfig[updateBinding]
		updated, promoted, err := s.applyBindingUpdate(ctx, tx, bindingAccounts, applyInfo, promote, clobber, forceReload)
		if err != nil {
			return nil, nil, err
		}
		if updated {
			updateBindingResults = append(updateBindingResults, updateBinding)
		}
		if promoted {
			promoteBindingResults = append(promoteBindingResults, updateBinding)
		}
	}

	createResults := make([]types.AppCreateResponse, 0, len(newApps))
	for _, newApp := range newApps {
		s.Trace().Msgf("Applying create app %s", newApp)
		applyInfo := applyConfig[newApp]
		if isDev {
			applyInfo.IsDev = isDev // Override the dev status from the apply command cli
		}
		appVerify := verify || applyInfo.Verify
		res, err := s.CreateAppTx(ctx, tx, newApp.String(), approve, dryRun, applyInfo, repoCache, bindingAccounts)
		if err != nil {
			return nil, nil, err
		}
		if appVerify && !dryRun {
			if err := s.verifyCreatedApp(ctx, tx, newApp); err != nil {
				return nil, nil, err
			}
		}

		createResults = append(createResults, *res)
	}

	for _, updateApp := range updatedApps {
		s.Trace().Msgf("Applying update app %s", updateApp)
		applyInfo := applyConfig[updateApp]
		appVerify := verify || applyInfo.Verify
		applyResult, err := s.applyAppUpdate(ctx, tx, updateApp, applyInfo, approve, dryRun,
			promote, reload, clobber, repoCache, forceReload, appVerify, bindingAccounts)
		if err != nil {
			return nil, nil, err
		}

		updateResults = append(updateResults, applyResult.Updated...)
		if applyResult.Promoted {
			promoteResults = append(promoteResults, updateApp)
		}
		reloadResults = append(reloadResults, applyResult.Reloaded...)
		skippedResults = append(skippedResults, applyResult.Skipped...)
		if applyResult.ApproveResult != nil {
			approveResults = append(approveResults, *applyResult.ApproveResult)
		}
	}

	if verifyRequested && !dryRun {
		if err := s.reapplyPendingBindingGrants(ctx, tx, bindingAccounts, bindingList); err != nil {
			return nil, nil, err
		}
	}

	// Get list of all updated apps
	allUpdatedApps := []types.AppPathDomain{}
	allUpdatedApps = append(allUpdatedApps, updateResults...)
	allUpdatedApps = append(allUpdatedApps, reloadResults...)
	allUpdatedApps = append(allUpdatedApps, promoteResults...)
	for _, app := range approveResults {
		allUpdatedApps = append(allUpdatedApps, app.AppPathDomain)
	}
	for _, app := range createResults {
		allUpdatedApps = append(allUpdatedApps, app.AppPathDomain)
	}
	allAppMap := make(map[types.AppPathDomain]bool)
	for _, app := range allUpdatedApps {
		allAppMap[app] = true
	}
	allUpdatedApps = slices.Collect(maps.Keys(allAppMap))

	if inputTx.Tx == nil {
		if err := s.CompleteTransaction(ctx, tx, allUpdatedApps, dryRun, "apply"); err != nil {
			return nil, nil, err
		}
	}
	// Apply succeeded and (if we own it) the DB transaction has committed: keep
	// the binding accounts and grants created on the services, run the deferred
	// traffic switches, and execute the deferred grant revokes last. When the
	// caller owns the transaction, this is a no-op and the caller's scope decides.
	if err := deployScope.commit(ctx); err != nil {
		return nil, nil, err
	}

	ret := &types.AppApplyResponse{
		DryRun:                dryRun,
		CommitId:              newSha,
		SkippedApply:          false,
		CreateResults:         createResults,
		UpdateResults:         updateResults,
		ApproveResults:        approveResults,
		PromoteResults:        promoteResults,
		ReloadResults:         reloadResults,
		SkippedResults:        skippedResults,
		FilteredApps:          filteredApps,
		CreateBindingResults:  createBindingResults,
		UpdateBindingResults:  updateBindingResults,
		PromoteBindingResults: promoteBindingResults,
	}

	return ret, allUpdatedApps, nil
}

func convertToMapString(input map[string]any, convertToml bool) (map[string]string, error) {
	ret := make(map[string]string)
	for k, v := range input {
		if value, ok := v.(string); ok {
			if convertToml {
				ret[k] = "\"" + value + "\""
			} else {
				ret[k] = value
			}
		} else {
			var val []byte
			var err error
			if convertToml {
				val, err = toml.Marshal(v)
			} else {
				val, err = json.Marshal(v)
			}
			if err != nil {
				return nil, err
			}
			ret[k] = string(val)
		}
	}
	return ret, nil
}

func convertToStringMap(input map[string]any) (map[string]string, error) {
	ret := make(map[string]string, len(input))
	for k, v := range input {
		value, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("config value %s is not a string", k)
		}
		ret[k] = value
	}
	return ret, nil
}

func (s *Server) applyAppUpdate(ctx context.Context, tx types.Transaction, appPathDomain types.AppPathDomain, newInfo *types.CreateAppRequest,
	approve, dryRun, promote bool, reload types.AppReloadOption, clobber bool, repoCache *RepoCache, forceReload, verify bool,
	bindingAccounts *bindingAccountManager) (*types.AppApplyResult, error) {
	verify = verify && !dryRun
	liveApp, err := s.GetAppEntry(ctx, tx, appPathDomain)
	if err != nil {
		return nil, fmt.Errorf("app missing during update %w", err)
	}

	prodApp := liveApp
	if !liveApp.IsDev {
		// For prod apps, update the staging app
		liveApp, err = s.getStageApp(ctx, tx, liveApp)
		if err != nil {
			return nil, err
		}
	}

	oldInfoStr := string(liveApp.Metadata.VersionMetadata.ApplyInfo)
	var oldInfo *types.CreateAppRequest
	if len(oldInfoStr) > 0 {
		if err := json.Unmarshal([]byte(oldInfoStr), &oldInfo); err != nil {
			return nil, fmt.Errorf("error unmarshalling stored app info: %w", err)
		}
		oldInfo.AppAuthn = cmp.Or(oldInfo.AppAuthn, types.AppAuthnDefault)
	}
	newInfo.AppAuthn = cmp.Or(newInfo.AppAuthn, types.AppAuthnDefault)
	newInfo.Bindings, err = s.resolveAppBindings(ctx, tx, autoBindingAppID(liveApp), newInfo.Bindings, dryRun, bindingAccounts)
	if err != nil {
		return nil, err
	}

	authChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.AppAuthn
	}, newInfo.AppAuthn, liveApp.Metadata.AuthnType, clobber)
	if authChanged {
		if err := s.validateAppAuthnType(string(newInfo.AppAuthn)); err != nil {
			return nil, err
		}
		liveApp.Metadata.AuthnType = newInfo.AppAuthn
	}

	gitAuthChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.GitAuthName
	}, newInfo.GitAuthName, liveApp.Metadata.GitAuthName, clobber)
	if gitAuthChanged {
		liveApp.Metadata.GitAuthName = newInfo.GitAuthName
	}

	specChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.Spec
	}, newInfo.Spec, liveApp.Metadata.Spec, clobber)
	if specChanged {
		if newInfo.Spec == "" {
			liveApp.Metadata.SpecFiles = nil
			liveApp.Metadata.Spec = ""
		} else {
			appFiles := s.GetAppSpec(newInfo.Spec)
			if len(appFiles) == 0 {
				return nil, fmt.Errorf("invalid app spec %s for app %s", newInfo.Spec, appPathDomain)
			}
			liveApp.Metadata.SpecFiles = &appFiles
			liveApp.Metadata.Spec = newInfo.Spec
		}
	}

	gitBranchChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.GitBranch
	}, newInfo.GitBranch, liveApp.Metadata.VersionMetadata.GitBranch, clobber)
	if gitBranchChanged {
		liveApp.Metadata.VersionMetadata.GitBranch = newInfo.GitBranch
	}
	gitCommitChanged := false
	if newInfo.GitCommit != "" {
		gitCommitChanged = checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
			return info.GitCommit
		}, newInfo.GitCommit, liveApp.Metadata.VersionMetadata.GitCommit, clobber)
		if gitCommitChanged {
			liveApp.Metadata.VersionMetadata.GitCommit = newInfo.GitCommit
		}
	}

	var oldParams map[string]string
	if oldInfo != nil {
		oldParams = oldInfo.ParamValues
	}
	paramsChanged := mergeMap(oldParams, newInfo.ParamValues, liveApp.Metadata.ParamValues, clobber)

	var oldContOptions map[string]string
	if oldInfo != nil {
		oldContOptions = oldInfo.ContainerOptions
	}
	contConfigChanged := mergeMap(oldContOptions, newInfo.ContainerOptions, liveApp.Metadata.ContainerOptions, clobber)

	var oldContArgs map[string]string
	if oldInfo != nil {
		oldContArgs = oldInfo.ContainerArgs
	}
	contArgsChanged := mergeMap(oldContArgs, newInfo.ContainerArgs, liveApp.Metadata.ContainerArgs, clobber)

	var oldContVolumes []string
	if oldInfo != nil {
		oldContVolumes = oldInfo.ContainerVolumes
	}
	contVolsChanged := mergeSlice(oldContVolumes, newInfo.ContainerVolumes, &liveApp.Metadata.ContainerVolumes, clobber)

	var oldAppConfig map[string]string
	if oldInfo != nil {
		oldAppConfig = oldInfo.AppConfig
	}
	appConfigChanged := mergeMap(oldAppConfig, newInfo.AppConfig, liveApp.Metadata.AppConfig, clobber)

	var oldBindings []string
	if oldInfo != nil {
		oldBindings = oldInfo.Bindings
	}
	bindingsChanged := mergeSlice(oldBindings, newInfo.Bindings, &liveApp.Metadata.Bindings, clobber)

	var oldBindingSourcePerms []string
	if oldInfo != nil {
		oldBindingSourcePerms = oldInfo.BindingSourcePerms
	}
	bindingSourcePermsChanged := mergeSlice(oldBindingSourcePerms, newInfo.BindingSourcePerms, &liveApp.Metadata.BindingSourcePerms, clobber)
	var approvalResult *types.ApproveResult
	if bindingSourcePermsChanged && approve {
		liveApp.Metadata.ApprovedBindingSourcePerms = append([]string{}, liveApp.Metadata.BindingSourcePerms...)
		approvalResult = &types.ApproveResult{
			Id:                         liveApp.Id,
			AppPathDomain:              liveApp.AppPathDomain(),
			NewLoads:                   liveApp.Metadata.Loads,
			NewPermissions:             liveApp.Metadata.Permissions,
			ApprovedLoads:              liveApp.Metadata.Loads,
			ApprovedPermissions:        liveApp.Metadata.Permissions,
			NewBindingSourcePerms:      liveApp.Metadata.BindingSourcePerms,
			ApprovedBindingSourcePerms: liveApp.Metadata.ApprovedBindingSourcePerms,
			NeedsApproval:              true,
		}
	}

	updated := specChanged || gitBranchChanged || gitCommitChanged || paramsChanged ||
		contConfigChanged || contArgsChanged || contVolsChanged || appConfigChanged || authChanged || gitAuthChanged || bindingsChanged || bindingSourcePermsChanged
	updatedApps := make([]types.AppPathDomain, 0)
	if updated {
		liveApp.Metadata.VersionMetadata.ApplyInfo, err = json.Marshal(newInfo)
		if err != nil {
			return nil, err
		}

		updatedApps = append(updatedApps, liveApp.AppPathDomain())
		if promote && !liveApp.IsDev {
			updatedApps = append(updatedApps, prodApp.AppPathDomain())
		}
	}

	reloadApp := reload == types.AppReloadOptionMatched || updated && reload == types.AppReloadOptionUpdated
	promoteApp := false
	ret := &types.AppApplyResult{
		DryRun:        dryRun,
		ApproveResult: approvalResult,
	}
	if reloadApp {
		// Reload does the version increment and promotion
		reloadResult, err := s.ReloadApp(ctx, tx, prodApp, liveApp, approve, dryRun, promote,
			newInfo.GitBranch, newInfo.GitCommit, newInfo.GitAuthName, repoCache, forceReload, verify)
		if err != nil {
			return nil, err
		}
		ret.ApproveResult = reloadResult.ApproveResult
		ret.Reloaded = reloadResult.ReloadResults
		ret.Skipped = reloadResult.SkippedResults
		promoteApp = len(reloadResult.PromoteResults) > 0
	} else if updated {
		// No reload, increment version and promote (if enabled). The sync id
		// is updated only when applied through a sync, imperative apply does
		// not reset it
		if syncId := system.GetContextValue(ctx, types.SYNC_ID); syncId != "" {
			liveApp.Metadata.AppliedSyncId = syncId
		}
		stagingFileStore, err := metadata.NewFileStore(liveApp.Id, liveApp.Metadata.VersionMetadata.Version, s.db, tx)
		if err != nil {
			return nil, fmt.Errorf("error initializing staging file store: %w", err)
		}

		err = stagingFileStore.IncrementAppVersion(ctx, tx, &liveApp.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error incrementing app version: %w", err)
		}
		if err := s.db.UpdateAppMetadata(ctx, tx, liveApp); err != nil {
			return nil, err
		}
		if promote && !liveApp.IsDev {
			if err = s.promoteApp(ctx, tx, liveApp, prodApp); err != nil {
				return nil, err
			}
			promoteApp = true
		}
	}

	ret.Updated = updatedApps
	ret.Promoted = promoteApp
	return ret, nil
}

func prepareBindingApplyInfo(newInfo *types.CreateBindingRequest) error {
	newInfo.Grants = normalizeGrantList(newInfo.Grants)
	if newInfo.Config == nil {
		newInfo.Config = map[string]string{}
	}
	applyInfo, err := json.Marshal(newInfo)
	if err != nil {
		return err
	}
	newInfo.ApplyInfo = applyInfo
	return nil
}

func (s *Server) applyBindingUpdate(ctx context.Context, tx types.Transaction, bindingAccounts *bindingAccountManager, newInfo *types.CreateBindingRequest,
	promote, clobber, reapplyAll bool) (bool, bool, error) {
	if err := prepareBindingApplyInfo(newInfo); err != nil {
		return false, false, err
	}

	binding, err := s.db.GetBinding(ctx, tx, newInfo.Path)
	if err != nil {
		return false, false, err
	}
	if binding.Source != newInfo.Source {
		return false, false, fmt.Errorf("binding %s already exists with different source: %s", newInfo.Path, binding.Source)
	}
	if binding.DerivedFrom == "" && len(newInfo.Grants) > 0 {
		return false, false, fmt.Errorf("grants are not supported for base bindings, only derived bindings can have grants")
	}

	if binding.StagedMetadata.Config == nil {
		binding.StagedMetadata.Config = map[string]string{}
	}

	var oldInfo *types.CreateBindingRequest
	oldInfoStr := string(binding.StagedMetadata.ApplyInfo)
	if oldInfoStr != "" {
		if err := json.Unmarshal([]byte(oldInfoStr), &oldInfo); err != nil {
			return false, false, fmt.Errorf("error unmarshalling stored binding info: %w", err)
		}
		oldInfo.Grants = normalizeGrantList(oldInfo.Grants)
		if oldInfo.Config == nil {
			oldInfo.Config = map[string]string{}
		}
	}

	var oldGrants []string
	if oldInfo != nil {
		oldGrants = oldInfo.Grants
	} else {
		oldGrants = append([]string{}, binding.StagedMetadata.Grants...)
	}
	configChanged := !stringMapEqual(binding.StagedMetadata.Config, newInfo.Config)
	if configChanged {
		return false, false, fmt.Errorf("binding config updates are not supported for existing binding %s", newInfo.Path)
	}
	grantsChanged := mergeSlice(oldGrants, newInfo.Grants, &binding.StagedMetadata.Grants, clobber)
	applyInfoChanged := string(binding.StagedMetadata.ApplyInfo) != string(newInfo.ApplyInfo)

	stagingGrantsAppliedChanged := false
	if binding.DerivedFrom != "" {
		derivedFrom, service, err := s.getBindingUpdateRefs(ctx, tx, binding)
		if err != nil {
			return false, false, err
		}
		stagingService := service
		if service.Staging != "" {
			stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
			if err != nil {
				return false, false, fmt.Errorf("error getting staging service: %w", err)
			}
		}
		grantsApplied, err := bindingAccounts.applyGrants(ctx, stagingService, binding, derivedFrom, true, reapplyAll)
		if err != nil {
			return false, false, fmt.Errorf("error applying staging grants: %w", err)
		}
		if !bindingGrantSetEqual(binding.StagedMetadata.GrantsApplied, grantsApplied) {
			binding.StagedMetadata.GrantsApplied = grantsApplied
			stagingGrantsAppliedChanged = true
		}
	}

	updated := grantsChanged || applyInfoChanged || stagingGrantsAppliedChanged
	if updated {
		binding.StagedMetadata.ApplyInfo = append([]byte{}, newInfo.ApplyInfo...)
	}

	promoted := false
	if promote && !stringMapEqual(binding.Metadata.Config, binding.StagedMetadata.Config) {
		return false, false, fmt.Errorf("binding config promotion is not supported for existing binding %s", newInfo.Path)
	}
	if promote && !bindingMetadataPromoteEqual(binding.Metadata, binding.StagedMetadata) {
		binding.Metadata.Config = maps.Clone(binding.StagedMetadata.Config)
		binding.Metadata.Grants = append([]string{}, binding.StagedMetadata.Grants...)
		binding.Metadata.ApplyInfo = append([]byte{}, binding.StagedMetadata.ApplyInfo...)
		if binding.DerivedFrom != "" {
			derivedFrom, service, err := s.getBindingUpdateRefs(ctx, tx, binding)
			if err != nil {
				return false, false, err
			}
			binding.Metadata.GrantsApplied, err = bindingAccounts.applyGrants(ctx, service, binding, derivedFrom, false, reapplyAll)
			if err != nil {
				return false, false, err
			}
		} else {
			binding.Metadata.GrantsApplied = append([]types.BindingGrant{}, binding.StagedMetadata.GrantsApplied...)
		}
		promoted = true
	}

	if updated || promoted {
		if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
			return false, false, err
		}
	}

	return updated, promoted, nil
}

func (s *Server) verifyCreatedApp(ctx context.Context, tx types.Transaction, appPathDomain types.AppPathDomain) error {
	appEntry, err := s.GetAppEntry(ctx, tx, appPathDomain)
	if err != nil {
		return err
	}

	verifyApp := func(entry *types.AppEntry) error {
		application, err := s.setupApp(ctx, entry, tx)
		if err != nil {
			return fmt.Errorf("error setting up app %s: %w", entry.AppPathDomain(), err)
		}
		if _, err := application.Reload(ctx, true, true, types.DryRun(false), apppkg.ReloadOptions{ReloadContainer: true, Verify: true}); err != nil {
			if container.ClusterRollbackClean(err) {
				return fmt.Errorf("verify failed for app %s: %w. All changes have been reverted", entry.AppPathDomain(), err)
			}
			return fmt.Errorf("verify failed for app %s: %w", entry.AppPathDomain(), err)
		}
		return nil
	}

	if !appEntry.IsDev {
		stageAppEntry, err := s.getStageApp(ctx, tx, appEntry)
		if err != nil {
			return err
		}
		if err := verifyApp(stageAppEntry); err != nil {
			return err
		}
	}
	if err := verifyApp(appEntry); err != nil {
		return err
	}
	return nil
}

func (s *Server) reapplyPendingBindingGrants(ctx context.Context, tx types.Transaction, bindingAccounts *bindingAccountManager, bindingPaths []string) error {
	for _, bindingPath := range bindingPaths {
		binding, err := s.db.GetBinding(ctx, tx, bindingPath)
		if err != nil {
			return err
		}
		if binding.DerivedFrom == "" {
			continue
		}

		derivedFrom, service, err := s.getBindingUpdateRefs(ctx, tx, binding)
		if err != nil {
			return err
		}

		updated := false
		stagingService := service
		if service.Staging != "" {
			stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
			if err != nil {
				return fmt.Errorf("error getting staging service: %w", err)
			}
		}

		stagedGrantsApplied, err := bindingAccounts.applyGrants(ctx, stagingService, binding, derivedFrom, true, false)
		if err != nil {
			return fmt.Errorf("error reapplying staging grants for binding %s: %w", binding.Path, err)
		}
		if !bindingGrantSetEqual(binding.StagedMetadata.GrantsApplied, stagedGrantsApplied) {
			binding.StagedMetadata.GrantsApplied = stagedGrantsApplied
			updated = true
		}

		prodGrantsApplied, err := bindingAccounts.applyGrants(ctx, service, binding, derivedFrom, false, false)
		if err != nil {
			return fmt.Errorf("error reapplying production grants for binding %s: %w", binding.Path, err)
		}
		if !bindingGrantSetEqual(binding.Metadata.GrantsApplied, prodGrantsApplied) {
			binding.Metadata.GrantsApplied = prodGrantsApplied
			updated = true
		}

		if updated {
			if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Server) getBindingUpdateRefs(ctx context.Context, tx types.Transaction, binding *types.Binding) (*types.Binding, *types.Service, error) {
	derivedFrom, err := s.db.GetBinding(ctx, tx, binding.DerivedFrom)
	if err != nil {
		return nil, nil, fmt.Errorf("base binding %s not found: %w", binding.DerivedFrom, err)
	}

	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting binding service: %w", err)
	}
	return derivedFrom, service, nil
}

func bindingMetadataPromoteEqual(a, b types.BindingMetadata) bool {
	return stringSetEqual(normalizeGrantList(a.Grants), normalizeGrantList(b.Grants)) &&
		stringMapEqual(a.Config, b.Config) &&
		bindingGrantSetEqual(a.GrantsApplied, b.GrantsApplied) &&
		string(a.ApplyInfo) == string(b.ApplyInfo)
}

func stringMapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if b[k] != av {
			return false
		}
	}
	return true
}

func stringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	slices.Sort(ac)
	slices.Sort(bc)
	return slices.Equal(ac, bc)
}

func bindingGrantSetEqual(a, b []types.BindingGrant) bool {
	toStrings := func(grants []types.BindingGrant) []string {
		ret := make([]string, 0, len(grants))
		for _, grant := range grants {
			ret = append(ret, grant.String())
		}
		return ret
	}
	return stringSetEqual(toStrings(a), toStrings(b))
}

func mergeMap(old, new, live map[string]string, clobber bool) bool {
	if clobber {
		// Force overwrite the live map
		if reflect.DeepEqual(live, new) {
			return false
		}
		// Force update all values
		clear(live)
		for k, v := range new {
			live[k] = v
		}
		return true
	}

	updated := false
	if old == nil {
		// First run of apply
		for k, v := range new {
			// Add values from new, retaining existing live values
			updated = true
			live[k] = v
		}
	} else {
		// Three way merge
		for k, v := range old {
			newV, ok := new[k]
			if ok && v != newV {
				// Changed from old to new
				if live[k] != newV {
					updated = true
					live[k] = newV
				}
			}
			if !ok {
				// Removed from new
				_, present := live[k]
				if present {
					updated = true
					delete(live, k)
				}
			}
		}

		for k, v := range new {
			_, ok := old[k]
			if !ok {
				// Added in new
				updated = true
				live[k] = v
			}
		}
	}
	return updated
}

func mergeSlice(old, new []string, live *[]string, clobber bool) bool {
	if clobber {
		if reflect.DeepEqual(*live, new) {
			return false
		}
		// Force update all values
		*live = append([]string{}, new...)
		return true
	}

	updated := false
	liveDict := make(map[string]bool)
	for _, v := range *live {
		liveDict[v] = true
	}
	newDict := make(map[string]bool)
	for _, v := range new {
		newDict[v] = true
	}
	oldDict := make(map[string]bool)
	for _, v := range old {
		oldDict[v] = true
	}

	if old == nil {
		// First run of apply
		for _, v := range new {
			// Add values from new, retaining existing live values
			if !liveDict[v] {
				updated = true
				*live = append(*live, v)
			}
		}
	} else {
		// Three way merge
		for _, v := range old {
			if !newDict[v] && liveDict[v] {
				// Removed from new
				updated = true
				tmp := []string{}
				for _, lv := range *live {
					if lv != v {
						tmp = append(tmp, lv)
					}
				}
				*live = tmp
			}
		}
		for _, v := range new {
			if !oldDict[v] && !liveDict[v] {
				// Added in new
				updated = true
				*live = append(*live, v)
			}
		}
	}

	return updated
}

func checkPropertyChanged(oldInfo *types.CreateAppRequest, fetchVal func(*types.CreateAppRequest) any, newVal, liveVal any, clobber bool) bool {
	if clobber || oldInfo == nil {
		return !reflect.DeepEqual(liveVal, newVal)
	}
	var oldVal = fetchVal(oldInfo)
	return !reflect.DeepEqual(oldVal, newVal) && !reflect.DeepEqual(liveVal, newVal)
}

type applyBuiltins struct {
	createAppBuiltin     *starlark.Builtin
	createBindingBuiltin *starlark.Builtin
	appDefs              []*starlarkstruct.Struct
	bindingDefs          []*starlarkstruct.Struct
}

func (s *Server) builtinsForApply(applyDev bool) (*applyBuiltins, error) {
	collector := &applyBuiltins{
		appDefs:     make([]*starlarkstruct.Struct, 0),
		bindingDefs: make([]*starlarkstruct.Struct, 0),
	}

	createAppDefBuiltin := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path, source starlark.String
		var dev, verify starlark.Bool
		var params = starlark.NewDict(0)
		var auth, gitAuth, gitBranch, gitCommit, appSpec, stageAt starlark.String
		var appConfig = starlark.NewDict(0)
		var containerOpts = starlark.NewDict(0)
		var containerArgs = starlark.NewDict(0)
		var containerVols = &starlark.List{}
		var bindings = &starlark.List{}
		var bindingSourcePerms = &starlark.List{}

		if err := starlark.UnpackArgs(APP, args, kwargs, "path", &path, "source", &source, "dev?", &dev,
			"auth?", &auth, "git_auth?", &gitAuth, "git_branch?", &gitBranch, "git_commit?", &gitCommit,
			"params?", &params, "spec?", &appSpec, "stage_at?", &stageAt, "app_config", &appConfig,
			"container_opts?", &containerOpts, "container_args?", &containerArgs, "container_vols?", &containerVols,
			"bindings?", &bindings, "bind_perm?", &bindingSourcePerms, "verify?", &verify,
		); err != nil {
			return nil, err
		}

		fields := starlark.StringDict{
			"path":           path,
			"source":         source,
			"dev":            cmp.Or(dev, starlark.Bool(applyDev)),
			"auth":           auth,
			"git_auth":       gitAuth,
			"git_branch":     gitBranch,
			"git_commit":     gitCommit,
			"params":         params,
			"spec":           appSpec,
			"stage_at":       stageAt,
			"app_config":     appConfig,
			"container_opts": containerOpts,
			"container_args": containerArgs,
			"container_vols": containerVols,
			"bindings":       bindings,
			"bind_perm":      bindingSourcePerms,
			"verify":         verify,
		}

		appStruct := starlarkstruct.FromStringDict(starlark.String(APP), fields)
		collector.appDefs = append(collector.appDefs, appStruct)
		return appStruct, nil
	}

	createBindingDefBuiltin := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path, source starlark.String
		var config = starlark.NewDict(0)
		var grants = &starlark.List{}

		if err := starlark.UnpackArgs(BINDING, args, kwargs, "path", &path, "source", &source, "grants?", &grants, "config?", &config); err != nil {
			return nil, err
		}

		fields := starlark.StringDict{
			"path":   path,
			"source": source,
			"grants": grants,
			"config": config,
		}

		bindingStruct := starlarkstruct.FromStringDict(starlark.String(BINDING), fields)
		collector.bindingDefs = append(collector.bindingDefs, bindingStruct)
		return bindingStruct, nil
	}

	collector.createAppBuiltin = starlark.NewBuiltin(APP, createAppDefBuiltin)
	collector.createBindingBuiltin = starlark.NewBuiltin(BINDING, createBindingDefBuiltin)
	return collector, nil
}

func bindingDefToApplyInfo(bindingDef *starlarkstruct.Struct) (*types.CreateBindingRequest, error) {
	path, err := apptype.GetStringAttr(bindingDef, "path")
	if err != nil {
		return nil, err
	}

	source, err := apptype.GetStringAttr(bindingDef, "source")
	if err != nil {
		return nil, err
	}

	grants, err := apptype.GetListStringAttr(bindingDef, "grants", true)
	if err != nil {
		return nil, err
	}

	config, err := apptype.GetDictAttr(bindingDef, "config", true)
	if err != nil {
		return nil, err
	}
	configStr, err := convertToStringMap(config)
	if err != nil {
		return nil, err
	}

	return &types.CreateBindingRequest{
		Path:   path,
		Source: source,
		Grants: grants,
		Config: configStr,
	}, nil
}
