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
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const (
	APP = "app"
)

func (s *Server) loadApplyInfo(fileName string, data []byte, branch string, applyDev bool) ([]*types.CreateAppRequest, error) {
	appDefs := make([]*starlarkstruct.Struct, 0)

	createAppBuiltin := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path, source starlark.String
		var dev starlark.Bool
		var params = starlark.NewDict(0)
		var auth, gitAuth, gitBranch, gitCommit, appSpec starlark.String
		var appConfig = starlark.NewDict(0)
		var containerOpts = starlark.NewDict(0)
		var containerArgs = starlark.NewDict(0)
		var containerVols = &starlark.List{}

		if err := starlark.UnpackArgs(APP, args, kwargs, "path", &path, "source", &source, "dev?", &dev,
			"auth?", &auth, "git_auth?", &gitAuth, "git_branch?", &gitBranch, "git_commit?", &gitCommit,
			"params?", &params, "spec?", &appSpec, "app_config", &appConfig,
			"container_opts?", &containerOpts, "container_args?", &containerArgs, "container_vols?", &containerVols,
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
			"app_config":     appConfig,
			"container_opts": containerOpts,
			"container_args": containerArgs,
			"container_vols": containerVols,
		}

		appStruct := starlarkstruct.FromStringDict(starlark.String(APP), fields)
		appDefs = append(appDefs, appStruct)
		return appStruct, nil
	}

	builtins := starlark.StringDict{
		APP:            starlark.NewBuiltin(APP, createAppBuiltin),
		apptype.CONFIG: starlark.NewBuiltin(apptype.CONFIG, apptype.CreateConfigBuiltin(s.config.NodeConfig, s.config.System.AllowedEnv)),
	}

	thread := &starlark.Thread{
		Name:  fileName,
		Print: func(_ *starlark.Thread, msg string) { s.Info().Msg(msg) },
	}

	thread.SetLocal(types.TL_BRANCH, branch)
	thread.SetLocal(types.TL_DEV, applyDev)

	options := syntax.FileOptions{}
	_, err := starlark.ExecFileOptions(&options, thread, fileName, data, builtins)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			s.Error().Err(evalErr).Msgf("Error loading app definitions: %s", evalErr.Backtrace())
		}
		return nil, fmt.Errorf("error loading app definitions: %w", err)
	}

	ret := make([]*types.CreateAppRequest, 0, len(appDefs))
	for _, appDef := range appDefs {
		applyConfig, err := appDefToApplyInfo(appDef)
		if err != nil {
			return nil, err
		}
		ret = append(ret, applyConfig)
	}

	return ret, nil
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
		Path:             path,
		SourceUrl:        source,
		IsDev:            dev,
		ParamValues:      paramStr,
		AppAuthn:         types.AppAuthnType(auth),
		GitAuthName:      gitAuth,
		GitBranch:        gitBranch,
		GitCommit:        gitCommit,
		Spec:             types.AppSpec(spec),
		AppConfig:        appConfigStr,
		ContainerOptions: containerOptsStr,
		ContainerArgs:    containerArgsStr,
		ContainerVolumes: containerVols,
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
	forceReload bool, lastRunCommitId string, repoCache *RepoCache, isDev bool) (*types.AppApplyResponse, []types.AppPathDomain, error) {
	var tx types.Transaction
	var err error
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
		if !forceReload && lastRunCommitId != "" && newSha == lastRunCommitId && (commit == "" || commit == lastRunCommitId) {
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

	applyConfig := map[types.AppPathDomain]*types.CreateAppRequest{}
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
	for _, f := range globFiles {
		s.Trace().Msgf("Applying file %s", f)
		fileBytes, err := sourceFS.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading file %s: %w", f, err)
		}

		fileConfig, err := s.loadApplyInfo(f, fileBytes, branch, isDev)
		if err != nil {
			return nil, nil, err
		}

		for _, config := range fileConfig {
			appPathDomain, err := parseAppPath(config.Path)
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
				return nil, nil, fmt.Errorf("duplicate app %s defined in file %s", config.Path, f)
			}
			applyConfig[appPathDomain] = config
		}
	}

	filteredApps := make([]types.AppPathDomain, 0, len(applyConfig))
	for appPathDomain := range applyConfig {
		match, err := MatchGlob(appPathGlob, appPathDomain)
		if err != nil {
			return nil, nil, err
		}
		if !match {
			continue
		}
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

	createResults := make([]types.AppCreateResponse, 0, len(newApps))
	for _, newApp := range newApps {
		s.Trace().Msgf("Applying create app %s", newApp)
		applyInfo := applyConfig[newApp]
		if isDev {
			applyInfo.IsDev = isDev // Override the dev status from the apply command cli
		}
		res, err := s.CreateAppTx(ctx, tx, newApp.String(), approve, dryRun, applyInfo, repoCache)
		if err != nil {
			return nil, nil, err
		}

		createResults = append(createResults, *res)
	}

	for _, updateApp := range updatedApps {
		s.Trace().Msgf("Applying update app %s", updateApp)
		applyInfo := applyConfig[updateApp]
		applyResult, err := s.applyAppUpdate(ctx, tx, updateApp, applyInfo, approve, dryRun,
			promote, reload, clobber, repoCache, forceReload)
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
		// Commit the transaction if not dry run and update the in memory app store
		if err := s.CompleteTransaction(ctx, tx, allUpdatedApps, dryRun, "apply"); err != nil {
			return nil, nil, err
		}
	}

	ret := &types.AppApplyResponse{
		DryRun:         dryRun,
		CommitId:       newSha,
		SkippedApply:   false,
		CreateResults:  createResults,
		UpdateResults:  updateResults,
		ApproveResults: approveResults,
		PromoteResults: promoteResults,
		ReloadResults:  reloadResults,
		SkippedResults: skippedResults,
		FilteredApps:   filteredApps,
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

func (s *Server) applyAppUpdate(ctx context.Context, tx types.Transaction, appPathDomain types.AppPathDomain, newInfo *types.CreateAppRequest,
	approve, dryRun, promote bool, reload types.AppReloadOption, clobber bool, repoCache *RepoCache, forceReload bool) (*types.AppApplyResult, error) {
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

	authChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.AppAuthn
	}, newInfo.AppAuthn, liveApp.Settings.AuthnType, clobber)
	if authChanged {
		return nil, fmt.Errorf("app %s authentication changed, cannot apply changes. Use \"app update-settings\"", appPathDomain)
	}

	gitAuthChanged := checkPropertyChanged(oldInfo, func(info *types.CreateAppRequest) any {
		return info.GitAuthName
	}, newInfo.GitAuthName, liveApp.Settings.GitAuthName, clobber)
	if gitAuthChanged {
		return nil, fmt.Errorf("app %s git auth changed, cannot apply changes. Use \"app update-settings\"", appPathDomain)
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

	updated := specChanged || gitBranchChanged || gitCommitChanged || paramsChanged ||
		contConfigChanged || contArgsChanged || contVolsChanged || appConfigChanged
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
		DryRun: dryRun,
	}
	if reloadApp {
		// Reload does the version increment and promotion
		reloadResult, err := s.ReloadApp(ctx, tx, prodApp, liveApp, approve, dryRun, promote,
			newInfo.GitBranch, newInfo.GitCommit, newInfo.GitAuthName, repoCache, forceReload)
		if err != nil {
			return nil, err
		}
		ret.ApproveResult = reloadResult.ApproveResult
		ret.Reloaded = reloadResult.ReloadResults
		ret.Skipped = reloadResult.SkippedResults
		promoteApp = len(reloadResult.PromoteResults) > 0
	} else if updated {
		// No reload, increment version and promote (if enabled)
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
