// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"strings"

	apppkg "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func (s *Server) ReloadApp(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, stageAppEntry *types.AppEntry,
	approve, dryRun, promote bool, branch, commit, gitAuth string, repoCache *RepoCache, forceReload, verify bool) (*types.AppReloadResult, error) {
	verify = verify && !dryRun
	prodAppEntry := appEntry
	var err error
	if !appEntry.IsDev {
		if stageAppEntry != nil {
			appEntry = stageAppEntry
		} else {
			appEntry, err = s.getStageApp(ctx, tx, appEntry)
			if err != nil {
				return nil, err
			}
		}
	}

	var reloaded bool
	if reloaded, err = s.loadAppCode(ctx, tx, appEntry, branch, commit, gitAuth, repoCache, forceReload); err != nil {
		return nil, err
	}
	if !reloaded {
		ret := &types.AppReloadResult{
			DryRun:         dryRun,
			ApproveResult:  nil,
			ReloadResults:  []types.AppPathDomain{},
			PromoteResults: []types.AppPathDomain{},
			SkippedResults: []types.AppPathDomain{appEntry.AppPathDomain()},
		}
		return ret, nil
	}

	// Track which sync entry last applied to this app. Imperative commands do
	// not reset the sync id. The prod app picks this up on promote.
	if syncId := system.GetContextValue(ctx, types.SYNC_ID); syncId != "" {
		appEntry.Metadata.AppliedSyncId = syncId
	}

	// Persist the metadata so that any git info is saved
	if err := s.db.UpdateAppMetadata(ctx, tx, appEntry); err != nil {
		return nil, err
	}
	if err := s.db.UpdateAppSettings(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	app, err := s.setupApp(ctx, appEntry, tx)
	if err != nil {
		return nil, fmt.Errorf("error setting up app %s: %w", appEntry, err)
	}

	auditResult, err := app.Audit()
	if err != nil {
		return nil, fmt.Errorf("error auditing app %s: %w", appEntry, err)
	}

	var approvalResult *types.ApproveResult
	if auditResult.NeedsApproval && !approve {
		return nil, fmt.Errorf("app %s needs approval", appEntry)
	}
	if approve {
		s.approveAuditResult(app, auditResult)
		if err := s.db.UpdateAppMetadata(ctx, tx, app.AppEntry); err != nil {
			return nil, err
		}
		if auditResult.NeedsApproval {
			approvalResult = auditResult
		}
	}
	reloadResults := make([]types.AppPathDomain, 0)
	promoteResults := make([]types.AppPathDomain, 0)
	if _, err := app.Reload(ctx, true, true, types.DryRun(dryRun), apppkg.ReloadOptions{ReloadContainer: true, Verify: verify}); err != nil {
		if verify {
			if container.ClusterRollbackClean(err) {
				return nil, fmt.Errorf("verify failed for app %s: %w. All changes have been reverted", appEntry.AppPathDomain(), err)
			}
			return nil, fmt.Errorf("verify failed for app %s: %w", appEntry.AppPathDomain(), err)
		}
		return nil, fmt.Errorf("error reloading app %s: %w", appEntry, err)
	}
	// Persist name in metadata
	if err := s.db.UpdateAppMetadata(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	reloadResults = append(reloadResults, appEntry.AppPathDomain())
	if promote && !appEntry.IsDev {
		if err = s.promoteApp(ctx, tx, appEntry, prodAppEntry); err != nil {
			return nil, err
		}
		promoteResults = append(promoteResults, appEntry.AppPathDomain())
		prodApp, err := s.setupApp(ctx, prodAppEntry, tx)
		if err != nil {
			return nil, fmt.Errorf("error setting up prod app %s: %w", prodAppEntry, err)
		}

		if _, err := prodApp.Reload(ctx, true, true, types.DryRun(dryRun), apppkg.ReloadOptions{ReloadContainer: true, Verify: verify}); err != nil {
			if verify {
				if container.ClusterRollbackClean(err) {
					return nil, fmt.Errorf("verify failed for app %s: %w. All changes have been reverted", prodAppEntry.AppPathDomain(), err)
				}
				return nil, fmt.Errorf("verify failed for app %s: %w", prodAppEntry.AppPathDomain(), err)
			}
			return nil, fmt.Errorf("error reloading prod app %s: %w", appEntry, err)
		}
		// Persist name in metadata
		if err := s.db.UpdateAppMetadata(ctx, tx, prodAppEntry); err != nil {
			return nil, err
		}
		reloadResults = append(reloadResults, prodAppEntry.AppPathDomain())
	}

	ret := &types.AppReloadResult{
		DryRun:         dryRun,
		ApproveResult:  approvalResult,
		ReloadResults:  reloadResults,
		PromoteResults: promoteResults,
		SkippedResults: []types.AppPathDomain{},
	}
	return ret, nil
}

func (s *Server) ReloadApps(ctx context.Context, appPathGlob string, approve, dryRun, promote bool,
	branch, commit, gitAuth string, forceReload, verify bool) (_ *types.AppReloadResponse, retErr error) {
	verify = verify && !dryRun
	filteredApps, err := s.FilterApps(appPathGlob, false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	// The repo cache is shared between the image pre-build pass and the main
	// reload loop, so each git repo is checked out only once.
	repoCache, err := NewRepoCache(s)
	if err != nil {
		return nil, err
	}
	defer repoCache.Cleanup()

	if verify && s.config.System.UseImagePreBuildStep {
		// Build container images before the metadata transaction is opened.
		// Image names are content-hashed, so the main loop's ImageExists check
		// finds them and skips the (slow) in-transaction build. If anything
		// diverges, the main loop builds in-transaction as before; this pass
		// only warms the image cache and cannot change the deployed result.
		if err := s.preBuildReloadImages(ctx, filteredApps, approve, branch, commit, gitAuth, repoCache, forceReload); err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Operation-level cluster rollback: if any app fails after earlier apps
	// already mutated their Kubernetes deployments in-place, roll those earlier
	// changes back too, so the cluster matches the rolled-back DB transaction.
	ctx, dscope := s.beginDeployScope(ctx, true)
	defer func() { retErr = dscope.finish(ctx, retErr) }()

	reloadResults := make([]types.AppPathDomain, 0, len(filteredApps))
	approveResults := make([]types.ApproveResult, 0, len(filteredApps))
	promoteResults := make([]types.AppPathDomain, 0, len(filteredApps))
	skippedResults := make([]types.AppPathDomain, 0, len(filteredApps))

	// Track the staging and prod apps
	for _, appInfo := range filteredApps {
		appEntry, err := s.GetAppEntry(ctx, tx, appInfo.AppPathDomain)
		if err != nil {
			return nil, err
		}
		stageAppEntry := appEntry
		if !appEntry.IsDev {
			stageAppEntry, err = s.getStageApp(ctx, tx, appEntry)
			if err != nil {
				return nil, err
			}
		}
		ret, err := s.ReloadApp(ctx, tx, appEntry, stageAppEntry, approve, dryRun, promote,
			branch, commit, gitAuth, repoCache, forceReload, verify)
		if err != nil {
			return nil, err
		}

		reloadResults = append(reloadResults, ret.ReloadResults...)
		if ret.ApproveResult != nil {
			approveResults = append(approveResults, *ret.ApproveResult)
		}
		promoteResults = append(promoteResults, ret.PromoteResults...)
		skippedResults = append(skippedResults, ret.SkippedResults...)
	}

	// Commit the transaction if not dry run and update the in memory app store
	updatedApps := make([]types.AppPathDomain, 0, len(reloadResults))
	updatedApps = append(updatedApps, reloadResults...)
	if err := s.CompleteTransaction(ctx, tx, updatedApps, dryRun, "reload"); err != nil {
		return nil, err
	}
	if err := dscope.commit(ctx); err != nil {
		return nil, err
	}

	ret := &types.AppReloadResponse{
		DryRun:         dryRun,
		ReloadResults:  reloadResults,
		ApproveResults: approveResults,
		PromoteResults: promoteResults,
		SkippedResults: skippedResults,
	}

	return ret, nil
}

// preBuildReloadImages builds the container image for each app to be reloaded,
// before the main reload transaction starts. Each app's new source is loaded
// under a throwaway transaction that is rolled back once the build inputs have
// been extracted to disk, so no DB locks are held while the (potentially slow)
// image builds run.
func (s *Server) preBuildReloadImages(ctx context.Context, filteredApps []types.AppInfo, approve bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) error {
	for _, appInfo := range filteredApps {
		if appInfo.IsDev {
			// Dev apps build through DevReload from local disk, not pre-built
			continue
		}
		application, plan, err := s.prepareAppImage(ctx, appInfo.AppPathDomain, approve, branch, commit, gitAuth, repoCache, forceReload)
		if err != nil {
			return err
		}
		if application == nil {
			continue
		}
		// The throwaway transaction is closed at this point; the build reads
		// only from the temp source dir captured in the plan
		buildErr := application.ExecuteContainerBuild(ctx, plan)
		application.Close() //nolint:errcheck // throwaway app object, stop its background tickers
		if buildErr != nil {
			return buildErr
		}
	}
	return nil
}

// prepareAppImage loads the new app source for one app under a throwaway
// transaction and returns the app along with its container build plan (with
// the build inputs already extracted to a temp dir). The transaction is always
// rolled back; the main reload pass redoes the metadata work under the real
// transaction. Returns a nil app when there is nothing to reload.
func (s *Server) prepareAppImage(ctx context.Context, appPathDomain types.AppPathDomain, approve bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) (*apppkg.App, *apppkg.BuildPlan, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.GetAppEntry(ctx, tx, appPathDomain)
	if err != nil {
		return nil, nil, err
	}
	if !appEntry.IsDev {
		appEntry, err = s.getStageApp(ctx, tx, appEntry)
		if err != nil {
			return nil, nil, err
		}
	}

	reloaded, err := s.loadAppCode(ctx, tx, appEntry, branch, commit, gitAuth, repoCache, forceReload)
	if err != nil || !reloaded {
		return nil, nil, err
	}

	application, err := s.setupApp(ctx, appEntry, tx)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up app %s: %w", appEntry, err)
	}
	fail := func(err error) (*apppkg.App, *apppkg.BuildPlan, error) {
		application.Close() //nolint:errcheck // throwaway app object, stop its background tickers
		return nil, nil, err
	}

	// Mirror the audit/approval sequence of ReloadApp so the app loads with the
	// same (in-memory) approvals it will have in the main pass, and so apps
	// needing approval fail here, before any state has been mutated
	auditResult, err := application.Audit()
	if err != nil {
		return fail(fmt.Errorf("error auditing app %s: %w", appEntry, err))
	}
	if auditResult.NeedsApproval && !approve {
		return fail(fmt.Errorf("app %s needs approval", appEntry))
	}
	if approve {
		s.approveAuditResult(application, auditResult)
	}

	if _, err := application.Reload(ctx, true, true, types.DryRunFalse, apppkg.ReloadOptions{SkipContainer: true}); err != nil {
		return fail(fmt.Errorf("error reloading app %s: %w", appEntry, err))
	}

	plan, err := application.PrepareContainerBuild(ctx)
	if err != nil {
		return fail(err)
	}
	return application, plan, nil
}

func (s *Server) loadAppCode(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) (bool, error) {
	s.Debug().Msgf("Reloading app code %v", appEntry)

	if system.IsGit(appEntry.SourceUrl) {
		currentSha := appEntry.Metadata.VersionMetadata.GitCommit
		if !forceReload && currentSha != "" && currentSha == commit {
			// Commit is specified and matches the current version, skip reload
			s.Info().Msgf("App %s already at requested commit %s, skipping reload", appEntry.AppPathDomain(), currentSha)
			return false, nil
		}

		branch = cmp.Or(branch, appEntry.Metadata.VersionMetadata.GitBranch, "main")
		gitAuth = cmp.Or(gitAuth, appEntry.Metadata.GitAuthName)
		newSha, err := repoCache.GetSha(appEntry.SourceUrl, branch, gitAuth)
		if err != nil {
			return false, fmt.Errorf("error getting git commit sha for %s: %w", appEntry.SourceUrl, err)
		}
		if !forceReload && currentSha != "" && newSha == currentSha && (commit == "" || commit == currentSha) {
			// If no commit is specified, and the current version is the same as the latest commit, skip reload
			s.Debug().Msgf("App %s already at latest commit %s, skipping reload", appEntry.AppPathDomain(), newSha)
			return false, nil
		}

		// Checkout the git repo locally and load into database
		if err := s.loadSourceFromGit(ctx, tx, appEntry, branch, commit, gitAuth, repoCache); err != nil {
			return false, err
		}
	} else {
		// App is loaded from disk (not git), load files into DB
		if err := s.loadSourceFromDisk(ctx, tx, appEntry); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (s *Server) StagedUpdate(ctx context.Context, appPathGlob string, dryRun, promote bool, handler stagedUpdateHandler, args map[string]any, op string) (*types.AppStagedUpdateResponse, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	result, entries, promoteResults, err := s.StagedUpdateAppsTx(ctx, tx, appPathGlob, promote, handler, args)
	if err != nil {
		return nil, err
	}

	ret := &types.AppStagedUpdateResponse{
		DryRun:              dryRun,
		StagedUpdateResults: result,
		PromoteResults:      promoteResults,
	}

	if err := s.CompleteTransaction(ctx, tx, entries, dryRun, op); err != nil {
		return nil, err
	}

	return ret, nil
}

type stagedUpdateHandler func(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error)

func (s *Server) StagedUpdateAppsTx(ctx context.Context, tx types.Transaction, appPathGlob string, promote bool, handler stagedUpdateHandler, args map[string]any) ([]any, []types.AppPathDomain, []types.AppPathDomain, error) {
	filteredApps, err := s.FilterApps(appPathGlob, false)
	if err != nil {
		return nil, nil, nil, err
	}

	results := make([]any, 0, len(filteredApps))
	entries := make([]types.AppPathDomain, 0, len(filteredApps))
	promoteResults := make([]types.AppPathDomain, 0, len(filteredApps))
	for _, appInfo := range filteredApps {
		appEntry, err := s.GetAppEntry(ctx, tx, appInfo.AppPathDomain)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error getting prod app %s: %w", appInfo, err)
		}

		var prodAppEntry *types.AppEntry
		if !appEntry.IsDev {
			// For prod apps, update the staging app
			prodAppEntry = appEntry
			appEntry, err = s.getStageApp(ctx, tx, appEntry)
			if err != nil {
				return nil, nil, nil, err
			}

			stagingFileStore, err := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("error initializing staging file store: %w", err)
			}
			err = stagingFileStore.IncrementAppVersion(ctx, tx, &appEntry.Metadata)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("error incrementing app version: %w", err)
			}
		}

		result, app, err := handler(ctx, tx, appEntry, args)
		if err != nil {
			return nil, nil, nil, err
		}

		if err := s.db.UpdateAppMetadata(ctx, tx, appEntry); err != nil {
			return nil, nil, nil, err
		}

		if promote && prodAppEntry != nil {
			if err = s.promoteApp(ctx, tx, appEntry, prodAppEntry); err != nil {
				return nil, nil, nil, err
			}

			// prod app audit result is not added to results, since it will be same as the staging app
			prodApp, err := s.setupApp(ctx, prodAppEntry, tx)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("error setting up prod app %s: %w", prodAppEntry, err)
			}
			entries = append(entries, prodApp.AppPathDomain())
			promoteResults = append(promoteResults, prodAppEntry.AppPathDomain())
		}

		entries = append(entries, app)
		results = append(results, result)
	}

	return results, entries, promoteResults, nil
}

func (s *Server) auditHandler(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error) {
	appPathDomain := appEntry.AppPathDomain()
	app, err := s.setupApp(ctx, appEntry, tx)
	if err != nil {
		return nil, appPathDomain, err
	}
	result, err := s.auditApp(ctx, tx, app, true)
	if err != nil {
		return nil, appPathDomain, err
	}

	return result, appPathDomain, nil
}

// ApproveApps approves the plugin and permission usage for apps matching the
// glob. With dryRun, the pending permissions are returned without approving
func (s *Server) ApproveApps(ctx context.Context, appPathGlob string, dryRun, promote bool) (*types.AppStagedUpdateResponse, error) {
	return s.StagedUpdate(ctx, appPathGlob, dryRun, promote, s.auditHandler, map[string]any{}, "approve")
}

// UpdateAppParams updates a single param value for apps matching the glob.
// A value of "-" deletes the param. The change applies to staging and is
// promoted to prod when promote is set
func (s *Server) UpdateAppParams(ctx context.Context, appPathGlob string, dryRun, promote bool, paramName, paramValue string) (*types.AppStagedUpdateResponse, error) {
	args := map[string]any{
		"paramName":  paramName,
		"paramValue": paramValue,
	}
	return s.StagedUpdate(ctx, appPathGlob, dryRun, promote, s.updateParamHandler, args, "update-param")
}

// ReplaceAppParams replaces all the param values for apps matching the glob.
// The change applies to staging and is promoted to prod when promote is set
func (s *Server) ReplaceAppParams(ctx context.Context, appPathGlob string, dryRun, promote bool, params map[string]string) (*types.AppStagedUpdateResponse, error) {
	args := map[string]any{
		"params": params,
	}
	return s.StagedUpdate(ctx, appPathGlob, dryRun, promote, s.replaceParamsHandler, args, "update-param")
}

func (s *Server) replaceParamsHandler(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error) {
	params := args["params"].(map[string]string)
	appEntry.Metadata.ParamValues = maps.Clone(params)
	appPathDomain := appEntry.AppPathDomain()
	return appPathDomain, appPathDomain, nil
}

func (s *Server) PromoteApps(ctx context.Context, appPathGlob string, dryRun bool) (*types.AppPromoteResponse, error) {
	filteredApps, err := s.FilterApps(appPathGlob, false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	result := make([]types.AppPathDomain, 0, len(filteredApps))
	for _, appInfo := range filteredApps {
		// FilterApps returns only main apps; skip anything that is not a prod app
		if !strings.HasPrefix(string(appInfo.Id), types.ID_PREFIX_APP_PROD) {
			continue
		}

		prodAppEntry, err := s.GetAppEntry(ctx, tx, appInfo.AppPathDomain)
		if err != nil {
			return nil, fmt.Errorf("error getting prod app %s: %w", appInfo, err)
		}

		stagingApp, err := s.getStageApp(ctx, tx, prodAppEntry)
		if err != nil {
			return nil, err
		}

		if err = s.promoteApp(ctx, tx, stagingApp, prodAppEntry); err != nil {
			return nil, err
		}

		prodApp, err := s.setupApp(ctx, prodAppEntry, tx)
		if err != nil {
			return nil, fmt.Errorf("error setting up prod app %s: %w", prodAppEntry, err)
		}
		if _, err := prodApp.Reload(ctx, true, true, types.DryRun(dryRun), apppkg.ReloadOptions{ReloadContainer: false, Verify: false}); err != nil {
			return nil, fmt.Errorf("error reloading prod app %s: %w", prodApp.AppEntry, err)
		}
		result = append(result, appInfo.AppPathDomain)
	}

	if err = s.CompleteTransaction(ctx, tx, result, dryRun, "promote"); err != nil {
		return nil, err
	}

	return &types.AppPromoteResponse{
		DryRun:         dryRun,
		PromoteResults: result}, nil
}

func (s *Server) promoteApp(ctx context.Context, tx types.Transaction, stagingApp *types.AppEntry, prodApp *types.AppEntry) error {
	stagingFileStore, err := metadata.NewFileStore(stagingApp.Id, stagingApp.Metadata.VersionMetadata.Version, s.db, tx)
	if err != nil {
		return fmt.Errorf("error initializing staging file store: %w", err)
	}
	prodFileStore, err := metadata.NewFileStore(prodApp.Id, prodApp.Metadata.VersionMetadata.Version, s.db, tx)
	if err != nil {
		return fmt.Errorf("error initializing prod file store: %w", err)
	}
	prevVersion := prodApp.Metadata.VersionMetadata.Version
	newVersion := stagingApp.Metadata.VersionMetadata.Version

	existingProdVersion, _ := prodFileStore.GetAppVersion(ctx, tx, newVersion)
	prodApp.Metadata = stagingApp.Metadata
	if prevVersion != newVersion {
		prodApp.Metadata.VersionMetadata.PreviousVersion = prevVersion
		prodApp.Metadata.VersionMetadata.Version = newVersion // the prod app version after promote is the same as the staging app version
		// there might be some gaps in the prod app version numbers, but that is ok, the attempt is to have the version number in
		// sync with the staging app version number when a promote is done

		if existingProdVersion == nil {
			if err := stagingFileStore.PromoteApp(ctx, tx, prodApp.Id, &prodApp.Metadata); err != nil {
				return err
			}
		}
	}

	// Even if there is no version change, promotion is done to update other metadata settings like account links
	if err := s.db.UpdateAppMetadata(ctx, tx, prodApp); err != nil {
		return err
	}
	return nil
}

func (s *Server) UpdateAppSettings(ctx context.Context, appPathGlob string, dryRun bool, updateAppRequest types.UpdateAppRequest) (*types.AppUpdateSettingsResponse, error) {
	filteredApps, err := s.FilterApps(appPathGlob, false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	results := make([]types.AppPathDomain, 0, len(filteredApps))
	for _, appInfo := range filteredApps {
		_, err := s.GetAppEntry(ctx, tx, appInfo.AppPathDomain)
		if err != nil {
			return nil, fmt.Errorf("error getting prod app %s: %w", appInfo, err)
		}

		appResults, err := s.updateAppSettings(ctx, tx, appInfo.AppPathDomain, updateAppRequest)
		if err != nil {
			return nil, err
		}

		results = append(results, appResults...)
	}

	ret := &types.AppUpdateSettingsResponse{
		DryRun:        dryRun,
		UpdateResults: results,
	}

	if dryRun {
		return ret, nil
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	err = s.apps.ClearAppsAudit(ctx, results, "update_settings") // Delete instead of update to avoid having to initialize all the linked apps
	if err != nil {
		return nil, err
	}
	// Apps will get reloaded on the next request
	return ret, nil
}

func (s *Server) updateAppSettings(ctx context.Context, tx types.Transaction, appPathDomain types.AppPathDomain, updateAppRequest types.UpdateAppRequest) ([]types.AppPathDomain, error) {
	mainAppEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}

	linkedApps, err := s.db.GetLinkedApps(ctx, tx, mainAppEntry.Id)
	if err != nil {
		return nil, err
	}

	linkedApps = append(linkedApps, mainAppEntry) // Include the main app

	ret := make([]types.AppPathDomain, 0, len(linkedApps))
	for _, linkedApp := range linkedApps {
		if updateAppRequest.StageWriteAccess != types.BoolValueUndefined {
			if updateAppRequest.StageWriteAccess == types.BoolValueTrue {
				linkedApp.Settings.StageWriteAccess = true
			} else {
				linkedApp.Settings.StageWriteAccess = false
			}
		}

		if updateAppRequest.PreviewWriteAccess != types.BoolValueUndefined {
			if updateAppRequest.PreviewWriteAccess == types.BoolValueTrue {
				linkedApp.Settings.PreviewWriteAccess = true
			} else {
				linkedApp.Settings.PreviewWriteAccess = false
			}
		}

		if err := s.db.UpdateAppSettings(ctx, tx, linkedApp); err != nil {
			return nil, err
		}

		ret = append(ret, linkedApp.AppPathDomain())
	}

	return ret, nil
}

func (s *Server) accountLinkHandler(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error) {
	if appEntry.Metadata.Accounts == nil {
		appEntry.Metadata.Accounts = []types.AccountLink{}
	}

	plugin := args["plugin"].(string)
	account := args["account"].(string)

	matchIndex := -1
	for i, accountLink := range appEntry.Metadata.Accounts {
		if accountLink.Plugin == plugin {
			// Update existing value
			accountLink.AccountName = account
			matchIndex = i
			break
		}
	}
	if matchIndex == -1 {
		// Add new value
		appEntry.Metadata.Accounts = append(appEntry.Metadata.Accounts, types.AccountLink{
			Plugin:      plugin,
			AccountName: account,
		})
	} else {
		if account == "-" {
			// Delete the entry
			appEntry.Metadata.Accounts = append(appEntry.Metadata.Accounts[:matchIndex], appEntry.Metadata.Accounts[matchIndex+1:]...)
		} else {
			// Update existing value
			appEntry.Metadata.Accounts[matchIndex].AccountName = account
		}
	}

	appPathDomain := appEntry.AppPathDomain()
	return appPathDomain, appPathDomain, nil
}

func (s *Server) updateParamHandler(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error) {
	paramName := args["paramName"].(string)
	paramValue := args["paramValue"].(string)

	if appEntry.Metadata.ParamValues == nil {
		appEntry.Metadata.ParamValues = make(map[string]string)
	}

	paramValue = types.StripQuotes(strings.TrimSpace(paramValue))
	if paramValue == "-" {
		// Delete the entry
		delete(appEntry.Metadata.ParamValues, paramName)
	} else {
		// Update existing value
		appEntry.Metadata.ParamValues[paramName] = paramValue
	}

	appPathDomain := appEntry.AppPathDomain()
	return appPathDomain, appPathDomain, nil
}

func (s *Server) updateMetadataHandler(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, args map[string]any) (any, types.AppPathDomain, error) {
	updateMetadata := args["metadata"].(types.UpdateAppMetadataRequest)
	dryRun, _ := args["dryRun"].(bool)

	if updateMetadata.Spec != types.StringValueUndefined {
		// The type is being updated
		var appFiles types.SpecFiles
		if updateMetadata.Spec != "-" {
			appFiles = s.GetAppSpec(types.AppSpec(updateMetadata.Spec))
			if appFiles == nil {
				return nil, appEntry.AppPathDomain(), fmt.Errorf("invalid app spec %s", updateMetadata.Spec)
			}
			appEntry.Metadata.Spec = types.AppSpec(updateMetadata.Spec)
		} else {
			appFiles = make(types.SpecFiles)
			appEntry.Metadata.Spec = types.AppSpec("")
		}

		appEntry.Metadata.SpecFiles = &appFiles
	}

	if updateMetadata.ConfigType != "" && updateMetadata.ConfigType != types.AppMetadataConfigType(types.StringValueUndefined) {
		err := s.updateAppMetadataConfig(ctx, tx, appEntry, updateMetadata.ConfigType, updateMetadata.ConfigEntries, dryRun)
		if err != nil {
			return nil, appEntry.AppPathDomain(), err
		}
	}

	appPathDomain := appEntry.AppPathDomain()
	return appPathDomain, appPathDomain, nil
}

// updateAppMetadataConfig updates the app metadata config.
func (s *Server) updateAppMetadataConfig(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, configType types.AppMetadataConfigType, configEntries []string, dryRun bool) error {
	if len(configEntries) == 0 {
		return nil
	}
	value := configEntries[0]
	if configType == types.AppMetadataAuthnType || configType == types.AppMetadataGitAuthName {
		if len(configEntries) > 1 {
			return fmt.Errorf("expected only one value for %s, got %d", configType, len(configEntries))
		}
	}

	switch configType {
	case types.AppMetadataContainerVolumes:
		appEntry.Metadata.ContainerVolumes = configEntries
		return nil
	case types.AppMetadataBindings:
		resolvedBindings, err := s.resolveAppBindings(ctx, tx, autoBindingAppID(appEntry), configEntries, dryRun)
		if err != nil {
			return err
		}
		appEntry.Metadata.Bindings = resolvedBindings
		return nil
	case types.AppMetadataBindingPerms:
		appEntry.Metadata.BindingSourcePerms = configEntries
		return nil
	case types.AppMetadataAuthnType:
		if err := s.validateAppAuthnType(string(value)); err != nil {
			return err
		}
		appEntry.Metadata.AuthnType = types.AppAuthnType(value)
		return nil
	case types.AppMetadataGitAuthName:
		appEntry.Metadata.GitAuthName = string(value)
		return nil
	}

	for _, entry := range configEntries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return fmt.Errorf("invalid %s %s, need key=value", configType, entry)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if configType != types.AppMetadataAppConfig {
			value = types.StripQuotes(value)
		}

		switch configType {
		case types.AppMetadataContainerOptions:
			if appEntry.Metadata.ContainerOptions == nil {
				appEntry.Metadata.ContainerOptions = make(map[string]string)
			}
			if value != "-" {
				appEntry.Metadata.ContainerOptions[key] = value
			} else {
				delete(appEntry.Metadata.ContainerOptions, key)
			}
		case types.AppMetadataContainerArgs:
			if appEntry.Metadata.ContainerArgs == nil {
				appEntry.Metadata.ContainerArgs = make(map[string]string)
			}
			if value != "-" {
				appEntry.Metadata.ContainerArgs[key] = value
			} else {
				delete(appEntry.Metadata.ContainerArgs, key)
			}
		case types.AppMetadataAppConfig:
			if appEntry.Metadata.AppConfig == nil {
				appEntry.Metadata.AppConfig = make(map[string]string)
			}
			if value != "-" {
				appEntry.Metadata.AppConfig[key] = value
			} else {
				delete(appEntry.Metadata.AppConfig, key)
			}
		default:
			return fmt.Errorf("invalid config type %s", configType)
		}
	}

	return nil
}
