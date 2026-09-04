// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

func (s *Server) CreateSyncEntry(ctx context.Context, path string, scheduled, dryRun bool, sync *types.SyncMetadata) (_ *types.SyncCreateResponse, retErr error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionSyncCreate, ""); err != nil {
		return nil, err
	}
	if sync.Approve {
		// A sync entry with approve set approves plugin permissions on every run, in
		// system context, for any app its glob matches (including future apps). This
		// needs app:approve granted on all apps
		if err := s.enforceApproveAllApps(ctx); err != nil {
			return nil, err
		}
	}

	// Freeze the creator's authorization on the entry: background runs are
	// authorized against this snapshot, so later grant/role edits do not change
	// what an existing sync may do. Nil (call not RBAC enforced) means the
	// runs stay unrestricted
	rbacSnapshot, err := s.rbacManager.SnapshotUserGrants(ctx)
	if err != nil {
		return nil, err
	}
	sync.RBAC = rbacSnapshot

	// Check out the sync source before the transaction is opened, so the git
	// network operations do not run while the transaction below is held. The
	// warmed cache is passed to runSyncJob, whose in-transaction apply then
	// hits the cache. Errors are left for the sync job itself to report.
	repoCache, err := NewRepoCache(s)
	if err != nil {
		return nil, err
	}
	defer repoCache.Cleanup()
	if _, _, _, _, err := s.checkoutApplySource(ctx, path, sync.GitBranch, "", sync.GitAuth, "",
		sync.ForceReload, types.AppReloadOption(sync.Reload), repoCache, false); err != nil {
		s.Debug().Err(err).Msgf("git prefetch: error warming apply source for sync create %s", path)
	}
	if !dryRun {
		if err := s.prepareSyncDeploys(ctx, &types.SyncEntry{Path: path, Metadata: *sync}, repoCache); err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Own the operation-level rollback scope for the sync job below: if the job
	// or this transaction's commit fails, in-place Kubernetes changes and the
	// binding accounts/grants created on external services are reverted along
	// with the DB transaction.
	ctx, deployScope := s.beginDeployScope(ctx, true, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()

	genId, err := ksuid.NewRandom()
	if err != nil {
		return nil, err
	}
	id := "cl_syn_" + strings.ToLower(genId.String())

	if !scheduled {
		// Webhook sync entry
		secret, err := passwd.GeneratePassword()
		if err != nil {
			return nil, err
		}
		sync.WebhookSecret = fmt.Sprintf("cl_tkn_%s", base64.StdEncoding.EncodeToString([]byte(secret)))
	} else if sync.ScheduleFrequency <= 0 {
		sync.ScheduleFrequency = s.Config().System.DefaultScheduleMins
	}

	syncEntry := types.SyncEntry{
		Id:          id,
		Path:        path,
		IsScheduled: scheduled,
		UserID:      system.GetContextUserId(ctx),
		Metadata:    *sync,
	}

	// Persist the settings
	if err := s.db.CreateSync(ctx, tx, &syncEntry); err != nil {
		return nil, err
	}

	syncStatus, updatedApps, err := s.runSyncJob(ctx, tx, &syncEntry, dryRun, true, repoCache)
	if err != nil {
		return nil, err
	}
	if syncStatus.Error != "" {
		// The sync job failed, delete the entry
		return nil, errors.New(syncStatus.Error)
	}

	ret := types.SyncCreateResponse{
		Id:                syncEntry.Id,
		DryRun:            dryRun,
		WebhookUrl:        "", // TODO
		WebhookSecret:     syncEntry.Metadata.WebhookSecret,
		ScheduleFrequency: syncEntry.Metadata.ScheduleFrequency,
		SyncJobStatus:     *syncStatus,
	}

	if err := s.CompleteTransaction(ctx, tx, updatedApps, dryRun, "create_sync"); err != nil {
		return nil, err
	}
	if err := deployScope.commit(ctx); err != nil {
		return nil, err
	}

	return &ret, nil
}

func (s *Server) RunSync(ctx context.Context, id string, dryRun bool) (_ *types.SyncJobStatus, retErr error) {
	// Read the entry under a short-lived transaction and warm the git caches
	// before the main transaction is opened, so the sync's git network
	// operations do not run while the main transaction below is held
	readTx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	syncEntry, err := s.db.GetSyncEntry(ctx, readTx, id)
	readTx.Rollback() //nolint:errcheck
	if err != nil {
		return nil, err
	}

	// sync:run globally, or ownership of the entry, allows a manual run
	if err := s.enforceGlobalPerm(ctx, types.PermissionSyncRun, syncEntry.UserID); err != nil {
		return nil, err
	}

	repoCache, err := NewRepoCache(s)
	if err != nil {
		return nil, err
	}
	defer repoCache.Cleanup()
	if _, _, _, _, err := s.checkoutApplySource(ctx, syncEntry.Path, syncEntry.Metadata.GitBranch, "", syncEntry.Metadata.GitAuth, "",
		syncEntry.Metadata.ForceReload, types.AppReloadOption(syncEntry.Metadata.Reload), repoCache, false); err != nil {
		s.Debug().Err(err).Msgf("git prefetch: error warming apply source for sync run %s", id)
	}
	if !dryRun {
		if err := s.prepareSyncDeploys(context.WithValue(ctx, types.SYNC_ID, id), syncEntry, repoCache); err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Own the operation-level rollback scope for the sync job below.
	ctx, deployScope := s.beginDeployScope(ctx, true, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()

	syncStatus, updatedApps, err := s.runSyncJob(ctx, tx, syncEntry, dryRun, true, repoCache)
	if err != nil {
		return nil, err
	}
	if syncStatus.Error != "" {
		// The sync job job failed, status would be already updated
		return nil, errors.New(syncStatus.Error)
	}

	if err := s.CompleteTransaction(ctx, tx, updatedApps, dryRun, "sync_run"); err != nil {
		return nil, err
	}
	if err := deployScope.commit(ctx); err != nil {
		return nil, err
	}
	return syncStatus, nil
}

func (s *Server) DeleteSyncEntry(ctx context.Context, id string, dryRun bool) (*types.SyncDeleteResponse, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if s.rbacManager.APIEnforced(ctx) {
		// sync:delete globally, or ownership of the entry, allows the delete
		syncEntry, err := s.db.GetSyncEntry(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := s.enforceGlobalPerm(ctx, types.PermissionSyncDelete, syncEntry.UserID); err != nil {
			return nil, err
		}
	}

	if err := s.db.DeleteSync(ctx, tx, id); err != nil {
		return nil, err
	}

	ret := types.SyncDeleteResponse{
		Id:     id,
		DryRun: dryRun,
	}

	if dryRun {
		return &ret, nil
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (s *Server) ListSyncEntries(ctx context.Context) (*types.SyncListResponse, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	entries, err := s.db.GetSyncEntries(ctx, tx)
	if err != nil {
		return nil, err
	}

	if s.rbacManager.APIEnforced(ctx) {
		// Filter to entries the user can see: sync:read globally or entries they own
		visible := make([]*types.SyncEntry, 0, len(entries))
		for _, e := range entries {
			authorized, err := s.rbacManager.AuthorizeGlobalAPI(ctx, types.PermissionSyncRead, e.UserID)
			if err != nil {
				return nil, err
			}
			if authorized {
				visible = append(visible, e)
			}
		}
		entries = visible
	}

	for _, e := range entries {
		e.Metadata.WebhookUrl = "" // TODO: Set the actual webhook URL
	}

	ret := types.SyncListResponse{
		Entries: entries,
	}
	return &ret, nil
}

func (s *Server) syncRunner(timer *time.Ticker, stop <-chan struct{}) {
	s.Info().Msg("Starting sync runner loop")
	for {
		select {
		case <-stop:
			s.Info().Msg("Sync runner stopped")
			return
		case <-timer.C:
		}

		if !s.db.IsLeader() {
			s.Trace().Msg("Not leader, skipping sync")
			continue
		} else {
			s.Trace().Msg("Leader, running sync jobs")
		}
		if err := s.db.CleanupExpiredKV(context.Background()); err != nil {
			s.Error().Err(err).Msg("Error cleaning up expired KV entries")
		}
		// Job scheduling and run reconciliation share the leader's minute
		// loop with the sync runner
		s.jobsTick(context.Background())
		err := s.runSyncJobs()
		if err != nil {
			s.Error().Err(err).Msg("Error running sync")
			continue
		}
	}
}

// attachSyncRBAC attaches the sync entry's frozen creator authorization to a
// background run context; the run's apply/reload actions are then enforced
// against that snapshot (see rbac.SyncAuthorizer). Entries without a snapshot
// (created without RBAC enforcement, or predating it) run unrestricted
// (WithSyncAuthorizer is a no-op for a nil snapshot), and disabling RBAC
// disables snapshot enforcement too, consistent with every other check. A
// future webhook sync executor must build its run context through this helper
// as well
func (s *Server) attachSyncRBAC(ctx context.Context, entry *types.SyncEntry) context.Context {
	if !s.rbacManager.ConfigEnabled() {
		return ctx
	}
	return rbac.WithSyncAuthorizer(ctx, rbac.NewSyncAuthorizer(entry.Metadata.RBAC))
}

// enforceSyncReloadPerms authorizes everything a skipped-apply reload pass will
// do before any app is mutated: app:apply, app:approve (when the entry
// approves) and app:promote (when promoting) on every app
func (s *Server) enforceSyncReloadPerms(ctx context.Context, entry *types.SyncEntry,
	appPaths []types.AppPathDomain, appMap map[types.AppPathDomain]*types.AppEntry) error {
	for _, appPath := range appPaths {
		if err := s.enforceAppPermEntry(ctx, types.PermissionApply, appMap[appPath]); err != nil {
			return err
		}
		if entry.Metadata.Approve {
			// an approving reload approves plugin permissions, needs
			// app:approve on the app
			if err := s.enforceAppPermEntry(ctx, types.PermissionApprove, appMap[appPath]); err != nil {
				return err
			}
		}
		if entry.Metadata.Promote {
			if err := s.enforceAppPermEntry(ctx, types.PermissionPromote, appMap[appPath]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) runSyncJobs() error {
	ctx := context.Background()
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Create a new repo cache if not passed in
	repoCache, err := NewRepoCache(s)
	if err != nil {
		return err
	}
	defer repoCache.Cleanup()

	scheduleEntries, err := s.db.GetSyncEntries(ctx, tx)
	if err != nil {
		return err
	}
	// The transaction was needed only to read the sync entries; release its
	// read snapshot before the (potentially slow) jobs run, so it does not pin
	// the sqlite WAL and block checkpoints. Each job runs in its own transaction.
	tx.Rollback() //nolint:errcheck

	updatedAnyApps := false
	for _, entry := range scheduleEntries {
		if !entry.IsScheduled || entry.Metadata.ScheduleFrequency <= 0 {
			continue
		}

		if !entry.Status.LastExecutionTime.IsZero() && entry.Status.LastExecutionTime.Add(time.Duration(entry.Metadata.ScheduleFrequency)*time.Minute).After(time.Now()) {
			s.Trace().Msgf("Sync job %s not ready to run", entry.Id)
			continue
		}

		if entry.Status.FailureCount >= s.Config().System.MaxSyncFailureCount {
			s.Trace().Msgf("Sync job %s has failed too many times, skipping", entry.Id)
			continue
		}

		// Each scheduled run gets its own synthesized request id, so the
		// audit events it produces (apply, reload, promote, ...) share a
		// trace id even though there is no HTTP request behind the run. The
		// run is attributed to the user who created the sync and authorized
		// against the creator's frozen RBAC snapshot when one is present
		jobCtx := s.attachSyncRBAC(newBackgroundOperationContext(cmp.Or(entry.UserID, "scheduler")), entry)
		_, updatedApps, err := s.runSyncJob(jobCtx, types.Transaction{}, entry, false, true, repoCache) // each sync runs in its own transaction
		if err != nil {
			s.Error().Err(err).Msgf("Error running sync job %s", entry.Id)
			// One failure does not stop the rest
			continue
		}
		if len(updatedApps) > 0 {
			updatedAnyApps = true
		}
	}

	if updatedAnyApps {
		s.CleanupVersions()
	}
	return nil
}

func (s *Server) runSyncJob(ctx context.Context, inputTx types.Transaction, entry *types.SyncEntry,
	dryRun, checkCommitHash bool, repoCache *RepoCache) (_ *types.SyncJobStatus, _ []types.AppPathDomain, retErr error) {
	var tx types.Transaction
	var err error
	var prepErr error

	s.Debug().Msgf("Running sync job %s", entry.Id)
	if repoCache == nil {
		// Create a new repo cache if not passed in
		repoCache, err = NewRepoCache(s)
		if err != nil {
			return nil, nil, err
		}
		defer repoCache.Cleanup()
	}

	lastRunApps := entry.Status.ApplyResponse.FilteredApps
	lastRunCommitId := ""
	if checkCommitHash {
		lastRunCommitId = entry.Status.CommitId
	}

	if inputTx.Tx == nil {
		// Warm the git caches before the transaction is opened, so the apply
		// (and a possible reload=matched pass) run no network git operations
		// while holding a database transaction. Best-effort: errors are left
		// for the apply itself to report through the failure count/backoff
		if _, _, _, _, err := s.checkoutApplySource(ctx, entry.Path, entry.Metadata.GitBranch, "", entry.Metadata.GitAuth,
			lastRunCommitId, entry.Metadata.ForceReload, types.AppReloadOption(entry.Metadata.Reload), repoCache, false); err != nil {
			s.Debug().Err(err).Msgf("git prefetch: error warming apply source for sync %s", entry.Id)
		}
		if types.AppReloadOption(entry.Metadata.Reload) == types.AppReloadOptionMatched {
			s.prefetchAppSources(ctx, lastRunApps, "", "", "", repoCache, entry.Metadata.ForceReload)
		}

		// The deploy gates (before_deploy jobs) of the declared apps run
		// before the transaction opens; a gate failure counts as a sync
		// failure like an apply error. Callers passing a transaction in run
		// this pass before opening it
		if !dryRun {
			prepErr = s.prepareSyncDeploys(context.WithValue(ctx, types.SYNC_ID, entry.Id), entry, repoCache)
		}

		tx, err = s.db.BeginTransaction(ctx)
		if err != nil {
			return nil, nil, err
		}
		defer tx.Rollback() //nolint:errcheck
	} else {
		tx = inputTx
		// No rollback here if transaction is passed in
	}

	// Apps created/reloaded by this job are stamped with the sync id in their
	// metadata (AppliedSyncId)
	ctx = context.WithValue(ctx, types.SYNC_ID, entry.Id)

	// origCtx is the context before the rollback scope is attached; it is used
	// for the recursive full-apply call so that nested call owns a fresh scope.
	origCtx := ctx
	// Own the rollback scope only when we own the DB transaction (the
	// runSyncJobs path passes an empty transaction). When a transaction is
	// passed in, the caller (CreateSyncEntry/RunSync) owns it.
	ctx, deployScope := s.beginDeployScope(ctx, inputTx.Tx == nil, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()

	verify := entry.Metadata.Verify && !dryRun
	var applyInfo *types.AppApplyResponse
	var updatedApps []types.AppPathDomain
	applyErr := prepErr
	if applyErr == nil {
		applyInfo, updatedApps, applyErr = s.Apply(ctx, tx, entry.Path, "all", entry.Metadata.Approve, dryRun, entry.Metadata.Promote, types.AppReloadOption(entry.Metadata.Reload),
			entry.Metadata.GitBranch, "", entry.Metadata.GitAuth, entry.Metadata.Clobber, entry.Metadata.ForceReload, verify, lastRunCommitId, repoCache, false)
	}

	status := types.SyncJobStatus{
		LastExecutionTime: time.Now(),
		IsApply:           true,
		State:             "Enabled",
	}
	if applyErr != nil {
		s.Error().Err(applyErr).Msgf("Error applying sync job %s", entry.Id)
		status.Error = applyErr.Error()
		applyInfo = &types.AppApplyResponse{}
		applyInfo.DryRun = dryRun
		applyInfo.FilteredApps = lastRunApps
		status.FailureCount = entry.Status.FailureCount + 1
		if status.FailureCount >= s.Config().System.MaxSyncFailureCount {
			status.State = "Disabled"
		} else {
			status.State = "Failing"
		}
	} else {
		status.CommitId = applyInfo.CommitId
		status.FailureCount = 0
	}

	if applyErr == nil && !applyInfo.SkippedApply && entry.Metadata.Prune {
		// Delete the resources this sync created that are no longer declared.
		// Runs in the same transaction as the apply: a prune failure (a blocked
		// delete included) rolls the whole run back and counts as a sync failure
		prunedApps, prunedBindings, pruneErr := s.pruneSyncResources(ctx, tx, entry, applyInfo, dryRun)
		if pruneErr != nil {
			s.Error().Err(pruneErr).Msgf("Error pruning resources for sync job %s", entry.Id)
			status.Error = pruneErr.Error()
			status.FailureCount = entry.Status.FailureCount + 1
			if status.FailureCount >= s.Config().System.MaxSyncFailureCount {
				status.State = "Disabled"
			} else {
				status.State = "Failing"
			}
		} else {
			applyInfo.PrunedApps = prunedApps
			applyInfo.PrunedBindings = prunedBindings
		}
	}

	reloadResults := make([]types.AppPathDomain, 0, len(lastRunApps))
	approveResults := make([]types.ApproveResult, 0, len(lastRunApps))
	promoteResults := make([]types.AppPathDomain, 0, len(lastRunApps))

	if applyErr == nil && applyInfo.SkippedApply && entry.Metadata.Reload == string(types.AppReloadOptionMatched) {
		if len(applyInfo.FilteredApps) == 0 {
			// This run was skipped, use the last run apps
			applyInfo.FilteredApps = lastRunApps
		}

		// The apply was skipped, check if the apps need to be reloaded
		// The attempt is to avoid doing a full github checkout on the apply file repo and on the
		// app source repo, a list API is used to get the last commit
		appMap := map[types.AppPathDomain]*types.AppEntry{}
		appMissing := false
		for _, appPath := range lastRunApps {
			app, err := s.db.GetAppEntryTx(ctx, tx, appPath)
			if err != nil {
				appMissing = true
				s.Error().Err(err).Msgf("Error getting app %s", appPath)
				break
			}
			appMap[appPath] = app
		}

		if appMissing {
			// App has been deleted, run the full apply with the latest commit even if it was already applied
			if !checkCommitHash {
				return nil, nil, fmt.Errorf("unexpected error, sync rerun with no commit hash")
			}
			// The apply was skipped, so our rollback scope is empty here. Hand
			// off to the recursive full apply using origCtx so it owns a fresh
			// scope; mark this scope committed so its (empty) rollback is a no-op.
			if err := deployScope.commit(ctx); err != nil {
				return nil, nil, err
			}
			return s.runSyncJob(origCtx, inputTx, entry, dryRun, false, repoCache)
		} else {
			// Enforce all permissions before mutating anything (parity with the
			// apply path checks at Apply): global approve when approving, then
			// app:apply and app:promote per app
			reloadErr := s.enforceSyncReloadPerms(ctx, entry, lastRunApps, appMap)

			// In-place reloads register on the operation-level rollback stack
			// (in ctx); the deferred finish reverts earlier apps if a later one
			// fails, so the cluster matches the rolled-back DB transaction.
			for _, appPath := range lastRunApps {
				if reloadErr != nil {
					break // abort reloads
				}
				app := appMap[appPath]
				var reloadResult *types.AppReloadResult
				reloadResult, reloadErr = s.ReloadApp(ctx, tx, app, nil, entry.Metadata.Approve, false, entry.Metadata.Promote,
					app.Metadata.VersionMetadata.GitBranch, "", app.Metadata.GitAuthName, repoCache, entry.Metadata.ForceReload, verify)
				if reloadErr != nil {
					s.Error().Err(reloadErr).Msgf("Error reloading app %s sync job %s", appPath, entry.Id)
					break
				}

				reloadResults = append(reloadResults, reloadResult.ReloadResults...)
				if reloadResult.ApproveResult != nil {
					approveResults = append(approveResults, *reloadResult.ApproveResult)
				}
				promoteResults = append(promoteResults, reloadResult.PromoteResults...)
			}

			if reloadErr != nil {
				status.Error = reloadErr.Error()
				status.FailureCount = entry.Status.FailureCount + 1
				if status.FailureCount >= s.Config().System.MaxSyncFailureCount {
					status.State = "Disabled"
				} else {
					status.State = "Failing"
				}
				applyInfo.ReloadResults = reloadResults
				applyInfo.ApproveResults = approveResults
				applyInfo.PromoteResults = promoteResults
			}
		}
	}

	if status.Error != "" {
		tx.Rollback() //nolint:errcheck // rollback any changes to db done during apply or reload
		// CreateSyncEntry also aborts if the sync job fails, so rolling back the transaction here is fine
		// Use a new transaction to update the sync status
		tx, err = s.db.BeginTransaction(ctx)
		if err != nil {
			return nil, nil, err
		}
		defer tx.Rollback() //nolint:errcheck
		updatedApps = nil
	}

	status.ApplyResponse = *applyInfo
	err = s.db.UpdateSyncStatus(ctx, tx, entry.Id, &status)
	if err != nil {
		return nil, nil, err
	}

	if status.Error != "" {
		// Persist the failure status: LastExecutionTime, FailureCount and State
		// drive the retry backoff and the MaxSyncFailureCount disable. The sync
		// changes themselves were rolled back above; only the status is committed.
		// The deferred scope finish reverts the cluster and binding side effects.
		if !dryRun {
			if err := tx.Commit(); err != nil {
				return nil, nil, err
			}
		}
		return &status, updatedApps, nil
	}

	if inputTx.Tx == nil {
		if err := s.CompleteTransaction(ctx, tx, updatedApps, dryRun, "sync"); err != nil {
			return nil, nil, err
		}
		if err := deployScope.commit(ctx); err != nil {
			return nil, nil, err
		}
	}

	return &status, updatedApps, nil
}

// pruneSyncResources deletes the apps and bindings created by this sync entry
// that are no longer present in its declaration. Only resources stamped with
// this entry's id at create time (CreatedBySyncId) are considered: resources
// created imperatively (or by another sync) and later updated by this sync are
// never pruned. Deletes run in the caller's transaction, so a prune failure
// rolls back the whole sync run. The post-commit cleanup of pruned apps (app
// store eviction, approval cache invalidation and runtime asset removal) is
// registered as a deploy transaction commit hook, run by the owning scope
// after the metadata commit; pruned bindings' backend artifact drops are
// recorded on the operation's account manager the same way a binding delete
// records them.
func (s *Server) pruneSyncResources(ctx context.Context, tx types.Transaction, entry *types.SyncEntry,
	applyInfo *types.AppApplyResponse, dryRun bool) ([]types.AppPathDomain, []string, error) {

	accounts := bindingEffectsFromContext(ctx)
	if accounts == nil {
		return nil, nil, fmt.Errorf("sync prune requires an operation scope")
	}

	declaredApps := make(map[types.AppPathDomain]bool, len(applyInfo.FilteredApps))
	for _, appPath := range applyInfo.FilteredApps {
		declaredApps[appPath] = true
	}
	// FilterApps returns main and dev apps; linked staging/preview apps are
	// cascade-deleted with their main app
	allApps, err := s.FilterApps("all", false)
	if err != nil {
		return nil, nil, err
	}
	pruneApps := make([]types.AppInfo, 0)
	prunedAppPaths := make([]types.AppPathDomain, 0)
	for _, appInfo := range allApps {
		if appInfo.CreatedBySyncId == entry.Id && !declaredApps[appInfo.AppPathDomain] {
			pruneApps = append(pruneApps, appInfo)
			prunedAppPaths = append(prunedAppPaths, appInfo.AppPathDomain)
		}
	}

	var prunedAppIds []types.AppId
	if len(pruneApps) > 0 {
		for _, appInfo := range pruneApps {
			s.Info().Msgf("Sync %s pruning app %s", entry.Id, appInfo.AppPathDomain)
		}
		// The delete permission checks run against the sync's authority
		// (background runs use the creator's frozen RBAC snapshot)
		if _, prunedAppIds, err = s.deleteAppsTx(ctx, tx, accounts, pruneApps); err != nil {
			return nil, nil, err
		}
	}

	declaredBindings := make(map[string]bool, len(applyInfo.FilteredBindings))
	for _, path := range applyInfo.FilteredBindings {
		declaredBindings[path] = true
	}
	allBindings, err := s.db.ListBindings(ctx, tx, "")
	if err != nil {
		return nil, nil, err
	}
	pruneBindings := make([]*types.Binding, 0)
	for _, binding := range allBindings {
		// Auto bindings exist only for their app and are deleted with it; they
		// are never declared, so they are not prune candidates themselves
		if strings.HasPrefix(binding.Path, autoBindingPathPrefix+"/") {
			continue
		}
		if binding.CreatedBySyncId == entry.Id && !declaredBindings[binding.Path] {
			pruneBindings = append(pruneBindings, binding)
		}
	}
	// Derived bindings are deleted before base bindings so a base pruned in the
	// same run deletes cleanly; a pruned base with a derived binding outside
	// this prune set still fails the run (delete the derived binding first)
	slices.SortStableFunc(pruneBindings, func(a, b *types.Binding) int {
		aDerived := strings.HasPrefix(a.Source, "/")
		bDerived := strings.HasPrefix(b.Source, "/")
		if aDerived == bDerived {
			return 0
		}
		if aDerived {
			return -1
		}
		return 1
	})
	prunedBindingPaths := make([]string, 0, len(pruneBindings))
	for _, binding := range pruneBindings {
		s.Info().Msgf("Sync %s pruning binding %s", entry.Id, binding.Path)
		if err := s.deleteBindingTx(ctx, tx, accounts, binding.Path); err != nil {
			return nil, nil, err
		}
		prunedBindingPaths = append(prunedBindingPaths, binding.Path)
	}

	if !dryRun && (len(pruneApps) > 0 || len(prunedBindingPaths) > 0) {
		if dt := container.DeployTxnFromContext(ctx); dt != nil {
			paths := slices.Clone(prunedAppPaths)
			ids := slices.Clone(prunedAppIds)
			dt.Register(types.AppId(entry.Id), "", nil, func(c context.Context) error {
				s.approvalCacheGen.Add(1)
				var errs []error
				for _, path := range paths {
					if err := s.apps.ClearLinkedApps(path); err != nil {
						errs = append(errs, err)
					}
				}
				if len(ids) > 0 {
					errs = append(errs, s.removeAppRuntimeResources(c, ids))
				}
				return errors.Join(errs...)
			})
		}
	}
	return prunedAppPaths, prunedBindingPaths, nil
}

// prepareSyncDeploys runs the deploy gate pre-pass of a sync run before its
// transaction opens: the apply file is loaded from the warmed repo cache and
// the before_deploy jobs of the existing apps it declares run from their
// new code (see prepareApplyDeploys). Skipped when the sync does not reload
func (s *Server) prepareSyncDeploys(ctx context.Context, entry *types.SyncEntry, repoCache *RepoCache) error {
	reload := types.AppReloadOption(cmp.Or(entry.Metadata.Reload, string(types.AppReloadOptionUpdated)))
	if reload == types.AppReloadOptionNone {
		return nil
	}
	branch := ""
	if system.IsGit(entry.Path) {
		branch = cmp.Or(entry.Metadata.GitBranch, "main")
	}
	dir, file, err := s.setupSource(ctx, entry.Path, branch, "", entry.Metadata.GitAuth, repoCache, false)
	if err != nil {
		return err
	}
	sourceFS, err := appfs.NewSourceFs(dir, appfs.NewDiskReadFS(s.Logger, dir, nil), false)
	if err != nil {
		return err
	}
	defer sourceFS.Close() //nolint:errcheck
	applyConfig, _, _, err := s.loadApplyConfigs(sourceFS, file, entry.Path, branch, false)
	if err != nil {
		return err
	}
	apps := make([]types.AppPathDomain, 0, len(applyConfig))
	for appPathDomain := range applyConfig {
		apps = append(apps, appPathDomain)
	}
	return s.prepareApplyDeploys(ctx, applyConfig, apps, entry.Metadata.Approve, entry.Metadata.Promote, entry.Metadata.Verify,
		reload, repoCache, entry.Metadata.ForceReload)
}
