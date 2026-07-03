// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

func (s *Server) CreateSyncEntry(ctx context.Context, path string, scheduled, dryRun bool, sync *types.SyncMetadata) (_ *types.SyncCreateResponse, retErr error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Own the operation-level cluster rollback for apps reloaded by the sync job
	// below, so that if the job or this transaction's commit fails, in-place
	// Kubernetes changes are reverted along with the DB transaction.
	ctx, dscope := s.beginDeployScope(ctx, true)
	defer func() { retErr = dscope.finish(ctx, retErr) }()

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
		sync.ScheduleFrequency = s.config.System.DefaultScheduleMins
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

	syncStatus, updatedApps, applyEffects, err := s.runSyncJob(ctx, tx, &syncEntry, dryRun, true, nil)
	defer applyEffects.rollbackAndClose(ctx)
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
	// The metadata transaction has committed, keep the binding accounts created
	// on the services.
	applyEffects.commit()
	if err := dscope.commit(ctx); err != nil {
		return nil, err
	}

	return &ret, nil
}

func (s *Server) RunSync(ctx context.Context, id string, dryRun bool) (_ *types.SyncJobStatus, retErr error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Own the operation-level cluster rollback for the sync job below.
	ctx, dscope := s.beginDeployScope(ctx, true)
	defer func() { retErr = dscope.finish(ctx, retErr) }()

	syncEntry, err := s.db.GetSyncEntry(ctx, tx, id)
	if err != nil {
		return nil, err
	}

	syncStatus, updatedApps, applyEffects, err := s.runSyncJob(ctx, tx, syncEntry, dryRun, true, nil)
	defer applyEffects.rollbackAndClose(ctx)
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
	// The metadata transaction has committed, keep the binding accounts created
	// on the services.
	applyEffects.commit()
	if err := dscope.commit(ctx); err != nil {
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

	for _, e := range entries {
		e.Metadata.WebhookUrl = "" // TODO: Set the actual webhook URL
	}

	ret := types.SyncListResponse{
		Entries: entries,
	}
	return &ret, nil
}

func (s *Server) syncRunner() {
	s.Info().Msg("Starting sync runner loop")
	for range s.syncTimer.C {
		if !s.db.IsLeader() {
			s.Trace().Msg("Not leader, skipping sync")
			continue
		} else {
			s.Trace().Msg("Leader, running sync jobs")
		}
		if err := s.db.CleanupExpiredKV(context.Background()); err != nil {
			s.Error().Err(err).Msg("Error cleaning up expired KV entries")
		}
		err := s.runSyncJobs()
		if err != nil {
			s.Error().Err(err).Msg("Error running sync")
			continue
		}
	}
	s.Warn().Msg("Sync runner stopped")
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
	updatedAnyApps := false
	for _, entry := range scheduleEntries {
		if !entry.IsScheduled || entry.Metadata.ScheduleFrequency <= 0 {
			continue
		}

		if !entry.Status.LastExecutionTime.IsZero() && entry.Status.LastExecutionTime.Add(time.Duration(entry.Metadata.ScheduleFrequency)*time.Minute).After(time.Now()) {
			s.Trace().Msgf("Sync job %s not ready to run", entry.Id)
			continue
		}

		if entry.Status.FailureCount >= s.config.System.MaxSyncFailureCount {
			s.Trace().Msgf("Sync job %s has failed too many times, skipping", entry.Id)
			continue
		}

		_, updatedApps, _, err := s.runSyncJob(ctx, types.Transaction{}, entry, false, true, repoCache) // each sync runs in its own transaction
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
	dryRun, checkCommitHash bool, repoCache *RepoCache) (_ *types.SyncJobStatus, _ []types.AppPathDomain, _ *bindingAccountManager, retErr error) {
	var tx types.Transaction
	var err error
	if inputTx.Tx == nil {
		tx, err = s.db.BeginTransaction(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		defer tx.Rollback() //nolint:errcheck
	} else {
		tx = inputTx
		// No rollback here if transaction is passed in
	}

	// Apps created/reloaded by this job are stamped with the sync id in their
	// metadata (AppliedSyncId)
	ctx = context.WithValue(ctx, types.SYNC_ID, entry.Id)

	// origCtx is the context before the rollback stack is attached; it is used
	// for the recursive full-apply call so that nested call owns a fresh stack.
	origCtx := ctx
	// Own the cluster rollback only when we own the DB transaction (the
	// runSyncJobs path passes an empty transaction). When a transaction is
	// passed in, the caller (CreateSyncEntry/RunSync) owns it.
	ctx, dscope := s.beginDeployScope(ctx, inputTx.Tx == nil)
	defer func() { retErr = dscope.finish(ctx, retErr) }()

	s.Debug().Msgf("Running sync job %s", entry.Id)
	if repoCache == nil {
		// Create a new repo cache if not passed in
		repoCache, err = NewRepoCache(s)
		if err != nil {
			return nil, nil, nil, err
		}
		defer repoCache.Cleanup()
	}

	lastRunApps := entry.Status.ApplyResponse.FilteredApps
	lastRunCommitId := ""
	if checkCommitHash {
		lastRunCommitId = entry.Status.CommitId
	}

	verify := entry.Metadata.Verify && !dryRun
	applyInfo, updatedApps, applyEffects, applyErr := s.Apply(ctx, tx, entry.Path, "all", entry.Metadata.Approve, dryRun, entry.Metadata.Promote, types.AppReloadOption(entry.Metadata.Reload),
		entry.Metadata.GitBranch, "", entry.Metadata.GitAuth, entry.Metadata.Clobber, entry.Metadata.ForceReload, verify, lastRunCommitId, repoCache, false)
	if inputTx.Tx == nil {
		defer applyEffects.rollbackAndClose(ctx)
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
		if status.FailureCount >= s.config.System.MaxSyncFailureCount {
			status.State = "Disabled"
		} else {
			status.State = "Failing"
		}
	} else {
		status.CommitId = applyInfo.CommitId
		status.FailureCount = 0
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
				return nil, nil, applyEffects, fmt.Errorf("unexpected error, sync rerun with no commit hash")
			}
			// The apply was skipped, so our rollback stack is empty here. Hand
			// off to the recursive full apply using origCtx so it owns a fresh
			// stack; mark this scope committed so its (empty) rollback is a no-op.
			if err := dscope.commit(ctx); err != nil {
				return nil, nil, applyEffects, err
			}
			return s.runSyncJob(origCtx, inputTx, entry, dryRun, false, repoCache)
		} else {
			var reloadErr error
			// In-place reloads register on the operation-level rollback stack
			// (in ctx); the deferred finish reverts earlier apps if a later one
			// fails, so the cluster matches the rolled-back DB transaction.
			for _, appPath := range lastRunApps {
				app := appMap[appPath]
				var reloadResult *types.AppReloadResult
				reloadResult, reloadErr = s.ReloadApp(ctx, tx, app, nil, entry.Metadata.Approve, false, entry.Metadata.Promote,
					app.Metadata.VersionMetadata.GitBranch, "", app.Metadata.GitAuthName, repoCache, entry.Metadata.ForceReload, verify)
				if reloadErr != nil {
					s.Error().Err(reloadErr).Msgf("Error reloading app %s sync job %s", appPath, entry.Id)
					status.Error = reloadErr.Error()
					status.FailureCount = entry.Status.FailureCount + 1
					if status.FailureCount >= s.config.System.MaxSyncFailureCount {
						status.State = "Disabled"
					} else {
						status.State = "Failing"
					}
					break // abort reloads
				}

				reloadResults = append(reloadResults, reloadResult.ReloadResults...)
				if reloadResult.ApproveResult != nil {
					approveResults = append(approveResults, *reloadResult.ApproveResult)
				}
				promoteResults = append(promoteResults, reloadResult.PromoteResults...)
			}

			if reloadErr != nil {
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
			return nil, nil, applyEffects, err
		}
		defer tx.Rollback() //nolint:errcheck
		updatedApps = nil
	}

	status.ApplyResponse = *applyInfo
	err = s.db.UpdateSyncStatus(ctx, tx, entry.Id, &status)
	if err != nil {
		return nil, nil, applyEffects, err
	}

	if status.Error == "" && inputTx.Tx == nil {
		if err := s.CompleteTransaction(ctx, tx, updatedApps, dryRun, "sync"); err != nil {
			return nil, nil, nil, err
		}
		// The metadata transaction has committed, keep the binding accounts created
		// on the services.
		applyEffects.commit()
		if err := dscope.commit(ctx); err != nil {
			return nil, nil, nil, err
		}
		return &status, updatedApps, nil, nil
	}
	if inputTx.Tx == nil {
		return &status, updatedApps, nil, nil
	}

	return &status, updatedApps, applyEffects, nil
}
