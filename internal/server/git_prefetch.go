// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const gitPrefetchWorkers = 8

// prefetchApplyAppSources checks out independent git app sources concurrently
// before the apply loop reaches them. This is enabled with the shared checkout
// cache: each worker publishes its immutable checkout there, and the later
// CreateAppTx/applyAppUpdate calls become local cache hits.
func (s *Server) prefetchApplyAppSources(applyConfig map[types.AppPathDomain]*types.CreateAppRequest,
	appPaths []types.AppPathDomain, repoCache *RepoCache, forceDev bool) {
	if repoCache.shared == nil {
		return
	}
	var wg sync.WaitGroup
	workers := make(chan struct{}, gitPrefetchWorkers)
	for _, appPath := range appPaths {
		request := applyConfig[appPath]
		if request == nil || forceDev || request.IsDev {
			continue
		}
		sourceURL := strings.Split(request.SourceUrl, "#")[0]
		if !system.IsGit(sourceURL) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			workers <- struct{}{}
			defer func() { <-workers }()
			branch := cmp.Or(request.GitBranch, "main")
			if _, _, _, _, err := repoCache.CheckoutRepo(sourceURL, branch, request.GitCommit,
				request.GitAuthName, false); err != nil {
				s.Debug().Err(err).Msgf("git prefetch: error checking out apply source %s", sourceURL)
			}
		}()
	}
	wg.Wait()
}

// prefetchAppSources warms the git repo cache (latest-commit shas and
// checkouts) for the given apps before a metadata transaction is opened. The
// later in-transaction reload then hits the cache and runs no network git
// operations while holding a database transaction; such transactions pin the
// sqlite WAL, blocking checkpoints (and other writers, once the transaction
// writes) for the duration of the fetch. Best-effort: errors are logged and
// left for the real in-transaction pass to report.
func (s *Server) prefetchAppSources(ctx context.Context, appPaths []types.AppPathDomain,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) {
	for _, appPath := range appPaths {
		appEntry, err := s.db.GetAppEntry(ctx, appPath)
		if err != nil {
			s.Debug().Err(err).Msgf("git prefetch: error reading app %s", appPath)
			continue
		}
		if appEntry.IsDev {
			// Dev apps reload from their local checkout, no git fetch
			continue
		}
		if strings.HasPrefix(string(appEntry.Id), types.ID_PREFIX_APP_PROD) {
			// The reload works on the staging app, mirror getStageApp without
			// holding a transaction
			stagePath, err := parseLinkedAppPathDomain(appEntry.LinkedAppPath)
			if err != nil {
				stagePath = pathBasedStageApp(appEntry)
			}
			if appEntry, err = s.db.GetAppEntry(ctx, stagePath); err != nil {
				s.Debug().Err(err).Msgf("git prefetch: error reading stage app for %s", appPath)
				continue
			}
		}
		s.prefetchAppSource(appEntry, branch, commit, gitAuth, repoCache, forceReload)
	}
}

// prefetchAppSource warms the repo cache for one app entry, mirroring the
// branch/auth resolution and the up-to-date skip checks of loadAppCode so the
// cache keys match and no checkout happens when the reload would skip anyway.
func (s *Server) prefetchAppSource(appEntry *types.AppEntry, branch, commit, gitAuth string,
	repoCache *RepoCache, forceReload bool) {
	if !system.IsGit(appEntry.SourceUrl) {
		return
	}
	currentSha := appEntry.Metadata.VersionMetadata.GitCommit
	if !forceReload && currentSha != "" && currentSha == commit {
		return // already at the requested commit, the reload will skip
	}
	branch = cmp.Or(branch, appEntry.Metadata.VersionMetadata.GitBranch, "main")
	gitAuth = cmp.Or(gitAuth, appEntry.Metadata.GitAuthName)
	newSha, err := repoCache.GetSha(appEntry.SourceUrl, branch, gitAuth)
	if err != nil {
		s.Debug().Err(err).Msgf("git prefetch: error getting sha for %s", appEntry.SourceUrl)
		return
	}
	if !forceReload && currentSha != "" && newSha == currentSha && (commit == "" || commit == currentSha) {
		return // already at the latest commit, the reload will skip without a checkout
	}
	if _, _, _, _, err := repoCache.CheckoutRepo(appEntry.SourceUrl, branch, commit, gitAuth, appEntry.IsDev); err != nil {
		s.Debug().Err(err).Msgf("git prefetch: error checking out %s", appEntry.SourceUrl)
	}
}
