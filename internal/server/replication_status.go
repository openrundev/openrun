// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// replicationStatusCacheTTL bounds how often the replica locations are listed
// (an S3 listing per litestream-enabled binding environment).
const replicationStatusCacheTTL = 30 * time.Second

// deriveReplicationState computes an app target's state from the sidecar
// container state and the replica's recency. The bucket only shows what
// arrived, not what is pending: a dead sidecar is flagged regardless of
// replica recency, and old uploads with a live sidecar read as idle (healthy
// for a quiet app), not as failure.
func deriveReplicationState(configDefined bool, sidecarRunning *bool, lastSync time.Time,
	syncInterval time.Duration, now time.Time) string {
	if !configDefined {
		return types.ReplicationStateMisconfigured
	}
	if lastSync.IsZero() {
		// Nothing replicated yet (e.g. an environment that has not deployed);
		// a missing sidecar is not a failure before there is data to protect
		return types.ReplicationStatePending
	}
	if sidecarRunning != nil && !*sidecarRunning {
		return types.ReplicationStateSidecarDown
	}
	threshold := max(10*syncInterval, 2*time.Minute)
	if now.Sub(lastSync) <= threshold {
		return types.ReplicationStateHealthy
	}
	return types.ReplicationStateIdle
}

// ReplicationStatus reports the replication state of the server's metadata
// databases and every litestream-enabled sqlite binding. Results are cached
// briefly to keep replica listings cheap; refresh bypasses the cache (used by
// the CLI, where an explicit invocation expects current state). No
// credentials are included.
func (s *Server) ReplicationStatus(ctx context.Context, refresh bool) ([]types.ReplicationStatusEntry, error) {
	s.replicationStatusMu.Lock()
	if !refresh && time.Since(s.replicationStatusAt) < replicationStatusCacheTTL && s.replicationStatusCache != nil {
		cached := s.replicationStatusCache
		s.replicationStatusMu.Unlock()
		return cached, nil
	}
	s.replicationStatusMu.Unlock()

	entries := []types.ReplicationStatusEntry{}
	entries = append(entries, s.metadataReplicationStatus(ctx)...)

	appEntries, err := s.appReplicationStatus(ctx)
	if err != nil {
		return nil, err
	}
	entries = append(entries, appEntries...)

	s.replicationStatusMu.Lock()
	s.replicationStatusCache = entries
	s.replicationStatusAt = time.Now()
	s.replicationStatusMu.Unlock()
	return entries, nil
}

func (s *Server) metadataReplicationStatus(ctx context.Context) []types.ReplicationStatusEntry {
	if s.litestream == nil {
		return nil
	}
	entries := []types.ReplicationStatusEntry{}
	for _, status := range s.litestream.Status(ctx) {
		entry := types.ReplicationStatusEntry{
			Kind:             "metadata",
			Target:           status.Name,
			LitestreamConfig: s.litestream.ConfigName(),
			Enabled:          true,
			LastSync:         status.LastSyncAt,
			LocalTXID:        status.LocalTXID,
			ReplicaTXID:      status.RemoteTXID,
			Error:            status.Error,
		}
		switch {
		case status.Error != "":
			entry.State = types.ReplicationStateError
		case status.InSync:
			entry.State = types.ReplicationStateHealthy
		default:
			entry.State = types.ReplicationStateSyncing
		}
		entries = append(entries, entry)
	}
	return entries
}

// sidecarStates returns the litestream sidecar container states by container
// name for docker/podman, or nil on kubernetes (the pod-level state is not
// inspected in this version; the replica listing still reports recency).
func (s *Server) sidecarStates(ctx context.Context) map[container.ContainerName]bool {
	command := s.Config().System.ContainerCommand
	if command == "" || command == types.CONTAINER_KUBERNETES {
		return nil
	}
	manager := container.NewCommandCM(s.Logger, s.Config(), "", "")
	containers, err := manager.ListOpenRunContainers(ctx)
	if err != nil {
		s.Warn().Err(err).Msg("error listing containers for replication status")
		return nil
	}
	states := map[container.ContainerName]bool{}
	for _, cont := range containers {
		name := container.ContainerName(cont.Names)
		if strings.HasSuffix(string(name), "-ls") {
			states[name] = strings.EqualFold(cont.State, "running")
		}
	}
	return states
}

func (s *Server) appReplicationStatus(ctx context.Context) ([]types.ReplicationStatusEntry, error) {
	allBindings, err := s.listBindingsInternal(ctx, "")
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sidecars := s.sidecarStates(ctx)
	litestreamConfigs := s.Config().Litestream
	now := time.Now()

	entries := []types.ReplicationStatusEntry{}
	for _, binding := range allBindings {
		if binding.ServiceType != bindings.SqliteServiceType {
			continue
		}
		service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
		if err != nil {
			continue // service removed; binding is unusable anyway
		}
		// Staged apps follow the linked staging service's config when one is
		// set (missing staging service falls back to the primary config)
		stagedServiceConfig := service.Config
		if service.Staging != "" {
			if stagingService, err := s.db.GetService(ctx, tx, service.ServiceType, service.Staging); err == nil {
				stagedServiceConfig = stagingService.Config
			}
		}
		if service.Config[bindings.SqliteConfigLitestream] == "" &&
			stagedServiceConfig[bindings.SqliteConfigLitestream] == "" {
			continue // local-only binding, nothing to report
		}

		users, err := s.db.AppsUsingBinding(ctx, tx, binding.Path)
		if err != nil {
			return nil, err
		}

		// Each environment row lists only its own side's app entries: the
		// prod app for the prod row, the stage (and dev/preview) companions
		// for the staged row
		var allPaths, prodPaths, stagedPaths []string
		var prodAppIds []types.AppId
		for _, use := range users {
			allPaths = append(allPaths, use.PathDomain)
			if strings.HasPrefix(string(use.Id), types.ID_PREFIX_APP_PROD) {
				prodAppIds = append(prodAppIds, use.Id)
				prodPaths = append(prodPaths, use.PathDomain)
			} else {
				stagedPaths = append(stagedPaths, use.PathDomain)
			}
		}
		slices.Sort(allPaths)
		slices.Sort(prodPaths)
		slices.Sort(stagedPaths)

		if len(prodAppIds) == 0 {
			// Not attached to a deployed app: no sidecar, no replication
			entries = append(entries, types.ReplicationStatusEntry{
				Kind:             "app",
				Target:           binding.Path,
				AppPaths:         allPaths,
				LitestreamConfig: service.Config[bindings.SqliteConfigLitestream],
				Enabled:          true,
				State:            types.ReplicationStatePending,
			})
			continue
		}

		for _, env := range []string{"prod", "staged"} {
			appId := prodAppIds[0]
			serviceConfig := service.Config
			envPaths := prodPaths
			if env == "staged" {
				appId = types.AppId(types.ID_PREFIX_APP_STAGE +
					strings.TrimPrefix(string(prodAppIds[0]), types.ID_PREFIX_APP_PROD))
				serviceConfig = stagedServiceConfig
				envPaths = stagedPaths
			}
			configName := serviceConfig[bindings.SqliteConfigLitestream]
			lsConfig, configDefined := litestreamConfigs[configName]
			// The file replica type is host-local and unusable from app
			// containers: deployment skips the sidecar, so replication can
			// never start; report it as misconfigured rather than pending
			if configDefined && lsConfig.Type == system.LitestreamReplicaTypeFile {
				configDefined = false
			}

			entry := types.ReplicationStatusEntry{
				Kind:             "app",
				Target:           binding.Path,
				AppPaths:         envPaths,
				Env:              env,
				LitestreamConfig: configName,
				Enabled:          configName != "",
			}
			if configName == "" {
				// This environment's service has litestream disabled (e.g. a
				// local-only staging service linked to a replicated prod one)
				entry.State = types.ReplicationStatePending
				entries = append(entries, entry)
				continue
			}

			var sidecarRunning *bool
			if sidecars != nil {
				running := sidecars[container.LitestreamSidecarName(appId)]
				sidecarRunning = &running
			}
			entry.SidecarRunning = sidecarRunning

			if configDefined {
				prefix := system.LitestreamBindingPrefix(lsConfig,
					serviceConfig[bindings.SqliteConfigPathPrefix], binding.Id, env)
				replicaDBs, err := system.ListLitestreamReplicaDBs(ctx, lsConfig, prefix)
				if err != nil {
					entry.Error = err.Error()
					entry.State = types.ReplicationStateError
					entries = append(entries, entry)
					continue
				}
				for _, db := range replicaDBs {
					entry.Files = append(entry.Files, types.ReplicationFileStatus{
						Path:        db.SubPath,
						LastSync:    db.LastUpdated,
						ReplicaTXID: db.MaxTXID,
						Size:        db.Size,
					})
					entry.ReplicaSize += db.Size
					if db.MaxTXID > entry.ReplicaTXID {
						entry.ReplicaTXID = db.MaxTXID
					}
					// The oldest per-file sync drives staleness: every
					// database in the binding should be advancing
					if entry.LastSync.IsZero() || db.LastUpdated.Before(entry.LastSync) {
						entry.LastSync = db.LastUpdated
					}
				}
			}

			syncInterval := time.Second
			if configDefined && lsConfig.SyncInterval != "" {
				if d, err := time.ParseDuration(lsConfig.SyncInterval); err == nil {
					syncInterval = d
				}
			}
			entry.State = deriveReplicationState(configDefined, sidecarRunning, entry.LastSync, syncInterval, now)
			entries = append(entries, entry)
		}
	}
	return entries, nil
}
