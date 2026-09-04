// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

type staleContainerManager interface {
	ListOpenRunContainers(ctx context.Context) ([]container.Container, error)
	StopContainer(ctx context.Context, name container.ContainerName) error
}

func (s *Server) startStaleContainerCleanup() {
	if s.Config().System.ContainerCommand == "" || s.Config().System.ContainerCommand == types.CONTAINER_KUBERNETES {
		return
	}
	if s.Config().System.StaleContainerCleanupIntervalMins <= 0 {
		return
	}

	interval := time.Duration(s.Config().System.StaleContainerCleanupIntervalMins) * time.Minute
	s.staleContainerCleanupTicker = time.NewTicker(interval)
	s.staleContainerCleanupStop = make(chan struct{})
	runCtx, cancel := context.WithCancel(context.Background())
	s.staleContainerCleanupCancel = cancel
	s.staleContainerCleanupDone = make(chan struct{})
	// ticker/stop/ctx/done are passed in rather than read from s inside the
	// loop: PauseBackground/ResumeBackground reassign these fields (under
	// bgMu) to pause and restart the loop across an in-place restart, and the
	// running goroutine must keep observing the instances it was started
	// with, not race against those reassignments on every loop iteration
	go s.staleContainerCleanupRunner(s.staleContainerCleanupTicker, s.staleContainerCleanupStop, runCtx, s.staleContainerCleanupDone)
}

func (s *Server) staleContainerCleanupRunner(ticker *time.Ticker, stop <-chan struct{}, runCtx context.Context, done chan<- struct{}) {
	defer close(done)
	s.Info().Msg("Starting stale container cleanup loop")
	for {
		select {
		case <-ticker.C:
		case <-stop:
			ticker.Stop()
			s.Info().Msg("Stale container cleanup loop stopped")
			return
		}
		// The sweep timeout derives from runCtx so PauseBackground can abort
		// a sweep already in flight, not just prevent the next one
		ctx, cancel := context.WithTimeout(runCtx, 2*time.Minute)
		err := s.cleanupStaleContainers(ctx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			s.Error().Err(err).Msg("Error cleaning up stale containers")
		}
	}
}

func (s *Server) cleanupStaleContainers(ctx context.Context) error {
	manager := container.NewCommandCM(s.Logger, s.Config(), "", "")
	active := s.apps.ActiveContainerNames()
	// Containers started by operations still in flight (reload/apply/sync
	// before their DB transaction commits) are not yet referenced by the app
	// store; treat them as active so they are not stopped mid-deploy.
	for name := range s.inFlightContainerNames() {
		active[name] = true
	}
	// always_on sidecars (workers) keep running while their app is
	// idle-stopped, and an idle-stopped app is closed (no longer in the app
	// store): keep them as long as their app still exists. Superseded
	// versions are stopped at deploy commit, not by the sweeper
	appIds := map[string]bool{}
	if s.db != nil { // nil only in tests exercising the sweep loop itself
		apps, err := s.FilterApps("all", true)
		if err != nil {
			// Without the app list the keep filter cannot tell an always_on
			// sidecar of a live app from a stale one; skip this sweep
			// instead of stopping them
			return fmt.Errorf("listing apps for stale container sweep: %w", err)
		}
		for _, appInfo := range apps {
			appIds[string(appInfo.Id)] = true
		}
	}
	// Job containers run in the foreground for an active run record; one
	// whose run is no longer active belongs to a lost run and is stopped
	activeRuns := s.activeJobRunIds(ctx)
	keep := func(cont container.Container) bool {
		if runId := cont.LabelValue(container.LABEL_PREFIX + container.JobRunLabel); runId != "" {
			return activeRuns == nil || activeRuns[runId]
		}
		return cont.HasLabel(container.SidecarAlwaysOnLabelKey, "true") &&
			appIds[cont.LabelValue(container.LABEL_PREFIX+"app.id")]
	}
	return cleanupStaleContainers(ctx, s.Logger, manager, active, keep)
}

// cleanupStaleContainers stops the managed containers not in active; keep,
// when set, exempts containers by their labels
func cleanupStaleContainers(ctx context.Context, logger *types.Logger, manager staleContainerManager,
	active map[container.ContainerName]bool, keep func(container.Container) bool) error {
	containers, err := manager.ListOpenRunContainers(ctx)
	if err != nil {
		return err
	}

	var retErr error
	for _, cont := range containers {
		containerName := container.ContainerName(cont.Names)
		if containerName == "" {
			logger.Warn().Str("container_id", cont.ID).Msg("Skipping OpenRun managed container with no name")
			continue
		}
		if active[containerName] || (keep != nil && keep(cont)) {
			continue
		}

		logger.Info().Str("container", string(containerName)).Msg("Stopping stale OpenRun managed container")
		if err := manager.StopContainer(ctx, containerName); err != nil {
			retErr = errors.Join(retErr, err)
			logger.Error().Err(err).Str("container", string(containerName)).Msg("Error stopping stale OpenRun managed container")
		}
	}
	return retErr
}
