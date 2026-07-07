// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
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
	go s.staleContainerCleanupRunner()
}

func (s *Server) staleContainerCleanupRunner() {
	s.Info().Msg("Starting stale container cleanup loop")
	for {
		select {
		case <-s.staleContainerCleanupTicker.C:
		case <-s.staleContainerCleanupStop:
			s.staleContainerCleanupTicker.Stop()
			s.Info().Msg("Stale container cleanup loop stopped")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := s.cleanupStaleContainers(ctx)
		cancel()
		if err != nil {
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
	return cleanupStaleContainers(ctx, s.Logger, manager, active)
}

func cleanupStaleContainers(ctx context.Context, logger *types.Logger, manager staleContainerManager, active map[container.ContainerName]bool) error {
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
		if active[containerName] {
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
