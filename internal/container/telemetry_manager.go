// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"time"

	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
)

func WrapContainerManager(cm ContainerManager, kind string) ContainerManager {
	if !telemetry.MetricsEnabled() {
		return cm
	}
	wrapped := &telemetryContainerManager{
		ContainerManager: cm,
		kind:             kind,
	}
	if devCM, ok := cm.(DevContainerManager); ok {
		return &telemetryDevContainerManager{
			telemetryContainerManager: wrapped,
			dev:                       devCM,
		}
	}
	return wrapped
}

type telemetryContainerManager struct {
	ContainerManager
	kind string
}

func (m *telemetryContainerManager) BuildImage(ctx context.Context, name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	start := time.Now()
	err := m.ContainerManager.BuildImage(ctx, name, sourceUrl, containerFile, containerArgs)
	telemetry.RecordContainerCall(ctx, m.kind, "build_image", start, err)
	return err
}

func (m *telemetryContainerManager) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	start := time.Now()
	exists, err := m.ContainerManager.ImageExists(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "image_exists", start, err)
	return exists, err
}

func (m *telemetryContainerManager) GetContainerState(ctx context.Context, name ContainerName, expectHash string) (string, bool, error) {
	start := time.Now()
	hostPort, running, err := m.ContainerManager.GetContainerState(ctx, name, expectHash)
	telemetry.RecordContainerCall(ctx, m.kind, "get_container_state", start, err)
	return hostPort, running, err
}

func (m *telemetryContainerManager) StartContainer(ctx context.Context, name ContainerName) error {
	start := time.Now()
	err := m.ContainerManager.StartContainer(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "start_container", start, err)
	return err
}

func (m *telemetryContainerManager) StopContainer(ctx context.Context, name ContainerName) error {
	start := time.Now()
	err := m.ContainerManager.StopContainer(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "stop_container", start, err)
	return err
}

func (m *telemetryContainerManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
	imageName ImageName, port int32, envMap map[string]string, volumes []*VolumeInfo,
	containerOptions map[string]string, paramMap map[string]string, versionHash string) error {
	start := time.Now()
	err := m.ContainerManager.RunContainer(ctx, appEntry, sourceDir, containerName, imageName, port, envMap, volumes, containerOptions, paramMap, versionHash)
	telemetry.RecordContainerCall(ctx, m.kind, "run_container", start, err)
	return err
}

func (m *telemetryContainerManager) GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error) {
	start := time.Now()
	logs, err := m.ContainerManager.GetContainerLogs(ctx, name, linesToShow)
	telemetry.RecordContainerCall(ctx, m.kind, "get_container_logs", start, err)
	return logs, err
}

func (m *telemetryContainerManager) VolumeExists(ctx context.Context, name VolumeName) bool {
	start := time.Now()
	exists := m.ContainerManager.VolumeExists(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "volume_exists", start, nil)
	return exists
}

func (m *telemetryContainerManager) VolumeCreate(ctx context.Context, name VolumeName) error {
	start := time.Now()
	err := m.ContainerManager.VolumeCreate(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "volume_create", start, err)
	return err
}

type telemetryDevContainerManager struct {
	*telemetryContainerManager
	dev DevContainerManager
}

func (m *telemetryDevContainerManager) RemoveImage(ctx context.Context, name ImageName) error {
	start := time.Now()
	err := m.dev.RemoveImage(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "remove_image", start, err)
	return err
}

func (m *telemetryDevContainerManager) RemoveContainer(ctx context.Context, name ContainerName) error {
	start := time.Now()
	err := m.dev.RemoveContainer(ctx, name)
	telemetry.RecordContainerCall(ctx, m.kind, "remove_container", start, err)
	return err
}
