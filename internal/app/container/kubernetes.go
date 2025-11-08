// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"

	"github.com/openrundev/openrun/internal/types"
)

type KubernetesContainerManager struct {
	*types.Logger
	config             *types.ServerConfig
	registryConfigJson []byte
}

func NewKubernetesContainerManager(logger *types.Logger, config *types.ServerConfig) (*KubernetesContainerManager, error) {
	registryConfigJson, err := GenerateDockerConfigJSON(&config.Registry)
	if err != nil {
		return nil, fmt.Errorf("error generating docker config json: %w", err)
	}

	return &KubernetesContainerManager{
		Logger:             logger,
		config:             config,
		registryConfigJson: registryConfigJson,
	}, nil
}

var _ ContainerManager = KubernetesContainerManager{}

func (c KubernetesContainerManager) BuildImage(ctx context.Context, name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	return ImageExists(ctx, string(name), &c.config.Registry, c.registryConfigJson)
}

func (c KubernetesContainerManager) GetContainerState(ctx context.Context, name ContainerName) (string, bool, error) {
	return "", false, nil
}

func (c KubernetesContainerManager) SupportsInPlaceContainerUpdate() bool {
	return true
}

func (c KubernetesContainerManager) InPlaceContainerUpdate(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) StartContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (c KubernetesContainerManager) StopContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (c KubernetesContainerManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) GetContainerLogs(ctx context.Context, name ContainerName) (string, error) {
	return "", nil
}

func (c KubernetesContainerManager) VolumeExists(ctx context.Context, name VolumeName) bool {
	return false
}

func (c KubernetesContainerManager) VolumeCreate(ctx context.Context, name VolumeName) error {
	return nil
}
