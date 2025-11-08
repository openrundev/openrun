// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/openrundev/openrun/internal/types"
)

type KubernetesContainerManager struct {
	*types.Logger
	config *types.SystemConfig
}

func NewKubernetesContainerManager(logger *types.Logger, config *types.SystemConfig) *KubernetesContainerManager {
	return &KubernetesContainerManager{logger, config}
}

var _ ContainerManager = KubernetesContainerManager{}

func (c KubernetesContainerManager) BuildImage(name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) ImageExists(name ImageName) (bool, error) {
	return false, nil
}

func (c KubernetesContainerManager) GetContainerState(name ContainerName) (string, bool, error) {
	return "", false, nil
}

func (c KubernetesContainerManager) SupportsInPlaceContainerUpdate() bool {
	return true
}

func (c KubernetesContainerManager) InPlaceContainerUpdate(appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) StartContainer(name ContainerName) error {
	return nil
}

func (c KubernetesContainerManager) StopContainer(name ContainerName) error {
	return nil
}

func (c KubernetesContainerManager) RunContainer(appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (c KubernetesContainerManager) GetContainerLogs(name ContainerName) (string, error) {
	return "", nil
}

func (c KubernetesContainerManager) VolumeExists(name VolumeName) bool {
	return false
}

func (c KubernetesContainerManager) VolumeCreate(name VolumeName) error {
	return nil
}
