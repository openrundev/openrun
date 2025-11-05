// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/openrundev/openrun/internal/types"
)

type ContainerName string

type ImageName string

type VolumeName string

type Container struct {
	ID         string `json:"ID"`
	Names      string `json:"Names"`
	Image      string `json:"Image"`
	State      string `json:"State"`
	Status     string `json:"Status"`
	PortString string `json:"Ports"`
	Port       int
}

type Image struct {
	Repository string `json:"Repository"`
}

type ContainerManager interface {
	RemoveImage(name ImageName) error
	BuildImage(name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error
	GetImages(name ImageName) ([]Image, error)
	RemoveContainer(name ContainerName) error
	GetContainers(name ContainerName, getAll bool) ([]Container, error)
	StartContainer(name ContainerName) error
	StopContainer(name ContainerName) error
	RunContainer(appEntry *types.AppEntry, containerName ContainerName,
		imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
		containerOptions map[string]string) error
	GetContainerLogs(name ContainerName) (string, error)
	VolumeExists(name VolumeName) bool
	VolumeCreate(name VolumeName) error
}
