// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

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

// ContainerManager is the interface for managing containers
type ContainerManager interface {
	BuildImage(name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error
	GetImages(name ImageName) ([]Image, error)
	GetContainerState(name ContainerName) (string, bool, error)
	SupportsInPlaceContainerUpdate(name ContainerName) bool
	InPlaceContainerUpdate(appEntry *types.AppEntry, containerName ContainerName,
		imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
		containerOptions map[string]string) error
	StartContainer(name ContainerName) error
	StopContainer(name ContainerName) error
	RunContainer(appEntry *types.AppEntry, containerName ContainerName,
		imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
		containerOptions map[string]string) error
	GetContainerLogs(name ContainerName) (string, error)
	VolumeExists(name VolumeName) bool
	VolumeCreate(name VolumeName) error
}

// DevContainerManager is the interface for managing containers in dev mode
type DevContainerManager interface {
	ContainerManager
	RemoveImage(name ImageName) error
	RemoveContainer(name ContainerName) error
}

func GenContainerName(appId types.AppId, contentHash string) ContainerName {
	if contentHash == "" {
		return ContainerName(fmt.Sprintf("clc-%s", appId))
	} else {
		return ContainerName(fmt.Sprintf("clc-%s-%s", appId, genLowerCaseId(contentHash)))
	}
}

func GenImageName(appId types.AppId, contentHash string) ImageName {
	if contentHash == "" {
		return ImageName(fmt.Sprintf("cli-%s", appId))
	} else {
		return ImageName(fmt.Sprintf("cli-%s-%s", appId, genLowerCaseId(contentHash)))
	}
}

func GenVolumeName(appId types.AppId, dirName string) VolumeName {
	dirHash := sha256.Sum256([]byte(dirName))
	hashHex := hex.EncodeToString(dirHash[:])
	return VolumeName(fmt.Sprintf("clv-%s-%s", appId, strings.ToLower(hashHex)))
}
