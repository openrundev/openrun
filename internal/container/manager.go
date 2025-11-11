// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
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

// ContainerManager is the interface for managing containers
type ContainerManager interface {
	BuildImage(ctx context.Context, name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error
	ImageExists(ctx context.Context, name ImageName) (bool, error)
	GetContainerState(ctx context.Context, name ContainerName) (string, bool, error)
	SupportsInPlaceContainerUpdate() bool
	InPlaceContainerUpdate(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
		imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
		containerOptions map[string]string) error
	StartContainer(ctx context.Context, name ContainerName) error
	StopContainer(ctx context.Context, name ContainerName) error
	RunContainer(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
		imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
		containerOptions map[string]string) error
	GetContainerLogs(ctx context.Context, name ContainerName) (string, error)
	VolumeExists(ctx context.Context, name VolumeName) bool
	VolumeCreate(ctx context.Context, name VolumeName) error
}

// DevContainerManager is the interface for managing containers in dev mode
type DevContainerManager interface {
	ContainerManager
	RemoveImage(ctx context.Context, name ImageName) error
	RemoveContainer(ctx context.Context, name ContainerName) error
}

func GenContainerName(appId types.AppId, cm ContainerManager, contentHash string) ContainerName {
	if cm.SupportsInPlaceContainerUpdate() || contentHash == "" {
		return ContainerName(fmt.Sprintf("clc-%s", appId))
	} else {
		return ContainerName(fmt.Sprintf("clc-%s-%s", appId, genLowerCaseId(contentHash)))
	}
}

func GenImageName(appId types.AppId, contentHash string) ImageName {
	if contentHash == "" {
		return ImageName(fmt.Sprintf("cli-%s", appId))
	} else {
		return ImageName(fmt.Sprintf("cli-%s:%s", appId, genLowerCaseId(contentHash)))
	}
}

func GenVolumeName(appId types.AppId, dirName string) VolumeName {
	dirHash := sha256.Sum256([]byte(dirName))
	hashHex := hex.EncodeToString(dirHash[:])
	return VolumeName(fmt.Sprintf("clv-%s-%s", appId, strings.ToLower(hashHex)))
}
