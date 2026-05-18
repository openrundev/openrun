// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

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

type VolumeInfo struct {
	IsSecret   bool
	VolumeName string
	SourcePath string
	TargetPath string
	ReadOnly   bool
}

// ContainerManager is the interface for managing containers
type ContainerManager interface {
	BuildImage(ctx context.Context, name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error
	ImageExists(ctx context.Context, name ImageName) (bool, error)
	// RefreshImage pulls (or HEADs) the named image from its registry and returns a
	// stable content-addressable digest (e.g. "sha256:..."). Only used for
	// image-spec apps so the container handler can detect when the upstream
	// reference has moved and recreate the container with the new content.
	RefreshImage(ctx context.Context, name ImageName) (digest string, err error)
	GetContainerState(ctx context.Context, name ContainerName, expectHash string) (hostPort string, running bool, err error)
	StartContainer(ctx context.Context, name ContainerName) error
	StopContainer(ctx context.Context, name ContainerName) error
	RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
		imageName ImageName, port int32, envMap map[string]string, volumes []*VolumeInfo,
		containerOptions map[string]string, paramMap map[string]string, versionHash string, isImageSpec bool) error
	GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error)
	VolumeExists(ctx context.Context, name VolumeName) bool
	VolumeCreate(ctx context.Context, name VolumeName) error
	SupportsInPlaceUpdate() bool
}

// DevContainerManager is the interface for managing containers in dev mode
type DevContainerManager interface {
	ContainerManager
	RemoveImage(ctx context.Context, name ImageName) error
	RemoveContainer(ctx context.Context, name ContainerName) error
}

func GenContainerName(appId types.AppId, cm ContainerManager, contentHash string, supportsInPlaceUpdate bool) ContainerName {
	if supportsInPlaceUpdate {
		return ContainerName(fmt.Sprintf("clc-%s", appId))
	} else {
		return ContainerName(fmt.Sprintf("clc-%s-%s", appId, genLowerCaseId(contentHash)))
	}
}

const IMAGE_NAME_PREFIX = "cli-"

func GenImageName(appId types.AppId, contentHash string) ImageName {
	if contentHash == "" {
		return ImageName(fmt.Sprintf("%s%s", IMAGE_NAME_PREFIX, appId))
	} else {
		return ImageName(fmt.Sprintf("%s%s:%s", IMAGE_NAME_PREFIX, appId, genLowerCaseId(contentHash)))
	}
}

func GenVolumeName(appId types.AppId, dirName string) VolumeName {
	dirHash := sha256.Sum256([]byte(dirName))
	hashHex := hex.EncodeToString(dirHash[:])
	return VolumeName(fmt.Sprintf("clv-%s-%s", appId, strings.ToLower(hashHex)))
}

// DigestPinned returns image with the given digest appended, replacing any
// existing @digest suffix. For example:
//
//	("mycompany/jp-app:latest",          "sha256:abc") -> "mycompany/jp-app:latest@sha256:abc"
//	("mycompany/jp-app@sha256:old",      "sha256:new") -> "mycompany/jp-app@sha256:new"
//	("mycompany/jp-app:v1@sha256:old",   "sha256:new") -> "mycompany/jp-app:v1@sha256:new"
//	("mycompany/jp-app",                 "sha256:abc") -> "mycompany/jp-app@sha256:abc"
//
// Both Docker and Kubernetes accept "repo:tag@digest" references; when both
// are present the digest is authoritative. Returns image unchanged if either
// argument is empty.
func DigestPinned(image, digest string) string {
	if image == "" || digest == "" {
		return image
	}
	base := image
	if i := strings.Index(base, "@"); i != -1 {
		base = base[:i]
	}
	return base + "@" + digest
}

// renderTemplate reads the source template file, executes it with the given data,
// and writes the output to the target file.
func renderTemplate(srcFilename, targetFilename string, data map[string]any) error {
	// Parse the source file as a template
	tmpl, err := template.ParseFiles(srcFilename)
	if err != nil {
		return fmt.Errorf("failed to parse template file: %w", err)
	}

	// Create the target file (overwrite if it exists)
	targetFile, err := os.Create(targetFilename)
	if err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer targetFile.Close() //nolint:errcheck

	// Execute the template with data, writing output to the target file
	if err := tmpl.Execute(targetFile, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

func makeAbsolute(sourceDir, path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return filepath.Join(sourceDir, path)
}

const UNNAMED_VOLUME = "<UNNAMED>"
