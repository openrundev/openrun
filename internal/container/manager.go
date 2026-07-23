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
	ID          string `json:"ID"`
	Names       string `json:"Names"`
	Image       string `json:"Image"`
	State       string `json:"State"`
	Status      string `json:"Status"`
	PortString  string `json:"Ports"`
	LabelString string `json:"Labels"` // Docker format: "key=value,key=value"
	Port        int
	Labels      map[string]string `json:"-"` // Podman format, parsed from the JSON map
}

// HasLabel reports whether the container carries the given label, handling
// both the Podman (map) and Docker (comma separated string) label formats.
func (c *Container) HasLabel(key, value string) bool {
	if c.Labels != nil {
		return c.Labels[key] == value
	}
	for kv := range strings.SplitSeq(c.LabelString, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key && v == value {
			return true
		}
	}
	return false
}

type VolumeInfo struct {
	IsSecret   bool
	VolumeName string
	SourcePath string
	TargetPath string
	ReadOnly   bool
}

// HealthProbe describes an HTTP health check that a container manager can
// translate into a native readiness/startup probe. A nil *HealthProbe means
// no probe should be configured (e.g. command-lifetime apps or apps without a
// health URL).
type HealthProbe struct {
	Path             string
	Port             int32
	Scheme           string // "HTTP" or "HTTPS"
	PeriodSecs       int32
	TimeoutSecs      int32
	FailureThreshold int32 // steady-state readiness tolerance
	StartupFailures  int32 // startup probe tolerance for slow boots
}

// HasPersistentVolume reports whether any mount is PVC-backed (a named volume
// or UNNAMED_VOLUME). Secrets (IsSecret) and config-maps (VolumeName == "")
// are per-pod and impose no single-writer constraint, so they are excluded.
// Under the default ReadWriteOnce access mode such a volume cannot be
// multi-attached, so its presence forces a downtime (Recreate) deploy rather
// than a surge-based rolling update.
//
// TODO: exempt volumes once per-app ReadOnlyMany/ReadWriteMany access modes
// are supported.
func HasPersistentVolume(volumes []*VolumeInfo) bool {
	for _, v := range volumes {
		if !v.IsSecret && v.VolumeName != "" {
			return true
		}
	}
	return false
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
		containerOptions map[string]string, paramMap map[string]string, versionHash string, isImageSpec bool,
		healthProbe *HealthProbe) error
	DeployContainer(ctx context.Context, req DeployRequest) (DeployResult, error)
	GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error)
	VolumeExists(ctx context.Context, name VolumeName) bool
	VolumeCreate(ctx context.Context, name VolumeName) error
	SupportsInPlaceUpdate() bool
}

// VersionReporter is implemented by managers that can report the version hash
// currently configured on a live workload.
type VersionReporter interface {
	CurrentVersionHash(ctx context.Context, name ContainerName) (string, error)
}

// AsVersionReporter unwraps any decorating container managers and returns the
// underlying VersionReporter if one is present.
func AsVersionReporter(cm ContainerManager) (VersionReporter, bool) {
	for cm != nil {
		if vr, ok := cm.(VersionReporter); ok {
			return vr, true
		}
		u, ok := cm.(interface{ Unwrap() ContainerManager })
		if !ok {
			break
		}
		cm = u.Unwrap()
	}
	return nil, false
}

// ContainerExitChecker is an optional manager capability: reporting whether a
// container is in a terminal state and cannot become healthy without outside
// intervention. Implemented by the command-based (Docker/Podman) manager,
// which runs containers without a restart policy, so an exited container
// never comes back on its own and health waits can fail fast. Kubernetes
// restarts crashed pods, so it does not implement this.
type ContainerExitChecker interface {
	// ContainerExited returns whether the named container has terminally
	// exited, along with its status text (e.g. "Exited (1) 5 seconds ago")
	// for error reporting. A missing container is not treated as exited.
	ContainerExited(ctx context.Context, name ContainerName) (exited bool, status string, err error)
}

// AsContainerExitChecker unwraps any decorating container managers and returns
// the underlying ContainerExitChecker if one is present.
func AsContainerExitChecker(cm ContainerManager) (ContainerExitChecker, bool) {
	for cm != nil {
		if c, ok := cm.(ContainerExitChecker); ok {
			return c, true
		}
		u, ok := cm.(interface{ Unwrap() ContainerManager })
		if !ok {
			break
		}
		cm = u.Unwrap()
	}
	return nil, false
}

// AppContainerStopper is an optional manager capability: stopping all of an
// app's version containers except the active one. Implemented by the
// command-based (Docker/Podman) manager, where superseded versions linger as
// separately named containers; Kubernetes cleans up through its own
// workload-cleanup path instead.
type AppContainerStopper interface {
	StopAppContainersExcept(ctx context.Context, appId types.AppId, keep ContainerName) error
}

// AsAppContainerStopper unwraps any decorating container managers and returns
// the underlying AppContainerStopper if one is present.
func AsAppContainerStopper(cm ContainerManager) (AppContainerStopper, bool) {
	for cm != nil {
		if s, ok := cm.(AppContainerStopper); ok {
			return s, true
		}
		u, ok := cm.(interface{ Unwrap() ContainerManager })
		if !ok {
			break
		}
		cm = u.Unwrap()
	}
	return nil, false
}

// DevRunOptions carries the dev-mode fast reload options for RunDevContainer.
type DevRunOptions struct {
	// RunHash identifies the full runtime config of the dev container. It is
	// stamped as a label on the container so a reload can detect that the
	// running container is already up to date and skip the recreate.
	RunHash string
	// WorkDir overrides the working directory (where the app source is mounted)
	WorkDir string
	// Command is the app start command, run via `sh -c`, overriding the image
	// entrypoint and cmd. Empty means use the image entrypoint/cmd as is.
	Command string
}

// DevContainerManager is the interface for managing containers in dev mode
type DevContainerManager interface {
	ContainerManager
	RemoveImage(ctx context.Context, name ImageName) error
	// RemoveSupersededImages removes the app's generated images other than
	// keep. A dev image hash change builds a new dev-<hash> tagged image; the
	// previous images are never used again and would otherwise accumulate on
	// the dev machine. Callers must remove containers using the old images
	// first. Failure to remove an image is not fatal to a reload.
	RemoveSupersededImages(ctx context.Context, keep ImageName) error
	// RemoveContainer force-removes a dev container. Dev reloads prioritize a
	// short feedback loop and must not wait for the runtime's graceful-stop
	// timeout when replacing a container.
	RemoveContainer(ctx context.Context, name ContainerName) error
	// BuildImageTarget builds like BuildImage but stops at the named
	// Containerfile stage (docker build --target). Empty target builds the
	// full image.
	BuildImageTarget(ctx context.Context, name ImageName, sourceUrl, containerFile string,
		containerArgs map[string]string, buildTarget string) error
	// RunDevContainer runs a dev mode container with the fast reload options
	// applied (source mount workdir, command override, run hash label).
	RunDevContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
		imageName ImageName, port int32, envMap map[string]string, volumes []*VolumeInfo,
		containerOptions map[string]string, paramMap map[string]string, devOpts DevRunOptions) error
	// GetDevContainerInfo reports whether a container with the given name
	// exists, whether it carries the given run hash label, its published host
	// port and whether it is currently running, in one container listing call.
	GetDevContainerInfo(ctx context.Context, name ContainerName, runHash string) (exists, matches bool, hostPort string, running bool, err error)
	// RestartDevContainer restarts (or starts, if stopped) a dev mode
	// container with no stop grace period, prioritizing the dev feedback loop.
	RestartDevContainer(ctx context.Context, name ContainerName) error
}

func GenContainerName(appId types.AppId, contentHash string, supportsInPlaceUpdate bool) ContainerName {
	if supportsInPlaceUpdate {
		return ContainerName(fmt.Sprintf("clc-%s", appId))
	} else {
		return ContainerName(fmt.Sprintf("clc-%s-%s", appId, shortHash(contentHash)))
	}
}

const IMAGE_NAME_PREFIX = "cli-"

func GenImageName(appId types.AppId, contentHash string) ImageName {
	if contentHash == "" {
		return ImageName(fmt.Sprintf("%s%s", IMAGE_NAME_PREFIX, appId))
	} else {
		return ImageName(fmt.Sprintf("%s%s:%s", IMAGE_NAME_PREFIX, appId, shortHash(contentHash)))
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
