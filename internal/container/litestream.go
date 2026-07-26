// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// DefaultLitestreamImage is the litestream image used for app restore and
// replicate containers when the named config does not pin one. Pinned to the
// 0.5 series: the LTX replica format ties restore compatibility to the bucket
// contents.
const DefaultLitestreamImage = "litestream/litestream:0.5"

// litestreamRoleLabel marks a container as an app's litestream replication
// companion, so version-superseding container stops skip it.
const litestreamRoleLabel = "role"
const litestreamRoleValue = "litestream"

// litestreamConfigHashLabel records the rendered config identity on the
// sidecar container so config changes recreate it while app version reloads
// leave it running (two replicators on one replica path can corrupt it).
const litestreamConfigHashLabel = "litestream.hash"

// LitestreamConfigFileName is the rendered config file mounted into the
// litestream sidecar.
const LitestreamConfigFileName = "litestream.yml"

// LitestreamMount is one app volume the litestream companion shares.
type LitestreamMount struct {
	VolumeName VolumeName
	TargetDir  string // mount path, same as in the app container
}

// LitestreamRestore is one database to restore before the app starts:
// litestream restore is per-file, the caller enumerates the replica.
type LitestreamRestore struct {
	ReplicaURL string // s3://bucket/path?endpoint=... (no credentials)
	OutputPath string // path inside the shared volume mount
}

// LitestreamAppSpec describes the litestream replication companion for one
// app: the rendered config (credentials excluded, passed via Env), the
// volume shared with the app container, and the databases to restore before
// the app starts. An app has at most one sqlite binding, so a single
// litestream config (endpoint, credentials, image) applies.
type LitestreamAppSpec struct {
	Image      string
	ConfigYAML string
	// ConfigHash identifies the full replication config (rendered yaml,
	// credentials, image); a change recreates the sidecar / rolls the pod.
	ConfigHash string
	Env        map[string]string // LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY
	Mounts     []LitestreamMount
	Restores   []LitestreamRestore
}

// LitestreamSidecarName returns the app's replication companion container
// name. One stable sidecar per app (not per version): the brief old/new app
// container overlap during a reload must not run two litestream processes
// against one replica path.
func LitestreamSidecarName(appId types.AppId) ContainerName {
	return ContainerName("clc-" + string(appId) + "-ls")
}

// VolumeInitializer is the optional manager capability for preparing a
// freshly created named volume for the app user: a new docker volume mount
// directory is root-owned, which a non-root app image (USER directives are
// common) cannot write to. The chmod runs with the app's own image, which is
// guaranteed present, as root.
type VolumeInitializer interface {
	InitVolumePermissions(ctx context.Context, image ImageName, volumeName VolumeName, targetDir string) error
}

// AsVolumeInitializer unwraps any decorating container managers and returns
// the underlying VolumeInitializer if one is present.
func AsVolumeInitializer(cm ContainerManager) (VolumeInitializer, bool) {
	for cm != nil {
		if v, ok := cm.(VolumeInitializer); ok {
			return v, true
		}
		u, ok := cm.(interface{ Unwrap() ContainerManager })
		if !ok {
			break
		}
		cm = u.Unwrap()
	}
	return nil, false
}

var _ VolumeInitializer = (*CommandCM)(nil)

func (c *CommandCM) InitVolumePermissions(ctx context.Context, image ImageName, volumeName VolumeName, targetDir string) error {
	args := []string{"run", "--rm", "--user", "0", "--entrypoint", "chmod",
		fmt.Sprintf("--volume=%s:%s", volumeName, targetDir),
		string(image), "-R", "0777", targetDir}
	c.Info().Msgf("Initializing volume %s permissions at %s", volumeName, targetDir)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error initializing volume %s permissions: %w %s", volumeName, err, output)
	}
	return nil
}

// litestreamStopGraceSecs is the stop grace period for the replication
// sidecar: SIGTERM triggers litestream's shutdown sync, which retries for up
// to 30s (DefaultShutdownSyncTimeout) before the runtime would SIGKILL.
const litestreamStopGraceSecs = 45

// LitestreamRunner is the optional manager capability for running the
// litestream restore step and replication sidecar. Implemented by the
// command-based (docker/podman) manager; kubernetes handles litestream
// declaratively inside the pod spec via DeployRequest.Litestream.
type LitestreamRunner interface {
	// RunLitestreamRestores runs the pre-start restore step: one one-shot
	// container per database, restoring files missing from the volume.
	RunLitestreamRestores(ctx context.Context, appId types.AppId, spec *LitestreamAppSpec) error
	// EnsureLitestreamSidecar starts (or recreates, on config change) the
	// app's replication sidecar container.
	EnsureLitestreamSidecar(ctx context.Context, appEntry *types.AppEntry, spec *LitestreamAppSpec) error
	// StopLitestreamSidecar gently stops the app's replication sidecar:
	// SIGTERM with a grace period covering litestream's final shutdown sync.
	// A missing or already stopped sidecar is not an error.
	StopLitestreamSidecar(ctx context.Context, appId types.AppId) error
}

// AsLitestreamRunner unwraps any decorating container managers and returns
// the underlying LitestreamRunner if one is present.
func AsLitestreamRunner(cm ContainerManager) (LitestreamRunner, bool) {
	for cm != nil {
		if r, ok := cm.(LitestreamRunner); ok {
			return r, true
		}
		u, ok := cm.(interface{ Unwrap() ContainerManager })
		if !ok {
			break
		}
		cm = u.Unwrap()
	}
	return nil, false
}

var _ LitestreamRunner = (*CommandCM)(nil)

func (c *CommandCM) litestreamMountArgs(spec *LitestreamAppSpec) []string {
	args := []string{}
	for _, mount := range spec.Mounts {
		args = append(args, fmt.Sprintf("--volume=%s:%s", mount.VolumeName, mount.TargetDir))
	}
	return args
}

func (c *CommandCM) litestreamEnvArgs(spec *LitestreamAppSpec) []string {
	args := []string{}
	for k, v := range spec.Env {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}
	return args
}

func (c *CommandCM) RunLitestreamRestores(ctx context.Context, appId types.AppId, spec *LitestreamAppSpec) error {
	for _, restore := range spec.Restores {
		args := []string{"run", "--rm"}
		args = append(args, c.litestreamMountArgs(spec)...)
		args = append(args, c.litestreamEnvArgs(spec)...)
		args = append(args, LocalhostHostGatewayArgs(c.config.System.ContainerCommand)...)
		args = append(args, string(spec.Image), "restore", "-if-db-not-exists",
			"-o", restore.OutputPath, restore.ReplicaURL)

		c.Info().Msgf("Litestream restore for app %s: %s -> %s", appId, restore.ReplicaURL, restore.OutputPath)
		cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("litestream restore of %s failed: %w %s", restore.OutputPath, err, output)
		}
	}
	return nil
}

func (c *CommandCM) EnsureLitestreamSidecar(ctx context.Context, appEntry *types.AppEntry, spec *LitestreamAppSpec) error {
	name := LitestreamSidecarName(appEntry.Id)

	containers, err := c.listContainers(ctx, []string{"name=" + string(name)}, true)
	if err != nil {
		return fmt.Errorf("error checking litestream sidecar: %w", err)
	}
	for _, cont := range containers {
		if ContainerName(cont.Names) != name {
			continue
		}
		if cont.HasLabel(LABEL_PREFIX+litestreamConfigHashLabel, spec.ConfigHash) {
			if strings.EqualFold(cont.State, "running") {
				c.Debug().Msgf("Litestream sidecar %s up to date", name)
				return nil
			}
			// Same config, just stopped (idle shutdown): restart it
			c.Info().Msgf("Restarting litestream sidecar %s", name)
			if err := c.StartContainer(ctx, name); err == nil {
				return nil
			} else {
				c.Warn().Err(err).Msgf("error restarting litestream sidecar %s, recreating", name)
			}
		}
		// Config changed (or the restart failed): recreate it
		c.Info().Msgf("Recreating litestream sidecar %s", name)
		if err := c.RemoveContainer(ctx, name); err != nil {
			return fmt.Errorf("error removing outdated litestream sidecar: %w", err)
		}
	}

	configPath := filepath.Join(c.appRunDir, LitestreamConfigFileName+".gen")
	if err := os.MkdirAll(c.appRunDir, 0700); err != nil {
		return fmt.Errorf("error creating app run dir: %w", err)
	}
	if err := os.WriteFile(configPath, []byte(spec.ConfigYAML), 0600); err != nil {
		return fmt.Errorf("error writing litestream config: %w", err)
	}

	args := []string{"run", "--name", string(name), "--detach"}
	args = append(args, c.litestreamMountArgs(spec)...)
	args = append(args, fmt.Sprintf("--volume=%s:/etc/litestream.yml:ro", configPath))
	args = append(args, c.litestreamEnvArgs(spec)...)
	args = append(args, LocalhostHostGatewayArgs(c.config.System.ContainerCommand)...)
	args = append(args, "--label", LABEL_PREFIX+"app.id="+string(appEntry.Id))
	args = append(args, "--label", LABEL_PREFIX+"app.path="+appEntry.Path)
	args = append(args, "--label", LABEL_PREFIX+"server.home="+serverHomeLabelValue())
	args = append(args, "--label", LABEL_PREFIX+litestreamRoleLabel+"="+litestreamRoleValue)
	args = append(args, "--label", LABEL_PREFIX+litestreamConfigHashLabel+"="+spec.ConfigHash)
	args = append(args, string(spec.Image), "replicate", "-config", "/etc/litestream.yml")

	c.Info().Msgf("Starting litestream sidecar %s", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error starting litestream sidecar: %w %s", err, output)
	}
	return nil
}

func (c *CommandCM) StopLitestreamSidecar(ctx context.Context, appId types.AppId) error {
	name := LitestreamSidecarName(appId)
	containers, err := c.listContainers(ctx, []string{"name=" + string(name)}, false)
	if err != nil {
		return fmt.Errorf("error checking litestream sidecar: %w", err)
	}
	if len(containers) == 0 {
		return nil // no running sidecar
	}

	// SIGTERM starts litestream's final shutdown sync; the grace period lets
	// it complete before the runtime escalates to SIGKILL
	c.Info().Msgf("Stopping litestream sidecar %s after final sync", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand,
		"stop", "-t", strconv.Itoa(litestreamStopGraceSecs), string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error stopping litestream sidecar %s: %w %s", name, err, output)
	}
	return nil
}
