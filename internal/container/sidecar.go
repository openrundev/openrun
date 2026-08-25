// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// ResolvedSidecar is a sidecar declaration with every runtime value
// resolved by the app's container handler: the image to run (the app's
// generated image or the digest pinned foreign reference), the effective
// env (inherited app env overlaid with the sidecar's own, without the
// CL_SIDECAR_*_ADDR vars, which depend on the version hash and are added at
// run time), parsed volumes and the resolved defaults.
type ResolvedSidecar struct {
	Name       string
	Image      string
	IsAppImage bool
	Command    []string
	Args       []string
	Env        map[string]string
	InheritEnv bool
	Port       int32
	// HealthPath is the HTTP readiness path for port'd sidecars; empty means
	// a TCP connect check on Port
	HealthPath string
	Volumes    []*VolumeInfo
	AlwaysOn   bool
	Options    map[string]string
	// DevWorkDir is the dev mode working dir (the app source mount dir) for
	// app image sidecars; empty in prod
	DevWorkDir string
}

// Label keys (full, with LABEL_PREFIX) and values for the sidecar container
// labels, for the server's container listing
const (
	RoleLabelKey        = LABEL_PREFIX + litestreamRoleLabel
	SidecarNameLabelKey = LABEL_PREFIX + sidecarNameLabel
	SidecarAppLabelKey  = LABEL_PREFIX + sidecarAppLabel
	SidecarRoleValue    = sidecarRoleValue
	LitestreamRoleValue = litestreamRoleValue
	// SidecarAlwaysOnLabelKey marks a sidecar that keeps running across
	// app idle shutdowns; the stale container sweeper leaves such sidecars
	// of existing apps alone (an idle-stopped app is closed and no longer
	// references its containers)
	SidecarAlwaysOnLabelKey = LABEL_PREFIX + "sidecar.always_on"
)

const (
	sidecarRoleValue = "sidecar"
	// sidecarNameLabel records the sidecar name on its container
	sidecarNameLabel = "sidecar"
	// sidecarAppLabel records the app container a sidecar belongs to, so the
	// superseded-version stop keeps the active version's sidecars
	sidecarAppLabel = "sidecar.app"
	// sidecarHashLabel records the sidecar's resolved config hash, so a
	// reload can reuse an up to date container and recreate a changed one
	sidecarHashLabel = "sidecar.hash"
)

// SidecarContainerName returns the container name of an app's sidecar for
// one version: clc-<appId>-<hash>-<name>, or clc-<appId>-<name> for dev
// apps (which have no version hash).
func SidecarContainerName(appId types.AppId, versionHash, sidecarName string) ContainerName {
	if versionHash == "" {
		return ContainerName(fmt.Sprintf("clc-%s-%s", appId, sidecarName))
	}
	return ContainerName(fmt.Sprintf("clc-%s-%s-%s", appId, shortHash(versionHash), sidecarName))
}

// SidecarNetworkName returns the app's private bridge network, shared by the
// app container and its sidecars on docker/podman.
func SidecarNetworkName(appId types.AppId) string {
	return "cln-" + string(appId)
}

// SidecarRunner is the optional manager capability for running app sidecars
// as peer containers on a per app network. Implemented by the command-based
// (docker/podman) manager; kubernetes runs sidecars inside the app pod via
// DeployRequest.Sidecars. Sidecar containers are otherwise managed through
// the generic container operations (state, start, stop, remove, logs).
type SidecarRunner interface {
	// EnsureSidecarNetwork creates the app network when missing and makes
	// the manager attach app containers it runs to it
	EnsureSidecarNetwork(ctx context.Context, appId types.AppId) error
	// RunSidecar starts one sidecar container for the given app container,
	// stamped with its config hash
	RunSidecar(ctx context.Context, appEntry *types.AppEntry, sourceDir string, appContainer ContainerName,
		containerName ContainerName, sidecar *ResolvedSidecar, addrEnv map[string]string,
		paramMap map[string]string, versionHash, configHash string) error
	// GetSidecarInfo reports whether the sidecar container exists, whether
	// its config hash label matches, its loopback published host port and
	// whether it is running
	GetSidecarInfo(ctx context.Context, name ContainerName, configHash string) (exists, matches bool, hostPort string, running bool, err error)
	// RemoveContainerIfExists force-removes a container, ignoring a missing one
	RemoveContainerIfExists(ctx context.Context, name ContainerName) error
}

// AsSidecarRunner unwraps any decorating container managers and returns the
// underlying SidecarRunner if one is present.
func AsSidecarRunner(cm ContainerManager) (SidecarRunner, bool) {
	for cm != nil {
		if r, ok := cm.(SidecarRunner); ok {
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

var _ SidecarRunner = (*CommandCM)(nil)

func (c *CommandCM) EnsureSidecarNetwork(ctx context.Context, appId types.AppId) error {
	name := SidecarNetworkName(appId)
	inspect := exec.CommandContext(ctx, c.config.System.ContainerCommand, "network", "inspect", name)
	if err := inspect.Run(); err == nil {
		c.appNetwork = name
		return nil
	}
	c.Info().Msgf("Creating app network %s", name)
	args := []string{"network", "create",
		"--label", LABEL_PREFIX + "app.id=" + string(appId),
		"--label", LABEL_PREFIX + "server.home=" + serverHomeLabelValue(),
		name}
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// A concurrent create may have won the race
		if recheck := exec.CommandContext(ctx, c.config.System.ContainerCommand, "network", "inspect", name); recheck.Run() == nil {
			c.appNetwork = name
			return nil
		}
		return fmt.Errorf("error creating app network %s: %s : %w", name, output, err)
	}
	c.appNetwork = name
	return nil
}

func (c *CommandCM) GetSidecarInfo(ctx context.Context, name ContainerName, configHash string) (bool, bool, string, bool, error) {
	containers, err := c.listContainers(ctx, []string{"name=" + string(name)}, true)
	if err != nil {
		return false, false, "", false, fmt.Errorf("error checking sidecar container: %w", err)
	}
	for _, cont := range containers {
		// The name filter is a substring match, verify exact name
		if cont.Names != string(name) {
			continue
		}
		matches := cont.HasLabel(LABEL_PREFIX+sidecarHashLabel, configHash)
		hostPort := ""
		if cont.Port > 0 {
			hostPort = "127.0.0.1:" + strconv.Itoa(cont.Port)
		}
		return true, matches, hostPort, strings.EqualFold(cont.State, "running"), nil
	}
	return false, false, "", false, nil
}

func (c *CommandCM) RemoveContainerIfExists(ctx context.Context, name ContainerName) error {
	containers, err := c.listContainers(ctx, []string{"name=" + string(name)}, true)
	if err != nil {
		return err
	}
	for _, cont := range containers {
		if cont.Names == string(name) {
			return c.RemoveContainer(ctx, name)
		}
	}
	return nil
}

func (c *CommandCM) RunSidecar(ctx context.Context, appEntry *types.AppEntry, sourceDir string, appContainer ContainerName,
	containerName ContainerName, sidecar *ResolvedSidecar, addrEnv map[string]string,
	paramMap map[string]string, versionHash, configHash string) error {
	if c.appNetwork == "" {
		return fmt.Errorf("app network not initialized for sidecar %s", sidecar.Name)
	}
	imageUrl := sidecar.Image
	if strings.HasPrefix(imageUrl, IMAGE_NAME_PREFIX) && c.config.Registry.URL != "" {
		if c.config.Registry.Project != "" {
			imageUrl = c.config.Registry.URL + "/" + c.config.Registry.Project + "/" + imageUrl
		} else {
			imageUrl = c.config.Registry.URL + "/" + imageUrl
		}
	}

	args := []string{"run", "--name", string(containerName), "--detach", "--network", c.appNetwork,
		"--restart", "on-failure"}
	if sidecar.Port > 0 {
		// Published on loopback so the server can probe readiness before
		// the app container starts, whatever tooling the sidecar image has
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1::%d", sidecar.Port))
	}
	mountArgs, err := c.genMountArgs(sourceDir, sidecar.Volumes, paramMap)
	if err != nil {
		return fmt.Errorf("error generating sidecar mount args: %w", err)
	}
	args = append(args, mountArgs...)

	args = append(args, "--label", LABEL_PREFIX+"app.id="+string(appEntry.Id))
	args = append(args, "--label", LABEL_PREFIX+"app.path="+appEntry.Path)
	args = append(args, "--label", LABEL_PREFIX+"server.home="+serverHomeLabelValue())
	args = append(args, "--label", LABEL_PREFIX+litestreamRoleLabel+"="+sidecarRoleValue)
	args = append(args, "--label", LABEL_PREFIX+sidecarNameLabel+"="+sidecar.Name)
	args = append(args, "--label", LABEL_PREFIX+sidecarAppLabel+"="+string(appContainer))
	args = append(args, "--label", LABEL_PREFIX+sidecarHashLabel+"="+configHash)
	if sidecar.AlwaysOn {
		args = append(args, "--label", SidecarAlwaysOnLabelKey+"=true")
	}
	if appEntry.IsDev {
		args = append(args, "--label", LABEL_PREFIX+"dev=true")
	} else {
		args = append(args, "--label", LABEL_PREFIX+"dev=false")
		args = append(args, "--label", LABEL_PREFIX+"app.version="+strconv.Itoa(appEntry.Metadata.VersionMetadata.Version))
		args = append(args, "--label", LABEL_PREFIX+"version.hash="+versionHash)
	}
	if sidecar.DevWorkDir != "" {
		args = append(args, "--workdir", sidecar.DevWorkDir)
	}

	for k, v := range sidecar.Env {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}
	for k, v := range addrEnv {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	commandOptions, err := ParseCommandOptions(c.config.System.ContainerCommand, sidecar.Options)
	if err != nil {
		return fmt.Errorf("error parsing sidecar %s options: %w", sidecar.Name, err)
	}
	args = append(args, LocalhostHostGatewayArgs(c.config.System.ContainerCommand)...)
	commandOptionArgs, err := CommandOptionArgs(commandOptions, c.config.Security.AllowedContainerArgs)
	if err != nil {
		return err
	}
	args = append(args, commandOptionArgs...)

	if len(sidecar.Command) > 0 {
		args = append(args, "--entrypoint", sidecar.Command[0])
	}
	args = append(args, imageUrl)
	if len(sidecar.Command) > 1 {
		args = append(args, sidecar.Command[1:]...)
	}
	args = append(args, sidecar.Args...)

	c.Debug().Msgf("Running sidecar with args: %v", RedactEnvArgs(args))
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running sidecar %s: %s : %s", sidecar.Name, output, err)
	}
	return nil
}
