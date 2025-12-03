// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"bufio"
	"bytes"
	"container/ring"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

var base32encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

func genLowerCaseId(name string) string {
	// The container id needs to be lower case. Use base32 to encode the name so that it can be lowercased
	return strings.ToLower(base32encoder.EncodeToString([]byte(name)))
}

var mu sync.Mutex
var buildLockChannel chan string // channel to hold the build ids, max size is MaxConcurrentBuilds

// acquireBuildLock acquires a build lock for the given build id. If the lock is not available,
// it will wait for the lock to be available or the context to be done.
// The lock is released when the returned function is called.
func acquireBuildLock(ctx context.Context, config *types.SystemConfig, buildId string) (func(), error) {
	mu.Lock()
	if buildLockChannel == nil {
		buildLockChannel = make(chan string, config.MaxConcurrentBuilds)
	}
	mu.Unlock()

	timer := time.NewTimer(time.Duration(config.MaxBuildWaitSecs) * time.Second)
	defer timer.Stop()

	select {
	case buildLockChannel <- buildId:
		return func() { <-buildLockChannel }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
}

type ContainerCommand struct {
	*types.Logger
	appRunDir string
	appId     types.AppId
	config    *types.ServerConfig
}

var _ DevContainerManager = (*ContainerCommand)(nil)

func NewContainerCommand(logger *types.Logger, config *types.ServerConfig, appId types.AppId, appRunDir string) *ContainerCommand {
	return &ContainerCommand{
		Logger:    logger,
		config:    config,
		appId:     appId,
		appRunDir: appRunDir,
	}
}

func (c *ContainerCommand) RemoveImage(ctx context.Context, name ImageName) error {
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, "rmi", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error removing image: %s : %s", output, err)
	}

	return nil
}

func (c *ContainerCommand) BuildImage(ctx context.Context, imgName ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	targetUrl, found := strings.CutPrefix(c.config.Builder.Mode, "delegate:")
	if found {
		err := sendDelegateBuild(targetUrl, DelegateRequest{
			ImageTag:       string(imgName),
			ContainerFile:  containerFile,
			ContainerArgs:  containerArgs,
			RegistryConfig: &c.config.Registry,
		}, sourceUrl)
		if err != nil {
			return fmt.Errorf("error sending delegate build: %w", err)
		}
		return nil
	}

	if c.config.Builder.Mode != "command" && c.config.Builder.Mode != "auto" {
		return fmt.Errorf("invalid builder mode for command based container manager: %s", c.config.Builder.Mode)
	}

	return buildImageCommand(ctx, c.Logger, c.config, imgName, sourceUrl, containerFile, containerArgs, c.config.System.ContainerCommand)
}

func buildImageCommand(ctx context.Context, logger *types.Logger, config *types.ServerConfig,
	imgName ImageName, sourceUrl, containerFile string, containerArgs map[string]string, containerCommand string) error {
	releaseLock, err := acquireBuildLock(ctx, &config.System, string(imgName))
	if err != nil {
		return fmt.Errorf("error acquiring build lock: %w", err)
	}
	defer releaseLock()

	logger.Debug().Msgf("Building image %s from %s with %s", imgName, containerFile, sourceUrl)
	args := []string{containerCommand, "build", "-t", string(imgName), "-f", containerFile}

	for k, v := range containerArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, ".")
	cmd := exec.Command(args[0], args[1:]...)

	logger.Debug().Msgf("Running command: %s", cmd.String())
	cmd.Dir = sourceUrl
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error building image: %s : %s", output, err)
	}
	if config.Registry.URL != "" {
		err = pushToRemoteRegistry(ctx, logger, config, string(imgName), &config.Registry)
		if err != nil {
			return fmt.Errorf("error pushing image to remote registry: %w", err)
		}
	}

	return nil
}

func (c *ContainerCommand) RemoveContainer(ctx context.Context, name ContainerName) error {
	c.Debug().Msgf("Removing container %s", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, "rm", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error removing image: %s : %s", output, err)
	}

	return nil
}

// GetContainerState returns the host:port of the running container, "" if not running. running is true if the container is running.
func (c *ContainerCommand) GetContainerState(ctx context.Context, name ContainerName) (string, bool, error) {
	containers, err := c.getContainers(ctx, name, true)
	if err != nil {
		return "", false, fmt.Errorf("error getting containers: %w", err)
	}
	if len(containers) == 0 {
		return "", false, nil
	}

	return "127.0.0.1:" + strconv.Itoa(containers[0].Port), containers[0].State == "running", nil
}

func (c *ContainerCommand) getContainers(ctx context.Context, name ContainerName, getAll bool) ([]Container, error) {
	c.Debug().Msgf("Getting containers with name %s, getAll %t", name, getAll)
	args := []string{"ps", "--format", "json"}
	if name != "" {
		args = append(args, "--filter", fmt.Sprintf("name=%s", name))
	}

	if getAll {
		args = append(args, "--all")
	}
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error listing containers: %s : %s", output, err)
	}

	resp := []Container{}
	if len(output) == 0 {
		c.Debug().Msg("No containers found")
		return resp, nil
	}

	if output[0] == '[' { //nolint:staticcheck
		// Podman format (Names and Ports are arrays)
		type Port struct {
			// only HostPort is needed
			HostPort int `json:"host_port"`
		}

		type ContainerPodman struct {
			ID     string   `json:"ID"`
			Names  []string `json:"Names"`
			Image  string   `json:"Image"`
			State  string   `json:"State"`
			Status string   `json:"Status"`
			Ports  []Port   `json:"Ports"`
		}
		result := []ContainerPodman{}

		// JSON output (podman)
		err = json.Unmarshal(output, &result)
		if err != nil {
			return nil, err
		}

		for _, c := range result {
			port := 0
			if len(c.Ports) > 0 {
				port = c.Ports[0].HostPort
			}
			resp = append(resp, Container{
				ID:     c.ID,
				Names:  c.Names[0],
				Image:  c.Image,
				State:  c.State,
				Status: c.Status,
				Port:   port,
			})
		}
	} else if output[0] == '{' {
		// Newline separated JSON (Docker)
		decoder := json.NewDecoder(bytes.NewReader(output))
		for decoder.More() {
			var c Container
			if err := decoder.Decode(&c); err != nil {
				return nil, fmt.Errorf("error decoding container output: %v", err)
			}

			if c.PortString != "" {
				// "Ports":"127.0.0.1:55000-\u003e5000/tcp"
				_, v, ok := strings.Cut(c.PortString, ":")
				if !ok {
					return nil, fmt.Errorf("error parsing \":\" from port string: %s", c.PortString)
				}
				v, _, ok = strings.Cut(v, "-")
				if !ok {
					return nil, fmt.Errorf("error parsing \"-\" from port string: %s", v)
				}

				c.Port, err = strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("error converting to int port string: %s", v)
				}
			}

			resp = append(resp, c)
		}
	} else {
		return nil, fmt.Errorf("\"%s ps\" returned unknown output: %s", c.config.System.ContainerCommand, output)
	}

	c.Debug().Msgf("Found containers: %+v", resp)
	return resp, nil
}

func (c *ContainerCommand) GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error) {
	c.Debug().Msgf("Getting container logs %s", name)
	lines, err := c.ExecTailN(ctx, c.config.System.ContainerCommand, []string{"logs", string(name)}, linesToShow)
	if err != nil {
		return "", fmt.Errorf("error getting container %s logs: %s", name, err)
	}

	return strings.Join(lines, "\n"), nil
}

func (c *ContainerCommand) StopContainer(ctx context.Context, name ContainerName) error {
	c.Debug().Msgf("Stopping container %s", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, "stop", "-t", "1", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error stopping container: %s : %s", output, err)
	}

	return nil
}

func (c *ContainerCommand) StartContainer(ctx context.Context, name ContainerName) error {
	c.Debug().Msgf("Starting container %s", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, "start", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error starting container: %s : %s", output, err)
	}

	return nil
}

const LABEL_PREFIX = "dev.openrun."

func (c *ContainerCommand) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, volumes []*VolumeInfo,
	containerOptions map[string]string, paramMap map[string]string) error {
	c.Debug().Msgf("Running container %s from image %s with port %d env %+v mountArgs %+v",
		containerName, imageName, port, envMap, volumes)
	publish := fmt.Sprintf("127.0.0.1::%d", port)

	imageUrl := string(imageName)
	if c.config.Registry.URL != "" {
		if c.config.Registry.Project != "" {
			imageUrl = c.config.Registry.URL + "/" + c.config.Registry.Project + "/" + string(imageName)
		} else {
			imageUrl = c.config.Registry.URL + "/" + string(imageName)
		}
	}

	args := []string{"run", "--name", string(containerName), "--detach", "--publish", publish}
	mountArgs, err := c.genMountArgs(sourceDir, volumes, paramMap)
	if err != nil {
		return fmt.Errorf("error generating mount args: %w", err)
	}
	if len(mountArgs) > 0 {
		args = append(args, mountArgs...)
	}

	args = append(args, "--label", LABEL_PREFIX+"app.id="+string(appEntry.Id))
	if appEntry.IsDev {
		args = append(args, "--label", LABEL_PREFIX+"dev=true")
	} else {
		args = append(args, "--label", LABEL_PREFIX+"dev=false")
		args = append(args, "--label", LABEL_PREFIX+"app.version="+strconv.Itoa(appEntry.Metadata.VersionMetadata.Version))
		args = append(args, "--label", LABEL_PREFIX+"git.sha="+appEntry.Metadata.VersionMetadata.GitCommit)
		args = append(args, "--label", LABEL_PREFIX+"git.message="+appEntry.Metadata.VersionMetadata.GitMessage)
	}

	// Add env args
	for k, v := range envMap {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	// Add container related args
	for k, v := range containerOptions {
		if v == "" {
			args = append(args, fmt.Sprintf("--%s", k))
		} else {
			args = append(args, fmt.Sprintf("--%s=%s", k, v))
		}
	}

	args = append(args, imageUrl)

	c.Debug().Msgf("Running container with args: %v", args)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running container: %s : %s", output, err)
	}

	return nil
}

func (c *ContainerCommand) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	if c.config.Registry.URL != "" {
		return ImageExists(ctx, c.Logger, string(name), &c.config.Registry)
	}

	c.Debug().Msgf("Getting images with name %s", name)
	args := []string{"images", string(name)}
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("error listing images: %s : %s", output, err)
	}

	split := strings.SplitN(string(output), "\n", 3)
	if len(split) > 1 && len(strings.TrimSpace(split[1])) > 0 {
		return true, nil
	}

	return false, nil
}

// ExecTailN executes a command and returns the last n lines of output
func (c *ContainerCommand) ExecTailN(ctx context.Context, command string, args []string, n int) ([]string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %s", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("error creating stderr pipe: %s", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting command: %s", err)
	}

	multi := bufio.NewReader(io.MultiReader(stdout, stderr))

	// Create a ring buffer to hold the last 1000 lines of output
	ringBuffer := ring.New(n)

	scanner := bufio.NewScanner(multi)
	for scanner.Scan() {
		// Push the latest line into the ring buffer, displacing the oldest line if necessary
		ringBuffer.Value = scanner.Text()
		ringBuffer = ringBuffer.Next()
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning output: %s", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error waiting for command: %s", err)
	}

	ret := make([]string, 0, n)
	ringBuffer.Do(func(p any) {
		if line, ok := p.(string); ok {
			ret = append(ret, line)
		}
	})

	return ret, nil
}

func (c ContainerCommand) VolumeExists(ctx context.Context, name VolumeName) bool {
	c.Debug().Msgf("Checking volume exists %s", name)
	cmd := exec.CommandContext(ctx, c.config.System.ContainerCommand, "volume", "inspect", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.Debug().Msgf("volume exists check failed %s %s %s", name, err, output)
	}
	c.Debug().Msgf("volume exists %s %t", name, err == nil)
	return err == nil
}

func (c ContainerCommand) VolumeCreate(ctx context.Context, name VolumeName) error {
	c.Debug().Msgf("Creating volume %s", name)
	cmd := exec.Command(c.config.System.ContainerCommand, "volume", "create", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating volume %s: %w %s", name, err, output)
	}
	return nil
}

func (c *ContainerCommand) genMountArgs(sourceDir string, volumeInfo []*VolumeInfo, paramMap map[string]string) ([]string, error) {
	args := make([]string, 0, len(volumeInfo))

	for _, volInfo := range volumeInfo {
		if volInfo.IsSecret {
			// For cl_secret:file.prop:/data/file.prop, pass file.prop through the template
			// processor, write output to file.prop.gen and then bind mount it as
			// /source_dir/file.prop.gen:/data/file.prop
			tmplFileName := volInfo.SourcePath
			srcFile := makeAbsolute(sourceDir, tmplFileName)
			destFile := path.Join(c.appRunDir, path.Base(tmplFileName)+".gen")
			data := map[string]any{"params": paramMap}
			if sourceDir != "" {
				err := renderTemplate(srcFile, destFile, data)
				if err != nil {
					return nil, fmt.Errorf("error rendering template %s: %w", srcFile, err)
				}
			}
			volStr := fmt.Sprintf("%s:%s", destFile, volInfo.TargetPath)
			if volInfo.ReadOnly {
				volStr += ":ro"
			}
			c.Info().Msgf("Mounting secret %s for app %s src %s dest %s", volStr, c.appId, srcFile, destFile)
			args = append(args, fmt.Sprintf("--volume=%s", volStr))
			continue
		}

		if volInfo.VolumeName == "" {
			// bind mount
			args = append(args, fmt.Sprintf("--volume=%s:%s", volInfo.SourcePath, volInfo.TargetPath))
			continue
		}

		dir := volInfo.VolumeName
		if dir == UNNAMED_VOLUME {
			// unnamed volume, use the path for generating the volume name
			dir = volInfo.TargetPath
		}

		genVolumeName := GenVolumeName(c.appId, dir)
		volStr := fmt.Sprintf("%s:%s", genVolumeName, volInfo.TargetPath)
		if volInfo.SourcePath != "" {
			volStr = fmt.Sprintf("%s:%s:%s", genVolumeName, volInfo.SourcePath, volInfo.TargetPath)
		}

		if volInfo.ReadOnly {
			volStr += ":ro"
		}

		c.Info().Msgf("Mounting volume %s for app %s dir %s, mount arg %s", genVolumeName, c.appId, dir, volStr)
		args = append(args, fmt.Sprintf("--volume=%s", volStr))
	}
	return args, nil
}

const (
	DOCKER_COMMAND = "docker"
	PODMAN_COMMAND = "podman"

	kubeHostEnv = "KUBERNETES_SERVICE_HOST"
	kubePortEnv = "KUBERNETES_SERVICE_PORT"
)

func LookupContainerCommand(checkKubernetes bool) string {
	if checkKubernetes {
		// Check if running in Kubernetes
		_, hasHost := os.LookupEnv(kubeHostEnv)
		_, hasPort := os.LookupEnv(kubePortEnv)
		if hasHost || hasPort {
			return types.CONTAINER_KUBERNETES
		}
	}

	podmanExec := system.FindExec(PODMAN_COMMAND)
	if podmanExec != "" {
		return podmanExec
	}
	dockerExec := system.FindExec(DOCKER_COMMAND)
	if dockerExec != "" {
		return dockerExec
	}
	return ""
}
