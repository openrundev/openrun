// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

// Job container labels (with LABEL_PREFIX)
const (
	JobNameLabel = "job"
	JobRunLabel  = "job.run"
)

// JobRunRequest describes one job container run: an ephemeral container
// from Image, running Argv with Env, that is left in place when it exits so
// its logs can be read until the run record is retired
type JobRunRequest struct {
	AppEntry         *types.AppEntry
	RunId            string
	JobName          string
	ContainerName    ContainerName
	Image            string
	Argv             []string // entrypoint override followed by args; empty runs the image default
	Env              map[string]string
	Volumes          []*VolumeInfo
	ContainerOptions map[string]string
	ParamMap         map[string]string
	Timeout          time.Duration
}

// JobRunner runs job containers. RunJob blocks until the workload exits and
// returns its exit code; canceling ctx stops the workload. RemoveJob deletes
// the finished container (or Kubernetes Job); JobLogs reads its output
type JobRunner interface {
	RunJob(ctx context.Context, req JobRunRequest) (int, error)
	RemoveJob(ctx context.Context, name ContainerName) error
	JobLogs(ctx context.Context, name ContainerName, lines int) (string, error)
}

// AsJobRunner unwraps a container manager to its job runner
func AsJobRunner(cm ContainerManager) (JobRunner, bool) {
	for cm != nil {
		if r, ok := cm.(JobRunner); ok {
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

// JobContainerName returns the container (docker/podman) or Job (kubernetes)
// name of a run: clj-<app id>-<job>-<run suffix>
func JobContainerName(appId types.AppId, jobName, runId string) ContainerName {
	suffix := runId
	if idx := strings.LastIndex(runId, "_"); idx >= 0 {
		suffix = runId[idx+1:]
	}
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return ContainerName(fmt.Sprintf("clj-%s-%s-%s", appId, jobName, strings.ToLower(suffix)))
}

var _ JobRunner = (*CommandCM)(nil)

// RunJob runs the job container in the foreground: the run command returns
// when the container exits, with the container's exit code. The container
// is named and labeled, and not removed. A canceled context stops the
// container
func (c *CommandCM) RunJob(ctx context.Context, req JobRunRequest) (int, error) {
	imageUrl := req.Image
	if strings.HasPrefix(imageUrl, IMAGE_NAME_PREFIX) && c.config.Registry.URL != "" {
		if c.config.Registry.Project != "" {
			imageUrl = c.config.Registry.URL + "/" + c.config.Registry.Project + "/" + imageUrl
		} else {
			imageUrl = c.config.Registry.URL + "/" + imageUrl
		}
	}

	args := []string{"run", "--name", string(req.ContainerName)}
	mountArgs, err := c.genMountArgs("", req.Volumes, req.ParamMap)
	if err != nil {
		return -1, fmt.Errorf("error generating job mount args: %w", err)
	}
	args = append(args, mountArgs...)

	args = append(args, "--label", LABEL_PREFIX+"app.id="+string(req.AppEntry.Id))
	args = append(args, "--label", LABEL_PREFIX+"app.path="+req.AppEntry.Path)
	args = append(args, "--label", LABEL_PREFIX+"server.home="+serverHomeLabelValue())
	args = append(args, "--label", LABEL_PREFIX+JobNameLabel+"="+req.JobName)
	args = append(args, "--label", LABEL_PREFIX+JobRunLabel+"="+req.RunId)
	args = append(args, "--label", LABEL_PREFIX+"app.version="+strconv.Itoa(req.AppEntry.Metadata.VersionMetadata.Version))
	if req.AppEntry.IsDev {
		args = append(args, "--label", LABEL_PREFIX+"dev=true")
	} else {
		args = append(args, "--label", LABEL_PREFIX+"dev=false")
	}

	for k, v := range req.Env {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	commandOptions, err := ParseCommandOptions(c.config.System.ContainerCommand, req.ContainerOptions)
	if err != nil {
		return -1, fmt.Errorf("error parsing job container options: %w", err)
	}
	args = append(args, LocalhostHostGatewayArgs(c.config.System.ContainerCommand)...)
	commandOptionArgs, err := CommandOptionArgs(commandOptions, c.config.Security.AllowedContainerArgs)
	if err != nil {
		return -1, err
	}
	args = append(args, commandOptionArgs...)

	if len(req.Argv) > 0 {
		args = append(args, "--entrypoint", req.Argv[0])
	}
	args = append(args, imageUrl)
	if len(req.Argv) > 1 {
		args = append(args, req.Argv[1:]...)
	}

	c.Debug().Msgf("Running job container with args: %v", RedactEnvArgs(args))
	// The run command is started detached from ctx: on cancel the container
	// is stopped explicitly below, which makes the run command exit; killing
	// the client process alone would leave the container running
	cmd := exec.Command(c.config.System.ContainerCommand, args...)
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("error starting job container: %w", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		// The container may not exist yet when the cancel lands right after
		// the start: keep stopping until the run command exits, then give up
		// on the client process (the sweeper reaps a container that
		// outlives its run record)
		deadline := time.After(60 * time.Second)
	stopping:
		for {
			stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := c.StopContainer(stopCtx, req.ContainerName)
			cancel()
			if err != nil {
				c.Debug().Err(err).Msgf("stopping canceled job container %s", req.ContainerName)
			}
			select {
			case <-waitDone:
				break stopping
			case <-deadline:
				c.Warn().Msgf("canceled job container %s did not stop, killing the run command", req.ContainerName)
				_ = cmd.Process.Kill()
				<-waitDone
				break stopping
			case <-time.After(time.Second):
			}
		}
		return -1, ctx.Err()
	}
	if waitErr == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, fmt.Errorf("error running job container: %w", waitErr)
}

// RemoveJob force removes a job container
func (c *CommandCM) RemoveJob(ctx context.Context, name ContainerName) error {
	return c.RemoveContainer(ctx, name)
}

// JobLogs returns the last lines of a job container's output
func (c *CommandCM) JobLogs(ctx context.Context, name ContainerName, lines int) (string, error) {
	return c.GetContainerLogs(ctx, name, lines)
}
