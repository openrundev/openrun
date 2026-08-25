// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

// sidecarConfig is a sidecar spec with its volumes parsed at handler
// construction (volume sources are validated against the allowed mounts).
type sidecarConfig struct {
	spec    types.SidecarSpec
	volumes []*container.VolumeInfo
}

// parseSidecarConfigs validates and parses the merged sidecar specs.
func (h *ContainerHandler) parseSidecarConfigs(specs []types.SidecarSpec) ([]sidecarConfig, error) {
	ret := make([]sidecarConfig, 0, len(specs))
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			return nil, err
		}
		if spec.Port != 0 && spec.Port == h.port {
			return nil, fmt.Errorf("sidecar %s port %d conflicts with the app port", spec.Name, spec.Port)
		}
		volumes := make([]*container.VolumeInfo, 0, len(spec.Volumes))
		for _, vol := range spec.Volumes {
			volInfo, err := h.parseVolumeString(vol)
			if err != nil {
				return nil, fmt.Errorf("sidecar %s: error parsing volume %s: %w", spec.Name, vol, err)
			}
			volumes = append(volumes, volInfo)
		}
		ret = append(ret, sidecarConfig{spec: spec, volumes: volumes})
	}
	return ret, nil
}

// hasSidecars reports whether the app declares any sidecar.
func (h *ContainerHandler) hasSidecars() bool {
	return len(h.sidecars) > 0
}

// buildSidecars resolves the app's sidecars against the app's base env and
// generated image. The result is deterministic for a given handler state, so
// it is also the input of the sidecar part of the app version hash. The
// CL_SIDECAR_*_ADDR vars are not included (they depend on the version hash
// on docker/podman); sidecarAddrEnv adds them at run time.
func (h *ContainerHandler) buildSidecars(baseEnv map[string]string) []*container.ResolvedSidecar {
	ret := make([]*container.ResolvedSidecar, 0, len(h.sidecars))
	for _, sc := range h.sidecars {
		spec := sc.spec
		env := map[string]string{}
		if spec.InheritsEnv() {
			for k, v := range baseEnv {
				if k == "PORT" {
					// The app port is the app container's; a framework in the
					// sidecar honouring PORT must not bind it
					continue
				}
				env[k] = v
			}
		} else {
			// Non secret app identity only
			for _, k := range []string{"CL_APP_PATH", "CL_APP_URL"} {
				if v, ok := baseEnv[k]; ok {
					env[k] = v
				}
			}
		}
		for k, v := range spec.Env {
			env[k] = v
		}
		if spec.Port > 0 {
			env["PORT"] = fmt.Sprintf("%d", spec.Port)
		}

		image := string(h.GenImageName)
		if !spec.IsAppImage() {
			image = spec.ImageRef()
			h.sidecarDigestMu.RLock()
			digest := h.sidecarDigests[spec.Name]
			h.sidecarDigestMu.RUnlock()
			if digest != "" {
				image = container.DigestPinned(image, digest)
			}
		}

		healthPath := ""
		if spec.Health != "" {
			healthPath = strings.TrimPrefix(spec.Health, "http:")
		}
		volumes := append([]*container.VolumeInfo{}, sc.volumes...)
		devWorkDir := ""
		if spec.IsAppImage() && h.devSettings != nil {
			// Dev mode app image sidecars see the live source like the app
			// container: same bind mounts, same working dir
			volumes = append(volumes, h.devMounts...)
			devWorkDir = h.devSettings.Dir
		}
		ret = append(ret, &container.ResolvedSidecar{
			Name:       spec.Name,
			Image:      image,
			IsAppImage: spec.IsAppImage(),
			Command:    append([]string{}, spec.Command...),
			Args:       append([]string{}, spec.Args...),
			Env:        env,
			InheritEnv: spec.InheritsEnv(),
			Port:       spec.Port,
			HealthPath: healthPath,
			Volumes:    volumes,
			AlwaysOn:   spec.IsAlwaysOn(),
			Options:    spec.Options,
			DevWorkDir: devWorkDir,
		})
	}
	return ret
}

// sidecarConfigHash identifies one resolved sidecar's config as part of the
// app version hash. The app image name is excluded for app image sidecars:
// it is derived from the version hash itself (the app source and build args
// already identify it); foreign images are included by digest pinned
// reference.
func sidecarConfigHash(sidecar *container.ResolvedSidecar) (string, error) {
	mounts := make([]string, 0, len(sidecar.Volumes))
	for _, vol := range sidecar.Volumes {
		mounts = append(mounts, fmt.Sprintf("%+v", *vol))
	}
	image := sidecar.Image
	if sidecar.IsAppImage {
		image = ""
	}
	hashable := struct {
		Name       string
		Image      string
		Command    []string
		Args       []string
		Env        map[string]string
		Port       int32
		HealthPath string
		Mounts     []string
		AlwaysOn   bool
		Options    map[string]string
		DevWorkDir string
	}{sidecar.Name, image, sidecar.Command, sidecar.Args, sidecar.Env, sidecar.Port,
		sidecar.HealthPath, mounts, sidecar.AlwaysOn, sidecar.Options, sidecar.DevWorkDir}
	data, err := json.Marshal(hashable, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return getValuesHash(string(data))
}

// sidecarRunHash identifies a sidecar container's full runtime config,
// including the exact image it runs; stamped on the container so a reload
// can reuse an up to date container and recreate a changed one (in dev
// mode, where sidecar names carry no version hash, this is what detects a
// rebuilt dev image).
func sidecarRunHash(sidecar *container.ResolvedSidecar) (string, error) {
	configHash, err := sidecarConfigHash(sidecar)
	if err != nil {
		return "", err
	}
	return getValuesHash(configHash, sidecar.Image)
}

// sidecarsHash is the sidecar part of the app version hash: empty for apps
// without sidecars so their hash is unchanged.
func (h *ContainerHandler) sidecarsHash(baseEnv map[string]string) (string, error) {
	if !h.hasSidecars() {
		return "", nil
	}
	parts := []string{}
	for _, sidecar := range h.buildSidecars(baseEnv) {
		hash, err := sidecarConfigHash(sidecar)
		if err != nil {
			return "", err
		}
		parts = append(parts, sidecar.Name+":"+hash)
	}
	return getValuesHash(parts...)
}

// sidecarAddrEnv returns the CL_SIDECAR_<NAME>_ADDR vars for the app's
// port'd sidecars: localhost on kubernetes (same pod), the sidecar container
// name on docker/podman (resolved on the app network).
func (h *ContainerHandler) sidecarAddrEnv(versionHash string) map[string]string {
	env := map[string]string{}
	for _, sc := range h.sidecars {
		if sc.spec.Port == 0 {
			continue
		}
		host := "localhost"
		if !h.isKubernetes {
			host = string(container.SidecarContainerName(h.app.Id, versionHash, sc.spec.Name))
		}
		env[types.SidecarAddrEnvName(sc.spec.Name)] = fmt.Sprintf("%s:%d", host, sc.spec.Port)
	}
	return env
}

// withSidecarAddrEnv returns the app env map with the sidecar address vars
// added (a copy when there are sidecars).
func (h *ContainerHandler) withSidecarAddrEnv(envMap map[string]string, versionHash string) map[string]string {
	addrEnv := h.sidecarAddrEnv(versionHash)
	if len(addrEnv) == 0 {
		return envMap
	}
	merged := make(map[string]string, len(envMap)+len(addrEnv))
	for k, v := range envMap {
		merged[k] = v
	}
	for k, v := range addrEnv {
		merged[k] = v
	}
	return merged
}

// refreshSidecarImages resolves the current digest of each foreign sidecar
// image (pulling it on docker/podman), so the version hash and the running
// reference follow a moved tag, like image-spec apps.
func (h *ContainerHandler) refreshSidecarImages(ctx context.Context) error {
	for _, sc := range h.sidecars {
		if sc.spec.IsAppImage() {
			continue
		}
		digest, err := h.manager.RefreshImage(ctx, container.ImageName(sc.spec.ImageRef()))
		if err != nil {
			return fmt.Errorf("error refreshing sidecar %s image %s: %w", sc.spec.Name, sc.spec.ImageRef(), err)
		}
		if digest == "" {
			continue
		}
		h.sidecarDigestMu.Lock()
		if h.sidecarDigests == nil {
			h.sidecarDigests = map[string]string{}
		}
		h.sidecarDigests[sc.spec.Name] = digest
		h.sidecarDigestMu.Unlock()
	}
	return nil
}

// SidecarContainerNames returns the sidecar container names of the handler's
// active version (docker/podman), for active-container tracking so the stale
// container cleanup does not stop them.
func (h *ContainerHandler) SidecarContainerNames() []container.ContainerName {
	if h.isKubernetes || !h.hasSidecars() {
		return nil
	}
	h.stateLock.RLock()
	versionHash := h.activeVersionHash
	h.stateLock.RUnlock()
	names := make([]container.ContainerName, 0, len(h.sidecars))
	for _, sc := range h.sidecars {
		names = append(names, container.SidecarContainerName(h.app.Id, versionHash, sc.spec.Name))
	}
	return names
}

// ensureSidecars brings the app's sidecars up for one version on
// docker/podman, in declaration order, before the app container starts: the
// app network is created, each sidecar container is reused when its config
// hash label matches (started if stopped), recreated otherwise, and port'd
// sidecars are probed for readiness through their loopback published port.
// restartAppImage restarts up to date running app image sidecars (dev mode
// source change). No-op on kubernetes (sidecars live in the pod) and for
// apps without sidecars.
func (h *ContainerHandler) ensureSidecars(ctx context.Context, versionHash, sourceDir string,
	appContainer container.ContainerName, restartAppImage bool) error {
	if h.isKubernetes || !h.hasSidecars() {
		return nil
	}
	runner, ok := container.AsSidecarRunner(h.manager)
	if !ok {
		return fmt.Errorf("container manager does not support sidecars")
	}
	if err := runner.EnsureSidecarNetwork(ctx, h.app.Id); err != nil {
		return err
	}
	devCM, _ := h.manager.(container.DevContainerManager)
	addrEnv := h.sidecarAddrEnv(versionHash)
	for _, sidecar := range h.buildSidecars(h.envMap) {
		name := container.SidecarContainerName(h.app.Id, versionHash, sidecar.Name)
		configHash, err := sidecarRunHash(sidecar)
		if err != nil {
			return err
		}
		exists, matches, _, running, err := runner.GetSidecarInfo(ctx, name, configHash)
		if err != nil {
			return err
		}
		started := false
		switch {
		case exists && matches && running:
			if restartAppImage && sidecar.IsAppImage && devCM != nil {
				h.Debug().Msgf("Restarting sidecar %s for app %s", name, h.app.Id)
				if err := devCM.RestartDevContainer(ctx, name); err != nil {
					return fmt.Errorf("error restarting sidecar %s: %w", sidecar.Name, err)
				}
			}
		case exists && matches:
			h.Info().Msgf("Starting stopped sidecar %s for app %s", name, h.app.Id)
			if err := h.manager.StartContainer(ctx, name); err != nil {
				return fmt.Errorf("error starting sidecar %s: %w", sidecar.Name, err)
			}
			started = true
		default:
			if exists {
				h.Info().Msgf("Recreating sidecar %s for app %s", name, h.app.Id)
				if err := runner.RemoveContainerIfExists(ctx, name); err != nil {
					return fmt.Errorf("error removing outdated sidecar %s: %w", sidecar.Name, err)
				}
			} else {
				h.Info().Msgf("Starting sidecar %s for app %s", name, h.app.Id)
			}
			if err := runner.RunSidecar(ctx, h.app.AppEntry, sourceDir, appContainer, name, sidecar, addrEnv,
				h.paramMap, versionHash, configHash); err != nil {
				return err
			}
			started = true
		}
		if started {
			h.registerSidecarDeployTxn(ctx, name)
		}
		if err := h.waitForSidecarReady(ctx, name, sidecar); err != nil {
			if h.containerConfig.ShowLogsForFailure {
				logs, _ := h.manager.GetContainerLogs(ctx, name, h.containerConfig.LogLinesToShow)
				return fmt.Errorf("sidecar %s not ready: %w. Logs\n %s", sidecar.Name, err, logs)
			}
			return fmt.Errorf("sidecar %s not ready: %w", sidecar.Name, err)
		}
	}
	return nil
}

// registerSidecarDeployTxn registers a started sidecar on the operation
// level deploy transaction: stopped again on rollback, shielded from the
// stale container sweeper while the operation is in flight. Superseded
// versions are stopped through the app container's commit hook.
func (h *ContainerHandler) registerSidecarDeployTxn(ctx context.Context, name container.ContainerName) {
	dt := container.DeployTxnFromContext(ctx)
	if dt == nil {
		return
	}
	dt.Register(h.app.Id, name, func(c context.Context) error {
		return h.manager.StopContainer(c, name)
	}, nil)
}

// waitForSidecarReady probes a port'd sidecar through its loopback published
// port (TCP connect, or an HTTP GET of the health path) with the health
// check backoff; a sidecar without a port is ready once its container runs.
func (h *ContainerHandler) waitForSidecarReady(ctx context.Context, name container.ContainerName, sidecar *container.ResolvedSidecar) error {
	attempts := h.containerConfig.DeployHealthAttempts
	if h.app.IsDev {
		attempts = h.containerConfig.HealthAttemptsAfterStartup
	}
	if attempts <= 0 {
		attempts = 1
	}
	timeout := time.Duration(h.containerConfig.HealthTimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = time.Second
	}
	client := &http.Client{Timeout: timeout}

	sleepMillis := 50.0
	var lastErr error
	for attempt := 1; ; attempt++ {
		hostNamePort, running, err := h.manager.GetContainerState(ctx, name, "")
		if err != nil {
			return fmt.Errorf("error getting sidecar state: %w", err)
		}
		if running && sidecar.Port == 0 {
			return nil
		}
		if running && !strings.HasSuffix(hostNamePort, ":0") && hostNamePort != "" {
			if sidecar.HealthPath != "" {
				resp, err := client.Get("http://" + hostNamePort + sidecar.HealthPath)
				if err == nil {
					resp.Body.Close() //nolint:errcheck
					if resp.StatusCode == http.StatusOK {
						return nil
					}
					err = fmt.Errorf("health check returned status %d", resp.StatusCode)
				}
				lastErr = err
			} else {
				conn, err := net.DialTimeout("tcp", hostNamePort, timeout)
				if err == nil {
					conn.Close() //nolint:errcheck
					return nil
				}
				lastErr = err
			}
		} else if !running {
			lastErr = fmt.Errorf("container %s not running", name)
			if checker, ok := container.AsContainerExitChecker(h.manager); ok {
				if exited, status, exitErr := checker.ContainerExited(ctx, name); exitErr == nil && exited {
					return fmt.Errorf("container %s exited (%s)", name, status)
				}
			}
		} else {
			lastErr = fmt.Errorf("container %s has no published port", name)
		}
		if attempt >= attempts {
			break
		}
		sleepMillis = math.Min(sleepMillis*2, 2000)
		h.Debug().Msgf("Sidecar %s not ready, attempt %d: %v", name, attempt, lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(sleepMillis) * time.Millisecond):
		}
	}
	return fmt.Errorf("readiness check did not complete after %d attempts: %w", attempts, lastErr)
}

// stopIdleSidecars stops the sidecars that do not stay on across an app idle
// shutdown (port'd companions by default); always_on sidecars (workers by
// default) keep running. Restarted by ensureSidecars before the app on the
// next request.
func (h *ContainerHandler) stopIdleSidecars(ctx context.Context, versionHash string) error {
	if h.isKubernetes || !h.hasSidecars() {
		return nil
	}
	var errs []error
	for _, sc := range h.sidecars {
		if sc.spec.IsAlwaysOn() {
			continue
		}
		name := container.SidecarContainerName(h.app.Id, versionHash, sc.spec.Name)
		h.Debug().Msgf("Stopping idle sidecar %s for app %s", name, h.app.Id)
		if err := h.manager.StopContainer(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("sidecar %s: %w", sc.spec.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error stopping idle sidecars: %v", errs)
	}
	return nil
}
