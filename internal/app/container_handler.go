// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type ContainerState string

const (
	ContainerStateUnknown       ContainerState = "unknown"
	ContainerStateRunning       ContainerState = "running"
	ContainerStateIdleShutdown  ContainerState = "idle_shutdown"
	ContainerStateHealthFailure ContainerState = "health_failure"
)

type ContainerHandler struct {
	*types.Logger
	manager         container.ContainerManager
	app             *App
	serverConfig    *types.ServerConfig
	containerFile   string
	image           string              // image name as specified
	GenImageName    container.ImageName // generated image name
	port            int64               // Port number within the container
	hostNamePort    string              // host name : port number for the container
	lifetime        string
	scheme          string
	health          string
	buildDir        string
	sourceFS        appfs.ReadableFS
	paramMap        map[string]string
	volumeInfo      []*container.VolumeInfo
	containerConfig types.Container
	excludeGlob     []string

	// Idle shutdown related fields
	idleShutdownTicker *time.Ticker
	stateLock          sync.RWMutex
	currentState       ContainerState

	// Health check related fields
	healthCheckTicker *time.Ticker
	stripAppPath      bool
	mountArgs         []string
	cargs             map[string]string
	proxyTracker      *Tracker // Track bytes sent and received by the proxy
}

func NewContainerHandler(logger *types.Logger, app *App, containerFile string,
	serverConfig *types.ServerConfig, configPort int64, lifetime, scheme, health, buildDir string, sourceFS appfs.ReadableFS,
	paramMap map[string]string, containerConfig types.Container, stripAppPath bool,
	containerVolumes []string, secretsAllowed [][]string, cargs map[string]any) (*ContainerHandler, error) {

	var containerManager container.ContainerManager
	var err error
	switch serverConfig.System.ContainerCommand {
	case types.CONTAINER_KUBERNETES:
		containerManager, err = container.NewKubernetesContainerManager(logger, serverConfig)
		if err != nil {
			return nil, fmt.Errorf("error creating kubernetes container manager: %w", err)
		}
	default:
		containerManager = container.NewContainerCommand(logger, serverConfig, app.Id, app.AppRunPath)
	}

	image := ""
	volumes := []string{}
	if strings.HasPrefix(containerFile, types.CONTAINER_SOURCE_IMAGE_PREFIX) {
		// Using an image
		image = containerFile[len(types.CONTAINER_SOURCE_IMAGE_PREFIX):]
	} else {
		// Using a container file
		data, err := sourceFS.ReadFile(containerFile)
		if err != nil {
			return nil, fmt.Errorf("error reading container file %s : %w", containerFile, err)
		}

		result, err := parser.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("error parsing container file %s : %w", containerFile, err)
		}

		var filePort int64
		// Loop through the parsed result to find the EXPOSE and VOLUME instructions
		for _, child := range result.AST.Children {
			switch strings.ToUpper(child.Value) {
			case "EXPOSE":
				portVal, err := strconv.Atoi(strings.TrimSpace(child.Next.Value))
				if err != nil {
					// Can fail if value is an arg like $PORT
					logger.Warn().Msgf("Error parsing EXPOSE port %s in container file %s", child.Next.Value, containerFile)
				} else {
					filePort = int64(portVal)
				}
			case "VOLUME":
				v := extractVolumes(child)
				volumes = append(volumes, v...)
			}
		}

		if configPort == 0 {
			// No port configured in app config, use the one from the container file
			configPort = filePort
		}
	}

	volumes = dedupVolumes(append(volumes, containerVolumes...))
	logger.Debug().Msgf("volumes %v %s", volumes, containerFile)

	if configPort == 0 && lifetime != types.CONTAINER_LIFETIME_COMMAND {
		return nil, fmt.Errorf("port not specified in app config and in container file %s. Either "+
			"add a EXPOSE directive in %s or add port number in app config", containerFile, containerFile)
	}

	// Evaluate secrets in the paramMap
	for k, v := range paramMap {
		val, err := app.secretEvalFunc(secretsAllowed, app.AppConfig.Security.DefaultSecretsProvider, v)
		if err != nil {
			return nil, fmt.Errorf("error evaluating secret for %s: %w", k, err)
		}
		paramMap[k] = val
	}

	delete(paramMap, "secrets") // remove the secrets entry, which is a list of secrets the container is allowed to use

	cargs_map := map[string]string{}
	for k, v := range cargs {
		cargs_map[k] = fmt.Sprintf("%v", v)
	}
	for k, v := range app.Metadata.ContainerArgs {
		cargs_map[k] = v
	}

	// Evaluate secrets in the build args
	for k, v := range cargs_map {
		val, err := app.secretEvalFunc(secretsAllowed, app.AppConfig.Security.DefaultSecretsProvider, v)
		if err != nil {
			return nil, fmt.Errorf("error evaluating secret for %s: %w", k, err)
		}
		cargs_map[k] = val
	}

	m := &ContainerHandler{
		Logger:          logger,
		app:             app,
		containerFile:   containerFile,
		image:           image,
		serverConfig:    serverConfig,
		port:            configPort,
		lifetime:        lifetime,
		scheme:          scheme,
		buildDir:        buildDir,
		sourceFS:        sourceFS,
		manager:         containerManager,
		paramMap:        paramMap,
		containerConfig: containerConfig,
		stateLock:       sync.RWMutex{},
		currentState:    ContainerStateUnknown,
		stripAppPath:    stripAppPath,
		cargs:           cargs_map,
	}

	if containerConfig.IdleShutdownSecs > 0 &&
		(!app.IsDev || containerConfig.IdleShutdownDevApps) {
		// Start the idle shutdown check
		m.idleShutdownTicker = time.NewTicker(time.Duration(containerConfig.IdleShutdownSecs) * time.Second)
		go m.idleAppShutdown(context.Background())
	}

	m.health = m.GetHealthUrl(health)
	if containerConfig.StatusCheckIntervalSecs > 0 && m.lifetime != types.CONTAINER_LIFETIME_COMMAND {
		// Start the health check goroutine
		m.healthCheckTicker = time.NewTicker(time.Duration(containerConfig.StatusCheckIntervalSecs) * time.Second)
		go m.healthChecker(context.Background())
	}

	excludeGlob := []string{}
	templateFiles, err := fs.Glob(sourceFS, "*.go.html")
	if err != nil {
		return nil, err
	}

	if len(templateFiles) != 0 { // a.UsesHtmlTemplate is set in initRouter, so it cannot be used here
		excludeGlob = app.codeConfig.Routing.ContainerExclude
	}
	m.excludeGlob = excludeGlob

	volumeInfo := make([]*container.VolumeInfo, 0, len(volumes))
	for _, vol := range volumes {
		volInfo, err := m.parseVolumeString(vol)
		if err != nil {
			return nil, fmt.Errorf("error parsing volume %s: %w", vol, err)
		}
		volumeInfo = append(volumeInfo, volInfo)
	}
	m.volumeInfo = volumeInfo

	return m, nil
}

const (
	VOL_PREFIX_SECRET = "cl_secret:"
)

func dedupVolumes(volumes []string) []string {
	seenStripped := map[string]bool{}
	for _, v := range volumes {
		if strings.HasPrefix(v, VOL_PREFIX_SECRET) {
			stripped := v[len(VOL_PREFIX_SECRET):]
			seenStripped[stripped] = true
		}
	}

	ret := []string{}
	seen := map[string]bool{}
	for _, v := range volumes {
		if seenStripped[v] {
			// skip the stripped string, keep only the unstripped version
			continue
		}
		if seen[v] {
			// already seen, skip
			continue
		}
		seen[v] = true
		ret = append(ret, v)
	}

	return ret
}

func (h *ContainerHandler) idleAppShutdown(ctx context.Context) {
	for range h.idleShutdownTicker.C {
		if h.currentState != ContainerStateRunning {
			continue
		}
		idleTimeSecs := time.Now().Unix() - h.app.lastRequestTime.Load()
		if idleTimeSecs < int64(h.containerConfig.IdleShutdownSecs) {
			// Not idle
			h.Trace().Msgf("App %s not idle, last request %d seconds ago", h.app.Id, idleTimeSecs)
			continue
		}

		if h.proxyTracker != nil {
			sent, recv := h.proxyTracker.GetRollingTotals()
			totalBytes := sent + recv
			if totalBytes >= uint64(h.containerConfig.IdleBytesHighWatermark) {
				h.Trace().Msgf("App %s not idle, bytes sent %d, bytes received %d, total bytes %d at high watermark %d",
					h.app.Id, sent, recv, totalBytes, h.containerConfig.IdleBytesHighWatermark)
				continue
			}
			h.Info().Msgf("App %s idle, bytes sent %d, bytes received %d, total bytes %d below high watermark %d",
				h.app.Id, sent, recv, totalBytes, h.containerConfig.IdleBytesHighWatermark)
		}

		h.Debug().Msgf("Shutting down idle app %s after %d seconds", h.app.Id, idleTimeSecs)

		fullHash, err := h.getAppHash()
		if err != nil {
			h.Error().Err(err).Msgf("Error getting app hash for %s", h.app.Id)
			break
		}

		if h.app.notifyClose != nil {
			// Notify the server to close the app so that it gets reinitialized on next API call
			h.app.notifyClose <- h.app.AppPathDomain()
		}

		h.stateLock.Lock()
		h.currentState = ContainerStateIdleShutdown

		err = h.manager.StopContainer(ctx, container.GenContainerName(h.app.Id, h.manager, fullHash))
		if err != nil {
			h.Error().Err(err).Msgf("Error stopping idle app %s", h.app.Id)
		}
		h.stateLock.Unlock()
		break
	}

	h.Debug().Msgf("Idle checker stopped for app %s", h.app.Id)
}

func (h *ContainerHandler) healthChecker(ctx context.Context) {
	time.Sleep(60 * time.Second) // wait for 1 minute to let the app start up
	h.Debug().Msgf("Health checker started for app %s", h.app.Id)
	fullHash, err := h.getAppHash()
	if err != nil {
		h.Error().Err(err).Msgf("Error getting app hash for %s", h.app.Id)
		return
	}
	containerName := container.GenContainerName(h.app.Id, h.manager, fullHash)
	for range h.healthCheckTicker.C {
		err := h.WaitForHealth(h.containerConfig.StatusHealthAttempts, containerName)
		if err == nil {
			continue
		}
		h.Info().Msgf("Health check failed for app %s: %s", h.app.Id, err)

		if h.app.notifyClose != nil {
			// Notify the server to close the app so that it gets reinitialized on next API call
			h.app.notifyClose <- h.app.AppPathDomain()
		}

		h.stateLock.Lock()
		h.currentState = ContainerStateHealthFailure

		err = h.manager.StopContainer(ctx, container.GenContainerName(h.app.Id, h.manager, fullHash))
		if err != nil {
			h.Error().Err(err).Msgf("Error stopping app %s after health failure", h.app.Id)
		}
		h.stateLock.Unlock()
		break
	}

	h.Debug().Msgf("Health checker stopped for app %s", h.app.Id)
}

func extractVolumes(node *parser.Node) []string {
	ret := []string{}
	for node.Next != nil {
		node = node.Next
		ret = append(ret, types.StripQuotes(node.Value))
	}
	return ret
}

func (h *ContainerHandler) GetProxyUrl() string {
	return fmt.Sprintf("%s://%s", h.scheme, h.hostNamePort)
}

func (h *ContainerHandler) GetHealthUrl(appHealthUrl string) string {
	healthUrl := h.containerConfig.HealthUrl
	if appHealthUrl != "" && appHealthUrl != "/" {
		// Health check URL is specified in the app code, use that
		healthUrl = appHealthUrl
	}

	if healthUrl == "" {
		healthUrl = "/"
	} else if healthUrl[0] != '/' {
		healthUrl = "/" + healthUrl
	}
	return healthUrl
}

func getMapHash(input map[string]string) (string, error) {
	keys := []string{}
	for k := range input {
		keys = append(keys, k)
	}
	slices.Sort(keys) // Sort the keys to ensure consistent hash

	hashBuilder := strings.Builder{}
	for _, paramName := range keys {
		paramVal := input[paramName]
		// Default to string
		hashBuilder.WriteString(paramName)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(paramVal)
		hashBuilder.WriteByte(0)
	}

	sha := sha256.New()
	if _, err := sha.Write([]byte(hashBuilder.String())); err != nil {
		return "", err
	}
	return hex.EncodeToString(sha.Sum(nil)), nil
}

func getSliceHash(input []string) (string, error) {
	slices.Sort(input) // Sort the keys to ensure consistent hash

	hashBuilder := strings.Builder{}
	for _, v := range input {
		hashBuilder.WriteString(v)
		hashBuilder.WriteByte(0)
	}

	sha := sha256.New()
	if _, err := sha.Write([]byte(hashBuilder.String())); err != nil {
		return "", err
	}
	return hex.EncodeToString(sha.Sum(nil)), nil
}

func (h *ContainerHandler) GetEnvMap() (map[string]string, string) {
	paramKeys := []string{}
	for k := range h.paramMap {
		paramKeys = append(paramKeys, k)
	}
	slices.Sort(paramKeys) // Sort the keys to ensure consistent hash

	ret := map[string]string{}
	hashBuilder := strings.Builder{}
	for _, paramName := range paramKeys {
		paramVal := h.paramMap[paramName]
		// Default to string
		hashBuilder.WriteString(paramName)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(paramVal)
		hashBuilder.WriteByte(0)
		ret[paramName] = paramVal
	}

	// Add the app path to the return map and hash
	pathValue := h.app.Path
	if pathValue == "/" {
		pathValue = ""
	}
	hashBuilder.WriteString("CL_APP_PATH")
	hashBuilder.WriteByte(0)
	hashBuilder.WriteString(pathValue)
	hashBuilder.WriteByte(0)
	ret["CL_APP_PATH"] = pathValue

	// Add the port number to use into the env
	// Using PORT instead of CL_PORT since that seems to be the most common convention across apps
	hashBuilder.WriteString("PORT")
	hashBuilder.WriteByte(0)
	portStr := strconv.FormatInt(h.port, 10)
	hashBuilder.WriteString(portStr)
	hashBuilder.WriteByte(0)
	ret["PORT"] = portStr

	appUrl := types.GetAppUrl(h.app.AppPathDomain(), h.app.serverConfig)
	hashBuilder.WriteString("CL_APP_URL")
	hashBuilder.WriteByte(0)
	hashBuilder.WriteString(appUrl)
	hashBuilder.WriteByte(0)
	ret["CL_APP_URL"] = appUrl

	return ret, hashBuilder.String()
}

func (h *ContainerHandler) createSpecFiles() ([]string, error) {
	// Create the spec files if they are not already present
	created := []string{}
	for name, data := range *h.app.Metadata.SpecFiles {
		diskFile := path.Join(h.app.SourceUrl, name)
		_, err := os.Stat(diskFile)
		if err != nil {
			if err = os.WriteFile(diskFile, []byte(data), 0644); err != nil {
				return nil, fmt.Errorf("error writing spec file %s: %w", diskFile, err)
			}
			created = append(created, diskFile)
		}
	}

	return created, nil
}

func (h *ContainerHandler) createVolumes(ctx context.Context) error {
	for _, volInfo := range h.volumeInfo {
		if volInfo.VolumeName == "" {
			continue
		}
		dir := volInfo.VolumeName
		if dir == container.UNNAMED_VOLUME {
			// unnamed volume, use the path for generating the volume name
			dir = volInfo.TargetPath
		}

		genVolumeName := container.GenVolumeName(h.app.Id, dir)
		h.Info().Msgf("Applying volume %s for app %s dir %s", genVolumeName, h.app.Id, dir)
		if !h.manager.VolumeExists(ctx, genVolumeName) {
			err := h.manager.VolumeCreate(ctx, genVolumeName)
			if err != nil {
				return fmt.Errorf("error creating volume %s: %w", genVolumeName, err)
			}
		}
	}
	return nil
}

func parseBindPaths(vol string) (string, string, bool) {
	vol, readOnly := strings.CutSuffix(vol, ":ro")
	p1, p2, ok := strings.Cut(vol, ":")
	if ok {
		return p1, p2, readOnly
	}
	return "", p1, readOnly
}

// parseVolumeString parses the volume string. It returns four values
// 1. openrun prefix, if present
// 2. volume name, UNNAMED_VOLUME if unnamed, "" for bind
// 3. the rest of the volume string
// 4. error
func (h *ContainerHandler) parseVolumeString(vol string) (*container.VolumeInfo, error) {
	vol, hasSecretPrefix := strings.CutPrefix(vol, VOL_PREFIX_SECRET)
	if hasSecretPrefix {
		// Secret passed through bind mount
		src, dst, readOnly := parseBindPaths(vol)
		if src == "" || dst == "" {
			return nil, fmt.Errorf("expected bind mount (source:target) for cl_secret volume %s", vol)
		}
		return &container.VolumeInfo{
			IsSecret:   hasSecretPrefix,
			VolumeName: "",
			SourcePath: src,
			TargetPath: dst,
			ReadOnly:   readOnly,
		}, nil
	}

	src, dst, readOnly := parseBindPaths(vol)
	if strings.HasPrefix(src, "/") {
		// Bind mount
		return &container.VolumeInfo{
			VolumeName: "",
			SourcePath: src,
			TargetPath: dst,
			ReadOnly:   readOnly,
		}, nil
	}

	if src != "" {
		// Named volume
		return &container.VolumeInfo{
			VolumeName: src,
			SourcePath: "",
			TargetPath: dst,
			ReadOnly:   readOnly,
		}, nil

	} else {
		// Unnamed volume
		return &container.VolumeInfo{
			VolumeName: container.UNNAMED_VOLUME,
			SourcePath: "",
			TargetPath: dst,
			ReadOnly:   readOnly,
		}, nil
	}
}

func (h *ContainerHandler) DevReload(ctx context.Context, dryRun bool) error {
	devCM, ok := h.manager.(container.DevContainerManager)
	if !ok {
		return fmt.Errorf("container manager does not support dev operations")
	}

	if dryRun {
		// The image could be rebuild in case of a dry run, without touching the container.
		// But a temp image id will have to be used to avoid conflict with the existing image.
		// Dryrun is a no-op for now for containers
		return nil
	}

	if strings.HasPrefix(h.serverConfig.Builder.Mode, "delegate:") {
		return fmt.Errorf("delegated builds are not supported in dev mode")
	}
	if h.serverConfig.Registry.URL != "" {
		return fmt.Errorf("remote registry is not supported in dev mode")
	}

	h.GenImageName = container.ImageName(h.image)
	if h.GenImageName == "" {
		h.GenImageName = container.GenImageName(h.app.Id, "")
	}
	containerName := container.GenContainerName(h.app.Id, h.manager, "")

	_, running, err := devCM.GetContainerState(ctx, containerName)
	if err != nil {
		return fmt.Errorf("error checking container status: %w", err)
	}

	if running {
		err := h.manager.StopContainer(ctx, containerName)
		if err != nil {
			return fmt.Errorf("error stopping container: %w", err)
		}
	}

	if h.image == "" {
		// Using a container file, rebuild the image
		_ = devCM.RemoveImage(ctx, h.GenImageName)

		_, err := h.createSpecFiles()
		if err != nil {
			return err
		}
		buildDir := path.Join(h.app.SourceUrl, h.buildDir)
		err = h.manager.BuildImage(ctx, h.GenImageName, buildDir, h.containerFile, h.cargs)
		if err != nil {
			return err
		}
		// Don't remove the spec files, it is good if they are checked into the source repo
		// Makes the app independent of changes in the spec files
	}

	_ = devCM.RemoveContainer(ctx, containerName)

	if err = h.createVolumes(ctx); err != nil {
		// Create named volumes for the container
		return err
	}

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	if h.lifetime == types.CONTAINER_LIFETIME_COMMAND {
		// Command lifetime, service is not started, commands will be run with the image
		return nil
	}
	envMap, _ := h.GetEnvMap()
	err = devCM.RunContainer(ctx, h.app.AppEntry, h.app.SourceUrl, containerName,
		h.GenImageName, h.port, envMap, h.volumeInfo, h.app.Metadata.ContainerOptions, h.paramMap)
	if err != nil {
		return fmt.Errorf("error running container: %w", err)
	}

	hostNamePort, running, err := devCM.GetContainerState(ctx, containerName)
	if err != nil {
		return fmt.Errorf("error getting running containers: %w", err)
	}
	if hostNamePort == "" || !running {
		logs, _ := devCM.GetContainerLogs(ctx, containerName)
		return fmt.Errorf("container %s not running. Logs\n %s", containerName, logs)
	}
	h.currentState = ContainerStateRunning
	h.hostNamePort = hostNamePort

	if h.health != "" {
		err = h.WaitForHealth(h.containerConfig.HealthAttemptsAfterStartup, containerName)
		if err != nil {
			logs, _ := h.manager.GetContainerLogs(ctx, containerName)
			return fmt.Errorf("error waiting for health: %w. Logs\n %s", err, logs)
		}
	}

	return nil
}

func (h *ContainerHandler) WaitForHealth(attempts int, containerName container.ContainerName) error {
	client := &http.Client{
		Timeout: time.Duration(h.containerConfig.HealthTimeoutSecs) * time.Second,
	}

	var err error
	var resp *http.Response
	var hostNamePort string
	var running bool
	sleepMillis := 50
	for attempt := 1; attempt <= attempts; attempt++ {
		hostNamePort, running, err = h.manager.GetContainerState(context.Background(), containerName)
		if err != nil {
			return fmt.Errorf("error getting running containers: %w", err)
		}
		if running {
			h.currentState = ContainerStateRunning
			h.hostNamePort = hostNamePort
		} else {
			h.currentState = ContainerStateUnknown
			h.hostNamePort = ""
		}

		var proxyUrl *url.URL
		proxyUrl, err = url.Parse(h.GetProxyUrl())
		if err != nil || !running || proxyUrl.Host == "" {
			if err == nil {
				err = fmt.Errorf("could not find container proxy url")
			}
			sleepMillis *= 2
			sleepTimeMillis := math.Min(float64(sleepMillis), 5000)
			time.Sleep(time.Duration(sleepTimeMillis) * time.Millisecond)
			continue
		}
		if !h.stripAppPath {
			// Apps like Streamlit require the app path to be present
			proxyUrl = proxyUrl.JoinPath(h.app.Path)
		}

		proxyUrl = proxyUrl.JoinPath(h.health)
		resp, err = client.Get(proxyUrl.String())
		statusCode := "N/A"
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			statusCode = strconv.Itoa(resp.StatusCode)
		}

		if resp != nil {
			resp.Body.Close() //nolint:errcheck
		}

		h.Debug().Msgf("Attempt %d failed on %s : status %s err %s", attempt, proxyUrl, statusCode, err)
		sleepMillis *= 2
		sleepTimeMillis := math.Min(float64(sleepMillis), 5000)
		time.Sleep(time.Duration(sleepTimeMillis) * time.Millisecond)
	}

	h.Error().Msgf("Health check failed for app %s after %d attempts: %v", h.app.Id, attempts, err)
	return err
}

func (h *ContainerHandler) getAppHash() (string, error) {
	if h.app.IsDev {
		return "", nil
	}

	sourceHash, err := h.sourceFS.FileHash(h.excludeGlob)
	if err != nil {
		return "", fmt.Errorf("error getting file hash: %w", err)
	}

	_, envHash := h.GetEnvMap()

	coptHash, err := getMapHash(h.app.Metadata.ContainerOptions)
	if err != nil {
		return "", fmt.Errorf("error getting copt hash: %w", err)
	}
	cargHash, err := getMapHash(h.cargs)
	if err != nil {
		return "", fmt.Errorf("error getting carg hash: %w", err)
	}
	cvolHash, err := getSliceHash(h.app.Metadata.ContainerVolumes)
	if err != nil {
		return "", fmt.Errorf("error getting cvol hash: %w", err)
	}
	fullHashVal := fmt.Sprintf("%s-%s-%s-%s-%s", sourceHash, envHash, coptHash, cargHash, cvolHash)
	sha := sha256.New()
	if _, err := sha.Write([]byte(fullHashVal)); err != nil {
		return "", err
	}
	fullHash := hex.EncodeToString(sha.Sum(nil))
	h.Debug().Msgf("Source hash %s Env hash %s copt hash %s args hash %s cvol hash %s Full hash %s",
		sourceHash, envHash, coptHash, cargHash, cvolHash, fullHash)
	return fullHash, nil
}

func (h *ContainerHandler) ProdReload(ctx context.Context, dryRun bool) error {
	fullHash, err := h.getAppHash()
	if err != nil {
		return err
	}

	h.GenImageName = container.ImageName(h.image)
	if h.GenImageName == "" {
		h.GenImageName = container.GenImageName(h.app.Id, fullHash)
	}

	if dryRun {
		// The image could be rebuild in case of a dry run, without touching the container.
		// But a temp image id will have to be used to avoid conflict with the existing image.
		// Dryrun is a no-op for now for containers
		return nil
	}

	containerName := container.GenContainerName(h.app.Id, h.manager, fullHash)

	if h.lifetime != types.CONTAINER_LIFETIME_COMMAND {
		hostNamePort, running, err := h.manager.GetContainerState(ctx, containerName)
		if err != nil {
			return fmt.Errorf("error getting running containers: %w", err)
		}

		if hostNamePort != "" {
			// Container is present, make sure it is in the correct state
			h.stateLock.Lock()
			defer h.stateLock.Unlock()

			if !running {
				// This does not handle the case where volume list has changed
				h.Debug().Msgf("container not running, starting")
				err = h.manager.StartContainer(ctx, containerName)
				if err != nil {
					return fmt.Errorf("error starting container: %w", err)
				}

				if h.health != "" {
					err = h.WaitForHealth(h.containerConfig.HealthAttemptsAfterStartup, containerName)
					if err != nil {
						return fmt.Errorf("error waiting for health: %w", err)
					}
				}
			} else {
				// TODO handle case where image name is specified and param values change, need to restart container in that case
				h.hostNamePort = hostNamePort
				h.Debug().Msg("container already running")
			}

			h.currentState = ContainerStateRunning
			h.Debug().Msgf("updating port to %s", h.hostNamePort)
			return nil
		}
	}

	sourceDir := ""
	if h.image == "" {
		// Using a container file, build the image if required
		imageExists, err := h.manager.ImageExists(ctx, h.GenImageName)
		if err != nil {
			return fmt.Errorf("error getting images: %w", err)
		}

		if !imageExists {
			sourceDir, err = h.sourceFS.CreateTempSourceDir()
			if err != nil {
				return fmt.Errorf("error creating temp source dir: %w", err)
			}
			buildDir := path.Join(sourceDir, h.buildDir)
			buildErr := h.manager.BuildImage(ctx, h.GenImageName, buildDir, h.containerFile, h.cargs)

			if buildErr != nil {
				return fmt.Errorf("error building image: %w", buildErr)
			}
		}
	}

	if err = h.createVolumes(ctx); err != nil {
		// Create named volumes for the container
		return err
	}

	h.stateLock.Lock()
	defer h.stateLock.Unlock()
	// Start the container with newly built image

	if h.lifetime == types.CONTAINER_LIFETIME_COMMAND {
		// Command lifetime, service is not started, commands will be run with the image
		return nil
	}
	envMap, _ := h.GetEnvMap()
	err = h.manager.RunContainer(ctx, h.app.AppEntry, sourceDir, containerName,
		h.GenImageName, h.port, envMap, h.volumeInfo, h.app.Metadata.ContainerOptions, h.paramMap)
	if err != nil {
		return fmt.Errorf("error starting container after update: %w", err)
	}

	if sourceDir != "" {
		// Cleanup temp dir after image has been built and mount template file has been generated
		if err = os.RemoveAll(sourceDir); err != nil {
			return fmt.Errorf("error removing temp source dir: %w", err)
		}
	}

	if h.health != "" {
		err = h.WaitForHealth(h.containerConfig.HealthAttemptsAfterStartup, containerName)
		if err != nil {
			return fmt.Errorf("error waiting for health: %w", err)
		}
	}

	hostNamePort, running, err := h.manager.GetContainerState(ctx, containerName)
	if err != nil {
		return fmt.Errorf("error getting running containers: %w", err)
	}
	if hostNamePort == "" || !running {
		return fmt.Errorf("container not running") // todo add logs
	}
	h.currentState = ContainerStateRunning
	h.hostNamePort = hostNamePort

	return nil
}

func (h *ContainerHandler) Close() error {
	h.Debug().Msgf("Closing container handler for app %s", h.app.Id)
	if h.idleShutdownTicker != nil {
		h.idleShutdownTicker.Stop()
	}

	if h.healthCheckTicker != nil {
		h.healthCheckTicker.Stop()
	}
	return nil
}

func (h *ContainerHandler) Run(ctx context.Context, path string, cmdArgs []string, env []string) (*exec.Cmd, error) {
	args := []string{"run", "--rm"}
	envMap, _ := h.GetEnvMap()

	// Add env args
	for k, v := range envMap {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	// Add container related args
	for k, v := range h.app.Metadata.ContainerOptions {
		if v == "" {
			args = append(args, fmt.Sprintf("--%s", k))
		} else {
			args = append(args, fmt.Sprintf("--%s=%s", k, v))
		}
	}

	if len(h.mountArgs) > 0 {
		args = append(args, h.mountArgs...)
	}

	args = append(args, string(h.GenImageName), path)
	args = append(args, cmdArgs...)
	h.Debug().Msgf("Running command with args: %v", args)

	cmd := exec.CommandContext(ctx, h.serverConfig.System.ContainerCommand, args...)
	return cmd, nil
}
