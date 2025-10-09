// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
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
	"github.com/openrundev/openrun/internal/app/container"
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

type ContainerManager struct {
	*types.Logger
	command         container.ContainerCommand
	app             *App
	systemConfig    *types.SystemConfig
	containerFile   string
	image           string              // image name as specified
	GenImageName    container.ImageName // generated image name
	port            int64               // Port number within the container
	hostPort        int                 // Port number on the host
	lifetime        string
	scheme          string
	health          string
	buildDir        string
	sourceFS        appfs.ReadableFS
	paramMap        map[string]string
	volumes         []string // Volumes to be mounted
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

func NewContainerManager(logger *types.Logger, app *App, containerFile string,
	systemConfig *types.SystemConfig, configPort int64, lifetime, scheme, health, buildDir string, sourceFS appfs.ReadableFS,
	paramMap map[string]string, containerConfig types.Container, stripAppPath bool,
	containerVolumes []string, secretsAllowed [][]string, cargs map[string]any) (*ContainerManager, error) {

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

	m := &ContainerManager{
		Logger:          logger,
		app:             app,
		containerFile:   containerFile,
		image:           image,
		systemConfig:    systemConfig,
		port:            configPort,
		lifetime:        lifetime,
		scheme:          scheme,
		buildDir:        buildDir,
		sourceFS:        sourceFS,
		command:         container.ContainerCommand{Logger: logger},
		paramMap:        paramMap,
		volumes:         volumes,
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
		go m.idleAppShutdown()
	}

	m.health = m.GetHealthUrl(health)
	if containerConfig.StatusCheckIntervalSecs > 0 && m.lifetime != types.CONTAINER_LIFETIME_COMMAND {
		// Start the health check goroutine
		m.healthCheckTicker = time.NewTicker(time.Duration(containerConfig.StatusCheckIntervalSecs) * time.Second)
		go m.healthChecker()
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

func (m *ContainerManager) idleAppShutdown() {
	for range m.idleShutdownTicker.C {
		idleTimeSecs := time.Now().Unix() - m.app.lastRequestTime.Load()
		if m.currentState != ContainerStateRunning || idleTimeSecs < int64(m.containerConfig.IdleShutdownSecs) {
			// Not idle
			m.Trace().Msgf("App %s not idle, last request %d seconds ago", m.app.Id, idleTimeSecs)
			continue
		}

		if m.proxyTracker != nil {
			sent, recv := m.proxyTracker.GetRollingTotals()
			totalBytes := sent + recv
			if totalBytes >= uint64(m.containerConfig.IdleBytesHighWatermark) {
				m.Trace().Msgf("App %s not idle, bytes sent %d, bytes received %d, total bytes %d at high watermark %d",
					m.app.Id, sent, recv, totalBytes, m.containerConfig.IdleBytesHighWatermark)
				continue
			}
			m.Info().Msgf("App %s idle, bytes sent %d, bytes received %d, total bytes %d below high watermark %d",
				m.app.Id, sent, recv, totalBytes, m.containerConfig.IdleBytesHighWatermark)
		}

		m.Debug().Msgf("Shutting down idle app %s after %d seconds", m.app.Id, idleTimeSecs)

		fullHash, err := m.getAppHash()
		if err != nil {
			m.Error().Err(err).Msgf("Error getting app hash for %s", m.app.Id)
			break
		}

		if m.app.notifyClose != nil {
			// Notify the server to close the app so that it gets reinitialized on next API call
			m.app.notifyClose <- m.app.AppPathDomain()
		}

		m.stateLock.Lock()
		m.currentState = ContainerStateIdleShutdown

		err = m.command.StopContainer(m.systemConfig, container.GenContainerName(m.app.Id, fullHash))
		if err != nil {
			m.Error().Err(err).Msgf("Error stopping idle app %s", m.app.Id)
		}
		m.stateLock.Unlock()
		break
	}

	m.Debug().Msgf("Idle checker stopped for app %s", m.app.Id)
}

func (m *ContainerManager) healthChecker() {
	for range m.healthCheckTicker.C {
		err := m.WaitForHealth(m.containerConfig.StatusHealthAttempts)
		if err == nil {
			continue
		}
		m.Info().Msgf("Health check failed for app %s: %s", m.app.Id, err)

		fullHash, err := m.getAppHash()
		if err != nil {
			m.Error().Err(err).Msgf("Error getting app hash for %s", m.app.Id)
			break
		}

		if m.app.notifyClose != nil {
			// Notify the server to close the app so that it gets reinitialized on next API call
			m.app.notifyClose <- m.app.AppPathDomain()
		}

		m.stateLock.Lock()
		m.currentState = ContainerStateHealthFailure

		err = m.command.StopContainer(m.systemConfig, container.GenContainerName(m.app.Id, fullHash))
		if err != nil {
			m.Error().Err(err).Msgf("Error stopping app %s after health failure", m.app.Id)
		}
		m.stateLock.Unlock()
		break
	}

	m.Debug().Msgf("Health checker stopped for app %s", m.app.Id)
}

func extractVolumes(node *parser.Node) []string {
	ret := []string{}
	for node.Next != nil {
		node = node.Next
		ret = append(ret, types.StripQuotes(node.Value))
	}
	return ret
}

func (m *ContainerManager) GetProxyUrl() string {
	return fmt.Sprintf("%s://127.0.0.1:%d", m.scheme, m.hostPort)
}

func (m *ContainerManager) GetHealthUrl(appHealthUrl string) string {
	healthUrl := m.containerConfig.HealthUrl
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

func (m *ContainerManager) GetEnvMap() (map[string]string, string) {
	paramKeys := []string{}
	for k := range m.paramMap {
		paramKeys = append(paramKeys, k)
	}
	slices.Sort(paramKeys) // Sort the keys to ensure consistent hash

	ret := map[string]string{}
	hashBuilder := strings.Builder{}
	for _, paramName := range paramKeys {
		paramVal := m.paramMap[paramName]
		// Default to string
		hashBuilder.WriteString(paramName)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(paramVal)
		hashBuilder.WriteByte(0)
		ret[paramName] = paramVal
	}

	// Add the app path to the return map and hash
	pathValue := m.app.Path
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
	portStr := strconv.FormatInt(m.port, 10)
	hashBuilder.WriteString(portStr)
	hashBuilder.WriteByte(0)
	ret["PORT"] = portStr

	appUrl := types.GetAppUrl(m.app.AppPathDomain(), m.app.serverConfig)
	hashBuilder.WriteString("CL_APP_URL")
	hashBuilder.WriteByte(0)
	hashBuilder.WriteString(appUrl)
	hashBuilder.WriteByte(0)
	ret["CL_APP_URL"] = appUrl

	return ret, hashBuilder.String()
}

func (m *ContainerManager) createSpecFiles() ([]string, error) {
	// Create the spec files if they are not already present
	created := []string{}
	for name, data := range *m.app.Metadata.SpecFiles {
		diskFile := path.Join(m.app.SourceUrl, name)
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

const UNNAMED_VOLUME = "<UNNAMED>"

func (m *ContainerManager) createVolumes() error {
	for _, vol := range m.volumes {
		_, volName, volStr, err := m.parseVolumeString(vol)
		if err != nil {
			return fmt.Errorf("error parsing volume %s: %w", vol, err)
		}
		if volName == "" {
			continue
		}
		dir := volName
		if volName == UNNAMED_VOLUME {
			// unnamed volume, use the path for generating the volume name
			dir = volStr
		}

		genVolumeName := container.GenVolumeName(m.app.Id, dir)
		m.Info().Msgf("Applying volume %s for app %s dir %s", genVolumeName, m.app.Id, dir)
		if !m.command.VolumeExists(m.systemConfig, genVolumeName) {
			err := m.command.VolumeCreate(m.systemConfig, genVolumeName)
			if err != nil {
				return fmt.Errorf("error creating volume %s: %w", genVolumeName, err)
			}
		}
	}
	return nil
}

func (m *ContainerManager) genMountArgs(sourceDir string) ([]string, error) {
	args := []string{}

	for _, vol := range m.volumes {
		clPrefix, volName, volStr, err := m.parseVolumeString(vol)
		if err != nil {
			return nil, fmt.Errorf("error parsing volume %s: %w", vol, err)
		}

		if clPrefix == VOL_PREFIX_SECRET {
			// For cl_secret:file.prop:/data/file.prop, pass file.prop through the template
			// processor, write output to file.prop.gen and then bind mount it as
			// /source_dir/file.prop.gen:/data/file.prop
			split := strings.Split(volStr, ":")
			if len(split) < 2 {
				return nil, fmt.Errorf("expected bind mount (source:target) for cl_secret volume %s", vol)
			}
			tmplFileName := split[0]
			srcFile := path.Join(sourceDir, tmplFileName)
			destFile := path.Join(m.app.AppRunPath, path.Base(tmplFileName)+".gen")
			data := map[string]any{"params": m.paramMap}
			if sourceDir != "" {
				err = m.renderTemplate(srcFile, destFile, data)
				if err != nil {
					return nil, fmt.Errorf("error rendering template %s: %w", srcFile, err)
				}
			}
			volStr = fmt.Sprintf("%s:%s", destFile, strings.Join(split[1:], ":"))
			m.Info().Msgf("Mounting secret %s for app %s src %s dest %s", volStr, m.app.Id, srcFile, destFile)
		}

		if volName == "" {
			// bind mount
			args = append(args, fmt.Sprintf("--volume=%s", volStr))
		} else {
			dir := volName
			if volName == UNNAMED_VOLUME {
				// unnamed volume, use the path for generating the volume name
				dir = volStr
			}

			genVolumeName := container.GenVolumeName(m.app.Id, dir)
			split := strings.Split(volStr, ":")
			var volCliStr string
			if len(split) > 1 {
				split[0] = string(genVolumeName)
				volCliStr = strings.Join(split, ":")
			} else {
				volCliStr = string(genVolumeName) + ":" + volStr
			}
			m.Info().Msgf("Mounting volume %s for app %s dir %s, mount arg %s", genVolumeName, m.app.Id, dir, volCliStr)
			args = append(args, fmt.Sprintf("--volume=%s", volCliStr))
		}
	}
	return args, nil
}

// renderTemplate reads the source template file, executes it with the given data,
// and writes the output to the target file.
func (m *ContainerManager) renderTemplate(srcFilename, targetFilename string, data map[string]any) error {
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

// parseVolumeString parses the volume string. It returns four values
// 1. openrun prefix, if present
// 2. volume name, UNNAMED_VOLUME if unnamed, "" for bind
// 3. the rest of the volume string
// 4. error
func (m *ContainerManager) parseVolumeString(vol string) (string, string, string, error) {
	if strings.HasPrefix(vol, VOL_PREFIX_SECRET) {
		split := strings.Split(vol[len(VOL_PREFIX_SECRET):], ":")
		if len(split) == 1 {
			return "", "", "", fmt.Errorf("expected bind mount (source:target) for cl_secret volume %s", vol)
		}
		return VOL_PREFIX_SECRET, "", vol[len(VOL_PREFIX_SECRET):], nil
	}

	split := strings.Split(vol, ":")
	firstPart := split[0]
	if len(split) > 1 && strings.HasPrefix(firstPart, "/") {
		return "", "", vol, nil // bind mount
	}

	if len(split) == 1 {
		return "", UNNAMED_VOLUME, vol, nil // unnamed volume
	}

	return "", firstPart, vol, nil // named volume
}

func (m *ContainerManager) DevReload(dryRun bool) error {
	m.GenImageName = container.ImageName(m.image)
	if m.GenImageName == "" {
		m.GenImageName = container.GenImageName(m.app.Id, "")
	}
	containerName := container.GenContainerName(m.app.Id, "")

	containers, err := m.command.GetContainers(m.systemConfig, containerName, false)
	if err != nil {
		return fmt.Errorf("error getting running containers: %w", err)
	}

	if dryRun {
		// The image could be rebuild in case of a dry run, without touching the container.
		// But a temp image id will have to be used to avoid conflict with the existing image.
		// Dryrun is a no-op for now for containers
		return nil
	}

	if len(containers) != 0 {
		err := m.command.StopContainer(m.systemConfig, containerName)
		if err != nil {
			return fmt.Errorf("error stopping container: %w", err)
		}
	}

	if m.image == "" {
		// Using a container file, rebuild the image
		_ = m.command.RemoveImage(m.systemConfig, m.GenImageName)

		_, err := m.createSpecFiles()
		if err != nil {
			return err
		}
		buildDir := path.Join(m.app.SourceUrl, m.buildDir)
		err = m.command.BuildImage(m.systemConfig, m.GenImageName, buildDir, m.containerFile, m.cargs)
		if err != nil {
			return err
		}
		// Don't remove the spec files, it is good if they are checked into the source repo
		// Makes the app independent of changes in the spec files
	}

	_ = m.command.RemoveContainer(m.systemConfig, containerName)

	if err = m.createVolumes(); err != nil {
		// Create named volumes for the container
		return err
	}

	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	m.mountArgs, err = m.genMountArgs(m.app.SourceUrl)
	if err != nil {
		return err
	}

	if m.lifetime == types.CONTAINER_LIFETIME_COMMAND {
		// Command lifetime, service is not started, commands will be run with the image
		return nil
	}
	envMap, _ := m.GetEnvMap()
	err = m.command.RunContainer(m.systemConfig, m.app.AppEntry, containerName,
		m.GenImageName, m.port, envMap, m.mountArgs, m.app.Metadata.ContainerOptions)
	if err != nil {
		return fmt.Errorf("error running container: %w", err)
	}

	containers, err = m.command.GetContainers(m.systemConfig, containerName, false)
	if err != nil {
		return fmt.Errorf("error getting running containers: %w", err)
	}
	if len(containers) == 0 {
		logs, _ := m.command.GetContainerLogs(m.systemConfig, containerName)
		return fmt.Errorf("container %s not running. Logs\n %s", containerName, logs)
	}
	m.currentState = ContainerStateRunning
	m.hostPort = containers[0].Port

	if m.health != "" {
		err = m.WaitForHealth(m.containerConfig.HealthAttemptsAfterStartup)
		if err != nil {
			logs, _ := m.command.GetContainerLogs(m.systemConfig, containerName)
			return fmt.Errorf("error waiting for health: %w. Logs\n %s", err, logs)
		}
	}

	return nil
}

func (m *ContainerManager) WaitForHealth(attempts int) error {
	client := &http.Client{
		Timeout: time.Duration(m.containerConfig.HealthTimeoutSecs) * time.Second,
	}

	var err error
	var resp *http.Response
	proxyUrl, err := url.Parse(m.GetProxyUrl())
	if err != nil {
		return err
	}
	if !m.stripAppPath {
		// Apps like Streamlit require the app path to be present
		proxyUrl = proxyUrl.JoinPath(m.app.Path)
	}

	proxyUrl = proxyUrl.JoinPath(m.health)
	if err != nil {
		return err
	}

	for attempt := 1; attempt <= attempts; attempt++ {
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

		m.Debug().Msgf("Attempt %d failed on %s : status %s err %s", attempt, proxyUrl, statusCode, err)
		time.Sleep(1 * time.Second)
	}
	return err
}

func (m *ContainerManager) getAppHash() (string, error) {
	if m.app.IsDev {
		return "", nil
	}

	sourceHash, err := m.sourceFS.FileHash(m.excludeGlob)
	if err != nil {
		return "", fmt.Errorf("error getting file hash: %w", err)
	}

	_, envHash := m.GetEnvMap()

	coptHash, err := getMapHash(m.app.Metadata.ContainerOptions)
	if err != nil {
		return "", fmt.Errorf("error getting copt hash: %w", err)
	}
	cargHash, err := getMapHash(m.cargs)
	if err != nil {
		return "", fmt.Errorf("error getting carg hash: %w", err)
	}
	cvolHash, err := getSliceHash(m.app.Metadata.ContainerVolumes)
	if err != nil {
		return "", fmt.Errorf("error getting cvol hash: %w", err)
	}
	fullHashVal := fmt.Sprintf("%s-%s-%s-%s-%s", sourceHash, envHash, coptHash, cargHash, cvolHash)
	sha := sha256.New()
	if _, err := sha.Write([]byte(fullHashVal)); err != nil {
		return "", err
	}
	fullHash := hex.EncodeToString(sha.Sum(nil))
	m.Debug().Msgf("Source hash %s Env hash %s copt hash %s args hash %s cvol hash %s Full hash %s",
		sourceHash, envHash, coptHash, cargHash, cvolHash, fullHash)
	return fullHash, nil
}

func (m *ContainerManager) ProdReload(dryRun bool) error {
	fullHash, err := m.getAppHash()
	if err != nil {
		return err
	}

	m.GenImageName = container.ImageName(m.image)
	if m.GenImageName == "" {
		m.GenImageName = container.GenImageName(m.app.Id, fullHash)
	}

	containerName := container.GenContainerName(m.app.Id, fullHash)

	if m.lifetime != types.CONTAINER_LIFETIME_COMMAND {
		containers, err := m.command.GetContainers(m.systemConfig, containerName, true)
		if err != nil {
			return fmt.Errorf("error getting running containers: %w", err)
		}

		if dryRun {
			// The image could be rebuild in case of a dry run, without touching the container.
			// But a temp image id will have to be used to avoid conflict with the existing image.
			// Dryrun is a no-op for now for containers
			return nil
		}

		if len(containers) != 0 {
			m.stateLock.Lock()
			defer m.stateLock.Unlock()

			if containers[0].State != "running" {
				// This does not handle the case where volume list has changed
				m.Debug().Msgf("container state %s, starting", containers[0].State)
				err = m.command.StartContainer(m.systemConfig, containerName)
				if err != nil {
					return fmt.Errorf("error starting container: %w", err)
				}

				// Fetch port number after starting the container
				containers, err = m.command.GetContainers(m.systemConfig, containerName, true)
				if err != nil {
					return fmt.Errorf("error getting running containers: %w", err)
				}
				m.hostPort = containers[0].Port

				if m.health != "" {
					err = m.WaitForHealth(m.containerConfig.HealthAttemptsAfterStartup)
					if err != nil {
						return fmt.Errorf("error waiting for health: %w", err)
					}
				}
			} else {
				// TODO handle case where image name is specified and param values change, need to restart container in that case
				m.hostPort = containers[0].Port
				m.Debug().Msg("container already running")
			}

			m.currentState = ContainerStateRunning
			m.Debug().Msgf("updating port to %d", m.hostPort)
			return nil
		}
	}

	sourceDir := ""
	if m.image == "" {
		// Using a container file, build the image if required
		images, err := m.command.GetImages(m.systemConfig, m.GenImageName)
		if err != nil {
			return fmt.Errorf("error getting images: %w", err)
		}

		if len(images) == 0 {
			sourceDir, err = m.sourceFS.CreateTempSourceDir()
			if err != nil {
				return fmt.Errorf("error creating temp source dir: %w", err)
			}
			buildDir := path.Join(sourceDir, m.buildDir)
			buildErr := m.command.BuildImage(m.systemConfig, m.GenImageName, buildDir, m.containerFile, m.cargs)

			if buildErr != nil {
				return fmt.Errorf("error building image: %w", buildErr)
			}
		}
	}

	if err = m.createVolumes(); err != nil {
		// Create named volumes for the container
		return err
	}

	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	// Start the container with newly built image

	m.mountArgs, err = m.genMountArgs(sourceDir)
	if err != nil {
		return err
	}
	if sourceDir != "" {
		// Cleanup temp dir after image has been built and mount template file has been generated
		if err = os.RemoveAll(sourceDir); err != nil {
			return fmt.Errorf("error removing temp source dir: %w", err)
		}
	}

	if m.lifetime == types.CONTAINER_LIFETIME_COMMAND {
		// Command lifetime, service is not started, commands will be run with the image
		return nil
	}
	envMap, _ := m.GetEnvMap()

	err = m.command.RunContainer(m.systemConfig, m.app.AppEntry, containerName,
		m.GenImageName, m.port, envMap, m.mountArgs, m.app.Metadata.ContainerOptions)
	if err != nil {
		return fmt.Errorf("error starting container: %w", err)
	}

	containers, err := m.command.GetContainers(m.systemConfig, containerName, false)
	if err != nil {
		return fmt.Errorf("error getting running containers: %w", err)
	}
	if len(containers) == 0 {
		return fmt.Errorf("container not running") // todo add logs
	}
	m.currentState = ContainerStateRunning
	m.hostPort = containers[0].Port

	if m.health != "" {
		err = m.WaitForHealth(m.containerConfig.HealthAttemptsAfterStartup)
		if err != nil {
			return fmt.Errorf("error waiting for health: %w", err)
		}
	}

	return nil
}

func (m *ContainerManager) Close() error {
	m.Debug().Msgf("Closing container manager for app %s", m.app.Id)
	if m.idleShutdownTicker != nil {
		m.idleShutdownTicker.Stop()
	}

	if m.healthCheckTicker != nil {
		m.healthCheckTicker.Stop()
	}
	return nil
}

func (m *ContainerManager) Run(ctx context.Context, path string, cmdArgs []string, env []string) (*exec.Cmd, error) {
	args := []string{"run", "--rm"}
	envMap, _ := m.GetEnvMap()

	// Add env args
	for k, v := range envMap {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	// Add container related args
	for k, v := range m.app.Metadata.ContainerOptions {
		if v == "" {
			args = append(args, fmt.Sprintf("--%s", k))
		} else {
			args = append(args, fmt.Sprintf("--%s=%s", k, v))
		}
	}

	if len(m.mountArgs) > 0 {
		args = append(args, m.mountArgs...)
	}

	args = append(args, string(m.GenImageName), path)
	args = append(args, cmdArgs...)
	m.Debug().Msgf("Running command with args: %v", args)

	cmd := exec.CommandContext(ctx, m.systemConfig.ContainerCommand, args...)
	return cmd, nil
}
