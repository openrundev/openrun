// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

// ContainerInfo is the summary of a container managed by OpenRun
type ContainerInfo struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	AppId   string `json:"app_id"`
	AppPath string `json:"app_path"`
	Image   string `json:"image"`
	State   string `json:"state"`  // running / exited / ...
	Status  string `json:"status"` // human readable, "Up 2 hours"
	Ports   string `json:"ports"`
	Env     string `json:"env"`     // prod / stage / dev / preview
	Runtime string `json:"runtime"` // docker / podman / kubernetes
}

// ContainerMount is a mount point of a container
type ContainerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
}

// ContainerStats are the live resource stats of a container
type ContainerStats struct {
	CPUPercent string `json:"cpu_percent"`
	MemUsage   string `json:"mem_usage"`
	MemPercent string `json:"mem_percent"`
	NetIO      string `json:"net_io"`
	BlockIO    string `json:"block_io"`
	PIDs       string `json:"pids"`
}

// ContainerDetail is the full detail of a container managed by OpenRun
type ContainerDetail struct {
	ContainerInfo
	Command      string           `json:"command"`
	StartedAt    string           `json:"started_at"`
	CreatedAt    string           `json:"created_at"`
	RestartCount int              `json:"restart_count"`
	ExitCode     int              `json:"exit_code"`
	Health       string           `json:"health"`
	AppVersion   string           `json:"app_version"`
	SizeRw       int64            `json:"size_rw"`       // writable layer disk usage
	SizeRootFs   int64            `json:"size_root_fs"`  // total disk usage
	PortBindings []string         `json:"port_bindings"` // host->container port mappings
	Mounts       []ContainerMount `json:"mounts"`
	Stats        *ContainerStats  `json:"stats"`
}

// containerCmdTimeout bounds the one-shot container CLI calls (ps, inspect,
// logs, stats, start/stop). Without it a hung daemon (docker desktop VM not
// running) hangs the console request forever. The follow log stream is
// exempt: it is long-lived by design and ends on client disconnect
const containerCmdTimeout = 30 * time.Second

// runContainerCmd runs a one-shot container CLI command with a bounded
// timeout, returning the combined output
func runContainerCmd(ctx context.Context, runtime string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, containerCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, runtime, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("container command timed out, is the container daemon running?")
	}
	return out, err
}

const containerAppIdLabel = container.LABEL_PREFIX + "app.id"
const containerAppPathLabel = container.LABEL_PREFIX + "app.path"
const containerAppVersionLabel = container.LABEL_PREFIX + "app.version"

func (s *Server) containerRuntime() string {
	command := strings.TrimSpace(s.config.System.ContainerCommand)
	if command == "" || command == "auto" {
		command = container.LookupContainerCommand(true)
	}
	return command
}

// resolveContainerApps fills in the app path (with domain) and environment
// for containers based on their app id label. The app.path label loses the
// domain and points at the staging app for staged containers, so the id is
// mapped to the main app entry instead
func (s *Server) resolveContainerApps(infos []ContainerInfo) {
	appPaths := map[string]string{}
	if apps, err := s.FilterApps("all", true); err == nil {
		infoById := map[types.AppId]types.AppInfo{}
		for _, appInfo := range apps {
			infoById[appInfo.Id] = appInfo
		}
		for id, appInfo := range infoById {
			target := appInfo
			if appInfo.MainApp != "" {
				if mainInfo, ok := infoById[appInfo.MainApp]; ok {
					target = mainInfo
				}
			}
			appPaths[string(id)] = target.String()
		}
	}

	for i := range infos {
		if path, ok := appPaths[infos[i].AppId]; ok {
			infos[i].AppPath = path
		}
		switch {
		case strings.HasPrefix(infos[i].AppId, types.ID_PREFIX_APP_PROD):
			infos[i].Env = "prod"
		case strings.HasPrefix(infos[i].AppId, types.ID_PREFIX_APP_STAGE):
			infos[i].Env = "stage"
		case strings.HasPrefix(infos[i].AppId, types.ID_PREFIX_APP_DEV):
			infos[i].Env = "dev"
		case strings.HasPrefix(infos[i].AppId, types.ID_PREFIX_APP_PREVIEW):
			infos[i].Env = "preview"
		}
	}
}

// ListManagedContainers lists the containers managed by OpenRun. For docker or
// podman these are the containers carrying the OpenRun labels; for Kubernetes
// these are the pods in the OpenRun apps namespace
func (s *Server) ListManagedContainers(ctx context.Context) ([]ContainerInfo, error) {
	runtime := s.containerRuntime()
	if runtime == "" {
		return nil, fmt.Errorf("no container command is configured on the server")
	}
	if runtime == types.CONTAINER_KUBERNETES {
		infos, err := s.listKubernetesContainers(ctx)
		if err == nil {
			s.resolveContainerApps(infos)
		}
		return infos, err
	}

	out, err := runContainerCmd(ctx, runtime, "ps", "--all",
		"--filter", "label="+containerAppIdLabel, "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("error listing containers: %s : %s", out, err)
	}

	entries, err := parseJSONObjects(out)
	if err != nil {
		return nil, err
	}

	infos := make([]ContainerInfo, 0, len(entries))
	for _, entry := range entries {
		name := entryNames(entry)
		if strings.HasPrefix(name, "k8s_") {
			// kubelet managed pod containers (shared dockerd); these are
			// surfaced through the kubernetes runtime instead
			continue
		}
		labels := entryLabels(entry)
		infos = append(infos, ContainerInfo{
			Id:      entryString(entry, "ID", "Id"),
			Name:    name,
			AppId:   labels[containerAppIdLabel],
			AppPath: labels[containerAppPathLabel],
			Image:   entryString(entry, "Image"),
			State:   entryString(entry, "State"),
			Status:  entryString(entry, "Status"),
			Ports:   entryPorts(entry),
			Runtime: filepath.Base(runtime),
		})
	}
	s.resolveContainerApps(infos)
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].AppPath != infos[j].AppPath {
			return infos[i].AppPath < infos[j].AppPath
		}
		return infos[i].Name < infos[j].Name
	})
	return infos, nil
}

// GetManagedContainer returns the details of one OpenRun managed container.
// withStats also collects live resource stats and disk usage, which are slow
// (docker stats samples for about two seconds)
func (s *Server) GetManagedContainer(ctx context.Context, id string, withStats bool) (*ContainerDetail, error) {
	runtime := s.containerRuntime()
	if runtime == "" {
		return nil, fmt.Errorf("no container command is configured on the server")
	}
	if runtime == types.CONTAINER_KUBERNETES {
		detail, err := s.getKubernetesContainer(ctx, id)
		if err == nil {
			single := []ContainerInfo{detail.ContainerInfo}
			s.resolveContainerApps(single)
			detail.ContainerInfo = single[0]
		}
		return detail, err
	}

	inspectArgs := []string{"inspect", "--type", "container", id}
	if withStats {
		// Computing the writable layer size can be slow for large containers
		inspectArgs = []string{"inspect", "--size", "--type", "container", id}
	}
	out, err := runContainerCmd(ctx, runtime, inspectArgs...)
	if err != nil {
		return nil, fmt.Errorf("error inspecting container: %s : %s", out, err)
	}

	var inspected []map[string]any
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil, fmt.Errorf("error parsing inspect output: %w", err)
	}
	if len(inspected) != 1 {
		return nil, fmt.Errorf("container %s not found", id)
	}
	entry := inspected[0]

	config := entryMap(entry, "Config")
	labels := map[string]string{}
	for k, v := range entryMap(config, "Labels") {
		if vs, ok := v.(string); ok {
			labels[k] = vs
		}
	}
	if labels[containerAppIdLabel] == "" {
		return nil, fmt.Errorf("container %s is not managed by OpenRun", id)
	}

	state := entryMap(entry, "State")
	health := ""
	if h := entryMap(state, "Health"); h != nil {
		health = entryString(h, "Status")
	}

	command := strings.Join(entryStringSlice(config, "Entrypoint"), " ")
	cmd := strings.Join(entryStringSlice(config, "Cmd"), " ")
	if cmd != "" {
		command = strings.TrimSpace(command + " " + cmd)
	}

	detail := &ContainerDetail{
		ContainerInfo: ContainerInfo{
			Id:      entryString(entry, "Id", "ID"),
			Name:    strings.TrimPrefix(entryString(entry, "Name"), "/"),
			AppId:   labels[containerAppIdLabel],
			AppPath: labels[containerAppPathLabel],
			Image:   entryString(config, "Image"),
			State:   entryString(state, "Status"),
			Runtime: filepath.Base(runtime),
		},
		Command:      command,
		StartedAt:    entryString(state, "StartedAt"),
		CreatedAt:    entryString(entry, "Created"),
		RestartCount: int(entryFloat(entry, "RestartCount")),
		ExitCode:     int(entryFloat(state, "ExitCode")),
		Health:       health,
		AppVersion:   labels[containerAppVersionLabel],
		SizeRw:       int64(entryFloat(entry, "SizeRw")),
		SizeRootFs:   int64(entryFloat(entry, "SizeRootFs")),
	}

	// Network port bindings: NetworkSettings.Ports maps the container port
	// to the host addresses it is published on
	if netSettings := entryMap(entry, "NetworkSettings"); netSettings != nil {
		for containerPort, v := range entryMap(netSettings, "Ports") {
			hostBindings, ok := v.([]any)
			if !ok || len(hostBindings) == 0 {
				detail.PortBindings = append(detail.PortBindings, containerPort+" (not published)")
				continue
			}
			for _, hb := range hostBindings {
				binding, ok := hb.(map[string]any)
				if !ok {
					continue
				}
				hostIp := entryString(binding, "HostIp")
				if hostIp == "" {
					hostIp = "0.0.0.0"
				}
				detail.PortBindings = append(detail.PortBindings,
					fmt.Sprintf("%s:%s -> %s", hostIp, entryString(binding, "HostPort"), containerPort))
			}
		}
		sort.Strings(detail.PortBindings)
	}

	if mounts, ok := entry["Mounts"].([]any); ok {
		for _, m := range mounts {
			mount, ok := m.(map[string]any)
			if !ok {
				continue
			}
			source := entryString(mount, "Source")
			if source == "" {
				source = entryString(mount, "Name") // named volumes
			}
			detail.Mounts = append(detail.Mounts, ContainerMount{
				Type:        entryString(mount, "Type"),
				Source:      source,
				Destination: entryString(mount, "Destination"),
				ReadWrite:   entryBool(mount, "RW"),
			})
		}
	}

	single := []ContainerInfo{detail.ContainerInfo}
	s.resolveContainerApps(single)
	detail.ContainerInfo = single[0]

	if withStats && detail.State == "running" {
		detail.Stats = s.containerStats(ctx, runtime, id)
	}
	return detail, nil
}

// GetManagedContainerLogs returns the last tail lines of the container logs
func (s *Server) GetManagedContainerLogs(ctx context.Context, id string, tail int) (string, error) {
	runtime := s.containerRuntime()
	if runtime == "" {
		return "", fmt.Errorf("no container command is configured on the server")
	}
	if tail <= 0 {
		tail = 100
	}
	if runtime == types.CONTAINER_KUBERNETES {
		return s.getKubernetesContainerLogs(ctx, id, tail)
	}

	// Verify the container is OpenRun managed before exposing logs
	if _, err := s.GetManagedContainer(ctx, id, false); err != nil {
		return "", err
	}
	out, err := runContainerCmd(ctx, runtime, "logs", "--tail", fmt.Sprintf("%d", tail), id)
	if err != nil {
		return "", fmt.Errorf("error getting container logs: %s : %s", out, err)
	}
	return string(out), nil
}

// maxLogChunkBytes bounds the partial-line buffer of a log stream; a line
// longer than this is force-broken so memory stays bounded
const maxLogChunkBytes = 1024 * 1024

// GetManagedContainerLogsStream returns the last tail lines of the container
// logs as a stream of line chunks. With follow, the stream keeps delivering
// new output until ctx is canceled (client disconnect) or the container
// stops. Each yielded value is a plain string of one or more complete lines
// without the trailing newline (the stream writer adds one per value)
func (s *Server) GetManagedContainerLogsStream(ctx context.Context, id string, tail int, follow bool) (func(yield func(any, error) bool), error) {
	runtime := s.containerRuntime()
	if runtime == "" {
		return nil, fmt.Errorf("no container command is configured on the server")
	}
	if tail <= 0 {
		tail = 500
	}
	if runtime == types.CONTAINER_KUBERNETES {
		stream, err := container.GetWorkloadPodLogsStream(ctx, s.config, id, tail, follow)
		if err != nil {
			return nil, err
		}
		return streamLogLines(stream, nil), nil
	}

	// Verify the container is OpenRun managed before exposing logs
	if _, err := s.GetManagedContainer(ctx, id, false); err != nil {
		return nil, err
	}

	args := []string{"logs", "--tail", fmt.Sprintf("%d", tail)}
	if follow {
		args = append(args, "--follow")
	}
	args = append(args, id)
	cmd := exec.CommandContext(ctx, runtime, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// The runtime CLI emits the container's stderr stream on its own stderr;
	// share the stdout pipe so both are streamed
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	reap := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	return streamLogLines(stdout, reap), nil
}

// streamLogLines converts a log reader into a range func yielding chunks of
// complete lines as plain Go strings (not starlark values, so the stream
// writer sends them verbatim without quoting). One yield per read keeps the
// per-line overhead minimal for large tails while still flushing each line
// promptly in follow mode. cleanup runs when the stream ends or the consumer
// stops iterating
func streamLogLines(reader io.ReadCloser, cleanup func()) func(yield func(any, error) bool) {
	return func(yield func(any, error) bool) {
		defer func() {
			_ = reader.Close()
			if cleanup != nil {
				cleanup()
			}
		}()

		buf := make([]byte, 64*1024)
		partial := make([]byte, 0, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				data := buf[:n]
				if nl := bytes.LastIndexByte(data, '\n'); nl == -1 {
					partial = append(partial, data...)
					if len(partial) >= maxLogChunkBytes {
						// Force a break on newline-less output so the partial
						// buffer stays bounded
						if !yield(string(partial), nil) {
							return
						}
						partial = partial[:0]
					}
				} else {
					var out string
					if len(partial) > 0 {
						out = string(partial) + string(data[:nl])
						partial = partial[:0]
					} else {
						out = string(data[:nl])
					}
					partial = append(partial, data[nl+1:]...)
					if !yield(out, nil) {
						return
					}
				}
			}
			if err != nil {
				if len(partial) > 0 {
					if !yield(string(partial), nil) {
						return
					}
				}
				// Normal endings: EOF, the client went away (ctx cancel kills
				// the log command and closes the pipe). Anything else is
				// reported as a final line
				if err != io.EOF && !errors.Is(err, context.Canceled) && !errors.Is(err, os.ErrClosed) {
					yield(fmt.Sprintf("error reading logs: %s", err), nil)
				}
				return
			}
		}
	}
}

// StartManagedContainer starts a stopped OpenRun managed container
func (s *Server) StartManagedContainer(ctx context.Context, id string) error {
	return s.containerLifecycle(ctx, id, "start")
}

// StopManagedContainer stops a running OpenRun managed container
func (s *Server) StopManagedContainer(ctx context.Context, id string) error {
	return s.containerLifecycle(ctx, id, "stop")
}

func (s *Server) containerLifecycle(ctx context.Context, id, op string) error {
	runtime := s.containerRuntime()
	if runtime == "" {
		return fmt.Errorf("no container command is configured on the server")
	}
	if runtime == types.CONTAINER_KUBERNETES {
		return fmt.Errorf("use app reload to manage Kubernetes workloads")
	}
	// Verify the container is OpenRun managed
	if _, err := s.GetManagedContainer(ctx, id, false); err != nil {
		return err
	}
	if out, err := runContainerCmd(ctx, runtime, op, id); err != nil {
		return fmt.Errorf("error running container %s: %s : %s", op, out, err)
	}
	return nil
}

func (s *Server) containerStats(ctx context.Context, runtime, id string) *ContainerStats {
	out, err := runContainerCmd(ctx, runtime, "stats", "--no-stream", "--format", "json", id)
	if err != nil {
		s.Warn().Msgf("error getting container stats: %s : %s", out, err)
		return nil
	}
	entries, err := parseJSONObjects(out)
	if err != nil || len(entries) == 0 {
		return nil
	}
	entry := entries[0]
	return &ContainerStats{
		CPUPercent: entryString(entry, "CPUPerc", "cpu_percent", "CPU"),
		MemUsage:   entryString(entry, "MemUsage", "mem_usage", "MemUsageBytes"),
		MemPercent: entryString(entry, "MemPerc", "mem_percent"),
		NetIO:      entryString(entry, "NetIO", "net_io"),
		BlockIO:    entryString(entry, "BlockIO", "block_io"),
		PIDs:       entryString(entry, "PIDs", "pids"),
	}
}

func (s *Server) listKubernetesContainers(ctx context.Context) ([]ContainerInfo, error) {
	pods, err := container.ListWorkloadPods(ctx, s.config)
	if err != nil {
		return nil, err
	}
	infos := make([]ContainerInfo, 0, len(pods))
	for _, pod := range pods {
		infos = append(infos, kubernetesPodInfo(&pod))
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].AppPath != infos[j].AppPath {
			return infos[i].AppPath < infos[j].AppPath
		}
		return infos[i].Name < infos[j].Name
	})
	return infos, nil
}

func kubernetesPodInfo(pod *container.WorkloadPod) ContainerInfo {
	state := strings.ToLower(pod.Phase)
	status := pod.Phase
	if pod.Phase == "Running" {
		if pod.Ready {
			status = "Running (ready)"
		} else {
			status = "Running (not ready)"
		}
	}
	return ContainerInfo{
		Id:      pod.Name,
		Name:    pod.Name,
		AppId:   pod.AppId,
		AppPath: pod.AppPath,
		Image:   pod.Image,
		State:   state,
		Status:  status,
		Ports:   pod.PodIP,
		Runtime: types.CONTAINER_KUBERNETES,
	}
}

func (s *Server) getKubernetesContainer(ctx context.Context, id string) (*ContainerDetail, error) {
	pod, err := container.GetWorkloadPod(ctx, s.config, id)
	if err != nil {
		return nil, err
	}
	detail := &ContainerDetail{
		ContainerInfo: kubernetesPodInfo(pod),
		StartedAt:     pod.StartedAt,
		CreatedAt:     pod.CreatedAt,
		RestartCount:  pod.Restarts,
		AppVersion:    pod.AppVersion,
	}
	if pod.Ready {
		detail.Health = "ready"
	}
	for _, mount := range pod.Mounts {
		detail.Mounts = append(detail.Mounts, ContainerMount{
			Type:        "volume",
			Source:      mount.Name,
			Destination: mount.MountPath,
			ReadWrite:   !mount.ReadOnly,
		})
	}
	return detail, nil
}

func (s *Server) getKubernetesContainerLogs(ctx context.Context, id string, tail int) (string, error) {
	return container.GetWorkloadPodLogs(ctx, s.config, id, tail)
}

// parseJSONObjects handles both docker (newline separated JSON objects) and
// podman (JSON array) CLI output formats
func parseJSONObjects(out []byte) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var entries []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return nil, fmt.Errorf("error parsing container output: %w", err)
		}
		return entries, nil
	}
	entries := make([]map[string]any, 0)
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("error parsing container output line: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func entryString(entry map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := entry[key]; ok {
			if vs, ok := v.(string); ok {
				return vs
			}
		}
	}
	return ""
}

func entryFloat(entry map[string]any, key string) float64 {
	if v, ok := entry[key]; ok {
		if vf, ok := v.(float64); ok {
			return vf
		}
	}
	return 0
}

func entryBool(entry map[string]any, key string) bool {
	if v, ok := entry[key]; ok {
		if vb, ok := v.(bool); ok {
			return vb
		}
	}
	return false
}

func entryMap(entry map[string]any, key string) map[string]any {
	if v, ok := entry[key]; ok {
		if vm, ok := v.(map[string]any); ok {
			return vm
		}
	}
	return nil
}

func entryStringSlice(entry map[string]any, key string) []string {
	values := []string{}
	if v, ok := entry[key]; ok {
		if list, ok := v.([]any); ok {
			for _, item := range list {
				if s, ok := item.(string); ok {
					values = append(values, s)
				}
			}
		}
	}
	return values
}

// entryLabels handles docker ("k=v,k=v" string) and podman (map) label formats
func entryLabels(entry map[string]any) map[string]string {
	labels := map[string]string{}
	v, ok := entry["Labels"]
	if !ok {
		return labels
	}
	switch lv := v.(type) {
	case string:
		for _, pair := range strings.Split(lv, ",") {
			if k, val, found := strings.Cut(pair, "="); found {
				labels[k] = val
			}
		}
	case map[string]any:
		for k, val := range lv {
			if vs, ok := val.(string); ok {
				labels[k] = vs
			}
		}
	}
	return labels
}

// entryNames handles docker (string) and podman ([]string) name formats
func entryNames(entry map[string]any) string {
	switch nv := entry["Names"].(type) {
	case string:
		return nv
	case []any:
		names := []string{}
		for _, n := range nv {
			if s, ok := n.(string); ok {
				names = append(names, s)
			}
		}
		return strings.Join(names, ", ")
	}
	return ""
}

// entryPorts handles docker (string) and podman (list) port formats
func entryPorts(entry map[string]any) string {
	switch pv := entry["Ports"].(type) {
	case string:
		return pv
	case []any:
		ports := []string{}
		for _, p := range pv {
			if pm, ok := p.(map[string]any); ok {
				host := entryFloat(pm, "host_port")
				cont := entryFloat(pm, "container_port")
				if host > 0 {
					ports = append(ports, fmt.Sprintf("%d->%d", int(host), int(cont)))
				}
			}
		}
		return strings.Join(ports, ", ")
	}
	return ""
}
