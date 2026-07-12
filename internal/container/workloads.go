// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WorkloadPod is the status of one pod in the OpenRun apps namespace
type WorkloadPod struct {
	Name       string
	AppId      string
	AppPath    string
	AppVersion string
	Image      string
	Phase      string // Running / Pending / Succeeded / Failed
	Ready      bool
	Restarts   int
	StartedAt  string
	CreatedAt  string
	Node       string
	PodIP      string
	Mounts     []WorkloadMount
}

// WorkloadMount is a volume mount of a workload pod
type WorkloadMount struct {
	Name      string
	MountPath string
	ReadOnly  bool
}

func newWorkloadClient(config *types.ServerConfig) (kubernetes.Interface, string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, "", fmt.Errorf("error loading kubernetes config: %w", err)
	}
	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("error creating kubernetes client: %w", err)
	}
	namespace, err := currentNamespace()
	if err != nil {
		namespace = config.Kubernetes.Namespace
	}
	if namespace == "" {
		return nil, "", fmt.Errorf("kubernetes namespace not specified and not running in cluster")
	}
	return clientSet, namespace + "-apps", nil
}

func podToWorkload(pod *core.Pod) WorkloadPod {
	wl := WorkloadPod{
		Name:       pod.Name,
		AppId:      pod.Labels[LABEL_PREFIX+"app.id"],
		AppPath:    pod.Annotations[LABEL_PREFIX+"app.path"],
		AppVersion: pod.Labels[LABEL_PREFIX+"app.version"],
		Phase:      string(pod.Status.Phase),
		Ready:      isPodReady(pod),
		Node:       pod.Spec.NodeName,
		PodIP:      pod.Status.PodIP,
		CreatedAt:  pod.CreationTimestamp.Format(time.RFC3339),
	}
	if len(pod.Spec.Containers) > 0 {
		wl.Image = pod.Spec.Containers[0].Image
		for _, mount := range pod.Spec.Containers[0].VolumeMounts {
			wl.Mounts = append(wl.Mounts, WorkloadMount{
				Name:      mount.Name,
				MountPath: mount.MountPath,
				ReadOnly:  mount.ReadOnly,
			})
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		wl.Restarts += int(cs.RestartCount)
		if cs.State.Running != nil {
			wl.StartedAt = cs.State.Running.StartedAt.Format(time.RFC3339)
		}
	}
	return wl
}

// ListWorkloadPods lists the OpenRun managed pods in the apps namespace
func ListWorkloadPods(ctx context.Context, config *types.ServerConfig) ([]WorkloadPod, error) {
	return ListWorkloadPodsSelector(ctx, config, LABEL_PREFIX+"app.id")
}

// ListWorkloadPodsSelector lists namespace pods matching a label selector
// (e.g. app=kaniko for the image build pods)
func ListWorkloadPodsSelector(ctx context.Context, config *types.ServerConfig, selector string) ([]WorkloadPod, error) {
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	pods, err := client.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("error listing pods in %s: %w", namespace, err)
	}

	workloads := make([]WorkloadPod, 0, len(pods.Items))
	for i := range pods.Items {
		workloads = append(workloads, podToWorkload(&pods.Items[i]))
	}
	return workloads, nil
}

// NamespaceStats summarizes the pods of one OpenRun kubernetes namespace
type NamespaceStats struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"` // system / apps
	Pods      int    `json:"pods"`
	Running   int    `json:"running"`
	Pending   int    `json:"pending"`
	Failed    int    `json:"failed"`
	Succeeded int    `json:"succeeded"`
	Ready     int    `json:"ready"`
}

// GetNamespaceStats returns pod stats for the OpenRun system namespace and
// the apps namespace
func GetNamespaceStats(ctx context.Context, config *types.ServerConfig) ([]NamespaceStats, error) {
	client, appsNamespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	systemNamespace := strings.TrimSuffix(appsNamespace, "-apps")

	stats := make([]NamespaceStats, 0, 2)
	for _, entry := range []NamespaceStats{
		{Namespace: systemNamespace, Kind: "system"},
		{Namespace: appsNamespace, Kind: "apps"},
	} {
		pods, err := client.CoreV1().Pods(entry.Namespace).List(ctx, meta.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("error listing pods in %s: %w", entry.Namespace, err)
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			entry.Pods++
			switch pod.Status.Phase {
			case core.PodRunning:
				entry.Running++
			case core.PodPending:
				entry.Pending++
			case core.PodFailed:
				entry.Failed++
			case core.PodSucceeded:
				entry.Succeeded++
			}
			if isPodReady(pod) {
				entry.Ready++
			}
		}
		stats = append(stats, entry)
	}
	return stats, nil
}

// ClusterStats summarizes the cluster as visible to a regular in-cluster
// service account: the server version (open to any authenticated principal)
// and node counts/capacity (cluster scoped, best-effort since RBAC may deny)
type ClusterStats struct {
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	Nodes      int    `json:"nodes"`
	ReadyNodes int    `json:"ready_nodes"`
	CPU        string `json:"cpu"`         // total allocatable cpu cores
	Memory     string `json:"memory"`      // total allocatable memory
	NodesError string `json:"nodes_error"` // set when node access is denied
}

// GetClusterStats returns the cluster version and node summary
func GetClusterStats(ctx context.Context, config *types.ServerConfig) (*ClusterStats, error) {
	client, _, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}

	stats := &ClusterStats{}
	if version, err := client.Discovery().ServerVersion(); err == nil {
		stats.Version = version.GitVersion
		stats.Platform = version.Platform
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil {
		stats.NodesError = err.Error()
		return stats, nil
	}
	var cpuMilli, memoryBytes int64
	for i := range nodes.Items {
		node := &nodes.Items[i]
		stats.Nodes++
		for _, cond := range node.Status.Conditions {
			if cond.Type == core.NodeReady && cond.Status == core.ConditionTrue {
				stats.ReadyNodes++
				break
			}
		}
		if cpu, ok := node.Status.Allocatable[core.ResourceCPU]; ok {
			cpuMilli += cpu.MilliValue()
		}
		if memory, ok := node.Status.Allocatable[core.ResourceMemory]; ok {
			memoryBytes += memory.Value()
		}
	}
	stats.CPU = strconv.FormatFloat(float64(cpuMilli)/1000, 'f', -1, 64)
	stats.Memory = fmt.Sprintf("%.1f GiB", float64(memoryBytes)/(1024*1024*1024))
	return stats, nil
}

// WorkloadPodStatus is the kubernetes specific status of one managed pod:
// pod conditions, per-container states and recent events (the information
// kubectl describe surfaces)
type WorkloadPodStatus struct {
	Phase       string               `json:"phase"`
	Reason      string               `json:"reason"`
	Message     string               `json:"message"`
	Node        string               `json:"node"`
	Conditions  []PodCondition       `json:"conditions"`
	Containers  []PodContainerStatus `json:"containers"`
	Events      []PodEvent           `json:"events"`
	EventsError string               `json:"events_error"` // events are best-effort, RBAC may deny them
}

// PodCondition is one kubernetes pod condition
type PodCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// PodContainerStatus is the state of one container of a pod
type PodContainerStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"` // running / waiting / terminated
	Reason   string `json:"reason"`
	Message  string `json:"message"`
	Restarts int    `json:"restarts"`
	Ready    bool   `json:"ready"`
}

// PodEvent is one kubernetes event of a pod, newest first
type PodEvent struct {
	Type     string `json:"type"` // Normal / Warning
	Reason   string `json:"reason"`
	Message  string `json:"message"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen"`
}

// GetWorkloadPodStatus returns the kubernetes specific status of one OpenRun
// managed pod
func GetWorkloadPodStatus(ctx context.Context, config *types.ServerConfig, name string) (*WorkloadPodStatus, error) {
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	pod, err := client.CoreV1().Pods(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting pod %s: %w", name, err)
	}
	if pod.Labels[LABEL_PREFIX+"app.id"] == "" {
		return nil, fmt.Errorf("pod %s is not managed by OpenRun", name)
	}

	status := &WorkloadPodStatus{
		Phase:   string(pod.Status.Phase),
		Reason:  pod.Status.Reason,
		Message: pod.Status.Message,
		Node:    pod.Spec.NodeName,
	}
	for _, cond := range pod.Status.Conditions {
		status.Conditions = append(status.Conditions, PodCondition{
			Type:    string(cond.Type),
			Status:  string(cond.Status),
			Reason:  cond.Reason,
			Message: cond.Message,
		})
	}
	for _, cs := range pod.Status.ContainerStatuses {
		entry := PodContainerStatus{
			Name:     cs.Name,
			Restarts: int(cs.RestartCount),
			Ready:    cs.Ready,
		}
		switch {
		case cs.State.Running != nil:
			entry.State = "running"
		case cs.State.Waiting != nil:
			entry.State = "waiting"
			entry.Reason = cs.State.Waiting.Reason
			entry.Message = cs.State.Waiting.Message
		case cs.State.Terminated != nil:
			entry.State = "terminated"
			entry.Reason = cs.State.Terminated.Reason
			entry.Message = cs.State.Terminated.Message
		}
		status.Containers = append(status.Containers, entry)
	}

	// Events need list access on the namespace, which the service account may
	// not have; the rest of the status is still useful without them
	events, err := client.CoreV1().Events(namespace).List(ctx, meta.ListOptions{
		FieldSelector: "involvedObject.name=" + name + ",involvedObject.kind=Pod",
	})
	if err != nil {
		status.EventsError = err.Error()
		return status, nil
	}
	sort.Slice(events.Items, func(i, j int) bool {
		return events.Items[i].LastTimestamp.After(events.Items[j].LastTimestamp.Time)
	})
	const maxEvents = 15
	for i := range events.Items {
		if i >= maxEvents {
			break
		}
		event := &events.Items[i]
		status.Events = append(status.Events, PodEvent{
			Type:     event.Type,
			Reason:   event.Reason,
			Message:  event.Message,
			Count:    int(event.Count),
			LastSeen: event.LastTimestamp.Format(time.RFC3339),
		})
	}
	return status, nil
}

// GetWorkloadPod returns the status of one OpenRun managed pod
func GetWorkloadPod(ctx context.Context, config *types.ServerConfig, name string) (*WorkloadPod, error) {
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	pod, err := client.CoreV1().Pods(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting pod %s: %w", name, err)
	}
	if pod.Labels[LABEL_PREFIX+"app.id"] == "" {
		return nil, fmt.Errorf("pod %s is not managed by OpenRun", name)
	}
	wl := podToWorkload(pod)
	return &wl, nil
}

// GetWorkloadPodLogs returns the last tail lines of an OpenRun managed pod's logs
func GetWorkloadPodLogs(ctx context.Context, config *types.ServerConfig, name string, tail int) (string, error) {
	if _, err := GetWorkloadPod(ctx, config, name); err != nil {
		return "", err
	}
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return "", err
	}
	tailLines := int64(tail)
	data, err := client.CoreV1().Pods(namespace).
		GetLogs(name, &core.PodLogOptions{TailLines: &tailLines}).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting pod logs: %w", err)
	}
	return string(data), nil
}

// GetWorkloadPodLogsStream returns the logs of an OpenRun managed pod as a
// stream, optionally following new output. The caller closes the stream;
// canceling ctx also terminates it
func GetWorkloadPodLogsStream(ctx context.Context, config *types.ServerConfig, name string, tail int, follow bool) (io.ReadCloser, error) {
	if _, err := GetWorkloadPod(ctx, config, name); err != nil {
		return nil, err
	}
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	tailLines := int64(tail)
	stream, err := client.CoreV1().Pods(namespace).
		GetLogs(name, &core.PodLogOptions{TailLines: &tailLines, Follow: follow}).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("error streaming pod logs: %w", err)
	}
	return stream, nil
}
