// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"io"
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
	client, namespace, err := newWorkloadClient(config)
	if err != nil {
		return nil, err
	}
	pods, err := client.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{
		LabelSelector: LABEL_PREFIX + "app.id",
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
