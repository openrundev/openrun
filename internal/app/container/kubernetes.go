// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesContainerManager struct {
	*types.Logger
	config             *types.ServerConfig
	registryConfigJson []byte
	clientSet          *kubernetes.Clientset
	restConfig         *rest.Config
}

func NewKubernetesContainerManager(logger *types.Logger, config *types.ServerConfig) (*KubernetesContainerManager, error) {
	registryConfigJson, err := GenerateDockerConfigJSON(&config.Registry)
	if err != nil {
		return nil, fmt.Errorf("error generating docker config json: %w", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %w", err)
	}

	return &KubernetesContainerManager{
		Logger:             logger,
		config:             config,
		registryConfigJson: registryConfigJson,
		restConfig:         cfg,
		clientSet:          clientSet,
	}, nil
}

var _ ContainerManager = KubernetesContainerManager{}

func loadConfig() (*rest.Config, error) {
	// Try in-cluster; fall back to default kubeconfig
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func (k KubernetesContainerManager) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	return ImageExists(ctx, k.Logger, string(name), &k.config.Registry, k.registryConfigJson)
}

func (k KubernetesContainerManager) BuildImage(ctx context.Context, name ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	var destination string

	if k.config.Registry.Project != "" {
		destination = k.config.Registry.URL + "/" + k.config.Registry.Project + "/" + string(name)
	} else {
		destination = k.config.Registry.URL + "/" + string(name)
	}

	appId, _, _ := strings.Cut(string(name), ":")
	kanikoBuild := KanikoBuild{
		Namespace:   k.config.Kubernetes.Namespace,
		JobName:     fmt.Sprintf("%s-builder-%d", appId, time.Now().Unix()),
		Image:       k.config.Kubernetes.KanikoImage,
		SourceDir:   sourceUrl,
		Dockerfile:  containerFile,
		Destination: destination,
		ExtraArgs:   []string{"--verbosity=debug"},
	}
	return KanikoJob(ctx, k.Logger, k.clientSet, k.restConfig, &k.config.Registry, k.registryConfigJson, kanikoBuild)
}

func (k KubernetesContainerManager) GetContainerState(ctx context.Context, name ContainerName) (string, bool, error) {
	return "", false, nil
}

func (k KubernetesContainerManager) SupportsInPlaceContainerUpdate() bool {
	return true
}

func (k KubernetesContainerManager) InPlaceContainerUpdate(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (k KubernetesContainerManager) StartContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (k KubernetesContainerManager) StopContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (k KubernetesContainerManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (k KubernetesContainerManager) GetContainerLogs(ctx context.Context, name ContainerName) (string, error) {
	return "", nil
}

func (k KubernetesContainerManager) VolumeExists(ctx context.Context, name VolumeName) bool {
	return false
}

func (k KubernetesContainerManager) VolumeCreate(ctx context.Context, name VolumeName) error {
	return nil
}
