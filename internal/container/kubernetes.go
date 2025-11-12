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
	config     *types.ServerConfig
	clientSet  *kubernetes.Clientset
	restConfig *rest.Config
}

func NewKubernetesContainerManager(logger *types.Logger, config *types.ServerConfig) (*KubernetesContainerManager, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %w", err)
	}

	return &KubernetesContainerManager{
		Logger:     logger,
		config:     config,
		restConfig: cfg,
		clientSet:  clientSet,
	}, nil
}

var _ ContainerManager = (*KubernetesContainerManager)(nil)

func loadConfig() (*rest.Config, error) {
	// Try in-cluster; fall back to default kubeconfig
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func (k *KubernetesContainerManager) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	if k.config.Registry.URL == "" {
		return false, fmt.Errorf("registry url is required for kubernetes container manager")
	}
	return ImageExists(ctx, k.Logger, string(name), &k.config.Registry)
}

func (k *KubernetesContainerManager) BuildImage(ctx context.Context, imgName ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	targetUrl, found := strings.CutPrefix(k.config.Builder.Mode, "delegate:")
	if found {
		// delegated build
		err := sendDelegateBuild(targetUrl, DelegateRequest{
			ImageTag:       string(imgName),
			ContainerFile:  containerFile,
			ContainerArgs:  containerArgs,
			RegistryConfig: &k.config.Registry,
		}, sourceUrl)
		if err != nil {
			return fmt.Errorf("error sending delegate build: %w", err)
		}
		return nil
	}

	if k.config.Builder.Mode != "kaniko" && k.config.Builder.Mode != "auto" {
		return fmt.Errorf("invalid builder mode for kubernetes container manager: %s", k.config.Builder.Mode)
	}
	if k.config.Registry.URL == "" {
		return fmt.Errorf("registry url is required for kubernetes container manager")
	}

	var destination string
	if k.config.Registry.Project != "" {
		destination = k.config.Registry.URL + "/" + k.config.Registry.Project + "/" + string(imgName)
	} else {
		destination = k.config.Registry.URL + "/" + string(imgName)
	}

	// Generate Docker config JSON only for Kaniko (which needs it as a Kubernetes secret)
	dockerCfgJSON, err := GenerateDockerConfigJSON(&k.config.Registry)
	if err != nil {
		return fmt.Errorf("error generating docker config json: %w", err)
	}

	appId, _, _ := strings.Cut(string(imgName), ":")
	kanikoBuild := KanikoBuild{
		Namespace:   k.config.Kubernetes.Namespace,
		JobName:     fmt.Sprintf("%s-builder-%d", appId, time.Now().Unix()),
		Image:       k.config.Builder.KanikoImage,
		SourceDir:   sourceUrl,
		Dockerfile:  containerFile,
		Destination: destination,
		ExtraArgs:   []string{"--verbosity=debug"},
	}
	return KanikoJob(ctx, k.Logger, k.clientSet, k.restConfig, &k.config.Registry, dockerCfgJSON, kanikoBuild)
}

func (k *KubernetesContainerManager) GetContainerState(ctx context.Context, name ContainerName) (string, bool, error) {
	return "", false, nil
}

func (k *KubernetesContainerManager) SupportsInPlaceContainerUpdate() bool {
	return true
}

func (k *KubernetesContainerManager) InPlaceContainerUpdate(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (k *KubernetesContainerManager) StartContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (k *KubernetesContainerManager) StopContainer(ctx context.Context, name ContainerName) error {
	return nil
}

func (k *KubernetesContainerManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, mountArgs []string,
	containerOptions map[string]string) error {
	return nil
}

func (k *KubernetesContainerManager) GetContainerLogs(ctx context.Context, name ContainerName) (string, error) {
	return "", nil
}

func (k *KubernetesContainerManager) VolumeExists(ctx context.Context, name VolumeName) bool {
	return false
}

func (k *KubernetesContainerManager) VolumeCreate(ctx context.Context, name VolumeName) error {
	return nil
}
