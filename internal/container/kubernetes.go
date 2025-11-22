// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

type KubernetesContainerManager struct {
	*types.Logger
	config     *types.ServerConfig
	clientSet  *kubernetes.Clientset
	restConfig *rest.Config
}

func sanitizeContainerName(name string) string {
	name = sanitizeName(name)
	return name[:60] // max length for a Kubernetes object name is 63
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
	if k.config.Registry.URL == "" {
		return fmt.Errorf("registry url is required for kubernetes container manager")
	}

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

	if k.config.Builder.Mode == "command" || k.config.Builder.Mode == "podman" || k.config.Builder.Mode == "docker" || strings.HasPrefix(k.config.Builder.Mode, "/") {
		containerCommand := k.config.Builder.Mode
		if k.config.Builder.Mode == "command" {
			containerCommand = LookupContainerCommand(false)
			if containerCommand == "" {
				return fmt.Errorf("no container command found, install podman or docker")
			}
		}
		return buildImageCommand(ctx, k.Logger, k.config, imgName, sourceUrl, containerFile, containerArgs, containerCommand)
	}

	if k.config.Builder.Mode != "kaniko" && k.config.Builder.Mode != "auto" {
		return fmt.Errorf("invalid builder mode for kubernetes container manager: %s", k.config.Builder.Mode)
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
	name = ContainerName(sanitizeContainerName(string(name)))
	svc, err := k.clientSet.CoreV1().
		Services(k.config.Kubernetes.Namespace).
		Get(ctx, string(name), meta.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get service %s/%s: %w", k.config.Kubernetes.Namespace, string(name), err)
	}
	if len(svc.Spec.Ports) == 0 {
		return "", false, fmt.Errorf("service %s/%s has no ports", k.config.Kubernetes.Namespace, string(name))
	}

	svcPort := svc.Spec.Ports[0].Port
	hostNamePort := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, svcPort)

	// --- Get Deployment & ready pods ---
	dep, err := k.clientSet.AppsV1().
		Deployments(k.config.Kubernetes.Namespace).
		Get(ctx, string(name), meta.GetOptions{})
	if err != nil {
		return "", false, fmt.Errorf("get deployment %s/%s: %w", k.config.Kubernetes.Namespace, string(name), err)
	}

	return hostNamePort, dep.Status.ReadyReplicas > 0, nil
}

func (k *KubernetesContainerManager) StartContainer(ctx context.Context, name ContainerName) error {
	name = ContainerName(sanitizeContainerName(string(name)))
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		scale, err := k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).GetScale(ctx, string(name), meta.GetOptions{})
		if err != nil {
			return err
		}
		scale.Spec.Replicas = 1
		_, err = k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).UpdateScale(ctx, string(name), scale, meta.UpdateOptions{})
		return err
	})
}

func (k *KubernetesContainerManager) StopContainer(ctx context.Context, name ContainerName) error {
	name = ContainerName(sanitizeContainerName(string(name)))
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		scale, err := k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).GetScale(ctx, string(name), meta.GetOptions{})
		if err != nil {
			return err
		}
		scale.Spec.Replicas = 0 // scale down to zero
		_, err = k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).UpdateScale(ctx, string(name), scale, meta.UpdateOptions{})
		return err
	})
}

func (k *KubernetesContainerManager) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, volumes []*VolumeInfo,
	containerOptions map[string]string, paramMap map[string]string) error {
	imageName = ImageName(k.config.Registry.URL + "/" + string(imageName))
	containerName = ContainerName(sanitizeContainerName(string(containerName)))
	hostNamePort, err := k.createDeployment(ctx, string(containerName), string(imageName), int32(port), envMap)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	k.Logger.Info().Msgf("created app service %s with host name port %s", containerName, hostNamePort)
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

// createDeployment creates a Deployment + Service and returns the Service URL.
func (k *KubernetesContainerManager) createDeployment(ctx context.Context, name, image string, port int32, envMap map[string]string) (string, error) {
	labels := map[string]string{"app": name}
	replicas := int32(1) // min = max = 1

	// Convert envMap to Kubernetes EnvVar slice
	envVars := make([]core.EnvVar, 0, len(envMap))
	for key, value := range envMap {
		envVars = append(envVars, core.EnvVar{
			Name:  key,
			Value: value,
		})
	}

	dep := &apps.Deployment{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: k.config.Kubernetes.Namespace,
			Labels:    labels,
		},
		Spec: apps.DeploymentSpec{
			Replicas: &replicas,
			Selector: &meta.LabelSelector{
				MatchLabels: labels,
			},
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: labels,
				},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name:  name,
							Image: image,
							Ports: []core.ContainerPort{
								{
									ContainerPort: port,
									Protocol:      core.ProtocolTCP,
								},
							},
							Env: envVars,
						},
					},
				},
			},
		},
	}

	if _, err := k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).Create(ctx, dep, meta.CreateOptions{}); err != nil {
		return "", fmt.Errorf("create deployment: %w", err)
	}

	svc := &core.Service{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: k.config.Kubernetes.Namespace,
			Labels:    labels,
		},
		Spec: core.ServiceSpec{
			Type:     core.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []core.ServicePort{
				{
					Name:       "http",
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
					Protocol:   core.ProtocolTCP,
				},
			},
		},
	}

	svc, err := k.clientSet.CoreV1().Services(k.config.Kubernetes.Namespace).Create(ctx, svc, meta.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create service: %w", err)
	}

	if len(svc.Spec.Ports) == 0 {
		return "", fmt.Errorf("service has no ports")
	}

	// In-cluster DNS URL
	servicePort := svc.Spec.Ports[0].Port
	url := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, servicePort)

	return url, nil
}
