// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1apply "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	OPENRUN_FIELD_MANAGER = "openrun"
)

type KubernetesCM struct {
	*types.Logger
	config     *types.ServerConfig
	clientSet  *kubernetes.Clientset
	restConfig *rest.Config
	appConfig  *types.AppConfig
	appRunDir  string
	appId      types.AppId
}

func sanitizeContainerName(name string) string {
	name = sanitizeName(name)
	if len(name) > 50 {
		name = name[:50] // max length for a Kubernetes object name is 63, leave space for the suffix
	}
	return name
}

// TrimLabelValue trims the input string to 63 characters so that it can be used as a Kubernetes label value
func TrimLabelValue(input string) string {
	if len(input) > 63 {
		input = input[:63]
	}
	return input
}

// isPodReady checks if a pod is both running and has the Ready condition set to True.
// This is important because Kubernetes Services only route traffic to Ready pods.
func isPodReady(pod *core.Pod) bool {
	if pod.Status.Phase != core.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
			return true
		}
	}
	return false
}

func NewKubernetesCM(logger *types.Logger, config *types.ServerConfig, appConfig *types.AppConfig, appRunDir string, appId types.AppId) (*KubernetesCM, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %w", err)
	}

	return &KubernetesCM{
		Logger:     logger,
		config:     config,
		restConfig: cfg,
		clientSet:  clientSet,
		appConfig:  appConfig,
		appRunDir:  appRunDir,
		appId:      appId,
	}, nil
}

var _ ContainerManager = (*KubernetesCM)(nil)

func loadConfig() (*rest.Config, error) {
	// Try in-cluster; fall back to default kubeconfig
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func (k *KubernetesCM) SupportsInPlaceUpdate() bool {
	return true
}

func (k *KubernetesCM) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	if k.config.Registry.URL == "" {
		return false, fmt.Errorf("registry url is required for kubernetes container manager")
	}
	return ImageExists(ctx, k.Logger, string(name), &k.config.Registry)
}

func (k *KubernetesCM) BuildImage(ctx context.Context, imgName ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
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
		Namespace:     k.config.Kubernetes.Namespace,
		JobName:       fmt.Sprintf("%s-builder-%d", appId, time.Now().Unix()),
		Image:         k.config.Builder.KanikoImage,
		SourceDir:     sourceUrl,
		Dockerfile:    containerFile,
		Destination:   destination,
		ContainerArgs: containerArgs,
		ExtraArgs:     []string{"--verbosity=debug"},
	}
	return KanikoJob(ctx, k.Logger, k.clientSet, k.restConfig, &k.config.Registry, dockerCfgJSON, kanikoBuild)
}

func (k *KubernetesCM) GetContainerState(ctx context.Context, name ContainerName, expectHash string) (string, bool, error) {
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
	if k.config.Kubernetes.UseNodePort {
		hostNamePort = fmt.Sprintf("127.0.0.1:%d", svc.Spec.Ports[0].NodePort)
	}

	dep, err := k.clientSet.AppsV1().
		Deployments(k.config.Kubernetes.Namespace).
		Get(ctx, string(name), meta.GetOptions{})
	if err != nil {
		return "", false, fmt.Errorf("get deployment %s/%s: %w", k.config.Kubernetes.Namespace, string(name), err)
	}

	if expectHash != "" && dep.Spec.Template.Labels[VERSION_HASH_LABEL] != TrimLabelValue(expectHash) {
		// version hash mismatch, deployment is not in the correct state
		k.Logger.Warn().Msgf("deployment version hash mismatch: expected %s, got %s", TrimLabelValue(expectHash), dep.Spec.Template.Labels[VERSION_HASH_LABEL])
		return "", false, nil
	}

	updateCompleted := false
	if k.appConfig.Kubernetes.StrictVersionCheck {
		if dep.Spec.Replicas != nil {
			desired := *dep.Spec.Replicas
			updateCompleted = dep.Status.ObservedGeneration == dep.Generation &&
				dep.Status.UpdatedReplicas == desired &&
				dep.Status.ReadyReplicas == desired &&
				dep.Status.UnavailableReplicas == 0 &&
				dep.Status.Replicas == *dep.Spec.Replicas
		}
	} else {
		updateCompleted = true
	}

	// Get the pods which are part of this deployment
	pods, err := k.clientSet.CoreV1().Pods(k.config.Kubernetes.Namespace).List(ctx, meta.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", string(name)),
	})
	if err != nil {
		return "", false, fmt.Errorf("list pods for deployment %s/%s: %w", k.config.Kubernetes.Namespace, string(name), err)
	}

	runningCount := 0
	for _, pod := range pods.Items {
		if isPodReady(&pod) && (expectHash == "" || pod.Labels[VERSION_HASH_LABEL] == TrimLabelValue(expectHash)) {
			runningCount++
		}
	}

	k.Logger.Debug().Msgf("GetContainerState hostNamePort %s runningCount %d updateCompleted %t", hostNamePort, runningCount, updateCompleted)
	return hostNamePort, updateCompleted && runningCount > 0, nil
}

func (k *KubernetesCM) StartContainer(ctx context.Context, name ContainerName) error {
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

func (k *KubernetesCM) StopContainer(ctx context.Context, name ContainerName) error {
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

func (k *KubernetesCM) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
	imageName ImageName, port int64, envMap map[string]string, volumes []*VolumeInfo,
	containerOptions map[string]string, paramMap map[string]string, versionHash string) error {
	if strings.HasPrefix(string(imageName), IMAGE_NAME_PREFIX) {
		imageName = ImageName(k.config.Registry.URL + "/" + string(imageName))
	}
	containerName = ContainerName(sanitizeContainerName(string(containerName)))
	hostNamePort, err := k.createDeployment(ctx, string(containerName), string(imageName), int32(port), envMap, volumes, sourceDir, paramMap, appEntry, versionHash)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	k.Logger.Info().Msgf("created app service %s with host name port %s", containerName, hostNamePort)
	return nil
}

func (k *KubernetesCM) GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error) {
	name = ContainerName(sanitizeContainerName(string(name)))

	// List pods with the matching label
	pods, err := k.clientSet.CoreV1().Pods(k.config.Kubernetes.Namespace).List(ctx, meta.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", string(name)),
	})
	if err != nil {
		return "", fmt.Errorf("list pods for %s: %w", name, err)
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for %s", name)
	}

	// Get the first pod
	pod := pods.Items[0]
	if len(pod.Spec.Containers) == 0 {
		return "", fmt.Errorf("no containers found in pod %s", pod.Name)
	}

	// Get logs from the first container
	containerName := pod.Spec.Containers[0].Name
	tailLines := int64(linesToShow)
	logOptions := &core.PodLogOptions{
		Container: containerName,
		TailLines: &tailLines,
	}

	req := k.clientSet.CoreV1().Pods(k.config.Kubernetes.Namespace).GetLogs(pod.Name, logOptions)
	logStream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("get logs for pod %s container %s: %w", pod.Name, containerName, err)
	}
	defer logStream.Close() //nolint:errcheck

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, logStream); err != nil {
		return "", fmt.Errorf("read logs for pod %s container %s: %w", pod.Name, containerName, err)
	}

	return buf.String(), nil
}

func (k *KubernetesCM) VolumeExists(ctx context.Context, name VolumeName) bool {
	pvcName := sanitizeContainerName(string(name))
	_, err := k.clientSet.CoreV1().
		PersistentVolumeClaims(k.config.Kubernetes.Namespace).
		Get(ctx, pvcName, meta.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false
		}
		k.Logger.Warn().Err(err).Msgf("error checking if PVC %s exists", pvcName)
		return false
	}
	return true
}

func (k *KubernetesCM) VolumeCreate(ctx context.Context, name VolumeName) error {
	size, err := resource.ParseQuantity(k.appConfig.Kubernetes.DefaultVolumeSize)
	if err != nil {
		return fmt.Errorf("error parsing default volume size %s: %w", k.appConfig.Kubernetes.DefaultVolumeSize, err)
	}
	pvcName := sanitizeContainerName(string(name))
	pvc := corev1apply.PersistentVolumeClaim(pvcName, k.config.Kubernetes.Namespace).
		WithSpec(corev1apply.PersistentVolumeClaimSpec().
			WithAccessModes(core.ReadWriteOnce). // TODO: support other access modes
			WithResources(corev1apply.VolumeResourceRequirements().
				WithRequests(core.ResourceList{
					core.ResourceStorage: size,
				})))

	_, err = k.clientSet.CoreV1().
		PersistentVolumeClaims(k.config.Kubernetes.Namespace).
		Apply(ctx, pvc, meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER})
	if err != nil {
		return fmt.Errorf("apply PersistentVolumeClaim %s: %w", pvcName, err)
	}
	return nil
}

// processVolumes converts VolumeInfo entries to Kubernetes Volume and VolumeMount configurations.
// It creates Secrets for secret volumes, ConfigMaps for volumes without a VolumeName, and
// references existing PVCs for named volumes.
func (k *KubernetesCM) processVolumes(ctx context.Context, name string, volumes []*VolumeInfo, sourceDir string, paramMap map[string]string) (
	[]*corev1apply.VolumeApplyConfiguration, []*corev1apply.VolumeMountApplyConfiguration, error) {

	var podVolumes []*corev1apply.VolumeApplyConfiguration
	var volumeMounts []*corev1apply.VolumeMountApplyConfiguration
	volIndex := 0

	for _, vol := range volumes {
		if vol.IsSecret {
			// Create a Secret from the source file and mount it
			secretName := fmt.Sprintf("%s-secret-%d", name, volIndex)
			volIndex++

			srcFile := makeAbsolute(sourceDir, vol.SourcePath)
			destFile := path.Join(k.appRunDir, path.Base(vol.SourcePath)+".gen")
			data := map[string]any{"params": paramMap}
			if sourceDir != "" {
				err := renderTemplate(srcFile, destFile, data)
				if err != nil {
					return nil, nil, fmt.Errorf("error rendering template %s: %w", srcFile, err)
				}
			}

			secretData, err := os.ReadFile(destFile)
			if err != nil {
				return nil, nil, fmt.Errorf("read secret gen file %s: %w", destFile, err)
			}

			fileName := filepath.Base(vol.TargetPath)
			secretApply := corev1apply.Secret(secretName, k.config.Kubernetes.Namespace).
				WithData(map[string][]byte{fileName: secretData})

			if _, err := k.clientSet.CoreV1().Secrets(k.config.Kubernetes.Namespace).Apply(
				ctx, secretApply, meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER}); err != nil {
				return nil, nil, fmt.Errorf("apply secret %s: %w", secretName, err)
			}

			podVolumes = append(podVolumes, corev1apply.Volume().
				WithName(secretName).
				WithSecret(corev1apply.SecretVolumeSource().
					WithSecretName(secretName)))

			volumeMounts = append(volumeMounts, corev1apply.VolumeMount().
				WithName(secretName).
				WithMountPath(vol.TargetPath).
				WithSubPath(fileName).
				WithReadOnly(true))
			continue
		}

		if vol.VolumeName == "" {
			// Create a ConfigMap from the source file and mount it
			configMapName := fmt.Sprintf("%s-config-%d", name, volIndex)
			volIndex++

			srcFile := makeAbsolute(sourceDir, vol.SourcePath)
			data, err := os.ReadFile(srcFile)
			if err != nil {
				return nil, nil, fmt.Errorf("read config file %s: %w", srcFile, err)
			}

			fileName := filepath.Base(vol.TargetPath)
			configMapApply := corev1apply.ConfigMap(configMapName, k.config.Kubernetes.Namespace).
				WithData(map[string]string{fileName: string(data)})

			if _, err := k.clientSet.CoreV1().ConfigMaps(k.config.Kubernetes.Namespace).Apply(
				ctx, configMapApply, meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER}); err != nil {
				return nil, nil, fmt.Errorf("apply configmap %s: %w", configMapName, err)
			}

			podVolumes = append(podVolumes, corev1apply.Volume().
				WithName(configMapName).
				WithConfigMap(corev1apply.ConfigMapVolumeSource().
					WithName(configMapName)))

			volumeMounts = append(volumeMounts, corev1apply.VolumeMount().
				WithName(configMapName).
				WithMountPath(vol.TargetPath).
				WithSubPath(fileName).
				WithReadOnly(vol.ReadOnly))
			continue
		}

		dir := vol.VolumeName
		if dir == UNNAMED_VOLUME {
			// unnamed volume, use the path for generating the volume name
			dir = vol.TargetPath
		}

		// PVC-based volume (already created via VolumeCreate)
		genVolumeName := GenVolumeName(k.appId, dir)
		pvcName := sanitizeContainerName(string(genVolumeName))
		volumeName := pvcName // use the same name for the volume reference

		podVolumes = append(podVolumes, corev1apply.Volume().
			WithName(volumeName).
			WithPersistentVolumeClaim(corev1apply.PersistentVolumeClaimVolumeSource().
				WithClaimName(pvcName).
				WithReadOnly(vol.ReadOnly)))

		volumeMounts = append(volumeMounts, corev1apply.VolumeMount().
			WithName(volumeName).
			WithMountPath(vol.TargetPath).
			WithReadOnly(vol.ReadOnly))
	}

	return podVolumes, volumeMounts, nil
}

const VERSION_HASH_LABEL = LABEL_PREFIX + "version.hash"

// createDeployment creates a Deployment + Service using server-side apply and returns the Service URL.
func (k *KubernetesCM) createDeployment(ctx context.Context, name, image string,
	port int32, envMap map[string]string, volumes []*VolumeInfo, sourceDir string, paramMap map[string]string, appEntry *types.AppEntry, versionHash string) (string, error) {
	labels := map[string]string{"app": name}

	metadata := map[string]string{}
	metadata["app"] = name
	metadata[LABEL_PREFIX+"git.sha"] = TrimLabelValue(appEntry.Metadata.VersionMetadata.GitCommit)
	metadata[LABEL_PREFIX+"app.version"] = strconv.Itoa(appEntry.Metadata.VersionMetadata.Version)
	metadata[VERSION_HASH_LABEL] = TrimLabelValue(versionHash)
	replicas := int32(1) // min = max = 1

	// Convert envMap to Kubernetes EnvVar apply configurations
	envVars := make([]*corev1apply.EnvVarApplyConfiguration, 0, len(envMap))
	for key, value := range envMap {
		envVars = append(envVars, corev1apply.EnvVar().
			WithName(key).
			WithValue(value))
	}

	// Process volumes (creates Secrets/ConfigMaps as needed)
	podVolumes, volumeMounts, err := k.processVolumes(ctx, name, volumes, sourceDir, paramMap)
	if err != nil {
		return "", err
	}

	protocol := core.ProtocolTCP
	containerConfig := corev1apply.Container().
		WithName(name).
		WithImage(image).
		WithPorts(corev1apply.ContainerPort().
			WithContainerPort(port).
			WithProtocol(protocol)).
		WithEnv(envVars...)

	if len(volumeMounts) > 0 {
		containerConfig = containerConfig.WithVolumeMounts(volumeMounts...)
	}

	podSpec := corev1apply.PodSpec().
		WithContainers(containerConfig)
	if len(podVolumes) > 0 {
		podSpec = podSpec.WithVolumes(podVolumes...)
	}

	// Set deployment strategy
	strategy := appsv1apply.DeploymentStrategy().
		//WithType(appsv1.RecreateDeploymentStrategyType)
		WithType(appsv1.RollingUpdateDeploymentStrategyType)

	dep := appsv1apply.Deployment(name, k.config.Kubernetes.Namespace).
		WithLabels(labels).
		WithSpec(appsv1apply.DeploymentSpec().
			WithReplicas(replicas).
			WithSelector(metav1apply.LabelSelector().
				WithMatchLabels(labels)).
			WithStrategy(strategy).
			WithTemplate(corev1apply.PodTemplateSpec().
				WithLabels(metadata).
				WithSpec(podSpec)))

	if _, err := k.clientSet.AppsV1().Deployments(k.config.Kubernetes.Namespace).Apply(ctx, dep, meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER}); err != nil {
		return "", fmt.Errorf("apply deployment: %w", err)
	}

	serviceType := core.ServiceTypeClusterIP
	if k.config.Kubernetes.UseNodePort {
		serviceType = core.ServiceTypeNodePort
	}
	svcApply := corev1apply.Service(name, k.config.Kubernetes.Namespace).
		WithLabels(metadata).
		WithSpec(corev1apply.ServiceSpec().
			WithType(serviceType).
			WithSelector(labels).
			WithPorts(corev1apply.ServicePort().
				WithName("http").
				WithPort(port).
				WithTargetPort(intstr.FromInt(int(port))).
				WithProtocol(protocol)))

	svc, err := k.clientSet.CoreV1().Services(
		k.config.Kubernetes.Namespace).Apply(ctx, svcApply,
		meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER})
	if err != nil {
		return "", fmt.Errorf("apply service: %w", err)
	}

	if len(svc.Spec.Ports) == 0 {
		return "", fmt.Errorf("service has no ports")
	}

	// In-cluster DNS URL
	servicePort := svc.Spec.Ports[0].Port
	url := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, servicePort)
	if k.config.Kubernetes.UseNodePort {
		url = fmt.Sprintf("127.0.0.1:%d", svc.Spec.Ports[0].NodePort)
	}

	return url, nil
}
