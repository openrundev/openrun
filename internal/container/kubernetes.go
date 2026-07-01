// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1apply "k8s.io/client-go/applyconfigurations/apps/v1"
	autoscalingv2apply "k8s.io/client-go/applyconfigurations/autoscaling/v2"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	OPENRUN_FIELD_MANAGER = "openrun"
	KUBERNETES_NAME_MAX   = 63

	// Ownership labels used to identify objects (Secrets/ConfigMaps) generated
	// by OpenRun for a specific container, so snapshot/restore only ever lists,
	// overwrites, or deletes OpenRun-managed objects and never an unrelated
	// object that merely shares the common "app" label.
	MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
	INSTANCE_LABEL   = "app.kubernetes.io/instance"
	MANAGED_BY_VALUE = "openrun"
)

func applyOptions() meta.ApplyOptions {
	return meta.ApplyOptions{FieldManager: OPENRUN_FIELD_MANAGER, Force: true}
}

// ownershipLabels returns the labels marking a generated object as OpenRun-owned
// and scoped to the given container name.
func ownershipLabels(name string) map[string]string {
	return map[string]string{
		MANAGED_BY_LABEL: MANAGED_BY_VALUE,
		INSTANCE_LABEL:   TrimLabelValue(name),
	}
}

// ownershipSelector is the label selector matching only OpenRun-managed objects
// for the given container name.
func ownershipSelector(name string) string {
	return fmt.Sprintf("%s=%s,%s=%s", MANAGED_BY_LABEL, MANAGED_BY_VALUE, INSTANCE_LABEL, TrimLabelValue(name))
}

type KubernetesOptions struct {
	Cpus        string         `mapstructure:"cpus"`
	Memory      string         `mapstructure:"memory"`
	MinReplicas int32          `mapstructure:"min_replicas"` // min number of replicas to run the app on
	MaxReplicas int32          `mapstructure:"max_replicas"` // max number of replicas to run the app on
	Other       map[string]any `mapstructure:",remain"`
}

type DeployRequest struct {
	AppEntry           *types.AppEntry
	SourceDir          string
	ContainerName      ContainerName
	ImageName          ImageName
	Port               int32
	EnvMap             map[string]string
	Volumes            []*VolumeInfo
	ContainerOptions   map[string]string
	ParamMap           map[string]string
	VersionHash        string
	IsImageSpec        bool
	HealthProbe        *HealthProbe
	Verify             bool
	DeployAttempts     int
	LogLinesToShow     int
	ShowLogsForFailure bool
}

type DeployResult struct {
	ContainerName ContainerName
	VersionHash   string
	HostNamePort  string
}

func parseKubernetesOptions(options map[string]string) (KubernetesOptions, error) {
	var ret KubernetesOptions
	updatedOptions := make(map[string]string)
	kubernetesPrefix := "kubernetes."

	for k, v := range options {
		if strings.HasPrefix(k, kubernetesPrefix) {
			updatedOptions[strings.TrimPrefix(k, kubernetesPrefix)] = v
		} else if slices.Contains(KNOWN_OPTIONS, k) {
			updatedOptions[k] = v
		}
	}

	config := &mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		Result:           &ret,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return KubernetesOptions{}, err
	}
	err = decoder.Decode(updatedOptions)
	if err != nil {
		return KubernetesOptions{}, err
	}
	return ret, nil
}

type KubernetesCM struct {
	*types.Logger
	appNamespace string
	config       *types.ServerConfig
	clientSet    kubernetes.Interface
	restConfig   *rest.Config
	appConfig    *types.AppConfig
	appRunDir    string
	appId        types.AppId
}

func sanitizeContainerName(name string) string {
	name = sanitizeName(name)
	if len(name) > 50 {
		name = name[:50] // max length for a Kubernetes object name is 63, leave space for the suffix
	}
	return name
}

func suffixedKubernetesName(base, suffix string) string {
	maxBaseLen := KUBERNETES_NAME_MAX - len(suffix)
	if maxBaseLen < 1 {
		return suffix
	}
	if len(base) <= maxBaseLen {
		return base + suffix
	}
	sum := sha256.Sum256([]byte(base))
	hashSuffix := "-" + hex.EncodeToString(sum[:])[:8]
	maxPrefixLen := maxBaseLen - len(hashSuffix)
	if maxPrefixLen < 1 {
		return hashSuffix[1:] + suffix
	}
	return base[:maxPrefixLen] + hashSuffix + suffix
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

func currentNamespace() (string, error) {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func namespaceExists(ctx context.Context, client kubernetes.Interface, name string) (bool, error) {
	_, err := client.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, err // real error (RBAC, network, etc.)
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

	namespace, err := currentNamespace()
	if err != nil {
		logger.Warn().Msgf("error getting current namespace: %v", err)
		namespace = config.Kubernetes.Namespace
	}
	if namespace == "" {
		return nil, fmt.Errorf("namespace not specified and not running in cluster")
	}
	appNamespace := namespace + "-apps"
	appNamespaceExists, err := namespaceExists(context.Background(), clientSet, appNamespace)
	if err != nil {
		return nil, fmt.Errorf("error checking if app namespace exists: %w", err)
	}
	if !appNamespaceExists {
		return nil, fmt.Errorf("app namespace %s does not exist", appNamespace)
	}

	return &KubernetesCM{
		Logger:       logger,
		appNamespace: appNamespace,
		config:       config,
		restConfig:   cfg,
		clientSet:    clientSet,
		appConfig:    appConfig,
		appRunDir:    appRunDir,
		appId:        appId,
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

// registryRef returns the full registry path for an image or repo name,
// including the optional project component.
func (k *KubernetesCM) registryRef(name string) string {
	if k.config.Registry.Project != "" {
		return k.config.Registry.URL + "/" + k.config.Registry.Project + "/" + name
	}
	return k.config.Registry.URL + "/" + name
}

func (k *KubernetesCM) ImageExists(ctx context.Context, name ImageName) (bool, error) {
	if k.config.Registry.URL == "" {
		return false, fmt.Errorf("registry url is required for kubernetes container manager")
	}
	return ImageExists(ctx, k.Logger, string(name), &k.config.Registry)
}

func (k *KubernetesCM) RefreshImage(ctx context.Context, name ImageName) (string, error) {
	result, err := CheckImageReferenceExists(ctx, k.Logger, string(name), &k.config.Registry)
	if err == nil {
		if !result.Exists {
			return "", fmt.Errorf("image %s not found", name)
		}
		return result.Digest, nil
	}
	if isPermanentRegistryError(err) {
		return "", err
	}
	k.Warn().Err(err).Msgf("could not resolve digest for image %s", name)
	return "", nil
}

func (k *KubernetesCM) BuildImage(ctx context.Context, imgName ImageName, sourceUrl, containerFile string, containerArgs map[string]string) error {
	if k.config.Registry.URL == "" {
		return fmt.Errorf("registry url is required for kubernetes container manager")
	}

	targetUrl, found := strings.CutPrefix(k.config.Builder.Mode, "delegate:")
	if found {
		if k.config.System.BuilderAuthToken == "" {
			return fmt.Errorf("system.builder_auth_token must be set when using delegated builds")
		}
		err := sendDelegateBuild(targetUrl, DelegateRequest{
			ImageTag:       string(imgName),
			ContainerFile:  containerFile,
			ContainerArgs:  containerArgs,
			RegistryConfig: &k.config.Registry,
		}, sourceUrl, k.config.System.BuilderAuthToken)
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

	destination := k.registryRef(string(imgName))

	// Generate Docker config JSON only for Kaniko (which needs it as a Kubernetes secret)
	dockerCfgJSON, err := GenerateDockerConfigJSON(&k.config.Registry)
	if err != nil {
		return fmt.Errorf("error generating docker config json: %w", err)
	}

	extraArgs := []string{"--verbosity=debug"}
	if k.config.Builder.KanikoCache {
		// Cache build layers in the registry so a rebuild (e.g. app reload after
		// a source change) skips unchanged steps like dependency installs. The
		// cache repo is shared across apps, so identical layers are reused.
		cacheRepo := k.config.Builder.KanikoCacheRepo
		if cacheRepo == "" {
			cacheRepo = k.registryRef("kaniko-cache")
		}
		extraArgs = append(extraArgs, "--cache=true", "--cache-repo="+cacheRepo)
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
		ExtraArgs:     extraArgs,
	}
	return KanikoJob(ctx, k.Logger, k.clientSet, k.restConfig, &k.config.Registry, dockerCfgJSON, kanikoBuild)
}

func (k *KubernetesCM) GetContainerState(ctx context.Context, name ContainerName, expectHash string) (string, bool, error) {
	name = ContainerName(sanitizeContainerName(string(name)))
	svc, err := k.clientSet.CoreV1().
		Services(k.appNamespace).
		Get(ctx, string(name), meta.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get service %s/%s: %w", k.appNamespace, string(name), err)
	}
	if len(svc.Spec.Ports) == 0 {
		return "", false, fmt.Errorf("service %s/%s has no ports", k.appNamespace, string(name))
	}

	hostNamePort := k.serviceHostNamePort(svc)

	if expectHash == "" {
		// Steady-state check: is any pod the Service routes to Ready?
		selector := svc.Spec.Selector
		if len(selector) == 0 {
			selector = map[string]string{"app": string(name)}
		}
		running, err := k.readyPodsBehindService(ctx, selector)
		if err != nil {
			return "", false, err
		}
		return hostNamePort, running, nil
	}

	// Deploy wait: resolve the workload for this version. Stateless apps run a
	// per-version Deployment (serviceName-<short>); PVC apps update the Deployment
	// named after the Service. Try the versioned name first, then fall back.
	depName := workloadName(string(name), expectHash, false)
	dep, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, depName, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		depName = string(name)
		dep, err = k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, depName, meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			return hostNamePort, false, nil // not created yet
		}
	}
	if err != nil {
		return "", false, fmt.Errorf("get deployment %s/%s: %w", k.appNamespace, depName, err)
	}

	if dep.Spec.Template.Labels[VERSION_HASH_LABEL] != TrimLabelValue(expectHash) {
		k.Logger.Warn().Msgf("deployment version hash mismatch: expected %s, got %s", TrimLabelValue(expectHash), dep.Spec.Template.Labels[VERSION_HASH_LABEL])
		return "", false, nil
	}

	// Surface a Kubernetes-declared rollout failure immediately so the caller
	// stops waiting and rolls back, instead of polling until its own timeout.
	if msg, failed := rolloutFailed(dep); failed {
		return "", false, fmt.Errorf("deployment %s/%s rollout failed: %s", k.appNamespace, depName, msg)
	}

	// Require the rollout to have fully completed (all desired pods of this
	// version Ready), so a single Ready pod mid-rollout is not reported as done.
	updateCompleted := k.isDeploymentReady(dep, expectHash)

	pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(versionSelector(string(name), expectHash)).String(),
	})
	if err != nil {
		return "", false, fmt.Errorf("list pods for deployment %s/%s: %w", k.appNamespace, depName, err)
	}
	runningCount := 0
	for _, pod := range pods.Items {
		if isPodReady(&pod) {
			runningCount++
		}
	}

	k.Logger.Debug().Msgf("GetContainerState dep %s runningCount %d updateCompleted %t", depName, runningCount, updateCompleted)
	return hostNamePort, updateCompleted && runningCount > 0, nil
}

// readyPodsBehindService reports whether any pod matching the Service selector
// is Ready.
func (k *KubernetesCM) readyPodsBehindService(ctx context.Context, selector map[string]string) (bool, error) {
	if len(selector) == 0 {
		return false, nil
	}
	selectorStr := labels.Set(selector).String()
	pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{LabelSelector: selectorStr})
	if err != nil {
		return false, fmt.Errorf("list pods for selector %q: %w", selectorStr, err)
	}
	for i := range pods.Items {
		if isPodReady(&pods.Items[i]) {
			return true, nil
		}
	}
	return false, nil
}

func (k *KubernetesCM) StartContainer(ctx context.Context, name ContainerName) error {
	return k.scaleActiveDeployment(ctx, string(name), 1)
}

func (k *KubernetesCM) StopContainer(ctx context.Context, name ContainerName) error {
	return k.scaleActiveDeployment(ctx, string(name), 0)
}

// scaleActiveDeployment scales the Deployment currently behind the Service (the
// active version for stateless apps; the stable name for PVC apps).
func (k *KubernetesCM) scaleActiveDeployment(ctx context.Context, serviceName string, replicas int32) error {
	serviceName = sanitizeContainerName(serviceName)
	depName, err := k.activeDeploymentName(ctx, serviceName)
	if err != nil {
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		scale, err := k.clientSet.AppsV1().Deployments(k.appNamespace).GetScale(ctx, depName, meta.GetOptions{})
		if err != nil {
			return err
		}
		scale.Spec.Replicas = replicas
		_, err = k.clientSet.AppsV1().Deployments(k.appNamespace).UpdateScale(ctx, depName, scale, meta.UpdateOptions{})
		return err
	})
}

func (k *KubernetesCM) RunContainer(ctx context.Context, appEntry *types.AppEntry, sourceDir string, containerName ContainerName,
	imageName ImageName, port int32, envMap map[string]string, volumes []*VolumeInfo,
	containerOptions map[string]string, paramMap map[string]string, versionHash string, isImageSpec bool,
	healthProbe *HealthProbe) error {
	if strings.HasPrefix(string(imageName), IMAGE_NAME_PREFIX) {
		imageName = ImageName(k.registryRef(string(imageName)))
	}
	kubernetesOptions, err := parseKubernetesOptions(containerOptions)
	if err != nil {
		return fmt.Errorf("error parsing kubernetes options: %w", err)
	}
	serviceName := sanitizeContainerName(string(containerName))
	usesPV := HasPersistentVolume(volumes)
	wlName := workloadName(serviceName, versionHash, usesPV)

	// PVC apps update the Service in place (version-agnostic selector). Stateless
	// apps only create the Service on first deploy (pointing at this version);
	// on later deploys the Service keeps pointing at the old version until the
	// caller promotes the new one (blue-green).
	createService := usesPV
	if !usesPV {
		exists, err := k.serviceExists(ctx, serviceName)
		if err != nil {
			return err
		}
		createService = !exists
	}

	hostNamePort, err := k.createDeployment(ctx, serviceName, wlName, createService, string(imageName), port, envMap,
		volumes, sourceDir, paramMap, appEntry, versionHash, kubernetesOptions, isImageSpec, healthProbe)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	k.Logger.Info().Msgf("applied workload %s for service %s host name port %s", wlName, serviceName, hostNamePort)
	return nil
}

func (k *KubernetesCM) serviceExists(ctx context.Context, serviceName string) (bool, error) {
	_, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, serviceName, meta.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("get service %s/%s: %w", k.appNamespace, serviceName, err)
}

func (k *KubernetesCM) GetContainerLogs(ctx context.Context, name ContainerName, linesToShow int) (string, error) {
	return k.getContainerLogs(ctx, name, linesToShow, "")
}

func (k *KubernetesCM) getContainerLogs(ctx context.Context, name ContainerName, linesToShow int, versionHash string) (string, error) {
	name = ContainerName(sanitizeContainerName(string(name)))

	// List pods with the matching label
	selector := map[string]string{"app": string(name)}
	if versionHash != "" {
		selector[VERSION_HASH_LABEL] = TrimLabelValue(versionHash)
	}
	pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(selector).String(),
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

	req := k.clientSet.CoreV1().Pods(k.appNamespace).GetLogs(pod.Name, logOptions)
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
		PersistentVolumeClaims(k.appNamespace).
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
	pvc := corev1apply.PersistentVolumeClaim(pvcName, k.appNamespace).
		WithSpec(corev1apply.PersistentVolumeClaimSpec().
			WithAccessModes(core.ReadWriteOnce). // TODO: support other access modes
			WithResources(corev1apply.VolumeResourceRequirements().
				WithRequests(core.ResourceList{
					core.ResourceStorage: size,
				})))

	_, err = k.clientSet.CoreV1().
		PersistentVolumeClaims(k.appNamespace).
		Apply(ctx, pvc, applyOptions())
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
			secretName := suffixedKubernetesName(name, fmt.Sprintf("-secret-%d", volIndex))
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
			secretApply := corev1apply.Secret(secretName, k.appNamespace).
				WithLabels(ownershipLabels(name)).
				WithData(map[string][]byte{fileName: secretData})

			if _, err := k.clientSet.CoreV1().Secrets(k.appNamespace).Apply(
				ctx, secretApply, applyOptions()); err != nil {
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
			configMapName := suffixedKubernetesName(name, fmt.Sprintf("-config-%d", volIndex))
			volIndex++

			srcFile := makeAbsolute(sourceDir, vol.SourcePath)
			data, err := os.ReadFile(srcFile)
			if err != nil {
				return nil, nil, fmt.Errorf("read config file %s: %w", srcFile, err)
			}

			fileName := filepath.Base(vol.TargetPath)
			configMapApply := corev1apply.ConfigMap(configMapName, k.appNamespace).
				WithLabels(ownershipLabels(name)).
				WithData(map[string]string{fileName: string(data)})

			if _, err := k.clientSet.CoreV1().ConfigMaps(k.appNamespace).Apply(
				ctx, configMapApply, applyOptions()); err != nil {
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

// shortHash returns a label/name-safe version suffix. Keep more than 8 chars so
// workloads with nearby hashes do not collide on the Kubernetes object name.
func shortHash(versionHash string) string {
	h := strings.ToLower(versionHash)
	if len(h) > 16 {
		h = h[:16]
	}
	return h
}

// workloadName is the name of the Deployment (and its owned HPA, Secrets and
// ConfigMaps). PVC-backed apps update in place under the stable service name;
// stateless apps get a per-version name so blue-green versions can coexist.
func workloadName(serviceName, versionHash string, usesPV bool) string {
	if usesPV {
		return serviceName
	}
	suffix := shortHash(versionHash)
	maxServiceLen := 63 - len(suffix) - 1
	if maxServiceLen > 0 && len(serviceName) > maxServiceLen {
		serviceName = serviceName[:maxServiceLen]
	}
	return serviceName + "-" + suffix
}

// workloadSelector is the immutable Deployment selector. PVC-backed apps keep
// a stable selector because Kubernetes does not allow changing it between
// versions; stateless apps use a per-version selector.
func workloadSelector(serviceName, versionHash string, usesPV bool) map[string]string {
	sel := map[string]string{"app": serviceName}
	if !usesPV {
		sel[VERSION_HASH_LABEL] = TrimLabelValue(versionHash)
	}
	return sel
}

func versionSelector(serviceName, versionHash string) map[string]string {
	return map[string]string{
		"app":              serviceName,
		VERSION_HASH_LABEL: TrimLabelValue(versionHash),
	}
}

// createDeployment server-side-applies one version's Deployment (plus its HPA
// and mounted Secrets/ConfigMaps under workloadName), and, when createService is
// set, the stable Service pointing at this version. It returns the Service URL.
//
// Apps with a persistent (PVC-backed) volume cannot run two pods against the
// same ReadWriteOnce volume, so they use a single replica and the Recreate
// strategy (in place, brief downtime). Stateless apps run as a separate
// per-version Deployment and a surge rolling update (maxUnavailable=0), so the
// old version keeps serving until the caller promotes the new one.
func (k *KubernetesCM) createDeployment(ctx context.Context, serviceName, wlName string, createService bool, image string,
	port int32, envMap map[string]string, volumes []*VolumeInfo, sourceDir string, paramMap map[string]string,
	appEntry *types.AppEntry, versionHash string, kubernetesOptions KubernetesOptions, isImageSpec bool,
	healthProbe *HealthProbe) (string, error) {
	usesPV := HasPersistentVolume(volumes)
	workloadSelectorLabels := workloadSelector(serviceName, versionHash, usesPV)
	// Services pick only the active version's Ready pods. Even PVC-backed apps
	// include the version hash so a stateless <-> PVC transition cannot
	// load-balance across old and new workloads that share the app label.
	serviceSelectorLabels := versionSelector(serviceName, versionHash)

	metadata := map[string]string{}
	metadata["app"] = serviceName
	metadata[LABEL_PREFIX+"app.id"] = TrimLabelValue(string(appEntry.Id))
	metadata[LABEL_PREFIX+"git.sha"] = TrimLabelValue(appEntry.Metadata.VersionMetadata.GitCommit)
	metadata[LABEL_PREFIX+"app.version"] = strconv.Itoa(appEntry.Metadata.VersionMetadata.Version)
	metadata[VERSION_HASH_LABEL] = TrimLabelValue(versionHash)
	annotations := map[string]string{
		LABEL_PREFIX + "app.id":   string(appEntry.Id),
		LABEL_PREFIX + "app.path": appEntry.Path,
	}

	// Set replicas from kubernetesOptions, defaulting to 1. PVC-backed apps are
	// pinned to a single replica regardless of min/max replicas, since multiple
	// pods cannot share a ReadWriteOnce volume.
	replicas := int32(1)
	if usesPV {
		if kubernetesOptions.MinReplicas > 1 || kubernetesOptions.MaxReplicas > 1 {
			k.Logger.Warn().Msgf("app %s uses a persistent volume; ignoring min/max replicas and running a single replica", serviceName)
		}
	} else {
		if kubernetesOptions.MinReplicas > 0 {
			replicas = kubernetesOptions.MinReplicas
		}
		if kubernetesOptions.MaxReplicas > 0 && kubernetesOptions.MaxReplicas < replicas {
			replicas = kubernetesOptions.MaxReplicas
		}
	}

	// Convert envMap to Kubernetes EnvVar apply configurations
	envVars := make([]*corev1apply.EnvVarApplyConfiguration, 0, len(envMap))
	for key, value := range envMap {
		envVars = append(envVars, corev1apply.EnvVar().
			WithName(key).
			WithValue(value))
	}

	// Process volumes (creates Secrets/ConfigMaps as needed). These are named
	// after the (possibly versioned) workload so blue-green versions get
	// isolated config that is GC'd with their Deployment.
	podVolumes, volumeMounts, err := k.processVolumes(ctx, wlName, volumes, sourceDir, paramMap)
	if err != nil {
		return "", err
	}

	protocol := core.ProtocolTCP
	containerConfig := corev1apply.Container().
		WithName(serviceName).
		WithImage(image).
		WithPorts(corev1apply.ContainerPort().
			WithContainerPort(port).
			WithProtocol(protocol)).
		WithEnv(envVars...)

	if isImageSpec && !strings.Contains(image, "@") {
		// Image-spec apps consume an externally-managed reference. The handler
		// normally digest-pins the image before deployment. PullAlways only
		// applies when no digest was resolved, so a moved tag is still checked.
		containerConfig = containerConfig.WithImagePullPolicy(core.PullAlways)
	}

	// A readiness probe gates traffic and the rolling update on actual app
	// health: with maxUnavailable=0 the old version keeps serving until a new
	// pod is Ready, so a broken update never receives traffic. A startup probe
	// gives slow-booting apps a longer grace period without loosening the
	// steady-state readiness threshold.
	if healthProbe != nil {
		scheme := core.URIScheme(healthProbe.Scheme)
		if scheme == "" {
			scheme = core.URISchemeHTTP
		}
		newHTTPGet := func() *corev1apply.HTTPGetActionApplyConfiguration {
			return corev1apply.HTTPGetAction().
				WithPath(healthProbe.Path).
				WithPort(intstr.FromInt(int(healthProbe.Port))).
				WithScheme(scheme)
		}
		containerConfig = containerConfig.
			WithReadinessProbe(corev1apply.Probe().
				WithHTTPGet(newHTTPGet()).
				WithPeriodSeconds(healthProbe.PeriodSecs).
				WithTimeoutSeconds(healthProbe.TimeoutSecs).
				WithFailureThreshold(healthProbe.FailureThreshold)).
			WithStartupProbe(corev1apply.Probe().
				WithHTTPGet(newHTTPGet()).
				WithPeriodSeconds(healthProbe.PeriodSecs).
				WithTimeoutSeconds(healthProbe.TimeoutSecs).
				WithFailureThreshold(healthProbe.StartupFailures))
	}

	if len(volumeMounts) > 0 {
		containerConfig = containerConfig.WithVolumeMounts(volumeMounts...)
	}

	// Add resource requirements if cpus or memory are specified
	if kubernetesOptions.Cpus != "" || kubernetesOptions.Memory != "" {
		resources := corev1apply.ResourceRequirements()
		requestsList := core.ResourceList{}
		limitsList := core.ResourceList{}

		if kubernetesOptions.Cpus != "" {
			cpus, err := CPUString(kubernetesOptions.Cpus, false)
			if err != nil {
				return "", fmt.Errorf("error parsing cpus value %q: %w", kubernetesOptions.Cpus, err)
			}
			cpuQuantity, err := resource.ParseQuantity(cpus + "m") // convert to millicores
			if err != nil {
				return "", fmt.Errorf("invalid cpus value %q: %w", kubernetesOptions.Cpus, err)
			}
			requestsList[core.ResourceCPU] = cpuQuantity
		}

		if kubernetesOptions.Memory != "" {
			memory, err := BytesString(kubernetesOptions.Memory)
			if err != nil {
				return "", fmt.Errorf("error parsing memory value %q: %w", kubernetesOptions.Memory, err)
			}
			memQuantity, err := resource.ParseQuantity(memory)
			if err != nil {
				return "", fmt.Errorf("invalid memory value %q: %w", kubernetesOptions.Memory, err)
			}
			requestsList[core.ResourceMemory] = memQuantity
			limitsList[core.ResourceMemory] = memQuantity
		}

		resources = resources.WithRequests(requestsList).WithLimits(limitsList)
		containerConfig = containerConfig.WithResources(resources)
	}

	podSpec := corev1apply.PodSpec().
		WithContainers(containerConfig)
	if len(podVolumes) > 0 {
		podSpec = podSpec.WithVolumes(podVolumes...)
	}

	// Set deployment strategy. PVC-backed apps use Recreate (single-writer,
	// brief downtime); other apps use a surge rolling update that keeps the
	// old version serving until the new pods are Ready (maxUnavailable=0).
	strategy := appsv1apply.DeploymentStrategy()
	if usesPV {
		strategy = strategy.WithType(appsv1.RecreateDeploymentStrategyType)
	} else {
		strategy = strategy.
			WithType(appsv1.RollingUpdateDeploymentStrategyType).
			WithRollingUpdate(appsv1apply.RollingUpdateDeployment().
				WithMaxUnavailable(intstr.FromInt(0)).
				WithMaxSurge(intstr.FromInt(1)))
	}

	// progressDeadlineSeconds is the point at which Kubernetes declares a stalled
	// rollout failed (ProgressDeadlineExceeded). Keep it above the worst-case
	// healthy startup window (StartupFailures × period) but below the caller's
	// WaitForHealth budget, so a genuinely failing rollout is reported and
	// rolled back promptly rather than waiting out the full client timeout.
	progressDeadline := int32(120)
	if healthProbe != nil {
		if pd := healthProbe.StartupFailures*healthProbe.PeriodSecs + 30; pd > progressDeadline {
			progressDeadline = pd
		}
	}
	if k.appConfig.Container.DeployProgressDeadlineSecs > 0 {
		progressDeadline = int32(k.appConfig.Container.DeployProgressDeadlineSecs)
	}

	dep := appsv1apply.Deployment(wlName, k.appNamespace).
		WithLabels(metadata).
		WithAnnotations(annotations).
		WithSpec(appsv1apply.DeploymentSpec().
			WithReplicas(replicas).
			WithProgressDeadlineSeconds(progressDeadline).
			WithSelector(metav1apply.LabelSelector().
				WithMatchLabels(workloadSelectorLabels)).
			WithStrategy(strategy).
			WithTemplate(corev1apply.PodTemplateSpec().
				WithLabels(metadata).
				WithAnnotations(annotations).
				WithSpec(podSpec)))

	if _, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Apply(ctx, dep, applyOptions()); err != nil {
		return "", fmt.Errorf("apply deployment: %w", err)
	}

	// Create HPA if MaxReplicas > 1. Skipped for PVC-backed apps, which are
	// pinned to a single replica and cannot scale horizontally on a
	// ReadWriteOnce volume.
	if kubernetesOptions.MaxReplicas > 1 && !usesPV {
		minReplicas := kubernetesOptions.MinReplicas
		if minReplicas < 1 {
			minReplicas = 1
		}
		hpa := autoscalingv2apply.HorizontalPodAutoscaler(wlName, k.appNamespace).
			WithLabels(workloadSelectorLabels).
			WithSpec(autoscalingv2apply.HorizontalPodAutoscalerSpec().
				WithScaleTargetRef(autoscalingv2apply.CrossVersionObjectReference().
					WithAPIVersion("apps/v1").
					WithKind("Deployment").
					WithName(wlName)).
				WithMinReplicas(minReplicas).
				WithMaxReplicas(kubernetesOptions.MaxReplicas).
				WithMetrics(autoscalingv2apply.MetricSpec().
					WithType(autoscalingv2.ResourceMetricSourceType).
					WithResource(autoscalingv2apply.ResourceMetricSource().
						WithName(core.ResourceCPU).
						WithTarget(autoscalingv2apply.MetricTarget().
							WithType(autoscalingv2.UtilizationMetricType).
							WithAverageUtilization(k.appConfig.Kubernetes.ScalingThresholdCPU)))))

		if _, err := k.clientSet.AutoscalingV2().HorizontalPodAutoscalers(k.appNamespace).Apply(
			ctx, hpa, applyOptions()); err != nil {
			return "", fmt.Errorf("apply hpa: %w", err)
		}
		k.Logger.Info().Msgf("created HPA for %s with min=%d max=%d", wlName, minReplicas, kubernetesOptions.MaxReplicas)
	} else {
		// Horizontal scaling is no longer desired (max replicas reduced to <=1,
		// or the app became PVC-backed). Remove any HPA left over from a prior
		// version so it does not keep scaling a workload the new code assumes is
		// single-replica.
		if err := k.clientSet.AutoscalingV2().HorizontalPodAutoscalers(k.appNamespace).Delete(
			ctx, wlName, meta.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return "", fmt.Errorf("delete stale hpa %s: %w", wlName, err)
		}
	}

	if !createService {
		// Blue-green: the new version's workload is up but off-traffic; the
		// caller flips the stable Service to it via PromoteVersion.
		return "", nil
	}
	return k.applyService(ctx, serviceName, serviceSelectorLabels, port)
}

// applyService server-side-applies the stable Service with the given selector
// and returns its in-cluster URL.
func (k *KubernetesCM) applyService(ctx context.Context, serviceName string, selectorLabels map[string]string, port int32) (string, error) {
	serviceType := core.ServiceTypeClusterIP
	if k.config.Kubernetes.UseNodePort {
		serviceType = core.ServiceTypeNodePort
	}
	protocol := core.ProtocolTCP
	svcApply := corev1apply.Service(serviceName, k.appNamespace).
		WithLabels(map[string]string{"app": serviceName}).
		WithSpec(corev1apply.ServiceSpec().
			WithType(serviceType).
			WithSelector(selectorLabels).
			WithPorts(corev1apply.ServicePort().
				WithName("http").
				WithPort(port).
				WithTargetPort(intstr.FromInt(int(port))).
				WithProtocol(protocol)))

	svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Apply(ctx, svcApply, applyOptions())
	if err != nil {
		return "", fmt.Errorf("apply service: %w", err)
	}
	if len(svc.Spec.Ports) == 0 {
		return "", fmt.Errorf("service has no ports")
	}
	return k.serviceHostNamePort(svc), nil
}

// serviceHostNamePort returns the address callers use to reach the Service: the
// host NodePort in NodePort mode, otherwise the in-cluster DNS name. The Service
// must have at least one port.
func (k *KubernetesCM) serviceHostNamePort(svc *core.Service) string {
	if k.config.Kubernetes.UseNodePort {
		return fmt.Sprintf("127.0.0.1:%d", svc.Spec.Ports[0].NodePort)
	}
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, svc.Spec.Ports[0].Port)
}

var _ VersionReporter = (*KubernetesCM)(nil)

func (k *KubernetesCM) deployAppID(appEntry *types.AppEntry) types.AppId {
	if appEntry != nil {
		return appEntry.Id
	}
	return k.appId
}

func (k *KubernetesCM) DeployContainer(ctx context.Context, req DeployRequest) (DeployResult, error) {
	appID := k.deployAppID(req.AppEntry)
	if hostNamePort, running, err := k.GetContainerState(ctx, req.ContainerName, req.VersionHash); err != nil {
		k.cleanupSourceDir(req.SourceDir, appID)
		return DeployResult{}, fmt.Errorf("error getting running containers: %w", err)
	} else if hostNamePort != "" && running && k.isActiveVersion(ctx, req.ContainerName, req.VersionHash) {
		k.cleanupSourceDir(req.SourceDir, appID)
		k.Debug().Msgf("app %s already on version %s, reusing", appID, req.VersionHash)
		return DeployResult{
			ContainerName: req.ContainerName,
			VersionHash:   req.VersionHash,
			HostNamePort:  hostNamePort,
		}, nil
	}

	if HasPersistentVolume(req.Volumes) {
		return k.deployInPlace(ctx, req)
	}
	return k.deployBlueGreen(ctx, req)
}

func (k *KubernetesCM) isActiveVersion(ctx context.Context, name ContainerName, versionHash string) bool {
	cur, err := k.CurrentVersionHash(ctx, name)
	if err != nil {
		return false
	}
	return cur == TrimLabelValue(versionHash)
}

// deployBlueGreen stands up the new stateless version as a separate workload,
// waits for Kubernetes readiness, then flips the stable Service selector.
func (k *KubernetesCM) deployBlueGreen(ctx context.Context, req DeployRequest) (DeployResult, error) {
	serviceName := req.ContainerName
	appID := k.deployAppID(req.AppEntry)

	if err := k.RunContainer(ctx, req.AppEntry, req.SourceDir, serviceName,
		req.ImageName, req.Port, req.EnvMap, req.Volumes, req.ContainerOptions, req.ParamMap,
		req.VersionHash, req.IsImageSpec, req.HealthProbe); err != nil {
		if rmErr := k.RemoveVersion(ctx, serviceName, req.VersionHash); rmErr != nil {
			k.Error().Err(rmErr).Msgf("failed to remove partially-created version for app %s", appID)
		}
		k.cleanupSourceDir(req.SourceDir, appID)
		return DeployResult{}, fmt.Errorf("error creating new version for app %s: %w", appID, err)
	}
	k.cleanupSourceDir(req.SourceDir, appID)

	// waitForDeployReady resolves the stable Service host:port, which promotion
	// does not change, so it is reused as the deploy result below.
	hostNamePort, err := k.waitForDeployReady(ctx, serviceName, req.VersionHash, req.DeployAttempts)
	if err != nil {
		if rmErr := k.RemoveVersion(ctx, serviceName, req.VersionHash); rmErr != nil {
			k.Error().Err(rmErr).Msgf("failed to remove unhealthy new version for app %s", appID)
		}
		if req.ShowLogsForFailure {
			logs, _ := k.getContainerLogs(ctx, serviceName, req.LogLinesToShow, req.VersionHash)
			return DeployResult{}, fmt.Errorf("new version did not become healthy: %w. Logs\n %s", err, logs)
		}
		return DeployResult{}, fmt.Errorf("new version did not become healthy: %w", err)
	}

	_, prevSelector, err := k.PromoteVersion(ctx, serviceName, req.VersionHash)
	if err != nil {
		if rmErr := k.RemoveVersion(ctx, serviceName, req.VersionHash); rmErr != nil {
			k.Error().Err(rmErr).Msgf("failed to remove new version for app %s after promote error", appID)
		}
		return DeployResult{}, fmt.Errorf("error promoting new version for app %s: %w", appID, err)
	}

	// The old version's pods are cleaned up asynchronously, so wait for the
	// Service endpoints to converge to the new version before returning;
	// otherwise a request proxied right after promotion can still hit an old pod.
	k.waitForServiceVersionEndpoints(ctx, sanitizeContainerName(string(serviceName)), req.VersionHash)
	k.waitForNodePortConnectivity(ctx, hostNamePort)

	activeName := workloadName(sanitizeContainerName(string(serviceName)), req.VersionHash, false)
	onCommit := func(c context.Context) error {
		return k.cleanupInactiveWorkloads(c, serviceName)
	}

	if dt := DeployTxnFromContext(ctx); dt != nil {
		dt.Register(appID,
			func(c context.Context) error {
				var errs []error
				if len(prevSelector) > 0 {
					if e := k.restoreServiceSelector(c, serviceName, prevSelector); e != nil {
						errs = append(errs, e)
					}
				}
				if e := k.deleteWorkloadObjects(c, activeName); e != nil {
					errs = append(errs, e)
				}
				return errors.Join(errs...)
			},
			onCommit)
	} else {
		k.cleanupInactiveWorkloadsAsync(serviceName, appID, "after promotion")
	}

	return DeployResult{
		ContainerName: serviceName,
		VersionHash:   req.VersionHash,
		HostNamePort:  hostNamePort,
	}, nil
}

// deployInPlace mutates the stable Kubernetes workload. It snapshots first so
// a failed verified reload can restore the previous Deployment and owned
// ConfigMaps/Secrets.
func (k *KubernetesCM) deployInPlace(ctx context.Context, req DeployRequest) (DeployResult, error) {
	appID := k.deployAppID(req.AppEntry)
	var rollbackSnap any
	snap, snapErr := k.Snapshot(ctx, req.ContainerName)
	if snapErr != nil {
		if req.Verify {
			k.cleanupSourceDir(req.SourceDir, appID)
			return DeployResult{}, fmt.Errorf("cannot safely reload app %s: failed to capture rollback snapshot before update: %w", appID, snapErr)
		}
		k.Warn().Err(snapErr).Msgf("could not snapshot app %s before reload; rollback on failure unavailable", appID)
	} else {
		rollbackSnap = snap
	}

	fail := func(err error) error {
		return k.failWithRollback(ctx, appID, rollbackSnap, err)
	}

	if err := k.RunContainer(ctx, req.AppEntry, req.SourceDir, req.ContainerName,
		req.ImageName, req.Port, req.EnvMap, req.Volumes, req.ContainerOptions, req.ParamMap,
		req.VersionHash, req.IsImageSpec, req.HealthProbe); err != nil {
		k.cleanupSourceDir(req.SourceDir, appID)
		return DeployResult{}, fail(fmt.Errorf("error starting container after update: %w", err))
	}
	k.cleanupSourceDir(req.SourceDir, appID)

	// waitForDeployReady returns a non-empty host:port only once the version is
	// confirmed running, so no separate GetContainerState re-check is needed.
	hostNamePort, err := k.waitForDeployReady(ctx, req.ContainerName, req.VersionHash, req.DeployAttempts)
	if err != nil {
		if req.ShowLogsForFailure {
			logs, _ := k.GetContainerLogs(ctx, req.ContainerName, req.LogLinesToShow)
			return DeployResult{}, fail(fmt.Errorf("error waiting for health: %w. Logs\n %s", err, logs))
		}
		return DeployResult{}, fail(fmt.Errorf("error waiting for health: %w", err))
	}
	k.waitForNodePortConnectivity(ctx, hostNamePort)

	onCommit := func(c context.Context) error {
		return k.cleanupInactiveWorkloads(c, req.ContainerName)
	}
	if dt := DeployTxnFromContext(ctx); dt != nil {
		var onRollback func(context.Context) error
		if rollbackSnap != nil {
			onRollback = func(c context.Context) error { return k.Restore(c, rollbackSnap) }
		}
		dt.Register(appID, onRollback, onCommit)
	} else {
		k.cleanupInactiveWorkloadsAsync(req.ContainerName, appID, "after in-place deployment")
	}

	return DeployResult{
		ContainerName: req.ContainerName,
		VersionHash:   req.VersionHash,
		HostNamePort:  hostNamePort,
	}, nil
}

// isDeploymentReady reports whether a Deployment has fully rolled out the
// expected version with all desired replicas Ready.
func (k *KubernetesCM) isDeploymentReady(dep *appsv1.Deployment, expectHash string) bool {
	if dep.Spec.Template.Labels[VERSION_HASH_LABEL] != TrimLabelValue(expectHash) {
		return false
	}
	if dep.Spec.Replicas == nil {
		return false
	}
	desired := *dep.Spec.Replicas
	return dep.Status.ObservedGeneration == dep.Generation &&
		dep.Status.UpdatedReplicas == desired &&
		dep.Status.ReadyReplicas == desired &&
		dep.Status.UnavailableReplicas == 0 &&
		dep.Status.Replicas == desired
}

// rolloutFailed reports a Kubernetes-declared rollout failure
// (ProgressDeadlineExceeded) on the current generation, returning the condition
// message. It lets callers stop waiting and roll back instead of waiting out
// their own timeout.
func rolloutFailed(dep *appsv1.Deployment) (string, bool) {
	for _, cond := range dep.Status.Conditions {
		if dep.Status.ObservedGeneration == dep.Generation &&
			cond.Type == appsv1.DeploymentProgressing &&
			cond.Status == core.ConditionFalse &&
			cond.Reason == "ProgressDeadlineExceeded" {
			return cond.Message, true
		}
	}
	return "", false
}

// waitForDeployReady blocks until the Deployment for the named container+version
// reports fully ready, returning the Service host:port to reach it. It returns
// early with an error on a declared rollout failure, or when the context is
// cancelled or the budget is exhausted.
//
// It uses a Kubernetes Watch so it reacts immediately when the Deployment
// transitions to Ready, avoiding the polling overhead that would otherwise
// accumulate across many sequential deploys. Once the Deployment is observed
// ready, a ticker re-checks the pods/Service as a safety net (they can briefly
// lag the Deployment status, and the watch only wakes on Deployment events). If
// the Watch API returns an error it falls back to waitForDeployReadyPolling.
func (k *KubernetesCM) waitForDeployReady(ctx context.Context, name ContainerName, expectHash string, attempts int) (string, error) {
	if attempts <= 0 {
		attempts = 30
	}
	probePeriodSecs := k.appConfig.Container.DeployProbePeriodSecs
	if probePeriodSecs <= 0 {
		probePeriodSecs = 1
	}
	// The watch reacts to readiness/failure events immediately; this timeout is
	// only the backstop for a rollout that emits no terminal event. Track the
	// same budget the polling fallback would spend (plus one probe period of
	// headroom for the post-ready pod re-check) so lowering deploy_health_attempts
	// to fail fast bounds the watch path too, instead of a fixed extra window.
	timeout := deployReadyBudget(attempts, probePeriodSecs) + time.Duration(probePeriodSecs)*time.Second
	watchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve the deployment name: try the per-version name first (stateless
	// blue-green apps), fall back to the stable name (PVC-backed apps).
	svcName := sanitizeContainerName(string(name))
	depName := workloadName(svcName, expectHash, false)
	dep, getErr := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(watchCtx, depName, meta.GetOptions{})
	if apierrors.IsNotFound(getErr) {
		stableDep, stableErr := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(watchCtx, svcName, meta.GetOptions{})
		if stableErr != nil {
			return k.waitForDeployReadyPolling(watchCtx, name, expectHash, attempts, probePeriodSecs)
		}
		if stableDep.Spec.Template.Labels[VERSION_HASH_LABEL] != TrimLabelValue(expectHash) {
			return k.waitForDeployReadyPolling(watchCtx, name, expectHash, attempts, probePeriodSecs)
		}
		depName = svcName
		dep = stableDep
		getErr = nil
	}
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return k.waitForDeployReadyPolling(watchCtx, name, expectHash, attempts, probePeriodSecs)
	}

	hostNamePort, done, err := k.watchUntilReady(watchCtx, name, expectHash, depName, dep, probePeriodSecs, timeout)
	if done {
		return hostNamePort, err
	}
	return k.waitForDeployReadyPolling(watchCtx, name, expectHash, attempts, probePeriodSecs)
}

// watchUntilReady waits via a Deployment watch until the rollout for expectHash
// is fully ready, returning (hostNamePort, done=true, err) on a terminal
// outcome. done=false signals the caller to fall back to polling; the watch and
// ticker are torn down (by deferred Stop) before returning, so the polling
// fallback never runs alongside an open watch.
func (k *KubernetesCM) watchUntilReady(ctx context.Context, name ContainerName, expectHash, depName string, dep *appsv1.Deployment, probePeriodSecs int, timeout time.Duration) (string, bool, error) {
	// sawReady tracks whether the Deployment has been observed fully rolled out.
	// Pods/the Service can briefly lag the Deployment's Ready status (API read
	// consistency), so once the Deployment is ready we re-check on a ticker; we
	// do not poll before then, leaving the pre-ready wait entirely to the watch.
	sawReady := false

	// evaluate a freshly observed Deployment: a non-nil error is terminal
	// (rollout failed or pod check errored); otherwise it reports the Service
	// host:port and whether a pod of this version is Ready.
	evaluate := func(d *appsv1.Deployment) (string, bool, error) {
		if msg, failed := rolloutFailed(d); failed {
			return "", false, fmt.Errorf("deployment %s/%s rollout failed: %s", k.appNamespace, depName, msg)
		}
		if !k.isDeploymentReady(d, expectHash) {
			return "", false, nil
		}
		sawReady = true
		return k.confirmPodReadiness(ctx, name, expectHash)
	}

	// Fast path: already ready (or already failed) before we set up the watch.
	if dep != nil {
		if hostNamePort, running, err := evaluate(dep); err != nil {
			return "", true, err
		} else if running {
			return hostNamePort, true, nil
		}
	}

	rv := ""
	if dep != nil {
		rv = dep.ResourceVersion
	}
	watcher, werr := k.clientSet.AppsV1().Deployments(k.appNamespace).Watch(ctx, meta.ListOptions{
		FieldSelector:   "metadata.name=" + depName,
		ResourceVersion: rv,
	})
	if werr != nil {
		k.Debug().Err(werr).Msg("deployment watch unavailable, falling back to polling")
		return "", false, nil
	}
	defer watcher.Stop()

	ticker := time.NewTicker(time.Duration(probePeriodSecs) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				k.Debug().Msg("deployment watch closed, falling back to polling")
				return "", false, nil
			}
			if event.Type == watch.Error {
				k.Debug().Msg("deployment watch returned error event, falling back to polling")
				return "", false, nil
			}
			evDep, ok := event.Object.(*appsv1.Deployment)
			if !ok {
				continue
			}
			if hostNamePort, running, err := evaluate(evDep); err != nil {
				return "", true, err
			} else if running {
				return hostNamePort, true, nil
			}
		case <-ticker.C:
			// Safety net only after the Deployment was observed ready: pods/the
			// Service may briefly lag its status. Skipped beforehand so the
			// pre-ready wait stays watch-driven rather than polled.
			if !sawReady {
				continue
			}
			hostNamePort, running, err := k.confirmPodReadiness(ctx, name, expectHash)
			if err != nil {
				return "", true, err
			}
			if running {
				return hostNamePort, true, nil
			}
		case <-ctx.Done():
			return "", true, fmt.Errorf("deployment %s/%s did not become ready within %v", k.appNamespace, depName, timeout)
		}
	}
}

// waitForNodePortConnectivity polls the NodePort TCP address until a connection
// is accepted, confirming that kube-proxy has propagated the endpoint rules.
// It is a no-op when not using NodePort mode or when hostNamePort is empty.
// Best-effort with a bounded budget: a NodePort that never becomes connectable
// (wrong node, firewall, rule never programmed) must not hang the deploy, so it
// gives up after 30s rather than blocking on the caller's context alone.
func (k *KubernetesCM) waitForNodePortConnectivity(ctx context.Context, hostNamePort string) {
	if !k.config.Kubernetes.UseNodePort || hostNamePort == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		conn, err := net.DialTimeout("tcp", hostNamePort, 200*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return
		}
		select {
		case <-ctx.Done():
			return // best-effort: don't fail the deploy on propagation lag
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// isPermanentAPIError reports whether a Kubernetes API error will not clear by
// retrying: RBAC denials and an unsupported/absent resource type. Best-effort
// waits return immediately on these instead of spinning out their full budget.
func isPermanentAPIError(err error) bool {
	return apierrors.IsForbidden(err) ||
		apierrors.IsUnauthorized(err) ||
		apierrors.IsMethodNotSupported(err) ||
		apierrors.IsNotFound(err)
}

// waitForServiceVersionEndpoints blocks until the Service's ready endpoints all
// resolve to pods of expectHash (and at least one is present). After a
// blue-green selector flip, the previous version's pods can briefly linger in
// kube-proxy's rotation until the EndpointSlices are reconciled; cleanup of the
// old workload runs asynchronously, so those pods are not yet deleted. Without
// this wait, a request proxied to the Service immediately after promotion can
// still reach an old pod. Best-effort: returns nil on timeout so a slow
// reconcile does not fail the deploy.
func (k *KubernetesCM) waitForServiceVersionEndpoints(ctx context.Context, serviceName, expectHash string) {
	deadline := time.Now().Add(30 * time.Second)
	waitRetry := func() bool {
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
			return true
		}
	}
	for {
		// Ready pods of the target version, re-listed each iteration so a freshly
		// added endpoint is matched rather than treated as stale.
		pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{
			LabelSelector: labels.Set(versionSelector(serviceName, expectHash)).String(),
		})
		if err != nil {
			if isPermanentAPIError(err) {
				k.Debug().Err(err).Msgf("skipping service %s endpoint convergence wait: cannot list pods", serviceName)
				return // retrying a permission/availability error just wastes the budget
			}
			k.Debug().Err(err).Msgf("could not list pods while waiting for service %s endpoints", serviceName)
			if !waitRetry() {
				return
			}
			continue
		}
		newPods := make(map[string]bool, len(pods.Items))
		for i := range pods.Items {
			if isPodReady(&pods.Items[i]) {
				newPods[pods.Items[i].Name] = true
			}
		}

		slices, err := k.clientSet.DiscoveryV1().EndpointSlices(k.appNamespace).List(ctx, meta.ListOptions{
			LabelSelector: discoveryv1.LabelServiceName + "=" + serviceName,
		})
		if err != nil {
			if isPermanentAPIError(err) {
				// E.g. clusters whose RBAC does not grant list on
				// discovery.k8s.io/endpointslices: retrying for the full budget
				// would add a fixed latency penalty to every promotion.
				k.Debug().Err(err).Msgf("skipping service %s endpoint convergence wait: cannot list endpointslices", serviceName)
				return
			}
			k.Debug().Err(err).Msgf("could not list endpointslices while waiting for service %s endpoints", serviceName)
			if !waitRetry() {
				return
			}
			continue
		}
		readyCount, converged := 0, true
		for si := range slices.Items {
			for _, ep := range slices.Items[si].Endpoints {
				// Per discovery/v1, a nil Ready means ready; only an explicit false
				// is not ready. Treating nil as not-ready would stall the full budget
				// on controllers that omit the field.
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				readyCount++
				if ep.TargetRef == nil || !newPods[ep.TargetRef.Name] {
					converged = false
				}
			}
		}
		if readyCount > 0 && converged {
			return
		}
		if time.Now().After(deadline) {
			k.Debug().Msgf("service %s endpoints did not converge to version %s within budget", serviceName, TrimLabelValue(expectHash))
			return // best-effort
		}
		if !waitRetry() {
			return
		}
	}
}

// confirmPodReadiness fetches the Service and pod list and reports whether at
// least one pod matching expectHash is Ready, plus the Service host:port. It is
// used in the Watch path where isDeploymentReady has already confirmed the
// rollout, so the redundant Deployment re-fetch done by GetContainerState is
// skipped.
func (k *KubernetesCM) confirmPodReadiness(ctx context.Context, name ContainerName, expectHash string) (string, bool, error) {
	svcName := sanitizeContainerName(string(name))
	svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, svcName, meta.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get service %s/%s: %w", k.appNamespace, svcName, err)
	}
	if len(svc.Spec.Ports) == 0 {
		return "", false, fmt.Errorf("service %s/%s has no ports", k.appNamespace, svcName)
	}
	hostNamePort := k.serviceHostNamePort(svc)

	running, err := k.readyPodsBehindService(ctx, versionSelector(svcName, expectHash))
	if err != nil {
		return "", false, err
	}
	return hostNamePort, running, nil
}

// deployReadyBudget is the wall-clock time waitForDeployReadyPolling spends
// across attempts probes: the probe backoff starts at one probe period (min
// 200 ms) and doubles up to 2 s. waitForDeployReady uses it to size the watch
// timeout so both paths honor the same configured budget.
func deployReadyBudget(attempts, probePeriodSecs int) time.Duration {
	total := 0
	ms := max(probePeriodSecs*1000, 200)
	for range attempts {
		total += ms
		ms = min(ms*2, 2000)
	}
	return time.Duration(total) * time.Millisecond
}

// waitForDeployReadyPolling is the polling fallback for waitForDeployReady. It
// returns the Service host:port once the version is ready. The probe backoff
// matches deployReadyBudget (start at one probe period, min 200 ms, double up
// to 2 s) so the two never drift.
func (k *KubernetesCM) waitForDeployReadyPolling(ctx context.Context, name ContainerName, expectHash string, attempts, probePeriodSecs int) (string, error) {
	sleepMillis := max(probePeriodSecs*1000, 200)
	for attempt := 1; attempt <= attempts; attempt++ {
		hostNamePort, running, err := k.GetContainerState(ctx, name, expectHash)
		if err != nil {
			return "", err
		}
		if running {
			return hostNamePort, nil
		}
		time.Sleep(time.Duration(sleepMillis) * time.Millisecond)
		sleepMillis = min(sleepMillis*2, 2000)
	}
	return "", fmt.Errorf("deployment did not become ready after %d attempts", attempts)
}

func (k *KubernetesCM) cleanupSourceDir(sourceDir string, appID types.AppId) {
	if sourceDir == "" {
		return
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		k.Warn().Err(err).Msgf("error removing temp source dir for app %s", appID)
	}
}

func (k *KubernetesCM) failWithRollback(ctx context.Context, appID types.AppId, snap any, origErr error) error {
	if snap == nil {
		return &DeployRollbackError{Err: origErr, Available: false}
	}
	k.Info().Msgf("verification failed for app %s, rolling back deployment", appID)
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	rbErr := k.Restore(rbCtx, snap)
	if rbErr != nil {
		k.Error().Err(rbErr).Msgf("native rollback failed for app %s; manual intervention may be required", appID)
	}
	return &DeployRollbackError{Err: origErr, Available: true, RollbackErr: rbErr}
}

// PromoteVersion points the stable Service at versionHash and returns the
// version hash and selector that were previously active.
func (k *KubernetesCM) PromoteVersion(ctx context.Context, serviceName ContainerName, versionHash string) (string, map[string]string, error) {
	n := sanitizeContainerName(string(serviceName))
	target := TrimLabelValue(versionHash)
	var prev string
	var prevSelector map[string]string
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, n, meta.GetOptions{})
		if err != nil {
			return err
		}
		prevSelector = maps.Clone(svc.Spec.Selector)
		prev = svc.Spec.Selector[VERSION_HASH_LABEL]
		if svc.Spec.Selector == nil {
			svc.Spec.Selector = map[string]string{}
		}
		svc.Spec.Selector["app"] = n
		svc.Spec.Selector[VERSION_HASH_LABEL] = target
		_, err = k.clientSet.CoreV1().Services(k.appNamespace).Update(ctx, svc, meta.UpdateOptions{})
		return err
	})
	if err != nil {
		return "", nil, fmt.Errorf("promote service %s to %s: %w", n, target, err)
	}
	if prev == target {
		prev = ""
	}
	return prev, prevSelector, nil
}

// RemoveVersion deletes the workload (Deployment plus owned HPA, Secrets and
// ConfigMaps) for one stateless version. A NotFound is treated as success.
func (k *KubernetesCM) RemoveVersion(ctx context.Context, serviceName ContainerName, versionHash string) error {
	if versionHash == "" {
		return nil
	}
	n := sanitizeContainerName(string(serviceName))
	return k.deleteWorkloadObjects(ctx, workloadName(n, versionHash, false))
}

func (k *KubernetesCM) deleteWorkloadObjects(ctx context.Context, wlName string) error {
	var errs []error
	errs = append(errs, k.deleteIfExists("deployment", func() error {
		return k.clientSet.AppsV1().Deployments(k.appNamespace).Delete(ctx, wlName, meta.DeleteOptions{})
	}))
	errs = append(errs, k.deleteIfExists("hpa", func() error {
		return k.clientSet.AutoscalingV2().HorizontalPodAutoscalers(k.appNamespace).Delete(ctx, wlName, meta.DeleteOptions{})
	}))
	// Secrets/ConfigMaps mounted by this version carry its ownership label.
	sel := ownershipSelector(wlName)
	secrets := k.clientSet.CoreV1().Secrets(k.appNamespace)
	if cur, err := secrets.List(ctx, meta.ListOptions{LabelSelector: sel}); err != nil {
		errs = append(errs, fmt.Errorf("list secrets for %s: %w", wlName, err))
	} else {
		for i := range cur.Items {
			name := cur.Items[i].Name
			errs = append(errs, k.deleteIfExists("secret", func() error { return secrets.Delete(ctx, name, meta.DeleteOptions{}) }))
		}
	}
	configMaps := k.clientSet.CoreV1().ConfigMaps(k.appNamespace)
	if cur, err := configMaps.List(ctx, meta.ListOptions{LabelSelector: sel}); err != nil {
		errs = append(errs, fmt.Errorf("list configmaps for %s: %w", wlName, err))
	} else {
		for i := range cur.Items {
			name := cur.Items[i].Name
			errs = append(errs, k.deleteIfExists("configmap", func() error { return configMaps.Delete(ctx, name, meta.DeleteOptions{}) }))
		}
	}
	return errors.Join(errs...)
}

// cleanupInactiveWorkloads deletes the workloads of an app's superseded
// versions. The active version is re-resolved from the live Service at call time
// (rather than captured by the caller), so a cleanup that runs after a delay —
// e.g. the asynchronous post-promotion cleanup — never deletes a version that
// became active in the meantime. Only Deployments created strictly before the
// active one are removed, so a concurrent newer deploy still in flight is also
// preserved.
// cleanupInactiveWorkloadsAsync deletes superseded workloads in a detached
// goroutine. Once the new version is live the old workloads are off-traffic, so
// the deletion need not block the deploy call. It uses a fresh bounded context
// (not the request's) so the cleanup is unaffected by the deploy returning;
// failures are logged and recovered by a later deploy's cleanup pass.
func (k *KubernetesCM) cleanupInactiveWorkloadsAsync(serviceName ContainerName, appID types.AppId, phase string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := k.cleanupInactiveWorkloads(ctx, serviceName); err != nil {
			k.Error().Err(err).Msgf("failed to clean up inactive workloads for app %s %s", appID, phase)
		}
	}()
}

func (k *KubernetesCM) cleanupInactiveWorkloads(ctx context.Context, serviceName ContainerName) error {
	n := sanitizeContainerName(string(serviceName))
	activeName, err := k.activeDeploymentName(ctx, n)
	if err != nil {
		return fmt.Errorf("resolve active deployment for %s: %w", n, err)
	}
	active, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, activeName, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		// No clear active workload (e.g. mid-transition); skip rather than risk
		// deleting a live or in-flight version. The next deploy will clean up.
		return nil
	}
	if err != nil {
		return fmt.Errorf("get active deployment %s/%s: %w", k.appNamespace, activeName, err)
	}

	deps, err := k.clientSet.AppsV1().Deployments(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(map[string]string{"app": n}).String(),
	})
	if err != nil {
		return fmt.Errorf("list deployments for %s: %w", n, err)
	}
	var errs []error
	for i := range deps.Items {
		dep := deps.Items[i]
		// Preserve the active version and anything created at or after it (a newer
		// deploy still in flight); only older, superseded versions are removed.
		if dep.Name == active.Name || !dep.CreationTimestamp.Before(&active.CreationTimestamp) {
			continue
		}
		errs = append(errs, k.deleteWorkloadObjects(ctx, dep.Name))
	}
	return errors.Join(errs...)
}

func (k *KubernetesCM) restoreServiceSelector(ctx context.Context, serviceName ContainerName, selector map[string]string) error {
	n := sanitizeContainerName(string(serviceName))
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, n, meta.GetOptions{})
		if err != nil {
			return err
		}
		svc.Spec.Selector = maps.Clone(selector)
		_, err = k.clientSet.CoreV1().Services(k.appNamespace).Update(ctx, svc, meta.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("restore service %s selector: %w", n, err)
	}
	return nil
}

// activeDeploymentName resolves the Deployment currently behind the Service:
// the versioned workload for stateless apps (from the Service selector's version
// hash), or the stable name for PVC apps.
func (k *KubernetesCM) activeDeploymentName(ctx context.Context, serviceName string) (string, error) {
	svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, serviceName, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		return serviceName, nil // no service yet; in-place name
	}
	if err != nil {
		return "", err
	}
	if h := svc.Spec.Selector[VERSION_HASH_LABEL]; h != "" {
		dep, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, serviceName, meta.GetOptions{})
		if err == nil && dep.Spec.Template.Labels[VERSION_HASH_LABEL] == h {
			return serviceName, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return "", err
		}
		return workloadName(serviceName, h, false), nil
	}
	return serviceName, nil
}

// CurrentVersionHash returns the version hash the stable Service currently
// routes to. It is used by stale app handlers to avoid acting on a newer
// deployment. For stateless apps it is the Service selector's version hash; for
// PVC apps (version-agnostic selector) it is the active Deployment's pod hash.
func (k *KubernetesCM) CurrentVersionHash(ctx context.Context, name ContainerName) (string, error) {
	serviceName := sanitizeContainerName(string(name))
	svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, serviceName, meta.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get service %s/%s: %w", k.appNamespace, serviceName, err)
	}
	if h := svc.Spec.Selector[VERSION_HASH_LABEL]; h != "" {
		return h, nil
	}
	dep, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, serviceName, meta.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get deployment %s/%s: %w", k.appNamespace, serviceName, err)
	}
	return dep.Spec.Template.Labels[VERSION_HASH_LABEL], nil
}

// k8sDeploySnapshot captures the live state of a deployment and its owned
// objects so a failed update can be rolled back. A nil deployment/hpa means it
// did not exist at snapshot time, so Restore deletes any that the failed update
// newly created.
type k8sDeploySnapshot struct {
	name       string
	deployment *appsv1.Deployment
	hpa        *autoscalingv2.HorizontalPodAutoscaler
	service    *core.Service
	secrets    map[string]*core.Secret
	configMaps map[string]*core.ConfigMap
}

// Snapshot captures the current Deployment plus the HPA, Secrets and
// ConfigMaps owned by the named container. Secrets/ConfigMaps are selected by
// the OpenRun ownership labels (see ownershipSelector) so only OpenRun-managed
// objects are captured, never an unrelated object sharing the "app" label.
func (k *KubernetesCM) Snapshot(ctx context.Context, name ContainerName) (any, error) {
	n := sanitizeContainerName(string(name))
	snap := &k8sDeploySnapshot{
		name:       n,
		secrets:    map[string]*core.Secret{},
		configMaps: map[string]*core.ConfigMap{},
	}

	dep, err := k.clientSet.AppsV1().Deployments(k.appNamespace).Get(ctx, n, meta.GetOptions{})
	if err == nil {
		snap.deployment = dep
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("snapshot get deployment %s: %w", n, err)
	}

	hpa, err := k.clientSet.AutoscalingV2().HorizontalPodAutoscalers(k.appNamespace).Get(ctx, n, meta.GetOptions{})
	if err == nil {
		snap.hpa = hpa
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("snapshot get hpa %s: %w", n, err)
	}

	svc, err := k.clientSet.CoreV1().Services(k.appNamespace).Get(ctx, n, meta.GetOptions{})
	if err == nil {
		snap.service = svc
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("snapshot get service %s: %w", n, err)
	}

	sel := ownershipSelector(n)
	secs, err := k.clientSet.CoreV1().Secrets(k.appNamespace).List(ctx, meta.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("snapshot list secrets %s: %w", n, err)
	}
	for i := range secs.Items {
		s := secs.Items[i]
		snap.secrets[s.Name] = &s
	}

	cms, err := k.clientSet.CoreV1().ConfigMaps(k.appNamespace).List(ctx, meta.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("snapshot list configmaps %s: %w", n, err)
	}
	for i := range cms.Items {
		c := cms.Items[i]
		snap.configMaps[c.Name] = &c
	}

	return snap, nil
}

// Restore reverts the Deployment, HPA, Secrets and ConfigMaps to the captured
// snapshot and deletes any of those objects that were created after it. It is
// best-effort: all steps run and the joined error (if any) is returned.
// PVC contents are not reverted.
func (k *KubernetesCM) Restore(ctx context.Context, snapshot any) error {
	snap, ok := snapshot.(*k8sDeploySnapshot)
	if !ok || snap == nil {
		return nil
	}
	var errs []error
	deployments := k.clientSet.AppsV1().Deployments(k.appNamespace)
	hpas := k.clientSet.AutoscalingV2().HorizontalPodAutoscalers(k.appNamespace)
	services := k.clientSet.CoreV1().Services(k.appNamespace)
	secrets := k.clientSet.CoreV1().Secrets(k.appNamespace)
	configMaps := k.clientSet.CoreV1().ConfigMaps(k.appNamespace)

	// Deployment
	if snap.deployment != nil {
		errs = append(errs, restoreObject(ctx, snap.deployment, deployments.Get, deployments.Create, deployments.Update))
	} else {
		errs = append(errs, k.deleteIfExists("deployment", func() error {
			return deployments.Delete(ctx, snap.name, meta.DeleteOptions{})
		}))
	}

	// HPA
	if snap.hpa != nil {
		errs = append(errs, restoreObject(ctx, snap.hpa, hpas.Get, hpas.Create, hpas.Update))
	} else {
		errs = append(errs, k.deleteIfExists("hpa", func() error {
			return hpas.Delete(ctx, snap.name, meta.DeleteOptions{})
		}))
	}

	if snap.service != nil {
		errs = append(errs, restoreObject(ctx, snap.service, services.Get, services.Create, services.Update))
	} else {
		errs = append(errs, k.deleteIfExists("service", func() error {
			return services.Delete(ctx, snap.name, meta.DeleteOptions{})
		}))
	}

	// Secrets and ConfigMaps: delete ones created after the snapshot, then
	// restore the captured ones.
	sel := ownershipSelector(snap.name)
	if cur, err := secrets.List(ctx, meta.ListOptions{LabelSelector: sel}); err != nil {
		errs = append(errs, fmt.Errorf("restore list secrets: %w", err))
	} else {
		for i := range cur.Items {
			if name := cur.Items[i].Name; snap.secrets[name] == nil {
				errs = append(errs, k.deleteIfExists("secret", func() error { return secrets.Delete(ctx, name, meta.DeleteOptions{}) }))
			}
		}
	}
	for _, s := range snap.secrets {
		errs = append(errs, restoreObject(ctx, s, secrets.Get, secrets.Create, secrets.Update))
	}

	if cur, err := configMaps.List(ctx, meta.ListOptions{LabelSelector: sel}); err != nil {
		errs = append(errs, fmt.Errorf("restore list configmaps: %w", err))
	} else {
		for i := range cur.Items {
			if name := cur.Items[i].Name; snap.configMaps[name] == nil {
				errs = append(errs, k.deleteIfExists("configmap", func() error { return configMaps.Delete(ctx, name, meta.DeleteOptions{}) }))
			}
		}
	}
	for _, c := range snap.configMaps {
		errs = append(errs, restoreObject(ctx, c, configMaps.Get, configMaps.Create, configMaps.Update))
	}

	return errors.Join(errs...)
}

// deleteIfExists runs del and treats a NotFound result as success.
func (k *KubernetesCM) deleteIfExists(kind string, del func() error) error {
	if err := del(); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("restore delete %s: %w", kind, err)
	}
	return nil
}

// restorableObject is satisfied by the typed API objects that restore captures
// and re-applies (Deployment, HPA, Secret, ConfigMap).
type restorableObject interface {
	runtime.Object
	meta.Object
}

// restoreObject restores prior to its captured state via the given typed
// client operations: it recreates the object if it no longer exists, otherwise
// overwrites the live spec. ManagedFields are cleared so the next server-side
// apply re-establishes field ownership cleanly.
func restoreObject[T restorableObject](
	ctx context.Context,
	prior T,
	get func(context.Context, string, meta.GetOptions) (T, error),
	create func(context.Context, T, meta.CreateOptions) (T, error),
	update func(context.Context, T, meta.UpdateOptions) (T, error),
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		clone := prior.DeepCopyObject().(T)
		clone.SetManagedFields(nil)
		cur, err := get(ctx, prior.GetName(), meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			clone.SetResourceVersion("")
			clone.SetUID("")
			_, cerr := create(ctx, clone, meta.CreateOptions{})
			return cerr
		}
		if err != nil {
			return err
		}
		clone.SetResourceVersion(cur.GetResourceVersion())
		_, uerr := update(ctx, clone, meta.UpdateOptions{})
		return uerr
	})
}
