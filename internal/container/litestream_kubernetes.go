// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

// sqliteVolumeFSGroup is the fsGroup set on pods with sqlite binding volumes:
// kubernetes chowns the volume to this group at mount time (on storage with
// ownership management) and adds it as a supplementary group to every
// container process, making the volume writable for arbitrary non-root app
// users. 65532 is the conventional "nonroot" id.
const sqliteVolumeFSGroup = int64(65532)

// sqliteVolumePermsInitContainer returns an init container that makes the
// sqlite binding volume directories writable for the app image's (possibly
// non-root) user: a fresh PVC mount is root-owned, and restore init
// containers write files as root. Runs the app's own image (guaranteed
// present) as root; requires a chmod binary in the image (true for standard
// base images; distroless images are not supported for sqlite bindings).
func (k *KubernetesCM) sqliteVolumePermsInitContainer(image string, volumes []*VolumeInfo) *corev1apply.ContainerApplyConfiguration {
	var mounts []*corev1apply.VolumeMountApplyConfiguration
	args := []string{"-R", "0777"}
	for _, vol := range volumes {
		if vol.IsSecret || vol.VolumeName == "" || !vol.InitPerms {
			continue
		}
		dir := vol.VolumeName
		if dir == UNNAMED_VOLUME {
			dir = vol.TargetPath
		}
		mounts = append(mounts, corev1apply.VolumeMount().
			WithName(sanitizeContainerName(string(GenVolumeName(k.appId, dir)))).
			WithMountPath(vol.TargetPath))
		args = append(args, vol.TargetPath)
	}
	if len(mounts) == 0 {
		return nil
	}
	return corev1apply.Container().
		WithName("sqlite-volume-perms").
		WithImage(image).
		WithCommand("chmod").
		WithArgs(args...).
		WithSecurityContext(corev1apply.SecurityContext().
			WithRunAsUser(0).
			WithRunAsNonRoot(false)).
		WithVolumeMounts(mounts...)
}

// litestreamObjectSuffix names the per-workload litestream ConfigMap and
// Secret, which carry the workload ownership labels so workload cleanup
// removes them.
const litestreamObjectSuffix = "-litestream"

// applyLitestreamObjects server-side-applies the litestream companion's
// ConfigMap (the rendered config, no credentials) and Secret (the credential
// env values) for one workload. Returns the object name (shared).
func (k *KubernetesCM) applyLitestreamObjects(ctx context.Context, wlName string, spec *LitestreamAppSpec) (string, error) {
	objName := suffixedKubernetesName(wlName, litestreamObjectSuffix)

	configMapApply := corev1apply.ConfigMap(objName, k.appNamespace).
		WithLabels(ownershipLabels(wlName)).
		WithData(map[string]string{LitestreamConfigFileName: spec.ConfigYAML})
	if _, err := k.clientSet.CoreV1().ConfigMaps(k.appNamespace).Apply(ctx, configMapApply, applyOptions()); err != nil {
		return "", fmt.Errorf("apply litestream configmap %s: %w", objName, err)
	}

	secretData := map[string][]byte{}
	for key, value := range spec.Env {
		secretData[key] = []byte(value)
	}
	secretApply := corev1apply.Secret(objName, k.appNamespace).
		WithLabels(ownershipLabels(wlName)).
		WithData(secretData)
	if _, err := k.clientSet.CoreV1().Secrets(k.appNamespace).Apply(ctx, secretApply, applyOptions()); err != nil {
		return "", fmt.Errorf("apply litestream secret %s: %w", objName, err)
	}
	return objName, nil
}

// litestreamPodAdditions returns the extra pod volume (config) and the init
// containers for the litestream companion: one restore init container per
// database (litestream restore is per-file; the databases were enumerated
// from the replica by the server), then the replication sidecar as a native
// sidecar (init container with restartPolicy Always, Kubernetes >= 1.29): it
// starts before the app container, restarts independently and is terminated
// after the app on pod shutdown, giving replication a final sync window.
func (k *KubernetesCM) litestreamPodAdditions(objName string, spec *LitestreamAppSpec) (
	[]*corev1apply.VolumeApplyConfiguration, []*corev1apply.ContainerApplyConfiguration, *corev1apply.ContainerApplyConfiguration) {

	configVolName := objName + "-cfg"
	podVolumes := []*corev1apply.VolumeApplyConfiguration{
		corev1apply.Volume().
			WithName(configVolName).
			WithConfigMap(corev1apply.ConfigMapVolumeSource().WithName(objName)),
	}

	// The app data volumes are already in the pod spec (the app container
	// mounts them); the companion containers reference the same pod volume
	// names at the same target paths so file paths match the app's view.
	dataMounts := make([]*corev1apply.VolumeMountApplyConfiguration, 0, len(spec.Mounts))
	for _, mount := range spec.Mounts {
		dataMounts = append(dataMounts, corev1apply.VolumeMount().
			WithName(sanitizeContainerName(string(mount.VolumeName))).
			WithMountPath(mount.TargetDir))
	}
	envFrom := corev1apply.EnvFromSource().
		WithSecretRef(corev1apply.SecretEnvSource().WithName(objName))

	var initContainers []*corev1apply.ContainerApplyConfiguration
	for i, restore := range spec.Restores {
		initContainers = append(initContainers, corev1apply.Container().
			WithName(fmt.Sprintf("litestream-restore-%d", i)).
			WithImage(spec.Image).
			WithArgs("restore", "-if-db-not-exists", "-o", restore.OutputPath, restore.ReplicaURL).
			WithEnvFrom(envFrom).
			WithVolumeMounts(dataMounts...))
	}

	sidecarMounts := append([]*corev1apply.VolumeMountApplyConfiguration{
		corev1apply.VolumeMount().
			WithName(configVolName).
			WithMountPath("/etc/litestream.yml").
			WithSubPath(LitestreamConfigFileName).
			WithReadOnly(true),
	}, dataMounts...)

	sidecar := corev1apply.Container().
		WithName("litestream").
		WithImage(spec.Image).
		WithArgs("replicate", "-config", "/etc/litestream.yml").
		WithRestartPolicy(core.ContainerRestartPolicyAlways).
		WithEnvFrom(envFrom).
		WithVolumeMounts(sidecarMounts...).
		WithResources(corev1apply.ResourceRequirements().
			WithRequests(core.ResourceList{
				core.ResourceCPU:    resource.MustParse("10m"),
				core.ResourceMemory: resource.MustParse("32Mi"),
			}).
			WithLimits(core.ResourceList{
				core.ResourceMemory: resource.MustParse("256Mi"),
			}))

	return podVolumes, initContainers, sidecar
}
