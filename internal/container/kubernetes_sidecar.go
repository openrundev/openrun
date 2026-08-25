// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"strings"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

// sidecarPodAdditions returns the pod volumes and the native sidecar
// containers (init containers with restartPolicy Always, Kubernetes >= 1.29)
// for the app's sidecars. Native sidecars start in list order before the app
// container, each gated by its startup probe, restart independently and are
// terminated after the app container. Sidecar volumes sharing a name with an
// app volume resolve to the same pod volume (already in existingVolumes).
func (k *KubernetesCM) sidecarPodAdditions(ctx context.Context, wlName, appImage, sourceDir string,
	paramMap map[string]string, existingVolumes []*corev1apply.VolumeApplyConfiguration) (
	[]*corev1apply.VolumeApplyConfiguration, []*corev1apply.ContainerApplyConfiguration, error) {
	if len(k.sidecars) == 0 {
		return nil, nil, nil
	}
	seenVolumes := map[string]bool{}
	for _, vol := range existingVolumes {
		if vol.Name != nil {
			seenVolumes[*vol.Name] = true
		}
	}

	var podVolumes []*corev1apply.VolumeApplyConfiguration
	var containers []*corev1apply.ContainerApplyConfiguration
	for _, sidecar := range k.sidecars {
		image := sidecar.Image
		if sidecar.IsAppImage {
			image = appImage
		}
		envVars := make([]*corev1apply.EnvVarApplyConfiguration, 0, len(sidecar.Env)+len(k.sidecarAddrEnv))
		for key, value := range sidecar.Env {
			envVars = append(envVars, corev1apply.EnvVar().WithName(key).WithValue(value))
		}
		if sidecar.InheritEnv {
			for key, value := range k.sidecarAddrEnv {
				envVars = append(envVars, corev1apply.EnvVar().WithName(key).WithValue(value))
			}
		}

		cont := corev1apply.Container().
			WithName(sanitizeContainerName(sidecar.Name)).
			WithImage(image).
			WithRestartPolicy(core.ContainerRestartPolicyAlways).
			WithEnv(envVars...)
		if !sidecar.IsAppImage && !strings.Contains(image, "@") {
			cont = cont.WithImagePullPolicy(core.PullAlways)
		}
		if len(sidecar.Command) > 0 {
			cont = cont.WithCommand(sidecar.Command...)
		}
		if len(sidecar.Args) > 0 {
			cont = cont.WithArgs(sidecar.Args...)
		}
		if sidecar.DevWorkDir != "" {
			cont = cont.WithWorkingDir(sidecar.DevWorkDir)
		}
		if sidecar.Port > 0 {
			cont = cont.WithPorts(corev1apply.ContainerPort().
				WithContainerPort(sidecar.Port).
				WithProtocol(core.ProtocolTCP))
			// The startup probe gates the start of the next container (and
			// the app); the liveness probe restarts a hung sidecar. No
			// readiness probe: a sick sidecar does not pull the app out of
			// the Service, the app decides how to treat a failing dependency
			newProbe := func() *corev1apply.ProbeApplyConfiguration {
				probe := corev1apply.Probe().
					WithPeriodSeconds(k.probePeriodSecs()).
					WithTimeoutSeconds(k.probeTimeoutSecs())
				if sidecar.HealthPath != "" {
					return probe.WithHTTPGet(corev1apply.HTTPGetAction().
						WithPath(sidecar.HealthPath).
						WithPort(intstr.FromInt(int(sidecar.Port))).
						WithScheme(core.URISchemeHTTP))
				}
				return probe.WithTCPSocket(corev1apply.TCPSocketAction().
					WithPort(intstr.FromInt(int(sidecar.Port))))
			}
			startupFailures := int32(k.appConfig.Container.HealthAttemptsAfterStartup)
			if startupFailures <= 0 {
				startupFailures = 1
			}
			livenessFailures := int32(k.appConfig.Container.StatusHealthAttempts)
			if livenessFailures <= 0 {
				livenessFailures = 1
			}
			cont = cont.
				WithStartupProbe(newProbe().WithFailureThreshold(startupFailures)).
				WithLivenessProbe(newProbe().WithFailureThreshold(livenessFailures))
		}

		if len(sidecar.Volumes) > 0 {
			vols, mounts, err := k.processVolumes(ctx, suffixedKubernetesName(wlName, "-"+sidecar.Name), wlName, sidecar.Volumes, sourceDir, paramMap)
			if err != nil {
				return nil, nil, fmt.Errorf("sidecar %s volumes: %w", sidecar.Name, err)
			}
			for _, vol := range vols {
				if vol.Name != nil && seenVolumes[*vol.Name] {
					continue
				}
				if vol.Name != nil {
					seenVolumes[*vol.Name] = true
				}
				podVolumes = append(podVolumes, vol)
			}
			cont = cont.WithVolumeMounts(mounts...)
		}

		resources, err := sidecarResources(sidecar)
		if err != nil {
			return nil, nil, err
		}
		if resources != nil {
			cont = cont.WithResources(resources)
		}
		containers = append(containers, cont)
	}
	return podVolumes, containers, nil
}

func (k *KubernetesCM) probePeriodSecs() int32 {
	if p := int32(k.appConfig.Container.DeployProbePeriodSecs); p > 0 {
		return p
	}
	return 1
}

func (k *KubernetesCM) probeTimeoutSecs() int32 {
	if t := int32(k.appConfig.Container.HealthTimeoutSecs); t > 0 {
		return t
	}
	return 1
}

// sidecarResources builds the resource requirements from the sidecar's
// kubernetes.cpus / kubernetes.memory options, nil when neither is set.
func sidecarResources(sidecar *ResolvedSidecar) (*corev1apply.ResourceRequirementsApplyConfiguration, error) {
	opts, err := parseKubernetesOptions(sidecar.Options)
	if err != nil {
		return nil, fmt.Errorf("sidecar %s options: %w", sidecar.Name, err)
	}
	if opts.Cpus == "" && opts.Memory == "" {
		return nil, nil
	}
	requests := core.ResourceList{}
	limits := core.ResourceList{}
	if opts.Cpus != "" {
		cpus, err := CPUString(opts.Cpus, false)
		if err != nil {
			return nil, fmt.Errorf("sidecar %s: error parsing cpus value %q: %w", sidecar.Name, opts.Cpus, err)
		}
		cpuQuantity, err := resource.ParseQuantity(cpus + "m")
		if err != nil {
			return nil, fmt.Errorf("sidecar %s: invalid cpus value %q: %w", sidecar.Name, opts.Cpus, err)
		}
		requests[core.ResourceCPU] = cpuQuantity
	}
	if opts.Memory != "" {
		memory, err := BytesString(opts.Memory)
		if err != nil {
			return nil, fmt.Errorf("sidecar %s: error parsing memory value %q: %w", sidecar.Name, opts.Memory, err)
		}
		memQuantity, err := resource.ParseQuantity(memory)
		if err != nil {
			return nil, fmt.Errorf("sidecar %s: invalid memory value %q: %w", sidecar.Name, opts.Memory, err)
		}
		requests[core.ResourceMemory] = memQuantity
		limits[core.ResourceMemory] = memQuantity
	}
	return corev1apply.ResourceRequirements().WithRequests(requests).WithLimits(limits), nil
}
