// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const jobTTLSecondsAfterFinished = int32(24 * 60 * 60)

var _ JobRunner = (*KubernetesCM)(nil)

// jobObjectName fits a job container name into a Kubernetes object name,
// hashing the middle when too long so the run suffix stays unique
func jobObjectName(name ContainerName) string {
	s := sanitizeName(string(name))
	if len(s) <= KUBERNETES_NAME_MAX {
		return s
	}
	suffixLen := 9 // "-" + the 8 char run suffix
	if len(s) <= suffixLen {
		return s
	}
	return suffixedKubernetesName(s[:len(s)-suffixLen], s[len(s)-suffixLen:])
}

// RunJob creates a batch/v1 Job for the run and waits for it to finish. The
// Job is left in place (with a one day TTL backstop) so JobLogs can read the
// pod until the run record is retired. Canceling ctx deletes the Job
func (k *KubernetesCM) RunJob(ctx context.Context, req JobRunRequest) (int, error) {
	image := req.Image
	if strings.HasPrefix(image, IMAGE_NAME_PREFIX) {
		image = k.registryRef(image)
	}
	kubernetesOptions, err := parseKubernetesOptions(req.ContainerOptions)
	if err != nil {
		return -1, fmt.Errorf("error parsing kubernetes options: %w", err)
	}
	name := jobObjectName(req.ContainerName)

	podLabels := map[string]string{
		"app":                        name,
		LABEL_PREFIX + "app.id":      TrimLabelValue(string(req.AppEntry.Id)),
		LABEL_PREFIX + JobNameLabel:  TrimLabelValue(req.JobName),
		LABEL_PREFIX + JobRunLabel:   TrimLabelValue(req.RunId),
		LABEL_PREFIX + "app.version": strconv.Itoa(req.AppEntry.Metadata.VersionMetadata.Version),
		MANAGED_BY_LABEL:             MANAGED_BY_VALUE,
		INSTANCE_LABEL:               TrimLabelValue(name),
	}
	annotations := map[string]string{
		LABEL_PREFIX + "app.id":    string(req.AppEntry.Id),
		LABEL_PREFIX + "app.path":  req.AppEntry.Path,
		LABEL_PREFIX + JobRunLabel: req.RunId,
	}

	envVars := make([]core.EnvVar, 0, len(req.Env))
	for key, value := range req.Env {
		envVars = append(envVars, core.EnvVar{Name: key, Value: value})
	}

	container := core.Container{
		Name:    "job",
		Image:   image,
		Env:     envVars,
		Command: req.Argv,
	}
	if !strings.Contains(image, "@") {
		container.ImagePullPolicy = core.PullAlways
	}
	if kubernetesOptions.Cpus != "" || kubernetesOptions.Memory != "" {
		requests := core.ResourceList{}
		limits := core.ResourceList{}
		if kubernetesOptions.Cpus != "" {
			cpus, err := CPUString(kubernetesOptions.Cpus, false)
			if err != nil {
				return -1, fmt.Errorf("error parsing cpus value %q: %w", kubernetesOptions.Cpus, err)
			}
			cpuQuantity, err := resource.ParseQuantity(cpus + "m")
			if err != nil {
				return -1, fmt.Errorf("invalid cpus value %q: %w", kubernetesOptions.Cpus, err)
			}
			requests[core.ResourceCPU] = cpuQuantity
		}
		if kubernetesOptions.Memory != "" {
			memory, err := BytesString(kubernetesOptions.Memory)
			if err != nil {
				return -1, fmt.Errorf("error parsing memory value %q: %w", kubernetesOptions.Memory, err)
			}
			memQuantity, err := resource.ParseQuantity(memory)
			if err != nil {
				return -1, fmt.Errorf("invalid memory value %q: %w", kubernetesOptions.Memory, err)
			}
			requests[core.ResourceMemory] = memQuantity
			limits[core.ResourceMemory] = memQuantity
		}
		container.Resources = core.ResourceRequirements{Requests: requests, Limits: limits}
	}

	backoffLimit := int32(0)
	ttl := jobTTLSecondsAfterFinished
	automount := false
	job := &batchv1.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:        name,
			Namespace:   k.appNamespace,
			Labels:      podLabels,
			Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttl,
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{Labels: podLabels, Annotations: annotations},
				Spec: core.PodSpec{
					RestartPolicy:                core.RestartPolicyNever,
					AutomountServiceAccountToken: &automount,
					Containers:                   []core.Container{container},
				},
			},
		},
	}
	if req.Timeout > 0 {
		deadline := int64(req.Timeout.Seconds())
		job.Spec.ActiveDeadlineSeconds = &deadline
	}

	if _, err := k.clientSet.BatchV1().Jobs(k.appNamespace).Create(ctx, job, meta.CreateOptions{}); err != nil {
		return -1, fmt.Errorf("create job %s: %w", name, err)
	}
	k.Info().Msgf("created kubernetes job %s for run %s", name, req.RunId)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := k.RemoveJob(delCtx, req.ContainerName); err != nil {
				k.Warn().Err(err).Msgf("error deleting canceled job %s", name)
			}
			cancel()
			return -1, ctx.Err()
		case <-ticker.C:
		}
		current, err := k.clientSet.BatchV1().Jobs(k.appNamespace).Get(ctx, name, meta.GetOptions{})
		if err != nil {
			if ctx.Err() != nil {
				continue
			}
			return -1, fmt.Errorf("get job %s: %w", name, err)
		}
		done := false
		failed := false
		for _, cond := range current.Status.Conditions {
			if cond.Status != core.ConditionTrue {
				continue
			}
			switch cond.Type {
			case batchv1.JobComplete:
				done = true
			case batchv1.JobFailed:
				done, failed = true, true
			}
		}
		if !done {
			continue
		}
		exitCode, found := k.jobPodExitCode(ctx, name)
		if !failed {
			return 0, nil
		}
		if found {
			return exitCode, nil
		}
		return -1, nil
	}
}

// jobPodExitCode reads the terminated exit code of the Job's pod container
func (k *KubernetesCM) jobPodExitCode(ctx context.Context, name string) (int, bool) {
	pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(map[string]string{"job-name": name}).String(),
	})
	if err != nil || len(pods.Items) == 0 {
		return -1, false
	}
	for _, pod := range pods.Items {
		for _, status := range pod.Status.ContainerStatuses {
			if status.State.Terminated != nil {
				return int(status.State.Terminated.ExitCode), true
			}
		}
	}
	return -1, false
}

// RemoveJob deletes the Job and its pods
func (k *KubernetesCM) RemoveJob(ctx context.Context, name ContainerName) error {
	propagation := meta.DeletePropagationBackground
	err := k.clientSet.BatchV1().Jobs(k.appNamespace).Delete(ctx, jobObjectName(name), meta.DeleteOptions{PropagationPolicy: &propagation})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete job %s: %w", name, err)
	}
	return nil
}

// JobLogs returns the last lines of the Job's pod output
func (k *KubernetesCM) JobLogs(ctx context.Context, name ContainerName, lines int) (string, error) {
	jobName := jobObjectName(name)
	pods, err := k.clientSet.CoreV1().Pods(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(map[string]string{"job-name": jobName}).String(),
	})
	if err != nil {
		return "", fmt.Errorf("list pods for job %s: %w", jobName, err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", jobName)
	}
	pod := pods.Items[0]
	tailLines := int64(lines)
	req := k.clientSet.CoreV1().Pods(k.appNamespace).GetLogs(pod.Name, &core.PodLogOptions{Container: "job", TailLines: &tailLines})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("get logs for pod %s: %w", pod.Name, err)
	}
	defer stream.Close() //nolint:errcheck
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, stream); err != nil {
		return "", fmt.Errorf("read logs for pod %s: %w", pod.Name, err)
	}
	return buf.String(), nil
}

// RemoveAppJobs deletes every Job of an app (app delete)
func (k *KubernetesCM) RemoveAppJobs(ctx context.Context, appId string) error {
	jobs, err := k.clientSet.BatchV1().Jobs(k.appNamespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set(map[string]string{LABEL_PREFIX + "app.id": TrimLabelValue(appId)}).String(),
	})
	if err != nil {
		return fmt.Errorf("list jobs for app %s: %w", appId, err)
	}
	propagation := meta.DeletePropagationBackground
	var errs []error
	for i := range jobs.Items {
		name := jobs.Items[i].Name
		if err := k.clientSet.BatchV1().Jobs(k.appNamespace).Delete(ctx, name, meta.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete job %s: %w", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}
