// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"encoding/json/v2"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The app env holds resolved secrets and binding credentials: it must be
// stored in a Secret the container loads with envFrom, never as literal
// values in the pod template, and that Secret must carry the workload's
// ownership labels so it is garbage collected with the version
func TestKubernetesCMCreateDeploymentEnvInSecret(t *testing.T) {
	ctx := context.Background()
	appEntry := &types.AppEntry{Metadata: types.AppMetadata{VersionMetadata: types.VersionMetadata{Version: 1}}}
	client := k8sfake.NewSimpleClientset()
	depPatch := captureDeploymentApply(client)
	serviceApplyReactor(client)
	var secretPatch []byte
	client.PrependReactor("patch", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa, ok := action.(k8stesting.PatchAction)
		if !ok || pa.GetPatchType() != k8sapitypes.ApplyPatchType {
			return false, nil, nil
		}
		secretPatch = pa.GetPatch()
		return true, &corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: pa.GetName(), Namespace: pa.GetNamespace()}}, nil
	})
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{},
		clientSet: client, sidecarAddrEnv: map[string]string{"SIDECAR_ADDR": "127.0.0.1:9000"}}

	envMap := map[string]string{"DB_PASSWORD": "hunter2", "API_KEY": "sk-live"}
	if _, err := k.createDeployment(ctx, "myapp", "myapp-hash", true, "img:latest", 8080, envMap, nil, "", nil, appEntry, "hash", KubernetesOptions{}, false, nil); err != nil {
		t.Fatalf("createDeployment: %v", err)
	}

	var secret corev1.Secret
	if err := json.Unmarshal(secretPatch, &secret); err != nil {
		t.Fatalf("unmarshal secret patch: %v", err)
	}
	if secret.Name != "myapp-hash-env" || secret.StringData["DB_PASSWORD"] != "hunter2" || secret.StringData["API_KEY"] != "sk-live" {
		t.Fatalf("env secret: %+v", secret)
	}
	if secret.Labels[MANAGED_BY_LABEL] != MANAGED_BY_VALUE || secret.Labels[INSTANCE_LABEL] != "myapp-hash" {
		t.Fatalf("env secret labels: %v", secret.Labels)
	}

	var dep appsv1.Deployment
	if err := json.Unmarshal(*depPatch, &dep); err != nil {
		t.Fatalf("unmarshal deployment patch: %v", err)
	}
	if string(*depPatch) == "" || containsAny(string(*depPatch), "hunter2", "sk-live") {
		t.Fatalf("deployment spec carries env values: %s", *depPatch)
	}
	c := dep.Spec.Template.Spec.Containers[0]
	if len(c.EnvFrom) != 1 || c.EnvFrom[0].SecretRef == nil || c.EnvFrom[0].SecretRef.Name != "myapp-hash-env" {
		t.Fatalf("envFrom: %+v", c.EnvFrom)
	}
	if len(c.Env) != 1 || c.Env[0].Name != "SIDECAR_ADDR" {
		t.Fatalf("env: %+v, want only the sidecar address", c.Env)
	}
}

// An empty env creates no Secret and no envFrom
func TestKubernetesCMCreateDeploymentNoEnvNoSecret(t *testing.T) {
	ctx := context.Background()
	appEntry := &types.AppEntry{Metadata: types.AppMetadata{VersionMetadata: types.VersionMetadata{Version: 1}}}
	client := k8sfake.NewSimpleClientset()
	depPatch := captureDeploymentApply(client)
	serviceApplyReactor(client)
	client.PrependReactor("patch", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Errorf("unexpected secret apply: %v", action)
		return false, nil, nil
	})
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}
	if _, err := k.createDeployment(ctx, "myapp", "myapp-hash", true, "img:latest", 8080, map[string]string{}, nil, "", nil, appEntry, "hash", KubernetesOptions{}, false, nil); err != nil {
		t.Fatalf("createDeployment: %v", err)
	}
	var dep appsv1.Deployment
	if err := json.Unmarshal(*depPatch, &dep); err != nil {
		t.Fatalf("unmarshal deployment patch: %v", err)
	}
	if c := dep.Spec.Template.Spec.Containers[0]; len(c.EnvFrom) != 0 {
		t.Fatalf("envFrom: %+v", c.EnvFrom)
	}
}

// A job run's env goes in a Secret owned by the Job and loaded with envFrom;
// RemoveJob and RemoveAppJobs delete it with the Job
func TestKubernetesCMRunJobEnvInSecret(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}
	appEntry := &types.AppEntry{Id: "app_prd_job1", Path: "/jobs", Metadata: types.AppMetadata{VersionMetadata: types.VersionMetadata{Version: 1}}}

	// Cancel the run once the Job exists: RunJob then deletes the Job and
	// returns, without waiting on the poll ticker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return false, nil, nil
	})
	var removed []string
	client.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		removed = append(removed, action.GetResource().Resource+"/"+action.(k8stesting.DeleteAction).GetName())
		return false, nil, nil
	})

	req := JobRunRequest{AppEntry: appEntry, RunId: "run1", JobName: "nightly", ContainerName: "clc-job1-nightly-run1",
		Image: "img:latest", Argv: []string{"run"}, Env: map[string]string{"DB_PASSWORD": "hunter2"}}
	if _, err := k.RunJob(ctx, req); err != context.Canceled {
		t.Fatalf("RunJob: %v, want context canceled", err)
	}
	jobName := jobObjectName(req.ContainerName)
	secretName := jobName + "-env"

	// The Job was created with envFrom only and the Secret was made its own
	createdJob := func() *batchv1.Job {
		for _, a := range client.Actions() {
			if ca, ok := a.(k8stesting.CreateAction); ok && a.GetResource().Resource == "jobs" {
				return ca.GetObject().(*batchv1.Job)
			}
		}
		return nil
	}()
	if createdJob == nil {
		t.Fatal("job not created")
	}
	c := createdJob.Spec.Template.Spec.Containers[0]
	if len(c.Env) != 0 || len(c.EnvFrom) != 1 || c.EnvFrom[0].SecretRef == nil || c.EnvFrom[0].SecretRef.Name != secretName {
		t.Fatalf("job container env=%+v envFrom=%+v", c.Env, c.EnvFrom)
	}
	for _, a := range client.Actions() {
		if ua, ok := a.(k8stesting.UpdateAction); ok && a.GetVerb() == "update" && a.GetResource().Resource == "secrets" {
			secret := ua.GetObject().(*corev1.Secret)
			if secret.StringData["DB_PASSWORD"] != "hunter2" || secret.Labels[LABEL_PREFIX+"app.id"] != "app_prd_job1" ||
				secret.Labels[MANAGED_BY_LABEL] != MANAGED_BY_VALUE {
				t.Fatalf("env secret: %+v", secret)
			}
			if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Kind != "Job" || secret.OwnerReferences[0].Name != jobName {
				t.Fatalf("env secret owner: %+v", secret.OwnerReferences)
			}
		}
	}
	// The canceled run deleted the Job and the Secret
	if !containsAll(removed, "jobs/"+jobName, "secrets/"+secretName) {
		t.Fatalf("deleted: %v", removed)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(context.Background(), secretName, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("env secret still present: %v", err)
	}

	// RemoveAppJobs deletes the app's env Secrets by label as well
	leftover := &corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: "clc-job1-nightly-run0-env", Namespace: "apps",
		Labels: jobEnvSecretLabels("clc-job1-nightly-run0", appEntry.Id)}}
	other := &corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: "other-app-env", Namespace: "apps",
		Labels: jobEnvSecretLabels("other", "app_prd_other")}}
	for _, s := range []*corev1.Secret{leftover, other} {
		if _, err := client.CoreV1().Secrets("apps").Create(context.Background(), s, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.RemoveAppJobs(context.Background(), string(appEntry.Id)); err != nil {
		t.Fatalf("RemoveAppJobs: %v", err)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(context.Background(), leftover.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("app env secret not deleted: %v", err)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(context.Background(), other.Name, meta.GetOptions{}); err != nil {
		t.Fatalf("other app's secret deleted: %v", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func containsAll(items []string, wants ...string) bool {
	for _, w := range wants {
		found := false
		for _, it := range items {
			if it == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
