package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestParseKubernetesOptions(t *testing.T) {
	opts := map[string]string{
		"kubernetes.cpus":         "500m",
		"kubernetes.memory":       "1Gi",
		"min_replicas":            "2",
		"kubernetes.max_replicas": "5",
		"kubernetes.custom":       "value",
		"ignored.option":          "nope",
	}

	got, err := parseKubernetesOptions(opts)
	if err != nil {
		t.Fatalf("parseKubernetesOptions returned error: %v", err)
	}

	if got.Cpus != "500m" {
		t.Fatalf("Cpus = %q, want %q", got.Cpus, "500m")
	}
	if got.Memory != "1Gi" {
		t.Fatalf("Memory = %q, want %q", got.Memory, "1Gi")
	}
	if got.MinReplicas != 2 {
		t.Fatalf("MinReplicas = %d, want %d", got.MinReplicas, 2)
	}
	if got.MaxReplicas != 5 {
		t.Fatalf("MaxReplicas = %d, want %d", got.MaxReplicas, 5)
	}
	if got.Other["custom"] != "value" {
		t.Fatalf("Other[custom] = %#v, want %q", got.Other["custom"], "value")
	}
	if _, ok := got.Other["ignored.option"]; ok {
		t.Fatalf("ignored option should not be decoded, got %#v", got.Other["ignored.option"])
	}
}

func TestParseKubernetesOptionsInvalidValue(t *testing.T) {
	_, err := parseKubernetesOptions(map[string]string{"min_replicas": "not-a-number"})
	if err == nil {
		t.Fatal("expected parseKubernetesOptions to fail for invalid min_replicas")
	}
}

func TestSanitizeContainerName(t *testing.T) {
	name := sanitizeContainerName("my_app:version_with_extra_text_that_should_be_trimmed_because_it_is_very_long")
	if strings.Contains(name, "_") || strings.Contains(name, ":") {
		t.Fatalf("sanitizeContainerName should replace underscores/colons, got %q", name)
	}
	if len(name) > 50 {
		t.Fatalf("sanitizeContainerName length = %d, want <= 50", len(name))
	}
}

func TestTrimLabelValue(t *testing.T) {
	long := strings.Repeat("a", 80)
	trimmed := TrimLabelValue(long)
	if len(trimmed) != 63 {
		t.Fatalf("TrimLabelValue length = %d, want 63", len(trimmed))
	}

	short := "short"
	if TrimLabelValue(short) != short {
		t.Fatalf("TrimLabelValue changed short input")
	}
}

func TestIsPodReady(t *testing.T) {
	readyPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	if !isPodReady(readyPod) {
		t.Fatal("isPodReady should return true for running pod with Ready=True")
	}

	notRunning := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	if isPodReady(notRunning) {
		t.Fatal("isPodReady should return false for non-running pod")
	}

	noReadyCondition := &corev1.Pod{
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if isPodReady(noReadyCondition) {
		t.Fatal("isPodReady should return false without Ready=True condition")
	}
}

func TestNamespaceExists(t *testing.T) {
	ctx := context.Background()

	t.Run("namespace exists", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(&corev1.Namespace{
			ObjectMeta: meta.ObjectMeta{Name: "apps"},
		})
		exists, err := namespaceExists(ctx, client, "apps")
		if err != nil {
			t.Fatalf("namespaceExists returned error: %v", err)
		}
		if !exists {
			t.Fatal("namespaceExists returned false for existing namespace")
		}
	})

	t.Run("namespace not found", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		exists, err := namespaceExists(ctx, client, "missing")
		if err != nil {
			t.Fatalf("namespaceExists returned error: %v", err)
		}
		if exists {
			t.Fatal("namespaceExists returned true for missing namespace")
		}
	})

	t.Run("returns real error", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		client.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("boom")
		})
		exists, err := namespaceExists(ctx, client, "apps")
		if err == nil {
			t.Fatal("namespaceExists should return reactor error")
		}
		if exists {
			t.Fatal("namespaceExists should be false when get call fails")
		}
	})
}

func TestKubernetesCMSupportsInPlaceUpdate(t *testing.T) {
	k := &KubernetesCM{}
	if !k.SupportsInPlaceUpdate() {
		t.Fatal("SupportsInPlaceUpdate should return true")
	}
}

func TestKubernetesCMImageExistsRequiresRegistryURL(t *testing.T) {
	k := &KubernetesCM{
		config: &types.ServerConfig{},
	}
	_, err := k.ImageExists(context.Background(), ImageName("sample:latest"))
	if err == nil {
		t.Fatal("ImageExists should fail when registry URL is empty")
	}
	if !strings.Contains(err.Error(), "registry url is required") {
		t.Fatalf("error = %q, expected missing registry message", err)
	}
}

func TestKubernetesCMBuildImageValidation(t *testing.T) {
	t.Run("requires registry URL", func(t *testing.T) {
		k := &KubernetesCM{
			config: &types.ServerConfig{},
		}
		err := k.BuildImage(context.Background(), ImageName("img:latest"), ".", "Dockerfile", nil)
		if err == nil {
			t.Fatal("BuildImage should fail when registry URL is empty")
		}
		if !strings.Contains(err.Error(), "registry url is required") {
			t.Fatalf("error = %q, expected missing registry message", err)
		}
	})

	t.Run("rejects invalid builder mode", func(t *testing.T) {
		k := &KubernetesCM{
			config: &types.ServerConfig{
				Registry: types.RegistryConfig{URL: "registry.example.com"},
				Builder:  types.BuilderConfig{Mode: "unknown-mode"},
			},
		}
		err := k.BuildImage(context.Background(), ImageName("img:latest"), ".", "Dockerfile", nil)
		if err == nil {
			t.Fatal("BuildImage should fail for invalid builder mode")
		}
		if !strings.Contains(err.Error(), "invalid builder mode") {
			t.Fatalf("error = %q, expected invalid builder mode message", err)
		}
	})
}

func TestKubernetesCMGetContainerState(t *testing.T) {
	ctx := context.Background()

	t.Run("service not found returns not running", func(t *testing.T) {
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{},
			appConfig:    &types.AppConfig{},
			clientSet:    k8sfake.NewSimpleClientset(),
		}
		host, running, err := k.GetContainerState(ctx, ContainerName("myapp"), "")
		if err != nil {
			t.Fatalf("GetContainerState returned error: %v", err)
		}
		if host != "" || running {
			t.Fatalf("host=%q running=%t, want empty,false", host, running)
		}
	})

	t.Run("service with no ports errors", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
		})
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{},
			appConfig:    &types.AppConfig{},
			clientSet:    client,
		}
		_, _, err := k.GetContainerState(ctx, ContainerName("myapp"), "")
		if err == nil || !strings.Contains(err.Error(), "has no ports") {
			t.Fatalf("error = %v, want no ports error", err)
		}
	})

	t.Run("strict version mismatch returns not running", func(t *testing.T) {
		replicas := int32(1)
		client := k8sfake.NewSimpleClientset(
			&corev1.Service{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
				Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
					{Port: 8080},
				}},
			},
			&appsv1.Deployment{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: meta.ObjectMeta{
							Labels: map[string]string{VERSION_HASH_LABEL: "actual"},
						},
					},
				},
			},
		)
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{},
			appConfig:    &types.AppConfig{Kubernetes: types.Kubernetes{StrictVersionCheck: true}},
			clientSet:    client,
		}
		host, running, err := k.GetContainerState(ctx, ContainerName("myapp"), "expected")
		if err != nil {
			t.Fatalf("GetContainerState returned error: %v", err)
		}
		if host != "" || running {
			t.Fatalf("host=%q running=%t, want empty,false", host, running)
		}
	})

	t.Run("strict version and ready pod returns running", func(t *testing.T) {
		replicas := int32(1)
		hash := "expected-hash"
		client := k8sfake.NewSimpleClientset(
			&corev1.Service{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
				Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
					{Port: 8080},
				}},
			},
			&appsv1.Deployment{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps", Generation: 2},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: meta.ObjectMeta{
							Labels: map[string]string{VERSION_HASH_LABEL: TrimLabelValue(hash)},
						},
					},
				},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  2,
					UpdatedReplicas:     1,
					ReadyReplicas:       1,
					UnavailableReplicas: 0,
					Replicas:            1,
				},
			},
			&corev1.Pod{
				ObjectMeta: meta.ObjectMeta{
					Name:      "myapp-pod",
					Namespace: "apps",
					Labels: map[string]string{
						"app":              "myapp",
						VERSION_HASH_LABEL: TrimLabelValue(hash),
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionTrue},
					},
				},
			},
		)
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{},
			appConfig:    &types.AppConfig{Kubernetes: types.Kubernetes{StrictVersionCheck: true}},
			clientSet:    client,
		}
		host, running, err := k.GetContainerState(ctx, ContainerName("myapp"), hash)
		if err != nil {
			t.Fatalf("GetContainerState returned error: %v", err)
		}
		if host != "myapp.apps.svc.cluster.local:8080" || !running {
			t.Fatalf("host=%q running=%t, want service DNS and true", host, running)
		}
	})

	t.Run("nodeport mode returns localhost endpoint", func(t *testing.T) {
		replicas := int32(1)
		client := k8sfake.NewSimpleClientset(
			&corev1.Service{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
				Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
					{Port: 8080, NodePort: 30080},
				}},
			},
			&appsv1.Deployment{
				ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{}}},
				},
			},
			&corev1.Pod{
				ObjectMeta: meta.ObjectMeta{Name: "myapp-pod", Namespace: "apps", Labels: map[string]string{"app": "myapp"}},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					Conditions: []corev1.PodCondition{
						{Type: corev1.PodReady, Status: corev1.ConditionTrue},
					},
				},
			},
		)
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{Kubernetes: types.KubernetesConfig{UseNodePort: true}},
			appConfig:    &types.AppConfig{Kubernetes: types.Kubernetes{StrictVersionCheck: false}},
			clientSet:    client,
		}
		host, running, err := k.GetContainerState(ctx, ContainerName("myapp"), "")
		if err != nil {
			t.Fatalf("GetContainerState returned error: %v", err)
		}
		if host != "127.0.0.1:30080" || !running {
			t.Fatalf("host=%q running=%t, want localhost nodeport and true", host, running)
		}
	})
}

func TestKubernetesCMStartStopContainer(t *testing.T) {
	var replicas int32
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getAction, ok := action.(k8stesting.GetAction)
		if !ok || getAction.GetSubresource() != "scale" {
			return false, nil, nil
		}
		return true, &autoscalingv1.Scale{Spec: autoscalingv1.ScaleSpec{Replicas: replicas}}, nil
	})
	client.PrependReactor("update", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateAction, ok := action.(k8stesting.UpdateAction)
		if !ok || updateAction.GetSubresource() != "scale" {
			return false, nil, nil
		}
		scale, ok := updateAction.GetObject().(*autoscalingv1.Scale)
		if !ok {
			return false, nil, nil
		}
		replicas = scale.Spec.Replicas
		return true, scale, nil
	})

	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		clientSet:    client,
	}

	if err := k.StartContainer(context.Background(), ContainerName("myapp")); err != nil {
		t.Fatalf("StartContainer returned error: %v", err)
	}
	if replicas != 1 {
		t.Fatalf("replicas after StartContainer = %d, want 1", replicas)
	}

	if err := k.StopContainer(context.Background(), ContainerName("myapp")); err != nil {
		t.Fatalf("StopContainer returned error: %v", err)
	}
	if replicas != 0 {
		t.Fatalf("replicas after StopContainer = %d, want 0", replicas)
	}
}

func TestKubernetesCMGetContainerLogsNoPods(t *testing.T) {
	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		clientSet:    k8sfake.NewSimpleClientset(),
	}
	_, err := k.GetContainerLogs(context.Background(), ContainerName("myapp"), 50)
	if err == nil || !strings.Contains(err.Error(), "no pods found") {
		t.Fatalf("error = %v, want no pods found", err)
	}
}

func TestKubernetesCMVolumeHelpers(t *testing.T) {
	ctx := context.Background()

	t.Run("VolumeExists", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(&corev1.PersistentVolumeClaim{
			ObjectMeta: meta.ObjectMeta{Name: "vol", Namespace: "apps"},
		})
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			clientSet:    client,
		}
		if !k.VolumeExists(ctx, VolumeName("vol")) {
			t.Fatal("VolumeExists should return true for existing PVC")
		}
		if k.VolumeExists(ctx, VolumeName("missing")) {
			t.Fatal("VolumeExists should return false for missing PVC")
		}
	})

	t.Run("VolumeCreate", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		addApplyPatchReactor(client, "persistentvolumeclaims", func(name, namespace string) runtime.Object {
			return &corev1.PersistentVolumeClaim{
				ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
			}
		})
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			appConfig:    &types.AppConfig{Kubernetes: types.Kubernetes{DefaultVolumeSize: "1Gi"}},
			clientSet:    client,
		}
		if err := k.VolumeCreate(ctx, VolumeName("vol")); err != nil {
			t.Fatalf("VolumeCreate returned error: %v", err)
		}
	})
}

func TestKubernetesCMProcessVolumes(t *testing.T) {
	ctx := context.Background()
	sourceDir := t.TempDir()
	appRunDir := t.TempDir()
	client := k8sfake.NewSimpleClientset()
	addApplyPatchReactor(client, "secrets", func(name, namespace string) runtime.Object {
		return &corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}}
	})
	addApplyPatchReactor(client, "configmaps", func(name, namespace string) runtime.Object {
		return &corev1.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}}
	})

	secretTemplate := filepath.Join(sourceDir, "secret.txt")
	configFile := filepath.Join(sourceDir, "config.yaml")
	if err := os.WriteFile(secretTemplate, []byte("secret: {{.params.token}}\n"), 0o600); err != nil {
		t.Fatalf("write secret template: %v", err)
	}
	if err := os.WriteFile(configFile, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		appRunDir:    appRunDir,
		appId:        types.AppId("app-1"),
		clientSet:    client,
	}

	volumes := []*VolumeInfo{
		{
			IsSecret:   true,
			SourcePath: "secret.txt",
			TargetPath: "/etc/secret.txt",
			ReadOnly:   true,
		},
		{
			IsSecret:   false,
			VolumeName: "",
			SourcePath: "config.yaml",
			TargetPath: "/etc/config.yaml",
			ReadOnly:   true,
		},
		{
			IsSecret:   false,
			VolumeName: UNNAMED_VOLUME,
			TargetPath: "/data",
			ReadOnly:   false,
		},
	}

	podVolumes, mounts, err := k.processVolumes(ctx, "myapp", volumes, sourceDir, map[string]string{"token": "abc123"})
	if err != nil {
		t.Fatalf("processVolumes returned error: %v", err)
	}
	if len(podVolumes) != 3 || len(mounts) != 3 {
		t.Fatalf("unexpected volume/mount counts: %d volumes, %d mounts", len(podVolumes), len(mounts))
	}
}

func TestKubernetesCMCreateDeploymentValidationErrors(t *testing.T) {
	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		appRunDir:    t.TempDir(),
		appId:        types.AppId("app-1"),
		clientSet:    k8sfake.NewSimpleClientset(),
		config:       &types.ServerConfig{},
		appConfig:    &types.AppConfig{Kubernetes: types.Kubernetes{ScalingThresholdCPU: 80}},
	}

	appEntry := &types.AppEntry{
		Metadata: types.AppMetadata{
			VersionMetadata: types.VersionMetadata{Version: 1, GitCommit: "deadbeef"},
		},
	}

	_, err := k.createDeployment(context.Background(), "myapp", "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{Cpus: "invalid"})
	if err == nil || !strings.Contains(err.Error(), "error parsing cpus value") {
		t.Fatalf("error = %v, want cpu parse error", err)
	}

	_, err = k.createDeployment(context.Background(), "myapp", "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{Memory: "invalid"})
	if err == nil || !strings.Contains(err.Error(), "error parsing memory value") {
		t.Fatalf("error = %v, want memory parse error", err)
	}
}

func newTestLogger() *types.Logger {
	return types.NewLogger(&types.LogConfig{Level: "INFO"})
}

func addApplyPatchReactor(client *k8sfake.Clientset, resource string, objFn func(name, namespace string) runtime.Object) {
	client.PrependReactor("patch", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(k8stesting.PatchAction)
		if !ok || patchAction.GetPatchType() != k8sapitypes.ApplyPatchType {
			return false, nil, nil
		}
		return true, objFn(patchAction.GetName(), patchAction.GetNamespace()), nil
	})
}
