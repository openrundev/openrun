package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
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

func TestKubernetesCMRefreshImageRejectsInvalidReference(t *testing.T) {
	k := &KubernetesCM{
		Logger: newTestLogger(),
		config: &types.ServerConfig{},
	}

	_, err := k.RefreshImage(context.Background(), ImageName("not a valid image ref"))
	if err == nil {
		t.Fatal("RefreshImage should fail for an invalid image reference")
	}
	if !strings.Contains(err.Error(), "parse ref") {
		t.Fatalf("error = %q, expected parse ref message", err)
	}
}

func TestImageRefreshFatalClassification(t *testing.T) {
	for _, msg := range []string{
		"manifest head: GET https://example/v2/: 401 Unauthorized",
		"manifest head: GET https://example/v2/: 403 Forbidden",
		"authentication required",
	} {
		if !isImageRefreshFatal(msg) {
			t.Fatalf("isImageRefreshFatal(%q) = false, want true", msg)
		}
	}
	if isImageRefreshFatal("manifest head: dial tcp: i/o timeout") {
		t.Fatal("timeout should not be classified as fatal")
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
			appConfig:    &types.AppConfig{},
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
			appConfig:    &types.AppConfig{},
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
			appConfig:    &types.AppConfig{},
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

	longWorkloadName := "clc-app-stg-3fh4ceunz5euxiftqywraidepfm-b755db8cce9f79c1"
	podVolumes, mounts, err = k.processVolumes(ctx, longWorkloadName, volumes[:1], sourceDir, map[string]string{"token": "abc123"})
	if err != nil {
		t.Fatalf("processVolumes with long workload returned error: %v", err)
	}
	if podVolumes[0].Name == nil || len(*podVolumes[0].Name) > KUBERNETES_NAME_MAX {
		t.Fatalf("secret volume name = %q, want length <= %d", valueOrEmpty(podVolumes[0].Name), KUBERNETES_NAME_MAX)
	}
	if mounts[0].Name == nil || *mounts[0].Name != *podVolumes[0].Name {
		t.Fatalf("mount name = %q, want matching volume name %q", valueOrEmpty(mounts[0].Name), valueOrEmpty(podVolumes[0].Name))
	}
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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

	_, err := k.createDeployment(context.Background(), "myapp", "myapp", true, "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{Cpus: "invalid"}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing cpus value") {
		t.Fatalf("error = %v, want cpu parse error", err)
	}

	_, err = k.createDeployment(context.Background(), "myapp", "myapp", true, "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{Memory: "invalid"}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing memory value") {
		t.Fatalf("error = %v, want memory parse error", err)
	}
}

func newTestLogger() *types.Logger {
	return types.NewLogger(&types.LogConfig{Level: "INFO"})
}

// captureDeploymentApply records the apply-patch bytes sent for deployments so
// tests can inspect the rendered Deployment spec (the fake clientset does not
// natively apply server-side patches).
func captureDeploymentApply(client *k8sfake.Clientset) *[]byte {
	patch := new([]byte)
	client.PrependReactor("patch", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa, ok := action.(k8stesting.PatchAction)
		if !ok || pa.GetPatchType() != k8sapitypes.ApplyPatchType {
			return false, nil, nil
		}
		*patch = pa.GetPatch()
		return true, &appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: pa.GetName(), Namespace: pa.GetNamespace()}}, nil
	})
	return patch
}

func serviceApplyReactor(client *k8sfake.Clientset) {
	addApplyPatchReactor(client, "services", func(name, namespace string) runtime.Object {
		return &corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		}
	})
}

func TestWorkloadNaming(t *testing.T) {
	if got := workloadName("clc-app", "deadbeefcafe", true); got != "clc-app" {
		t.Fatalf("PV workload name=%q, want clc-app", got)
	}
	if got := workloadName("clc-app", "deadbeefcafe1234567890", false); got != "clc-app-deadbeefcafe1234" {
		t.Fatalf("stateless workload name=%q, want clc-app-deadbeefcafe1234", got)
	}
	longName := workloadName("clc-this-is-a-very-long-service-name-that-needs-trimming", "deadbeefcafe1234567890", false)
	if len(longName) > 63 {
		t.Fatalf("workload name length=%d, want <= 63: %q", len(longName), longName)
	}
	sel := versionSelector("clc-app", "deadbeefcafe")
	if sel["app"] != "clc-app" || sel[VERSION_HASH_LABEL] != "deadbeefcafe" {
		t.Fatalf("service selector=%v, want app+version", sel)
	}
	pvSel := workloadSelector("clc-app", "deadbeefcafe", true)
	if _, ok := pvSel[VERSION_HASH_LABEL]; ok {
		t.Fatal("PV workload selector must not include the version hash")
	}
	longBase := strings.Repeat("a", 60)
	first := suffixedKubernetesName(longBase+"1111111111111111", "-secret-0")
	second := suffixedKubernetesName(longBase+"2222222222222222", "-secret-0")
	if len(first) > KUBERNETES_NAME_MAX || len(second) > KUBERNETES_NAME_MAX {
		t.Fatalf("suffixed names must fit Kubernetes limit: %q (%d), %q (%d)", first, len(first), second, len(second))
	}
	if first == second {
		t.Fatalf("suffixed names collided for distinct long bases: %q", first)
	}
}

func TestKubernetesCMPromoteVersion(t *testing.T) {
	ctx := context.Background()
	client := k8sfake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "myapp", VERSION_HASH_LABEL: "oldhash"}},
	})
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

	prev, prevSelector, err := k.PromoteVersion(ctx, "myapp", "newhash")
	if err != nil {
		t.Fatalf("PromoteVersion: %v", err)
	}
	if prev != "oldhash" {
		t.Fatalf("prev=%q, want oldhash", prev)
	}
	if prevSelector[VERSION_HASH_LABEL] != "oldhash" {
		t.Fatalf("prev selector version=%q, want oldhash", prevSelector[VERSION_HASH_LABEL])
	}
	svc, _ := client.CoreV1().Services("apps").Get(ctx, "myapp", meta.GetOptions{})
	if svc.Spec.Selector[VERSION_HASH_LABEL] != "newhash" {
		t.Fatalf("selector version=%q, want newhash", svc.Spec.Selector[VERSION_HASH_LABEL])
	}
	// Promoting the already-active version reports no previous version to GC.
	if prev2, _, err := k.PromoteVersion(ctx, "myapp", "newhash"); err != nil || prev2 != "" {
		t.Fatalf("re-promote prev=%q err=%v, want empty,nil", prev2, err)
	}
}

func TestKubernetesCMRemoveVersion(t *testing.T) {
	ctx := context.Background()
	wl := workloadName("myapp", "newhash", false) // myapp-newhash
	client := k8sfake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: wl, Namespace: "apps"}},
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: meta.ObjectMeta{Name: wl, Namespace: "apps"}},
		&corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: wl + "-secret-0", Namespace: "apps", Labels: ownershipLabels(wl)}},
		// A different version's Deployment must survive.
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: workloadName("myapp", "otherhash", false), Namespace: "apps"}},
	)
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

	if err := k.RemoveVersion(ctx, "myapp", "newhash"); err != nil {
		t.Fatalf("RemoveVersion: %v", err)
	}
	if _, err := client.AppsV1().Deployments("apps").Get(ctx, wl, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deployment %s should be deleted, err=%v", wl, err)
	}
	if _, err := client.AutoscalingV2().HorizontalPodAutoscalers("apps").Get(ctx, wl, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("hpa %s should be deleted, err=%v", wl, err)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(ctx, wl+"-secret-0", meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("secret should be deleted, err=%v", err)
	}
	if _, err := client.AppsV1().Deployments("apps").Get(ctx, workloadName("myapp", "otherhash", false), meta.GetOptions{}); err != nil {
		t.Fatalf("other version should survive, err=%v", err)
	}
	// Empty hash is a no-op.
	if err := k.RemoveVersion(ctx, "myapp", ""); err != nil {
		t.Fatalf("RemoveVersion(empty): %v", err)
	}
}

func TestKubernetesCMCleanupInactiveWorkloads(t *testing.T) {
	ctx := context.Background()
	serviceName := "myapp"
	active := workloadName(serviceName, "activehash", false)
	staleVersioned := workloadName(serviceName, "stalehash", false)
	staleStable := serviceName
	other := workloadName("otherapp", "stalehash", false)
	// The active version is the most recently created; stale versions predate it.
	// The Service selector points cleanupInactiveWorkloads at the active version.
	now := meta.Now()
	older := meta.NewTime(now.Add(-time.Hour))
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: meta.ObjectMeta{Name: serviceName, Namespace: "apps"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": serviceName, VERSION_HASH_LABEL: "activehash"}}},
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: active, Namespace: "apps", Labels: map[string]string{"app": serviceName}, CreationTimestamp: now}},
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: staleVersioned, Namespace: "apps", Labels: map[string]string{"app": serviceName}, CreationTimestamp: older}},
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: meta.ObjectMeta{Name: staleVersioned, Namespace: "apps"}},
		&corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: staleVersioned + "-secret-0", Namespace: "apps", Labels: ownershipLabels(staleVersioned)}},
		&corev1.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: staleVersioned + "-config-0", Namespace: "apps", Labels: ownershipLabels(staleVersioned)}},
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: staleStable, Namespace: "apps", Labels: map[string]string{"app": serviceName}, CreationTimestamp: older}},
		&corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: staleStable + "-secret-0", Namespace: "apps", Labels: ownershipLabels(staleStable)}},
		&appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: other, Namespace: "apps", Labels: map[string]string{"app": "otherapp"}, CreationTimestamp: older}},
	)
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

	if err := k.cleanupInactiveWorkloads(ctx, ContainerName(serviceName)); err != nil {
		t.Fatalf("cleanupInactiveWorkloads: %v", err)
	}
	if _, err := client.AppsV1().Deployments("apps").Get(ctx, active, meta.GetOptions{}); err != nil {
		t.Fatalf("active deployment should survive: %v", err)
	}
	for _, name := range []string{staleVersioned, staleStable} {
		if _, err := client.AppsV1().Deployments("apps").Get(ctx, name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("inactive deployment %s should be deleted, err=%v", name, err)
		}
	}
	if _, err := client.AutoscalingV2().HorizontalPodAutoscalers("apps").Get(ctx, staleVersioned, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("inactive hpa should be deleted, err=%v", err)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(ctx, staleVersioned+"-secret-0", meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("inactive secret should be deleted, err=%v", err)
	}
	if _, err := client.CoreV1().ConfigMaps("apps").Get(ctx, staleVersioned+"-config-0", meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("inactive configmap should be deleted, err=%v", err)
	}
	if _, err := client.AppsV1().Deployments("apps").Get(ctx, other, meta.GetOptions{}); err != nil {
		t.Fatalf("other app deployment should survive: %v", err)
	}
}

func TestKubernetesCMCreateDeploymentStrategy(t *testing.T) {
	ctx := context.Background()
	appEntry := &types.AppEntry{Metadata: types.AppMetadata{VersionMetadata: types.VersionMetadata{Version: 1}}}
	probe := &HealthProbe{Path: "/health", Port: 8080, Scheme: "HTTP", PeriodSecs: 10, TimeoutSecs: 5, FailureThreshold: 3, StartupFailures: 30}

	t.Run("no volume uses rolling update with surge and probes", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		depPatch := captureDeploymentApply(client)
		serviceApplyReactor(client)
		k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

		if _, err := k.createDeployment(ctx, "myapp", "myapp-hash", true, "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{MinReplicas: 2}, false, probe); err != nil {
			t.Fatalf("createDeployment: %v", err)
		}

		var dep appsv1.Deployment
		if err := json.Unmarshal(*depPatch, &dep); err != nil {
			t.Fatalf("unmarshal deployment patch: %v", err)
		}
		if dep.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
			t.Fatalf("strategy=%v, want RollingUpdate", dep.Spec.Strategy.Type)
		}
		if dep.Spec.Strategy.RollingUpdate == nil || dep.Spec.Strategy.RollingUpdate.MaxUnavailable == nil ||
			dep.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 0 {
			t.Fatalf("maxUnavailable not 0: %+v", dep.Spec.Strategy.RollingUpdate)
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 2 {
			t.Fatalf("replicas=%v, want 2", dep.Spec.Replicas)
		}
		if dep.Spec.ProgressDeadlineSeconds == nil {
			t.Fatal("progressDeadlineSeconds not set")
		}
		if len(dep.Spec.Template.Spec.Containers) == 0 {
			t.Fatal("no containers")
		}
		c := dep.Spec.Template.Spec.Containers[0]
		if c.ReadinessProbe == nil || c.ReadinessProbe.HTTPGet == nil || c.ReadinessProbe.HTTPGet.Path != "/health" {
			t.Fatalf("readiness probe missing or wrong: %+v", c.ReadinessProbe)
		}
		if c.StartupProbe == nil || c.StartupProbe.FailureThreshold != 30 {
			t.Fatalf("startup probe missing or wrong: %+v", c.StartupProbe)
		}
	})

	t.Run("configured progress deadline overrides default rollout deadline", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		depPatch := captureDeploymentApply(client)
		serviceApplyReactor(client)
		k := &KubernetesCM{
			Logger:       newTestLogger(),
			appNamespace: "apps",
			config:       &types.ServerConfig{},
			appConfig:    &types.AppConfig{Container: types.Container{DeployProgressDeadlineSecs: 30}},
			clientSet:    client,
		}

		if _, err := k.createDeployment(ctx, "myapp", "myapp-hash", true, "img:latest", 8080, nil, nil, "", nil, appEntry, "hash", KubernetesOptions{}, false, probe); err != nil {
			t.Fatalf("createDeployment: %v", err)
		}

		var dep appsv1.Deployment
		if err := json.Unmarshal(*depPatch, &dep); err != nil {
			t.Fatalf("unmarshal deployment patch: %v", err)
		}
		if dep.Spec.ProgressDeadlineSeconds == nil || *dep.Spec.ProgressDeadlineSeconds != 30 {
			t.Fatalf("progressDeadlineSeconds=%v, want 30", dep.Spec.ProgressDeadlineSeconds)
		}
	})

	t.Run("persistent volume uses recreate single replica and skips hpa", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset()
		depPatch := captureDeploymentApply(client)
		serviceApplyReactor(client)
		hpaApplied := false
		client.PrependReactor("patch", "horizontalpodautoscalers", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if pa, ok := action.(k8stesting.PatchAction); ok && pa.GetPatchType() == k8sapitypes.ApplyPatchType {
				hpaApplied = true
			}
			return false, nil, nil
		})
		k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client, appId: "app1"}
		vols := []*VolumeInfo{{VolumeName: "data", TargetPath: "/data"}}

		if _, err := k.createDeployment(ctx, "myapp", "myapp", true, "img:latest", 8080, nil, vols, "", nil, appEntry, "hash", KubernetesOptions{MinReplicas: 3, MaxReplicas: 5}, false, probe); err != nil {
			t.Fatalf("createDeployment: %v", err)
		}

		var dep appsv1.Deployment
		if err := json.Unmarshal(*depPatch, &dep); err != nil {
			t.Fatalf("unmarshal deployment patch: %v", err)
		}
		if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Fatalf("strategy=%v, want Recreate", dep.Spec.Strategy.Type)
		}
		if dep.Spec.Strategy.RollingUpdate != nil {
			t.Fatalf("rollingUpdate should be nil for Recreate: %+v", dep.Spec.Strategy.RollingUpdate)
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
			t.Fatalf("replicas=%v, want 1 (PV apps pinned to single replica)", dep.Spec.Replicas)
		}
		if hpaApplied {
			t.Fatal("HPA should not be created for a PV-backed app")
		}
	})
}

func TestKubernetesCMGetContainerStateExpectHashRequiresRollout(t *testing.T) {
	ctx := context.Background()
	replicas := int32(2)
	hash := "expected-hash"
	// Deployment template matches expectHash, one ready pod, but the rollout is
	// not complete (only 1 of 2 updated/ready). With expectHash set this must
	// report not-running.
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps", Generation: 2},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{VERSION_HASH_LABEL: TrimLabelValue(hash)}}},
			},
			Status: appsv1.DeploymentStatus{
				ObservedGeneration:  2,
				UpdatedReplicas:     1,
				ReadyReplicas:       1,
				UnavailableReplicas: 1,
				Replicas:            2,
			},
		},
		&corev1.Pod{
			ObjectMeta: meta.ObjectMeta{Name: "myapp-pod", Namespace: "apps", Labels: map[string]string{"app": "myapp", VERSION_HASH_LABEL: TrimLabelValue(hash)}},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		},
	)
	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		config:       &types.ServerConfig{},
		appConfig:    &types.AppConfig{},
		clientSet:    client,
	}
	_, running, err := k.GetContainerState(ctx, ContainerName("myapp"), hash)
	if err != nil {
		t.Fatalf("GetContainerState returned error: %v", err)
	}
	if running {
		t.Fatal("running=true, want false (incomplete rollout must not report running when a hash is expected)")
	}
}

func TestKubernetesCMGetContainerStateProgressDeadlineExceeded(t *testing.T) {
	ctx := context.Background()
	replicas := int32(1)
	hash := "expected-hash"
	// A deployment whose template matches expectHash but whose rollout Kubernetes
	// has declared failed must surface an error so the caller stops waiting and
	// rolls back, instead of polling until its own timeout.
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps", Generation: 2},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{VERSION_HASH_LABEL: TrimLabelValue(hash)}}},
			},
			Status: appsv1.DeploymentStatus{
				ObservedGeneration: 2,
				Conditions: []appsv1.DeploymentCondition{{
					Type:    appsv1.DeploymentProgressing,
					Status:  corev1.ConditionFalse,
					Reason:  "ProgressDeadlineExceeded",
					Message: "ReplicaSet has timed out progressing",
				}},
			},
		},
	)
	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		config:       &types.ServerConfig{},
		appConfig:    &types.AppConfig{},
		clientSet:    client,
	}
	if _, _, err := k.GetContainerState(ctx, ContainerName("myapp"), hash); err == nil {
		t.Fatal("expected an error when the rollout has ProgressDeadlineExceeded")
	}

	// Without an expected hash (steady-state check), the same condition must not
	// be treated as a fatal error.
	if _, _, err := k.GetContainerState(ctx, ContainerName("myapp"), ""); err != nil {
		t.Fatalf("steady-state check should not error on ProgressDeadlineExceeded: %v", err)
	}
}

func TestKubernetesCMGetContainerStateIgnoresStaleProgressDeadlineExceeded(t *testing.T) {
	ctx := context.Background()
	replicas := int32(1)
	hash := "expected-hash"
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps", Generation: 3},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{VERSION_HASH_LABEL: TrimLabelValue(hash)}}},
			},
			Status: appsv1.DeploymentStatus{
				ObservedGeneration: 2,
				Conditions: []appsv1.DeploymentCondition{{
					Type:    appsv1.DeploymentProgressing,
					Status:  corev1.ConditionFalse,
					Reason:  "ProgressDeadlineExceeded",
					Message: "stale timeout from previous generation",
				}},
			},
		},
	)
	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		config:       &types.ServerConfig{},
		appConfig:    &types.AppConfig{},
		clientSet:    client,
	}
	if _, _, err := k.GetContainerState(ctx, ContainerName("myapp"), hash); err != nil {
		t.Fatalf("stale ProgressDeadlineExceeded should not fail current rollout: %v", err)
	}
}

func TestKubernetesCMWaitForDeployReadyVersionedMissPollsInsteadOfWatchingStable(t *testing.T) {
	ctx := context.Background()
	replicas := int32(1)
	hash := "expected-hash"
	versionedName := workloadName("myapp", hash, false)
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: versionedName, Namespace: "apps", Generation: 1},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{VERSION_HASH_LABEL: TrimLabelValue(hash)}}},
			},
			Status: appsv1.DeploymentStatus{
				ObservedGeneration:  1,
				UpdatedReplicas:     1,
				ReadyReplicas:       1,
				Replicas:            1,
				UnavailableReplicas: 0,
			},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps", Generation: 1},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{VERSION_HASH_LABEL: "old-hash"}}},
			},
		},
		&corev1.Pod{
			ObjectMeta: meta.ObjectMeta{Name: "myapp-pod", Namespace: "apps", Labels: map[string]string{"app": "myapp", VERSION_HASH_LABEL: TrimLabelValue(hash)}},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		},
	)

	versionedGets := 0
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		get := action.(k8stesting.GetAction)
		if get.GetName() == versionedName {
			versionedGets++
			if versionedGets == 1 {
				return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, versionedName)
			}
		}
		return false, nil, nil
	})
	watchCalls := 0
	client.PrependWatchReactor("deployments", func(k8stesting.Action) (bool, watch.Interface, error) {
		watchCalls++
		return true, nil, errors.New("should not watch stale stable deployment")
	})

	k := &KubernetesCM{
		Logger:       newTestLogger(),
		appNamespace: "apps",
		config:       &types.ServerConfig{},
		appConfig:    &types.AppConfig{},
		clientSet:    client,
	}
	hostNamePort, err := k.waitForDeployReady(ctx, ContainerName("myapp"), hash, 1)
	if err != nil {
		t.Fatalf("waitForDeployReady returned error: %v", err)
	}
	if hostNamePort != "myapp.apps.svc.cluster.local:8080" {
		t.Fatalf("hostNamePort=%q, want service DNS", hostNamePort)
	}
	if watchCalls != 0 {
		t.Fatalf("watch calls=%d, want 0 when versioned get misses and stable deployment is stale", watchCalls)
	}
}

func TestKubernetesCMWaitForServiceVersionEndpointsRetriesListErrors(t *testing.T) {
	ctx := context.Background()
	hash := "expected-hash"
	readyPod := &corev1.Pod{
		ObjectMeta: meta.ObjectMeta{Name: "myapp-pod", Namespace: "apps", Labels: map[string]string{"app": "myapp", VERSION_HASH_LABEL: TrimLabelValue(hash)}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: meta.ObjectMeta{Name: "myapp-slice", Namespace: "apps", Labels: map[string]string{discoveryv1.LabelServiceName: "myapp"}},
		Endpoints: []discoveryv1.Endpoint{{
			TargetRef: &corev1.ObjectReference{Name: "myapp-pod", Namespace: "apps"},
		}},
	}

	t.Run("pod list error", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(readyPod.DeepCopy(), slice.DeepCopy())
		podLists := 0
		client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			podLists++
			if podLists == 1 {
				return true, nil, errors.New("temporary pod list failure")
			}
			return false, nil, nil
		})
		k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

		k.waitForServiceVersionEndpoints(ctx, "myapp", hash)

		if podLists < 2 {
			t.Fatalf("pod list calls=%d, want retry after transient error", podLists)
		}
	})

	t.Run("endpointslice list error", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(readyPod.DeepCopy(), slice.DeepCopy())
		sliceLists := 0
		client.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
			sliceLists++
			if sliceLists == 1 {
				return true, nil, errors.New("temporary endpointslice list failure")
			}
			return false, nil, nil
		})
		k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

		k.waitForServiceVersionEndpoints(ctx, "myapp", hash)

		if sliceLists < 2 {
			t.Fatalf("endpointslice list calls=%d, want retry after transient error", sliceLists)
		}
	})

	t.Run("permanent endpointslice rbac error bails immediately", func(t *testing.T) {
		client := k8sfake.NewSimpleClientset(readyPod.DeepCopy(), slice.DeepCopy())
		sliceLists := 0
		client.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
			sliceLists++
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "discovery.k8s.io", Resource: "endpointslices"}, "", errors.New("forbidden"))
		})
		k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

		done := make(chan struct{})
		go func() {
			k.waitForServiceVersionEndpoints(ctx, "myapp", hash)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("waitForServiceVersionEndpoints did not return promptly on a permanent RBAC error")
		}
		if sliceLists != 1 {
			t.Fatalf("endpointslice list calls=%d, want 1 (no retry on permanent error)", sliceLists)
		}
	})
}

func TestKubernetesCMSnapshotRestore(t *testing.T) {
	ctx := context.Background()
	origReplicas := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &origReplicas,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "myapp", Image: "img:v1"}}}},
		},
	}
	keepSecret := &corev1.Secret{
		ObjectMeta: meta.ObjectMeta{Name: "myapp-secret-0", Namespace: "apps", Labels: ownershipLabels("myapp")},
		Data:       map[string][]byte{"k": []byte("v1")},
	}
	// An unrelated object that merely shares the common "app" label must not be
	// touched by snapshot/restore (it is not OpenRun-managed).
	unrelatedSecret := &corev1.Secret{
		ObjectMeta: meta.ObjectMeta{Name: "unrelated", Namespace: "apps", Labels: map[string]string{"app": "myapp"}},
		Data:       map[string][]byte{"k": []byte("keepme")},
	}
	client := k8sfake.NewSimpleClientset(dep, keepSecret, unrelatedSecret)
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

	snap, err := k.Snapshot(ctx, ContainerName("myapp"))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Simulate a failed update: mutate the deployment, add a new secret, mutate the kept secret.
	newReplicas := int32(1)
	dep2 := dep.DeepCopy()
	dep2.Spec.Replicas = &newReplicas
	dep2.Spec.Template.Spec.Containers[0].Image = "img:v2-broken"
	if _, err := client.AppsV1().Deployments("apps").Update(ctx, dep2, meta.UpdateOptions{}); err != nil {
		t.Fatalf("update deployment: %v", err)
	}
	newSecret := &corev1.Secret{ObjectMeta: meta.ObjectMeta{Name: "myapp-secret-1", Namespace: "apps", Labels: ownershipLabels("myapp")}}
	if _, err := client.CoreV1().Secrets("apps").Create(ctx, newSecret, meta.CreateOptions{}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	mutated := keepSecret.DeepCopy()
	mutated.Data["k"] = []byte("v2")
	if _, err := client.CoreV1().Secrets("apps").Update(ctx, mutated, meta.UpdateOptions{}); err != nil {
		t.Fatalf("update secret: %v", err)
	}

	if err := k.Restore(ctx, snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	gotDep, err := client.AppsV1().Deployments("apps").Get(ctx, "myapp", meta.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if gotDep.Spec.Template.Spec.Containers[0].Image != "img:v1" {
		t.Fatalf("image=%s, want img:v1 (rolled back)", gotDep.Spec.Template.Spec.Containers[0].Image)
	}
	if gotDep.Spec.Replicas == nil || *gotDep.Spec.Replicas != 2 {
		t.Fatalf("replicas=%v, want 2 (rolled back)", gotDep.Spec.Replicas)
	}
	if _, err := client.CoreV1().Secrets("apps").Get(ctx, "myapp-secret-1", meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("secret created after snapshot should be deleted, got err=%v", err)
	}
	gotSecret, err := client.CoreV1().Secrets("apps").Get(ctx, "myapp-secret-0", meta.GetOptions{})
	if err != nil {
		t.Fatalf("get kept secret: %v", err)
	}
	if string(gotSecret.Data["k"]) != "v1" {
		t.Fatalf("secret data=%s, want v1 (restored)", gotSecret.Data["k"])
	}

	// The unrelated secret sharing only app=myapp must be untouched.
	gotUnrelated, err := client.CoreV1().Secrets("apps").Get(ctx, "unrelated", meta.GetOptions{})
	if err != nil {
		t.Fatalf("unrelated secret should survive restore, got err=%v", err)
	}
	if string(gotUnrelated.Data["k"]) != "keepme" {
		t.Fatalf("unrelated secret data=%s, want keepme (untouched)", gotUnrelated.Data["k"])
	}
}

func TestKubernetesCMSnapshotSurfacesListError(t *testing.T) {
	ctx := context.Background()
	dep := &appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: "myapp", Namespace: "apps"}}
	client := k8sfake.NewSimpleClientset(dep)
	// Deny listing secrets (e.g. missing RBAC); Snapshot must surface the error
	// so the verify path can refuse to do an irreversible in-place update.
	client.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden: cannot list secrets")
	})
	k := &KubernetesCM{Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{}, appConfig: &types.AppConfig{}, clientSet: client}

	if _, err := k.Snapshot(ctx, ContainerName("myapp")); err == nil {
		t.Fatal("Snapshot should return an error when listing secrets fails")
	}
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
