package container

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openruntypes "github.com/openrundev/openrun/internal/types"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestReadFileIf(t *testing.T) {
	t.Run("empty path returns empty string", func(t *testing.T) {
		got, err := readFileIf("")
		if err != nil {
			t.Fatalf("readFileIf returned error: %v", err)
		}
		if got != "" {
			t.Fatalf("readFileIf returned %q, want empty", got)
		}
	})

	t.Run("reads and trims file", func(t *testing.T) {
		tmp := t.TempDir()
		f := filepath.Join(tmp, "value.txt")
		if err := os.WriteFile(f, []byte("  hello \n"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		got, err := readFileIf(f)
		if err != nil {
			t.Fatalf("readFileIf returned error: %v", err)
		}
		if got != "hello" {
			t.Fatalf("readFileIf returned %q, want %q", got, "hello")
		}
	})
}

func TestMustHost(t *testing.T) {
	t.Run("adds https when missing", func(t *testing.T) {
		host, err := mustHost("registry.example.com")
		if err != nil {
			t.Fatalf("mustHost returned error: %v", err)
		}
		if host != "registry.example.com" {
			t.Fatalf("mustHost host = %q, want %q", host, "registry.example.com")
		}
	})

	t.Run("keeps explicit host and port", func(t *testing.T) {
		host, err := mustHost("https://registry.example.com:5000/path")
		if err != nil {
			t.Fatalf("mustHost returned error: %v", err)
		}
		if host != "registry.example.com:5000" {
			t.Fatalf("mustHost host = %q, want %q", host, "registry.example.com:5000")
		}
	})

	t.Run("fails when url has no host", func(t *testing.T) {
		_, err := mustHost("http:///missing-host")
		if err == nil {
			t.Fatal("mustHost should fail for URL without host")
		}
		if !strings.Contains(err.Error(), "no host") {
			t.Fatalf("mustHost error = %q, want no host message", err)
		}
	})
}

func TestInferECRRegion(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		provided string
		want     string
	}{
		{
			name:     "infer from host",
			host:     "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			provided: "us-east-1",
			want:     "us-west-2",
		},
		{
			name:     "fallback to provided region",
			host:     "registry.example.com",
			provided: "eu-central-1",
			want:     "eu-central-1",
		},
		{
			name: "fallback to default region",
			host: "registry.example.com",
			want: "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferECRRegion(tt.host, tt.provided)
			if got != tt.want {
				t.Fatalf("inferECRRegion(%q, %q) = %q, want %q", tt.host, tt.provided, got, tt.want)
			}
		})
	}
}

func TestGenerateDockerConfigJSON(t *testing.T) {
	t.Run("uses password file for basic auth", func(t *testing.T) {
		tmp := t.TempDir()
		passFile := filepath.Join(tmp, "password.txt")
		if err := os.WriteFile(passFile, []byte("s3cret\n"), 0o600); err != nil {
			t.Fatalf("write password file: %v", err)
		}

		cfg := &openruntypes.RegistryConfig{
			URL:          "registry.example.com",
			Username:     "alice",
			PasswordFile: passFile,
		}
		out, err := GenerateDockerConfigJSON(cfg)
		if err != nil {
			t.Fatalf("GenerateDockerConfigJSON returned error: %v", err)
		}

		var got dockerConfig
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal docker config: %v", err)
		}

		entry, ok := got.Auths["registry.example.com"]
		if !ok {
			t.Fatalf("missing auth entry for registry.example.com: %#v", got.Auths)
		}
		if entry.Username != "alice" || entry.Password != "s3cret" {
			t.Fatalf("unexpected auth entry: %#v", entry)
		}
		if entry.Auth == "" {
			t.Fatal("expected non-empty base64 auth")
		}
		if len(got.CredHelpers) != 0 {
			t.Fatalf("expected no cred helpers, got %#v", got.CredHelpers)
		}
	})

	t.Run("uses ecr credential helper", func(t *testing.T) {
		cfg := &openruntypes.RegistryConfig{
			URL:  "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			Type: "ecr",
		}
		out, err := GenerateDockerConfigJSON(cfg)
		if err != nil {
			t.Fatalf("GenerateDockerConfigJSON returned error: %v", err)
		}

		var got dockerConfig
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal docker config: %v", err)
		}
		if got.CredHelpers["123456789012.dkr.ecr.us-west-2.amazonaws.com"] != "ecr-login" {
			t.Fatalf("unexpected cred helper map: %#v", got.CredHelpers)
		}
		if len(got.Auths) != 0 {
			t.Fatalf("expected no auth entries for ecr, got %#v", got.Auths)
		}
	})

	t.Run("invalid registry URL fails", func(t *testing.T) {
		_, err := GenerateDockerConfigJSON(&openruntypes.RegistryConfig{URL: "http:///bad"})
		if err == nil {
			t.Fatal("GenerateDockerConfigJSON should fail for URL without host")
		}
	})
}

func TestBuildHTTPTransport(t *testing.T) {
	t.Run("invalid ca file content fails", func(t *testing.T) {
		tmp := t.TempDir()
		caFile := filepath.Join(tmp, "ca.crt")
		if err := os.WriteFile(caFile, []byte("not a cert"), 0o600); err != nil {
			t.Fatalf("write ca file: %v", err)
		}

		_, err := BuildHTTPTransport(&openruntypes.RegistryConfig{CAFile: caFile})
		if err == nil {
			t.Fatal("BuildHTTPTransport should fail for invalid CA PEM")
		}
	})

	t.Run("loads tls settings", func(t *testing.T) {
		tmp := t.TempDir()
		certFile, keyFile, certPEM := writeCertAndKey(t, tmp)
		caFile := filepath.Join(tmp, "ca.crt")
		if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
			t.Fatalf("write ca file: %v", err)
		}

		tr, err := BuildHTTPTransport(&openruntypes.RegistryConfig{
			CAFile:         caFile,
			ClientCertFile: certFile,
			ClientKeyFile:  keyFile,
			Insecure:       true,
		})
		if err != nil {
			t.Fatalf("BuildHTTPTransport returned error: %v", err)
		}
		if tr.TLSClientConfig == nil {
			t.Fatal("TLSClientConfig is nil")
		}
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("expected InsecureSkipVerify to be true")
		}
		if len(tr.TLSClientConfig.Certificates) != 1 {
			t.Fatalf("expected one client certificate, got %d", len(tr.TLSClientConfig.Certificates))
		}
		if tr.TLSClientConfig.RootCAs == nil {
			t.Fatal("RootCAs is nil")
		}
	})
}

func TestGetAuthFromRegistryConfig(t *testing.T) {
	t.Run("returns direct credentials", func(t *testing.T) {
		auth, err := getAuthFromRegistryConfig(&openruntypes.RegistryConfig{
			Username: "bob",
			Password: "pw",
		})
		if err != nil {
			t.Fatalf("getAuthFromRegistryConfig returned error: %v", err)
		}
		if auth == nil || auth.Username != "bob" || auth.Password != "pw" {
			t.Fatalf("unexpected auth result: %#v", auth)
		}
	})

	t.Run("returns nil without credentials", func(t *testing.T) {
		auth, err := getAuthFromRegistryConfig(&openruntypes.RegistryConfig{})
		if err != nil {
			t.Fatalf("getAuthFromRegistryConfig returned error: %v", err)
		}
		if auth != nil {
			t.Fatalf("expected nil auth, got %#v", auth)
		}
	})

	t.Run("reads password from file", func(t *testing.T) {
		tmp := t.TempDir()
		passFile := filepath.Join(tmp, "password.txt")
		if err := os.WriteFile(passFile, []byte("from-file\n"), 0o600); err != nil {
			t.Fatalf("write password file: %v", err)
		}

		auth, err := getAuthFromRegistryConfig(&openruntypes.RegistryConfig{
			Username:     "file-user",
			PasswordFile: passFile,
		})
		if err != nil {
			t.Fatalf("getAuthFromRegistryConfig returned error: %v", err)
		}
		if auth == nil || auth.Password != "from-file" {
			t.Fatalf("unexpected auth result: %#v", auth)
		}
	})

	t.Run("errors when password file is missing", func(t *testing.T) {
		_, err := getAuthFromRegistryConfig(&openruntypes.RegistryConfig{
			Username:     "u",
			PasswordFile: "/does/not/exist",
		})
		if err == nil {
			t.Fatal("expected error for missing password file")
		}
	})
}

func TestGetDockerConfig(t *testing.T) {
	t.Run("builds reference and options for basic auth", func(t *testing.T) {
		ref, opts, err := GetDockerConfig(context.Background(), "proj/app:latest", &openruntypes.RegistryConfig{
			URL:      "registry.example.com",
			Username: "user",
			Password: "pass",
		})
		if err != nil {
			t.Fatalf("GetDockerConfig returned error: %v", err)
		}
		if got, want := ref.String(), "registry.example.com/proj/app:latest"; got != want {
			t.Fatalf("ref.String() = %q, want %q", got, want)
		}
		if len(opts) != 3 {
			t.Fatalf("len(opts) = %d, want 3", len(opts))
		}
	})

	t.Run("errors when password file does not exist", func(t *testing.T) {
		_, _, err := GetDockerConfig(context.Background(), "proj/app:latest", &openruntypes.RegistryConfig{
			URL:          "registry.example.com",
			Username:     "user",
			PasswordFile: "/does/not/exist",
		})
		if err == nil {
			t.Fatal("expected GetDockerConfig to fail for missing password_file")
		}
		if !strings.Contains(err.Error(), "get auth from registry config") {
			t.Fatalf("error = %q, want auth extraction error", err)
		}
	})

	t.Run("errors on invalid reference", func(t *testing.T) {
		_, _, err := GetDockerConfig(context.Background(), "@@@", &openruntypes.RegistryConfig{
			URL: "registry.example.com",
		})
		if err == nil {
			t.Fatal("expected GetDockerConfig to fail for invalid image reference")
		}
		if !strings.Contains(err.Error(), "parse ref") {
			t.Fatalf("error = %q, want parse ref message", err)
		}
	})
}

func TestCheckImagesExistsConfigError(t *testing.T) {
	logger := openruntypes.NewLogger(&openruntypes.LogConfig{Level: "INFO"})
	_, err := CheckImagesExists(context.Background(), logger, "app:latest", &openruntypes.RegistryConfig{
		URL: "http:///bad",
	})
	if err == nil {
		t.Fatal("expected CheckImagesExists to fail for invalid registry config")
	}
	if !strings.Contains(err.Error(), "manifest head") && !strings.Contains(err.Error(), "get remote config") {
		t.Fatalf("error = %q, want wrapped manifest/get-remote-config message", err)
	}
}

func TestSanitizeName(t *testing.T) {
	got := sanitizeName("app_name:v1")
	if got != "app-name-v1" {
		t.Fatalf("sanitizeName returned %q, want %q", got, "app-name-v1")
	}
}

func TestTarGzDir(t *testing.T) {
	t.Run("archives directory contents with relative paths", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.Mkdir(filepath.Join(tmp, "sub"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "root.txt"), []byte("root"), 0o600); err != nil {
			t.Fatalf("write root file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "sub", "nested.txt"), []byte("nested"), 0o600); err != nil {
			t.Fatalf("write nested file: %v", err)
		}

		rc, err := tarGzDir(tmp)
		if err != nil {
			t.Fatalf("tarGzDir returned error: %v", err)
		}
		defer rc.Close() //nolint:errcheck

		zr, err := gzip.NewReader(rc)
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer zr.Close() //nolint:errcheck

		tr := tar.NewReader(zr)
		contents := map[string]string{}
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read tar entry: %v", err)
			}

			if hdr.FileInfo().Mode().IsRegular() {
				body, err := io.ReadAll(tr)
				if err != nil {
					t.Fatalf("read tar body: %v", err)
				}
				contents[hdr.Name] = string(body)
			}
		}

		if contents["root.txt"] != "root" {
			t.Fatalf("root.txt content = %q", contents["root.txt"])
		}
		if contents["sub/nested.txt"] != "nested" {
			t.Fatalf("sub/nested.txt content = %q", contents["sub/nested.txt"])
		}
		if _, ok := contents["."]; ok {
			t.Fatal("archive should not include root entry")
		}
	})

	t.Run("fails when src is not a directory", func(t *testing.T) {
		tmp := t.TempDir()
		file := filepath.Join(tmp, "file.txt")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		_, err := tarGzDir(file)
		if err == nil {
			t.Fatal("tarGzDir should fail for non-directory input")
		}
	})
}

func TestWaitForJobContainerStartOrExit(t *testing.T) {
	newClient := func() (*k8sfake.Clientset, *watch.FakeWatcher) {
		job := &batchv1.Job{
			ObjectMeta: meta.ObjectMeta{
				Name:      "build-job",
				Namespace: "test-ns",
				UID:       k8stypes.UID("job-uid"),
			},
		}
		cs := k8sfake.NewSimpleClientset(job)
		fw := watch.NewFake()
		cs.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
			return true, fw, nil
		})
		return cs, fw
	}

	t.Run("returns nil when container starts running", func(t *testing.T) {
		cs, fw := newClient()
		go func() {
			time.Sleep(20 * time.Millisecond)
			fw.Add(&corev1.Pod{
				ObjectMeta: meta.ObjectMeta{Name: "pod-1"},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "executor",
							State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
						},
					},
				},
			})
		}()

		err := waitForJobContainerStartOrExit(context.Background(), nil, cs, "test-ns", "build-job", "executor", time.Second)
		if err != nil {
			t.Fatalf("waitForJobContainerStartOrExit returned error: %v", err)
		}
	})

	t.Run("returns waiting reason errors", func(t *testing.T) {
		cs, fw := newClient()
		go func() {
			time.Sleep(20 * time.Millisecond)
			fw.Add(&corev1.Pod{
				ObjectMeta: meta.ObjectMeta{Name: "pod-1"},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "executor",
							State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
								Reason:  "ErrImagePull",
								Message: "failed pull",
							}},
						},
					},
				},
			})
		}()

		err := waitForJobContainerStartOrExit(context.Background(), nil, cs, "test-ns", "build-job", "executor", time.Second)
		if err == nil {
			t.Fatal("expected waitForJobContainerStartOrExit to return error")
		}
		if !strings.Contains(err.Error(), "ErrImagePull") {
			t.Fatalf("error = %q, want ErrImagePull", err)
		}
	})

	t.Run("times out when no decisive event arrives", func(t *testing.T) {
		cs, _ := newClient()
		err := waitForJobContainerStartOrExit(context.Background(), nil, cs, "test-ns", "build-job", "executor", 40*time.Millisecond)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if !strings.Contains(err.Error(), "timeout waiting") {
			t.Fatalf("error = %q, want timeout message", err)
		}
	})

	t.Run("unschedulable pod returns error", func(t *testing.T) {
		cs, fw := newClient()
		go func() {
			time.Sleep(20 * time.Millisecond)
			fw.Add(&corev1.Pod{
				ObjectMeta: meta.ObjectMeta{Name: "pod-1"},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:    corev1.PodScheduled,
							Status:  corev1.ConditionFalse,
							Reason:  corev1.PodReasonUnschedulable,
							Message: "no nodes",
						},
					},
				},
			})
		}()
		err := waitForJobContainerStartOrExit(context.Background(), nil, cs, "test-ns", "build-job", "executor", time.Second)
		if err == nil || !strings.Contains(err.Error(), "unschedulable") {
			t.Fatalf("error = %v, want unschedulable message", err)
		}
	})

	t.Run("watch error propagates message", func(t *testing.T) {
		cs, fw := newClient()
		go func() {
			time.Sleep(20 * time.Millisecond)
			fw.Error(&meta.Status{Message: "watch failed"})
		}()
		err := waitForJobContainerStartOrExit(context.Background(), nil, cs, "test-ns", "build-job", "executor", time.Second)
		if err == nil || !strings.Contains(err.Error(), "watch failed") {
			t.Fatalf("error = %v, want watch failed message", err)
		}
	})
}

func TestCreateOrUpdateSecret(t *testing.T) {
	ctx := context.Background()
	client := k8sfake.NewSimpleClientset()

	err := CreateOrUpdateSecret(ctx, client, "ns", "dockercfg", map[string][]byte{"k": []byte("v1")}, corev1.SecretTypeOpaque)
	if err != nil {
		t.Fatalf("CreateOrUpdateSecret(create) returned error: %v", err)
	}
	got, err := client.CoreV1().Secrets("ns").Get(ctx, "dockercfg", meta.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(got.Data["k"]) != "v1" {
		t.Fatalf("secret data = %q, want %q", string(got.Data["k"]), "v1")
	}

	err = CreateOrUpdateSecret(ctx, client, "ns", "dockercfg", map[string][]byte{"k": []byte("v2")}, corev1.SecretTypeDockerConfigJson)
	if err != nil {
		t.Fatalf("CreateOrUpdateSecret(update) returned error: %v", err)
	}
	got, err = client.CoreV1().Secrets("ns").Get(ctx, "dockercfg", meta.GetOptions{})
	if err != nil {
		t.Fatalf("get updated secret: %v", err)
	}
	if string(got.Data["k"]) != "v2" || got.Type != corev1.SecretTypeDockerConfigJson {
		t.Fatalf("updated secret mismatch: type=%q data=%q", got.Type, string(got.Data["k"]))
	}
}

func TestGetPodForJob(t *testing.T) {
	ctx := context.Background()
	client := k8sfake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: meta.ObjectMeta{Name: "pod-1", Namespace: "ns", Labels: map[string]string{"job-name": "job-a"}}},
	)

	pod, err := getPodForJob(ctx, client, "ns", "job-a")
	if err != nil {
		t.Fatalf("getPodForJob returned error: %v", err)
	}
	if pod.Name != "pod-1" {
		t.Fatalf("pod.Name = %q, want %q", pod.Name, "pod-1")
	}

	_, err = getPodForJob(ctx, client, "ns", "missing")
	if err == nil {
		t.Fatal("getPodForJob should fail when no pod exists for job")
	}
}

func TestTailLogsNoPod(t *testing.T) {
	_, err := tailLogs(context.Background(), k8sfake.NewSimpleClientset(), "ns", "missing", 10)
	if err == nil {
		t.Fatal("tailLogs should fail when no pod exists for job")
	}
}

func TestWaitForTerminalPhase(t *testing.T) {
	t.Run("returns succeeded phase", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		pod := &corev1.Pod{
			ObjectMeta: meta.ObjectMeta{Name: "pod-1", Namespace: "ns"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		}
		client := k8sfake.NewSimpleClientset(pod)

		go func() {
			time.Sleep(20 * time.Millisecond)
			p, _ := client.CoreV1().Pods("ns").Get(ctx, "pod-1", meta.GetOptions{})
			p.Status.Phase = corev1.PodSucceeded
			_, _ = client.CoreV1().Pods("ns").UpdateStatus(ctx, p, meta.UpdateOptions{})
		}()

		phase, err := waitForTerminalPhase(ctx, client, "ns", "pod-1")
		if err != nil {
			t.Fatalf("waitForTerminalPhase returned error: %v", err)
		}
		if phase != corev1.PodSucceeded {
			t.Fatalf("phase = %q, want %q", phase, corev1.PodSucceeded)
		}
	})

	t.Run("context cancellation is returned", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := waitForTerminalPhase(ctx, k8sfake.NewSimpleClientset(), "ns", "pod-1")
		if err == nil {
			t.Fatal("expected waitForTerminalPhase to return context error")
		}
	})
}

func writeCertAndKey(t *testing.T, dir string) (string, string, []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	return certFile, keyFile, certPEM
}
