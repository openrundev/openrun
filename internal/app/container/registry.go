package container

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/openrundev/openrun/internal/types"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type dockerAuthEntry struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type dockerConfig struct {
	Auths       map[string]dockerAuthEntry `json:"auths,omitempty"`
	CredHelpers map[string]string          `json:"credHelpers,omitempty"`
}

// ----- Helpers -----

func mustHost(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", rawurl, err)
	}
	if u.Scheme == "" {
		u, _ = url.Parse("https://" + rawurl)
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host in url %q", rawurl)
	}
	return u.Host, nil
}

func readFileIf(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

var ecrHostRe = regexp.MustCompile(`^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)

func inferECRRegion(host, provided string) string {
	m := ecrHostRe.FindStringSubmatch(host)
	if len(m) == 3 {
		return m[2]
	}
	if provided != "" {
		return provided
	}
	return "us-east-1"
}

// ----- Generate Docker config.json -----

func GenerateDockerConfigJSON(r *types.RegistryConfig) ([]byte, error) {
	out := dockerConfig{
		Auths:       map[string]dockerAuthEntry{},
		CredHelpers: map[string]string{},
	}

	host, err := mustHost(r.URL)
	if err != nil {
		return nil, fmt.Errorf("registry config %w", err)
	}

	switch strings.ToLower(r.Type) {
	case "ecr":
		out.CredHelpers[host] = "ecr-login"
	default:
		pass := r.Password
		if pass == "" && r.PasswordFile != "" {
			p, err := readFileIf(r.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("registry config: reading password_file: %w", err)
			}
			pass = p
		}
		if r.Username != "" && pass != "" {
			combined := base64.StdEncoding.EncodeToString([]byte(r.Username + ":" + pass))
			out.Auths[host] = dockerAuthEntry{
				Auth:     combined,
				Username: r.Username,
				Password: pass,
			}
		}
	}

	return json.MarshalIndent(out, "", "  ")
}

// ----- Build transport (CAs, mTLS, insecure) -----

func BuildHTTPTransport(r *types.RegistryConfig) (*http.Transport, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	insecureAny := false

	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, fmt.Errorf("registry config: read ca_file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("registry config: ca_file has no valid certs")
		}
	}
	if r.Insecure {
		insecureAny = true
	}
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}
	base.TLSClientConfig.RootCAs = pool
	if insecureAny {
		base.TLSClientConfig.InsecureSkipVerify = true // dev/airgap only
	}

	if r.ClientCertFile != "" && r.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(r.ClientCertFile, r.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("registry config: load client cert/key: %w", err)
		}
		base.TLSClientConfig.Certificates = append(base.TLSClientConfig.Certificates, cert)
	}
	return base, nil
}

// ----- Image existence check -----

func ImageExists(ctx context.Context, imageRef string, r *types.RegistryConfig, dockerCfgJSON []byte) (bool, error) {
	exists, err := HeadWithDockerConfig(ctx, imageRef, r, dockerCfgJSON)
	if err != nil {
		return false, err
	}
	return exists.Exists, nil
}

type ExistsResult struct {
	Exists bool
	Digest string
}

func HeadWithDockerConfig(ctx context.Context, imageRef string, r *types.RegistryConfig, dockerCfgJSON []byte) (ExistsResult, error) {
	tmpDir, err := os.MkdirTemp("", "dockercfg-*")
	if err != nil {
		return ExistsResult{}, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return ExistsResult{}, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), dockerCfgJSON, 0o600); err != nil {
		return ExistsResult{}, err
	}
	_ = os.Setenv("DOCKER_CONFIG", tmpDir)

	var parseOpts []name.Option
	needInsecure := false
	hostToReg := map[string]*types.RegistryConfig{}
	h, _ := mustHost(r.URL)
	hostToReg[h] = r
	if r.Insecure {
		needInsecure = true
	}
	if needInsecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageRef, parseOpts...)
	if err != nil {
		return ExistsResult{}, fmt.Errorf("parse ref: %w", err)
	}

	tr, err := BuildHTTPTransport(r)
	if err != nil {
		return ExistsResult{}, err
	}

	host := ref.Context().RegistryStr()
	reg := hostToReg[host]

	var opts = []remote.Option{remote.WithTransport(tr), remote.WithContext(ctx)}

	if strings.EqualFold(reg.Type, "ecr") {
		region := inferECRRegion(host, reg.AWSRegion)
		awsCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
		if err != nil {
			return ExistsResult{}, fmt.Errorf("aws config: %w", err)
		}
		svc := ecr.NewFromConfig(awsCfg)
		input := &ecr.GetAuthorizationTokenInput{}
		authOut, err := svc.GetAuthorizationToken(ctx, input)
		if err != nil || len(authOut.AuthorizationData) == 0 {
			return ExistsResult{}, fmt.Errorf("ecr auth token: %w", err)
		}
		enc := *authOut.AuthorizationData[0].AuthorizationToken
		dec, _ := base64.StdEncoding.DecodeString(enc) // "AWS:<password>"
		parts := strings.SplitN(string(dec), ":", 2)
		user := "AWS"
		pass := ""
		if len(parts) == 2 {
			user, pass = parts[0], parts[1]
		}
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: user, Password: pass}))
	} else {
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	desc, err := remote.Head(ref, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return ExistsResult{Exists: false}, nil
		}
		return ExistsResult{}, fmt.Errorf("manifest head: %w", err)
	}
	return ExistsResult{Exists: true, Digest: desc.Digest.String()}, nil
}

// ----- K8s: create-or-update Secret -----

func CreateOrUpdateSecret(ctx context.Context, cs *kubernetes.Clientset, ns, name string, data map[string][]byte, typ corev1.SecretType) error {
	existing, err := cs.CoreV1().Secrets(ns).Get(ctx, name, meta.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			secr := &corev1.Secret{
				ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
				Type:       typ,
				Data:       data,
			}
			_, err := cs.CoreV1().Secrets(ns).Create(ctx, secr, meta.CreateOptions{})
			return err
		}
		return err
	}
	existing.Type = typ
	existing.Data = data
	_, err = cs.CoreV1().Secrets(ns).Update(ctx, existing, meta.UpdateOptions{})
	return err
}

type KanikoBuild struct {
	Namespace   string
	JobName     string
	Image       string // e.g. "cgr.dev/chainguard/kaniko:latest"
	Context     string // e.g. "/workspace" or "git://..."
	Dockerfile  string
	Destination string
	ExtraArgs   []string
}

func SubmitKanikoJob(ctx context.Context, cs *kubernetes.Clientset, r *types.RegistryConfig, dockerCfgJSON []byte, kb KanikoBuild) (*batchv1.Job, error) {
	ns := kb.Namespace
	if ns == "" {
		ns = "default"
	}
	if kb.Image == "" {
		kb.Image = "cgr.dev/chainguard/kaniko:latest"
	}
	if kb.JobName == "" {
		kb.JobName = "kaniko-build-" + fmt.Sprint(time.Now().Unix())
	}

	// Secret with docker config
	dcfgSecretName := kb.JobName + "-dockercfg"
	if err := CreateOrUpdateSecret(ctx, cs, ns, dcfgSecretName,
		map[string][]byte{".dockerconfigjson": dockerCfgJSON},
		corev1.SecretTypeDockerConfigJson,
	); err != nil {
		return nil, fmt.Errorf("create/update docker cfg secret: %w", err)
	}

	// Optional certs secret + per-registry flags
	certData := map[string][]byte{}
	registryArgs := []string{}
	host, _ := mustHost(r.URL)
	if r.CAFile != "" {
		b, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, fmt.Errorf("registry config: read ca_file: %w", err)
		}
		fn := fmt.Sprintf("%s-ca.crt", strings.ReplaceAll(host, ":", "_"))
		certData[fn] = b
		registryArgs = append(registryArgs, fmt.Sprintf("--registry-certificate %s=/certs/%s", host, fn))
	}
	if r.ClientCertFile != "" && r.ClientKeyFile != "" {
		certB, err := os.ReadFile(r.ClientCertFile)
		if err != nil {
			return nil, fmt.Errorf("registry config: read client_cert_file: %w", err)
		}
		keyB, err := os.ReadFile(r.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("registry config: read client_key_file: %w", err)
		}
		cfn := fmt.Sprintf("%s-client.crt", strings.ReplaceAll(host, ":", "_"))
		kfn := fmt.Sprintf("%s-client.key", strings.ReplaceAll(host, ":", "_"))
		certData[cfn] = certB
		certData[kfn] = keyB
		registryArgs = append(registryArgs, fmt.Sprintf("--registry-client-cert %s=/certs/%s,/certs/%s", host, cfn, kfn))
	}
	if r.Insecure {
		registryArgs = append(registryArgs, fmt.Sprintf("--insecure-registry %s", host))
	}

	vols := []corev1.Volume{
		{
			Name: "docker-config",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: dcfgSecretName},
			},
		},
	}
	vmounts := []corev1.VolumeMount{
		{Name: "docker-config", MountPath: "/kaniko/.docker", ReadOnly: true},
	}

	if len(certData) > 0 {
		certSecretName := kb.JobName + "-certs"
		if err := CreateOrUpdateSecret(ctx, cs, ns, certSecretName, certData, corev1.SecretTypeOpaque); err != nil {
			return nil, fmt.Errorf("create/update cert secret: %w", err)
		}
		vols = append(vols, corev1.Volume{
			Name: "certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: certSecretName},
			},
		})
		vmounts = append(vmounts, corev1.VolumeMount{Name: "certs", MountPath: "/certs", ReadOnly: true})
	}

	args := []string{
		fmt.Sprintf("--context=%s", kb.Context),
		fmt.Sprintf("--dockerfile=%s", kb.Dockerfile),
		fmt.Sprintf("--destination=%s", kb.Destination),
	}
	args = append(args, registryArgs...)
	args = append(args, kb.ExtraArgs...)

	backoff := int32(0)
	job := &batchv1.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      kb.JobName,
			Namespace: ns,
			Labels:    map[string]string{"app": "kaniko"},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoff,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{"app": "kaniko"},
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Volumes:       vols,
					Containers: []corev1.Container{{
						Name:  "executor",
						Image: kb.Image,
						Args:  args,
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "echo ok"}},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
							FailureThreshold:    6,
							TimeoutSeconds:      2,
							SuccessThreshold:    1,
						},
						VolumeMounts: vmounts,
					}},
				},
			},
		},
	}
	return cs.BatchV1().Jobs(ns).Create(ctx, job, meta.CreateOptions{})
}
