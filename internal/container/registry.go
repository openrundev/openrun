package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
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
	if !strings.HasPrefix(rawurl, "http://") && !strings.HasPrefix(rawurl, "https://") {
		rawurl = "https://" + rawurl
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", rawurl, err)
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

func ImageExists(ctx context.Context, logger *types.Logger, imageRef string, r *types.RegistryConfig) (bool, error) {
	exists, err := CheckImagesExists(ctx, logger, imageRef, r)
	if err != nil {
		return false, err
	}
	return exists.Exists, nil
}

type ExistsResult struct {
	Exists bool
	Digest string
}

// getAuthFromRegistryConfig extracts authentication information directly from RegistryConfig
func getAuthFromRegistryConfig(registryConfig *types.RegistryConfig) (*authn.Basic, error) {
	// Read password from file if needed
	pass := registryConfig.Password
	if pass == "" && registryConfig.PasswordFile != "" {
		p, err := readFileIf(registryConfig.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read password_file: %w", err)
		}
		pass = p
	}

	// Return basic auth if we have credentials
	if registryConfig.Username != "" && pass != "" {
		return &authn.Basic{
			Username: registryConfig.Username,
			Password: pass,
		}, nil
	}

	return nil, nil
}

func GetDockerConfig(ctx context.Context, imageRef string, registryConfig *types.RegistryConfig) (name.Reference, []remote.Option, error) {
	var parseOpts []name.Option
	if registryConfig.Insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}

	imageRef = registryConfig.URL + "/" + imageRef
	ref, err := name.ParseReference(imageRef, parseOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ref: %w", err)
	}

	tr, err := BuildHTTPTransport(registryConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("build http transport: %w", err)
	}

	var opts = []remote.Option{remote.WithTransport(tr), remote.WithContext(ctx)}

	if strings.EqualFold(registryConfig.Type, "ecr") {
		region := inferECRRegion(ref.Context().RegistryStr(), registryConfig.AWSRegion)
		awsCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
		if err != nil {
			return nil, nil, fmt.Errorf("aws config: %w", err)
		}
		svc := ecr.NewFromConfig(awsCfg)
		input := &ecr.GetAuthorizationTokenInput{}
		authOut, err := svc.GetAuthorizationToken(ctx, input)
		if err != nil || len(authOut.AuthorizationData) == 0 {
			return nil, nil, fmt.Errorf("ecr auth token: %w", err)
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
		// Extract authentication directly from registry config
		auth, err := getAuthFromRegistryConfig(registryConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("get auth from registry config: %w", err)
		}
		if auth != nil {
			opts = append(opts, remote.WithAuth(auth))
		} else {
			// Fall back to anonymous auth if no credentials found
			opts = append(opts, remote.WithAuth(authn.Anonymous))
		}
	}

	return ref, opts, nil
}

func CheckImagesExists(ctx context.Context, logger *types.Logger, imageRef string, registryConfig *types.RegistryConfig) (ExistsResult, error) {
	ref, opts, err := GetDockerConfig(ctx, imageRef, registryConfig)
	if err != nil {
		return ExistsResult{}, fmt.Errorf("get remote config: %w", err)
	}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			logger.Info().Msgf("image %s does not exist", imageRef)
			return ExistsResult{Exists: false}, nil
		}
		logger.Info().Msgf("image %s head error: %v", imageRef, err)
		return ExistsResult{}, fmt.Errorf("manifest head: %w", err)
	}
	logger.Info().Msgf("image %s exists with digest %s", imageRef, desc.Digest.String())
	return ExistsResult{Exists: true, Digest: desc.Digest.String()}, nil
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ":", "-")
	return name
}

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
	SourceDir   string // Local directory to tar up and send to Kaniko
	Dockerfile  string
	Destination string
	ExtraArgs   []string
}

func KanikoJob(ctx context.Context, logger *types.Logger, cs *kubernetes.Clientset, cfg *rest.Config, r *types.RegistryConfig, dockerCfgJSON []byte, kb KanikoBuild) error {
	kb.JobName = sanitizeName(kb.JobName)
	ns := kb.Namespace

	// Secret with docker config
	dcfgSecretName := sanitizeName(kb.JobName + "-dockercfg")
	if err := CreateOrUpdateSecret(ctx, cs, ns, dcfgSecretName,
		map[string][]byte{".dockerconfigjson": dockerCfgJSON},
		corev1.SecretTypeDockerConfigJson,
	); err != nil {
		return fmt.Errorf("create/update docker cfg secret: %w", err)
	}

	// Optional certs secret + per-registry flags
	certData := map[string][]byte{}
	registryArgs := []string{}
	host, _ := mustHost(r.URL)
	if r.CAFile != "" {
		b, err := os.ReadFile(r.CAFile)
		if err != nil {
			return fmt.Errorf("registry config: read ca_file: %w", err)
		}
		fn := fmt.Sprintf("%s-ca.crt", strings.ReplaceAll(host, ":", "_"))
		certData[fn] = b
		registryArgs = append(registryArgs, fmt.Sprintf("--registry-certificate %s=/certs/%s", host, fn))
	}
	if r.ClientCertFile != "" && r.ClientKeyFile != "" {
		certB, err := os.ReadFile(r.ClientCertFile)
		if err != nil {
			return fmt.Errorf("registry config: read client_cert_file: %w", err)
		}
		keyB, err := os.ReadFile(r.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("registry config: read client_key_file: %w", err)
		}
		cfn := fmt.Sprintf("%s-client.crt", strings.ReplaceAll(host, ":", "_"))
		kfn := fmt.Sprintf("%s-client.key", strings.ReplaceAll(host, ":", "_"))
		certData[cfn] = certB
		certData[kfn] = keyB
		registryArgs = append(registryArgs, fmt.Sprintf("--registry-client-cert %s=/certs/%s,/certs/%s", host, cfn, kfn))
	}
	if r.Insecure {
		registryArgs = append(registryArgs, "--insecure-registry")
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
		certSecretName := sanitizeName(kb.JobName + "-certs")
		if err := CreateOrUpdateSecret(ctx, cs, ns, certSecretName, certData, corev1.SecretTypeOpaque); err != nil {
			return fmt.Errorf("create/update cert secret: %w", err)
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
		"--context=tar://stdin",
		fmt.Sprintf("--dockerfile=%s", kb.Dockerfile),
		fmt.Sprintf("--destination=%s", kb.Destination),
	}

	args = append(args, registryArgs...)
	args = append(args, kb.ExtraArgs...)

	logger.Info().Msgf("submitting kaniko job %s, destination %s, args %v", kb.JobName, kb.Destination, args)

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
						Name:         "executor",
						Image:        kb.Image,
						Args:         args,
						Stdin:        true,
						StdinOnce:    true,
						VolumeMounts: vmounts,
					}},
				},
			},
		},
	}
	_, err := cs.BatchV1().Jobs(ns).Create(ctx, job, meta.CreateOptions{})
	if err != nil {
		return fmt.Errorf("submit build job failed: %w", err)
	}

	// Wait for pod to be created and reach a terminal or running state
	err = waitForJobContainerStartOrExit(ctx, logger, cs, ns, kb.JobName, "executor", 3*time.Minute)
	if err != nil {
		return fmt.Errorf("error waiting for terminal phase: %w", err)
	}

	// Get the actual pod name once (job creates pod with suffix)
	pod, err := getPodForJob(ctx, cs, ns, kb.JobName)
	if err != nil {
		return fmt.Errorf("error getting pod for job: %w", err)
	}
	podName := pod.Name
	phase := pod.Status.Phase
	logger.Debug().Msgf("kaniko job %s pod %s phase %s", kb.JobName, podName, phase)
	if phase == corev1.PodSucceeded || phase == corev1.PodFailed {
		logs, err := tailLogs(ctx, cs, ns, kb.JobName, 1000)
		if err != nil {
			return fmt.Errorf("build failed: pod phase: %s", phase)
		}
		return fmt.Errorf("build failed: pod phase: %s\nLogs:\n%s", phase, logs)
	}

	err = attachAndStream(ctx, cfg, cs, ns, podName, kb.SourceDir)
	if err != nil {
		return fmt.Errorf("error sending build context: %w", err)
	}
	logger.Debug().Msgf("kaniko job %s pod %s attached and streaming context", kb.JobName, podName)

	finalPhase, err := waitForTerminalPhase(ctx, cs, ns, podName)
	if err != nil {
		return fmt.Errorf("error waiting for terminal phase: %w", err)
	}
	logger.Info().Msgf("kaniko job %s pod %s final phase %s", kb.JobName, podName, finalPhase)
	if finalPhase != corev1.PodSucceeded {
		return fmt.Errorf("build failed: pod phase: %s", finalPhase)
	}

	return nil
}

func getPodForJob(ctx context.Context, cs *kubernetes.Clientset, ns, jobName string) (*corev1.Pod, error) {
	listOpts := meta.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, listOpts)
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pod found for job %s", jobName)
	}
	// Return the first pod (jobs typically create one pod)
	return &pods.Items[0], nil
}

func tailLogs(ctx context.Context, cs *kubernetes.Clientset, ns, jobName string, lines int64) (string, error) {
	pod, err := getPodForJob(ctx, cs, ns, jobName)
	if err != nil {
		return "", err
	}

	opts := &corev1.PodLogOptions{
		TailLines:  &lines,
		LimitBytes: ptr[int64](1 << 20), // 1 MiB
	}

	req := cs.CoreV1().Pods(ns).GetLogs(pod.Name, opts)

	rc, err := req.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer rc.Close() //nolint:errcheck

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rc); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func waitForJobContainerStartOrExit(
	ctx context.Context,
	logger *types.Logger,
	cs kubernetes.Interface,
	ns, jobName, containerName string,
	timeout time.Duration,
) error {
	// This avoids matching old pods if the Job re-creates.
	job, err := cs.BatchV1().Jobs(ns).Get(ctx, jobName, meta.GetOptions{})
	if err != nil {
		return fmt.Errorf("get job %q: %w", jobName, err)
	}
	sel := labels.Set{
		"job-name":       jobName,
		"controller-uid": string(job.UID),
	}.AsSelector().String()

	to := int64(timeout.Seconds())
	w, err := cs.CoreV1().Pods(ns).Watch(ctx, meta.ListOptions{
		LabelSelector:  sel,
		TimeoutSeconds: &to,
	})
	if err != nil {
		return fmt.Errorf("watch pods for job %q: %w", jobName, err)
	}
	defer w.Stop()

	// Helper to check a single pod for a decisive state.
	checkPod := func(p *corev1.Pod) (done bool, outErr error) {
		// Fail fast if unschedulable
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
				return true, fmt.Errorf("pod %s unschedulable: %s", p.Name, c.Message)
			}
		}

		// Look at init containers and main containers
		statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)

		for _, cs := range statuses {
			if containerName != "" && cs.Name != containerName {
				continue
			}
			// Running => logs available; Terminated => job finished (success or failure)
			if cs.State.Running != nil {
				return true, nil
			}
			if t := cs.State.Terminated; t != nil {
				// Exit 0 is success; non-zero bubble up with reason/message.
				if t.ExitCode == 0 {
					return true, nil
				}
				return true, fmt.Errorf("container %s terminated (exit=%d): %s: %s",
					cs.Name, t.ExitCode, t.Reason, t.Message)
			}
			if w := cs.State.Waiting; w != nil {
				switch w.Reason {
				// Terminal-ish waiting reasons we should surface immediately
				case "ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError", "CreateContainerError",
					"InvalidImageName", "CrashLoopBackOff":
					return true, fmt.Errorf("container %s waiting: %s: %s", cs.Name, w.Reason, w.Message)
				}
				// "ContainerCreating" and friends: just keep waiting
			}
		}

		// Also exit if Pod reached a terminal phase (covers jobs with no long-running container)
		switch p.Status.Phase {
		case corev1.PodSucceeded:
			return true, nil
		case corev1.PodFailed:
			return true, fmt.Errorf("pod %s failed: %s", p.Name, p.Status.Message)
		}

		return false, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("timeout waiting for container %q in job %q to start or exit", containerName, jobName)
		case ev, ok := <-w.ResultChan():
			if !ok {
				return fmt.Errorf("watch closed while waiting for job %q", jobName)
			}
			switch ev.Type {
			case watch.Added, watch.Modified:
				pod, ok := ev.Object.(*corev1.Pod)
				if !ok {
					continue
				}
				if done, e := checkPod(pod); done {
					return e
				}
			case watch.Deleted:
				// If the current pod is deleted, the Job controller may spin a new one; keep watching.
				continue
			case watch.Error:
				// The Object is typically *metav1.Status; surface it as an error.
				st, _ := ev.Object.(*meta.Status)
				if st != nil && st.Message != "" {
					return fmt.Errorf("watch error: %s", st.Message)
				}
				return fmt.Errorf("watch error")
			}
		}
	}
}

func waitForTerminalPhase(ctx context.Context, cs *kubernetes.Clientset, ns, name string) (corev1.PodPhase, error) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-t.C:
			p, err := cs.CoreV1().Pods(ns).Get(ctx, name, meta.GetOptions{})
			if err != nil {
				return "", err
			}
			switch p.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				return p.Status.Phase, nil
			}
		}
	}
}

func attachAndStream(ctx context.Context, cfg *rest.Config, cs *kubernetes.Clientset,
	ns, pod string, contextDir string) error {
	req := cs.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(ns).
		Name(pod).
		SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{
			Container: "executor",
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, k8sscheme.ParameterCodec)

	// Create tar gzip stream of contextDir
	tarGz, err := tarGzDir(contextDir)
	if err != nil {
		return fmt.Errorf("create tar gzip: %w", err)
	}
	defer tarGz.Close() //nolint:errcheck

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("new executor: %w", err)
	}

	// Create buffers to capture stdout/stderr
	var stdout, stderr bytes.Buffer

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  tarGz,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	if err != nil {
		// Include captured output in error for debugging
		if stderr.Len() > 0 {
			return fmt.Errorf("attach stream error: %w\nstderr: %s", err, stderr.String())
		}
		return fmt.Errorf("attach stream error: %w", err)
	}

	return nil
}

// TarGzDir returns an io.ReadCloser that streams a tar.gz of the *contents*
// of srcDir (not including the directory itself).
// Callers must Close() the returned reader when done.
func tarGzDir(srcDir string) (io.ReadCloser, error) {
	// Basic upfront validation so we can fail fast.
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("TarGzDir: %q is not a directory", srcDir)
	}

	pr, pw := io.Pipe()

	go func() {
		// Any error here will be propagated to the reader via CloseWithError.
		err := func() error {
			gz := gzip.NewWriter(pw)
			defer gz.Close() //nolint:errcheck

			tw := tar.NewWriter(gz)
			defer tw.Close() //nolint:errcheck

			root := filepath.Clean(srcDir)

			return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}

				relPath, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				// Skip the root dir itself; we only want its contents.
				if relPath == "." {
					return nil
				}

				hdr, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				// Use the relative path inside the archive.
				hdr.Name = relPath

				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}

				// Directories have no body.
				if info.IsDir() {
					return nil
				}

				// Only copy regular files.
				if !info.Mode().IsRegular() {
					return nil
				}

				f, err := os.Open(path)
				if err != nil {
					return err
				}
				_, err = io.Copy(tw, f)
				_ = f.Close()
				return err
			})
		}()

		// Propagate error (nil or not) to the reader.
		_ = pw.CloseWithError(err)
	}()

	return pr, nil
}

func ptr[T any](v T) *T { return &v }
