// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/hashicorp/vault/api"
	"github.com/openrundev/openrun/internal/types"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// SecretManager provides access to the secrets for the system
type SecretManager struct {
	// Secrets is a map of secret providers
	providers       map[string]secretProvider
	funcMap         template.FuncMap
	config          map[string]types.SecretConfig
	defaultProvider string
}

func NewSecretManager(ctx context.Context, secretConfig map[string]types.SecretConfig, defaultProvider string, serverConfig *types.ServerConfig) (*SecretManager, error) {
	providers := make(map[string]secretProvider)
	for name, conf := range secretConfig {
		var provider secretProvider
		if name == "asm" || strings.HasPrefix(name, "asm_") {
			provider = &awsSecretProvider{}
		} else if name == "ssm" || strings.HasPrefix(name, "ssm_") {
			provider = &awsSSMProvider{}
		} else if name == "vault" || strings.HasPrefix(name, "vault_") {
			provider = &vaultSecretProvider{}
		} else if name == "env" || strings.HasPrefix(name, "env_") {
			provider = &envSecretProvider{}
		} else if name == "prop" || strings.HasPrefix(name, "prop_") {
			provider = &propertiesSecretProvider{}
		} else if name == "kubernetes" || strings.HasPrefix(name, "kubernetes_") {
			provider = &kubernetesSecretProvider{namespace: serverConfig.Kubernetes.Namespace}
		} else {
			return nil, fmt.Errorf("unknown secret provider %s", name)
		}

		err := provider.Configure(ctx, conf)
		if err != nil {
			return nil, err
		}
		providers[name] = provider
	}

	funcMap := GetFuncMap()

	s := &SecretManager{
		providers:       providers,
		funcMap:         funcMap,
		config:          secretConfig,
		defaultProvider: defaultProvider,
	}
	s.funcMap["secret"] = s.templateSecretFunc
	s.funcMap["secret_from"] = s.templateSecretFromFunc
	return s, nil
}

// templateSecretFunc is a template function that retrieves a secret from the default secret manager.
// Since the template function does not support errors, it panics if there is an error
func (s *SecretManager) templateSecretFunc(secretKeys ...string) string {
	return s.appTemplateSecretFunc(false, nil, s.defaultProvider, "", secretKeys...)
}

// templateSecretFromFunc is a template function that retrieves a secret from the secret manager.
// Since the template function does not support errors, it panics if there is an error
func (s *SecretManager) templateSecretFromFunc(providerName string, secretKeys ...string) string {
	return s.appTemplateSecretFunc(false, nil, s.defaultProvider, providerName, secretKeys...)
}

// appTemplateSecretFunc is a template function that retrieves a secret from the secret manager.
// Since the template function does not support errors, it panics if there is an error. The appPerms
// are checked to see if the secret can be accessed by the plugin API call
func (s *SecretManager) appTemplateSecretFunc(checkAppPerms bool, appPerms [][]string, defaultProvider, providerName string, secretKeys ...string) string {
	if providerName == "" || strings.ToLower(providerName) == "default" {
		// Use the system default provider
		providerName = cmp.Or(defaultProvider, s.defaultProvider)
	}

	provider, ok := s.providers[providerName]
	if !ok {
		panic(fmt.Errorf("unknown secret provider %s", providerName))
	}

	if checkAppPerms {
		if len(appPerms) == 0 {
			panic("Plugin does not have access to any secrets, update app permissions")
		}

		permMatched := false
		for _, appPerm := range appPerms {
			matched := true
			for i, entry := range secretKeys {
				if i >= len(appPerm) {
					continue
				}
				if appPerm[i] != entry {
					regexMatch, err := types.RegexMatch(appPerm[i], entry)
					if err != nil {
						panic(fmt.Errorf("error matching secret value %s: %w", entry, err))
					}
					if !regexMatch {
						matched = false
						break
					}
				}
			}

			if matched {
				permMatched = true
				break
			}
		}

		if !permMatched {
			panic(fmt.Errorf("plugin does not have access to secret %s", strings.Join(secretKeys, provider.GetJoinDelimiter())))
		}
	}

	secretKey := strings.Join(secretKeys, provider.GetJoinDelimiter())
	config := s.config[providerName]
	printf, ok := config["keys_printf"]
	if ok && len(secretKeys) > 1 {
		printfStr, ok := printf.(string)
		if !ok {
			panic(fmt.Errorf("keys_printf must be a string"))
		}
		args := make([]any, 0, len(secretKeys))
		for _, key := range secretKeys {
			args = append(args, key)
		}
		secretKey = fmt.Sprintf(printfStr, args...)
	}

	ret, err := provider.GetSecret(context.Background(), secretKey)
	if err != nil {
		panic(fmt.Errorf("error getting secret %s from %s: %w", secretKey, providerName, err))
	}
	return ret
}

// EvalTemplate evaluates the input string and replaces any secret placeholders with the actual secret value
func (s *SecretManager) EvalTemplate(input string) (string, error) {
	if len(input) < 4 {
		return input, nil
	}

	if !strings.Contains(input, "{{") || !strings.Contains(input, "}}") {
		return input, nil
	}

	tmpl, err := template.New("secret template").Funcs(s.funcMap).Parse(input)
	if err != nil {
		return "", err
	}
	var doc bytes.Buffer
	err = tmpl.Execute(&doc, nil)
	if err != nil {
		return "", err
	}
	return doc.String(), nil
}

// EvalTemplate evaluates the input string and replaces any secret placeholders with the actual secret value
func (s *SecretManager) AppEvalTemplate(appSecrets [][]string, defaultProvider, input string) (string, error) {
	if len(input) < 4 {
		return input, nil
	}

	if !strings.Contains(input, "{{") || !strings.Contains(input, "}}") {
		return input, nil
	}

	funcMap := template.FuncMap{}
	for name, fn := range s.funcMap {
		funcMap[name] = fn
	}

	secretFunc := func(secretKeys ...string) string {
		return s.appTemplateSecretFunc(true, appSecrets, defaultProvider, "", secretKeys...)
	}

	secretFromFunc := func(providerName string, secretKeys ...string) string {
		return s.appTemplateSecretFunc(true, appSecrets, defaultProvider, providerName, secretKeys...)
	}

	funcMap["secret"] = secretFunc
	funcMap["secret_from"] = secretFromFunc

	tmpl, err := template.New("secret template").Funcs(funcMap).Parse(input)
	if err != nil {
		return "", err
	}
	var doc bytes.Buffer
	err = tmpl.Execute(&doc, nil)
	if err != nil {
		return "", err
	}
	return doc.String(), nil
}

// secretProvider is an interface for secret providers
type secretProvider interface {
	// Configure is called to configure the secret provider
	Configure(ctx context.Context, conf map[string]any) error

	// GetSecret returns the secret value for the given secret name
	GetSecret(ctx context.Context, secretName string) (string, error)

	// GetJoinDelimiter returns the delimiter used to join multiple secret keys
	GetJoinDelimiter() string
}

// awsSecretProvider is a secret provider that reads secrets from AWS Secrets Manager
type awsSecretProvider struct {
	client *secretsmanager.Client
}

func (a *awsSecretProvider) Configure(ctx context.Context, conf map[string]any) error {
	profileStr := ""
	profile, ok := conf["profile"]
	if ok {
		profileStr, ok = profile.(string)
		if !ok {
			return fmt.Errorf("profile must be a string")
		}
	}

	var cfg aws.Config
	var err error
	// IAM is automatically supported by config load
	if profileStr != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profileStr))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		return err
	}

	a.client = secretsmanager.NewFromConfig(cfg)
	return nil
}

func (a *awsSecretProvider) GetSecret(ctx context.Context, secretName string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}
	result, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return "", err
	}
	return aws.ToString(result.SecretString), nil
}

func (a *awsSecretProvider) GetJoinDelimiter() string {
	return "/"
}

var _ secretProvider = &awsSecretProvider{}

// awsSSMProvider is a secret provider that reads secrets from AWS SSM
type awsSSMProvider struct {
	client *ssm.Client
}

func (a *awsSSMProvider) Configure(ctx context.Context, conf map[string]any) error {
	profileStr := ""
	profile, ok := conf["profile"]
	if ok {
		profileStr, ok = profile.(string)
		if !ok {
			return fmt.Errorf("profile must be a string")
		}
	}

	var cfg aws.Config
	var err error
	// IAM is automatically supported by config load
	if profileStr != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profileStr))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		return err
	}

	a.client = ssm.NewFromConfig(cfg)
	return nil
}

func (a *awsSSMProvider) GetSecret(ctx context.Context, secretName string) (string, error) {
	input := &ssm.GetParameterInput{
		Name:           aws.String(secretName),
		WithDecryption: aws.Bool(true),
	}

	out, err := a.client.GetParameter(ctx, input)
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Parameter.Value), nil
}

func (a *awsSSMProvider) GetJoinDelimiter() string {
	return "/"
}

var _ secretProvider = &awsSSMProvider{}

// vaultSecretProvider is a secret provider that reads secrets from HashiCorp Vault
type vaultSecretProvider struct {
	client *api.Client
}

func getConfigString(conf map[string]any, key string) (string, error) {
	value, ok := conf[key]
	if !ok {
		return "", fmt.Errorf("missing '%s' in config", key)
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}

	return valueStr, nil
}

func (v *vaultSecretProvider) Configure(ctx context.Context, conf map[string]any) error {
	address, err := getConfigString(conf, "address")
	if err != nil {
		return fmt.Errorf("vault invalid config: %w", err)
	}
	token, err := getConfigString(conf, "token")
	if err != nil {
		return fmt.Errorf("vault invalid config: %w", err)
	}

	vaultConfig := &api.Config{
		Address: address,
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return err
	}

	// Set the token for authentication
	client.SetToken(token)
	v.client = client
	return nil
}

// GetSecret reads the secret at the given path and returns the one string value it contains.
// It handles both KV v1 and v2 engines automatically.
func (v *vaultSecretProvider) GetSecret(ctx context.Context, fullPath string) (string, error) {
	// 1) List all mounts so we can detect KV versions.
	mounts, err := v.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list mounts: %w", err)
	}

	// 2) Pick the longest‐matching mount for our path.
	//    Mount keys come back with trailing slashes, e.g. "secret/" or "kv/".
	type mountInfo struct {
		mountPath string           // e.g. "secret/" (with slash)
		opts      *api.MountOutput // contains .Options["version"]
	}
	var all []mountInfo
	for m, o := range mounts {
		all = append(all, mountInfo{mountPath: m, opts: o})
	}
	sort.Slice(all, func(i, j int) bool {
		// longer mountPath first (“secret/data/” before “secret/”)
		return len(all[i].mountPath) > len(all[j].mountPath)
	})

	var (
		chosen  *mountInfo
		relPath string
	)
	for _, mi := range all {
		// trim the trailing slash for comparison
		prefix := strings.TrimSuffix(mi.mountPath, "/")
		if fullPath == prefix || strings.HasPrefix(fullPath, prefix+"/") {
			chosen = &mi
			// everything after “prefix/”
			relPath = strings.TrimPrefix(fullPath, prefix+"/")
			break
		}
	}
	if chosen == nil {
		return "", fmt.Errorf("no mount found matching path %q", fullPath)
	}

	// 3) Decide API version (default to v1 if not set).
	ver := 1
	if v, ok := chosen.opts.Options["version"]; ok && v == "2" {
		ver = 2
	}

	// 4) Build the actual read path for the logical API.
	//    KV v2 lives under “<mount>/data/<relPath>”
	mountPrefix := strings.TrimSuffix(chosen.mountPath, "/")
	var readPath string
	if ver == 2 {
		readPath = fmt.Sprintf("%s/data/%s", mountPrefix, relPath)
	} else {
		readPath = fmt.Sprintf("%s/%s", mountPrefix, relPath)
	}

	// 5) Read the secret
	secret, err := v.client.Logical().ReadWithContext(ctx, readPath)
	if err != nil {
		return "", fmt.Errorf("error reading %s: %w", readPath, err)
	}
	if secret == nil {
		return "", fmt.Errorf("no secret found at %s", readPath)
	}

	// 6) Extract the data map
	var data map[string]interface{}
	if ver == 2 {
		// KV v2 nests values under “data”
		raw, ok := secret.Data["data"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("malformed data at %s", readPath)
		}
		data = raw
	} else {
		// KV v1 writes your keys at top level of Data
		data = secret.Data
	}

	if len(data) != 1 {
		return "", fmt.Errorf("expected exactly one key in secret at %s, got %d keys", readPath, len(data))
	}
	for _, v := range data {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("secret value at %s is not a string", readPath)
		}
		return str, nil
	}

	return "", fmt.Errorf("unexpected error extracting secret at %s", readPath)
}

func (v *vaultSecretProvider) GetJoinDelimiter() string {
	return "/"
}

var _ secretProvider = &vaultSecretProvider{}

// envSecretProvider is a secret provider that reads secrets from environment variables
type envSecretProvider struct {
}

func (e *envSecretProvider) Configure(ctx context.Context, conf map[string]any) error {
	return nil
}

func (e *envSecretProvider) GetSecret(ctx context.Context, secretName string) (string, error) {
	return os.Getenv(secretName), nil
}

func (e *envSecretProvider) GetJoinDelimiter() string {
	return "_"
}

var _ secretProvider = &envSecretProvider{}

// kubernetesSecretProvider is a secret provider that reads secrets from Kubernetes secrets
type kubernetesSecretProvider struct {
	clientSet *kubernetes.Clientset
	namespace string
}

func (k *kubernetesSecretProvider) Configure(ctx context.Context, conf map[string]any) error {
	// Override namespace from config if explicitly set
	if ns, ok := conf["namespace"]; ok {
		nsStr, ok := ns.(string)
		if !ok {
			return fmt.Errorf("namespace must be a string")
		}
		k.namespace = nsStr
	}

	// Try to load kubeconfig from config, otherwise use default loading
	var cfg *rest.Config
	var err error

	if kubeconfigPath, ok := conf["kubeconfig"]; ok {
		kubeconfigStr, ok := kubeconfigPath.(string)
		if !ok {
			return fmt.Errorf("kubeconfig must be a string")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigStr)
		if err != nil {
			return fmt.Errorf("error loading kubeconfig from %s: %w", kubeconfigStr, err)
		}
	} else {
		// Try in-cluster config first, then fall back to default kubeconfig
		cfg, err = rest.InClusterConfig()
		if err != nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
			if err != nil {
				return fmt.Errorf("error loading kubernetes config: %w", err)
			}
		}
	}

	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("error creating kubernetes clientset: %w", err)
	}

	k.clientSet = clientSet
	return nil
}

// GetSecret retrieves a secret from Kubernetes. The secretName should be in the format
// "secret-name/key" where secret-name is the Kubernetes secret name and key is the
// data key within the secret. If no key is specified, it returns the first (and only)
// key in the secret data.
func (k *kubernetesSecretProvider) GetSecret(ctx context.Context, secretName string) (string, error) {
	parts := strings.SplitN(secretName, "/", 2)
	k8sSecretName := parts[0]
	var dataKey string
	if len(parts) > 1 {
		dataKey = parts[1]
	}

	secret, err := k.clientSet.CoreV1().Secrets(k.namespace).Get(ctx, k8sSecretName, meta.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting kubernetes secret %s: %w", k8sSecretName, err)
	}

	if dataKey != "" {
		value, ok := secret.Data[dataKey]
		if !ok {
			return "", fmt.Errorf("key %s not found in kubernetes secret %s", dataKey, k8sSecretName)
		}
		return string(value), nil
	}

	// If no key specified, return the single key's value (error if multiple keys)
	if len(secret.Data) != 1 {
		return "", fmt.Errorf("kubernetes secret %s has %d keys, please specify which key to use", k8sSecretName, len(secret.Data))
	}

	for _, v := range secret.Data {
		return string(v), nil
	}

	return "", fmt.Errorf("kubernetes secret %s has no data", k8sSecretName)
}

func (k *kubernetesSecretProvider) GetJoinDelimiter() string {
	return "/"
}

var _ secretProvider = &kubernetesSecretProvider{}
