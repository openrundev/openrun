// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/hashicorp/vault/api"
	"github.com/openrundev/openrun/internal/passwd"
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
	dbProviderCount := 0
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
		} else if name == "db" || strings.HasPrefix(name, "db_") {
			// A single db provider is allowed: all db providers would share the
			// same secrets table (and, for auto keys, the same key file), so a
			// second one would overwrite the first one's rows and rekey would
			// strand them
			dbProviderCount++
			if dbProviderCount > 1 {
				return nil, fmt.Errorf("only one db secret provider can be configured")
			}
			provider = &dbSecretProvider{name: name}
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

// writableSecretProvider is implemented by secret providers which support
// storing secrets (currently the db provider)
type writableSecretProvider interface {
	secretProvider
	CreateSecret(ctx context.Context, name string, value []byte, meta types.SecretMetadata, createdBy string) error
	UpdateSecret(ctx context.Context, name string, value []byte, meta types.SecretMetadata, createdBy string) (bool, error)
	DeleteSecret(ctx context.Context, name string) error
	ListSecrets(ctx context.Context) ([]types.SecretInfo, error)
	// GetSecretInfo returns info about one stored secret. With includeValue,
	// the decrypted value is also returned, from the same fetch as the info
	GetSecretInfo(ctx context.Context, name string, includeValue bool) (*types.SecretInfo, []byte, error)
	Rekey(ctx context.Context) (rekeyed int, skipped int, err error)
}

var (
	secretNameRegex   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,127}$`)
	secretPrefixRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
)

const generateNameAttempts = 10

// BindDBStores connects the db secret providers to the metadata database.
// Called after the metadata database is initialized (the db provider cannot
// be used for server config values because of this ordering). A no-op when no
// db provider is configured
func (s *SecretManager) BindDBStores(ctx context.Context, store SecretStore) error {
	for _, provider := range s.providers {
		dbProvider, ok := provider.(*dbSecretProvider)
		if !ok {
			continue
		}
		if err := dbProvider.bind(ctx, store, s.EvalTemplate); err != nil {
			return err
		}
	}
	return nil
}

// writableProvider returns the named provider if it supports writes.
// providerName defaults to "db"
func (s *SecretManager) writableProvider(providerName string) (writableSecretProvider, error) {
	providerName = cmp.Or(providerName, "db")
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown secret provider %s", providerName)
	}
	writable, ok := provider.(writableSecretProvider)
	if !ok {
		return nil, fmt.Errorf("secret provider %s does not support storing secrets", providerName)
	}
	return writable, nil
}

// secretRef returns the template reference for using the secret in app
// params/config values
func (s *SecretManager) secretRef(providerName, name string) string {
	if providerName == s.defaultProvider {
		return fmt.Sprintf(`{{secret %q}}`, name)
	}
	return fmt.Sprintf(`{{secret_from %q %q}}`, providerName, name)
}

// decodeSecretValue decodes the request value. Encoding "base64" is used to
// pass binary values (file contents); the decoded bytes are stored
func decodeSecretValue(value, encoding string) ([]byte, error) {
	switch encoding {
	case "":
		return []byte(value), nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("value is not valid base64: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unknown encoding %q, must be \"\" or \"base64\"", encoding)
	}
}

// CreateSecret stores a secret value. If req.Name is set, that name is used
// (update allows overwriting an existing value). Otherwise a unique name is
// generated from req.Prefix. Returns the name and the {{secret}} template
// reference to use
func (s *SecretManager) CreateSecret(ctx context.Context, req *types.CreateSecretRequest, createdBy string, update bool) (*types.SecretCreateResponse, error) {
	providerName := cmp.Or(req.Provider, "db")
	provider, err := s.writableProvider(providerName)
	if err != nil {
		return nil, err
	}

	value, err := decodeSecretValue(req.Value, req.Encoding)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("secret value is required")
	}
	if len(value) > MaxSecretValueBytes {
		return nil, fmt.Errorf("secret value exceeds max size of %d bytes", MaxSecretValueBytes)
	}

	meta := types.SecretMetadata{
		Description: req.Description,
		SourceFile:  req.SourceFile,
	}

	if req.Name != "" {
		if req.Prefix != "" {
			return nil, fmt.Errorf("name and prefix cannot both be set")
		}
		if !secretNameRegex.MatchString(req.Name) {
			return nil, fmt.Errorf("invalid secret name %q: must start with a letter and contain only letters, digits, _ and -", req.Name)
		}

		updated := false
		if update {
			updated, err = provider.UpdateSecret(ctx, req.Name, value, meta, createdBy)
		} else {
			err = provider.CreateSecret(ctx, req.Name, value, meta, createdBy)
			if err == types.ErrSecretExists {
				return nil, fmt.Errorf("secret %s already exists, use the update option to overwrite", req.Name)
			}
		}
		if err != nil {
			return nil, err
		}
		return &types.SecretCreateResponse{
			Name:      req.Name,
			Provider:  providerName,
			SecretRef: s.secretRef(providerName, req.Name),
			Updated:   updated,
		}, nil
	}

	if req.Prefix == "" {
		return nil, fmt.Errorf("name or prefix is required")
	}
	if update {
		return nil, fmt.Errorf("update requires an explicit name, not a prefix")
	}
	if !secretPrefixRegex.MatchString(req.Prefix) {
		return nil, fmt.Errorf("invalid secret prefix %q: must start with a letter and contain only letters, digits, _ and -", req.Prefix)
	}

	// Generate a unique name; the insert fails on a name conflict (enforced by
	// the primary key, safe across servers sharing the database), retry with a
	// new random suffix
	for range generateNameAttempts {
		suffix, err := passwd.GenerateRandString(8, secretSuffixChars)
		if err != nil {
			return nil, err
		}
		name := req.Prefix + "_" + suffix

		err = provider.CreateSecret(ctx, name, value, meta, createdBy)
		if err == types.ErrSecretExists {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &types.SecretCreateResponse{
			Name:      name,
			Provider:  providerName,
			SecretRef: s.secretRef(providerName, name),
		}, nil
	}
	return nil, fmt.Errorf("could not generate a unique secret name with prefix %s", req.Prefix)
}

// DeleteSecret deletes a stored secret
func (s *SecretManager) DeleteSecret(ctx context.Context, providerName, name string) error {
	provider, err := s.writableProvider(providerName)
	if err != nil {
		return err
	}
	if !secretNameRegex.MatchString(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	return provider.DeleteSecret(ctx, name)
}

// ListSecrets returns info about stored secrets (never values), optionally
// filtered by a glob pattern on the name
func (s *SecretManager) ListSecrets(ctx context.Context, providerName, nameGlob string) ([]types.SecretInfo, error) {
	provider, err := s.writableProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate the glob up front: matching inside the loop would silently
	// accept an invalid pattern whenever the list is empty
	if nameGlob != "" && !doublestar.ValidatePattern(nameGlob) {
		return nil, fmt.Errorf("invalid glob pattern %q", nameGlob)
	}

	infos, err := provider.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	if nameGlob == "" {
		return infos, nil
	}

	filtered := make([]types.SecretInfo, 0, len(infos))
	for _, info := range infos {
		if match, err := doublestar.Match(nameGlob, info.Name); err == nil && match {
			filtered = append(filtered, info)
		}
	}
	return filtered, nil
}

// GetSecretInfo returns info about one stored secret. With reveal, the value
// is included: binary values are base64 encoded with Encoding set to "base64"
func (s *SecretManager) GetSecretInfo(ctx context.Context, providerName, name string, reveal bool) (*types.SecretGetResponse, error) {
	provider, err := s.writableProvider(providerName)
	if err != nil {
		return nil, err
	}
	if !secretNameRegex.MatchString(name) {
		return nil, fmt.Errorf("invalid secret name %q", name)
	}

	info, value, err := provider.GetSecretInfo(ctx, name, reveal)
	if err != nil {
		return nil, err
	}
	response := types.SecretGetResponse{SecretInfo: *info}

	if reveal {
		if utf8.Valid(value) {
			response.Value = string(value)
		} else {
			response.Value = base64.StdEncoding.EncodeToString(value)
			response.Encoding = "base64"
		}
	}
	return &response, nil
}

// RekeySecrets re-encrypts stored secrets with the active master key. Used
// after adding a new key to the key material to phase out old keys
func (s *SecretManager) RekeySecrets(ctx context.Context, providerName string) (*types.SecretRekeyResponse, error) {
	provider, err := s.writableProvider(providerName)
	if err != nil {
		return nil, err
	}
	rekeyed, skipped, err := provider.Rekey(ctx)
	if err != nil {
		return nil, err
	}
	return &types.SecretRekeyResponse{Rekeyed: rekeyed, Skipped: skipped}, nil
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
