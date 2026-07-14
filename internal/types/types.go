// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"cmp"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app/starlark_type"
)

// Added by goreleaser as build information
var (
	gitCommit  string // gitCommit is the git commit that was compiled
	gitVersion string // gitVersion is the build tag
)

func GetVersion() string {
	return cmp.Or(gitVersion, "dev")
}

func GetCommit() string {
	return cmp.Or(gitCommit, "dev_build")
}

const (
	OPENRUN_HOME            = "OPENRUN_HOME"
	ID_PREFIX_APP_PROD      = "app_prd_"
	ID_PREFIX_APP_DEV       = "app_dev_"
	ID_PREFIX_APP_STAGE     = "app_stg_"
	ID_PREFIX_APP_PREVIEW   = "app_pre_"
	ID_PREFIX_SERVICE       = "srv_"
	ID_PREFIX_BINDING       = "bnd_"
	ID_PREFIX_SERVER        = "srv_id_"
	ID_PREFIX_BUILDER_SES   = "bld_ses_"
	ID_PREFIX_BUILDER_ACT   = "bld_act_"
	INTERNAL_URL_PREFIX     = "/_openrun"
	WEBHOOK_URL_PREFIX      = "/_openrun_webhook"
	APP_INTERNAL_URL_PREFIX = "/_openrun_app"
	INTERNAL_APP_DELIM      = "_cl_"
	STAGE_SUFFIX            = INTERNAL_APP_DELIM + "stage"
	PREVIEW_SUFFIX          = INTERNAL_APP_DELIM + "preview"
	NO_SOURCE               = "-" // No source url is provided
)

type ContextKey string

const (
	USER_ID         ContextKey = "user_id"
	USER_SUBJECT    ContextKey = "user_subject"
	USER_EMAIL      ContextKey = "user_email"
	SHARED          ContextKey = "shared"
	REQUEST_ID      ContextKey = "request_id"
	APP_ID          ContextKey = "app_id"
	APP_PATH_DOMAIN ContextKey = "app_path_domain"
	APP_AUTH        ContextKey = "app_auth"
	GROUPS          ContextKey = "groups"
	RBAC_ENABLED    ContextKey = "rbac_enabled"
	CUSTOM_PERMS    ContextKey = "custom_perms"
	// TESTURL_DIRECTIVES holds the parsed _cl_ test URL directives
	// (rbac.UrlDirectives) for dev app requests when security.unsafe_enable_testurl_rbac
	// is set. Never present on prod app or management API requests.
	TESTURL_DIRECTIVES ContextKey = "testurl_directives"
	SYNC_ID            ContextKey = "sync_id"         // id of the sync entry driving the current apply
	APPLY_OPERATION    ContextKey = "apply_operation" // set when the current operation is a declarative apply
	// SYNC_RBAC holds the frozen creator authorization (rbac.SyncAuthorizer) for
	// background sync runs. Set only when the sync entry carries an RBAC snapshot
	// and RBAC is enabled; never present on interactive requests.
	SYNC_RBAC ContextKey = "sync_rbac"
	// TRUSTED_OPERATION marks a context as a trusted administrative path:
	// authenticated admin/UDS management API requests, token authenticated
	// webhooks and internal background operations. RBAC enforcement fails
	// CLOSED for contexts that carry neither this nor an enforcement marker,
	// so a context propagation bug denies instead of silently running as admin
	TRUSTED_OPERATION ContextKey = "trusted_operation"
)

const (
	TL_CONTEXT                  = "TL_context"
	TL_DEFER_MAP                = "TL_defer_map"
	TL_CURRENT_MODULE_FULL_PATH = "TL_current_module_full_path"
	TL_PLUGIN_API_FAILED_ERROR  = "TL_plugin_api_failed_error"
	TL_CONTAINER_URL            = "TL_container_url"
	TL_AUDIT_OPERATION          = "TL_audit_operation"
	TL_AUDIT_TARGET             = "TL_audit_target"
	TL_AUDIT_DETAIL             = "TL_audit_detail"
	TL_CONTAINER_HANDLER        = "TL_container_handler"
	TL_BRANCH                   = "TL_branch"
	TL_DEV                      = "TL_dev"
	TL_APP_URL                  = "TL_app_url"
)

const (
	CONTAINER_SOURCE_AUTO         = "auto"
	CONTAINER_SOURCE_NIXPACKS     = "nixpacks"
	CONTAINER_SOURCE_IMAGE_PREFIX = "image:"
	CONTAINER_LIFETIME_COMMAND    = "command"

	CONTAINER_KUBERNETES = "kubernetes"
)

const (
	ANONYMOUS_USER                 = "anonymous"
	ADMIN_USER                     = "admin"
	AUTH_MODIFIER_DELIMITER string = "+"
)

// Config entries shared between client and server
type GlobalConfig struct {
	ConfigFile string `toml:"config_file"`
	AdminUser  string `toml:"admin_user"`
	ServerUri  string `toml:"server_uri"`
}

// ServerConfig is the configuration for the OpenRun Server
type ServerConfig struct {
	GlobalConfig
	Http           HttpConfig                      `toml:"http"`
	Https          HttpsConfig                     `toml:"https"`
	Security       SecurityConfig                  `toml:"security"`
	Metadata       MetadataConfig                  `toml:"metadata"`
	Log            LogConfig                       `toml:"logging"`
	Telemetry      TelemetryConfig                 `toml:"telemetry"`
	System         SystemConfig                    `toml:"system"`
	Registry       RegistryConfig                  `toml:"registry"`
	Builder        BuilderConfig                   `toml:"builder"`
	Kubernetes     KubernetesConfig                `toml:"kubernetes"`
	GitAuth        map[string]GitAuthEntry         `toml:"git_auth"`
	Plugins        map[string]PluginSettings       `toml:"plugin"`
	Auth           map[string]AuthConfig           `toml:"auth"`
	SAML           map[string]SAMLConfig           `toml:"saml"`
	ClientAuth     map[string]ClientCertConfig     `toml:"client_auth"`
	Secret         map[string]SecretConfig         `toml:"secret"`
	Forward        map[string]ForwardConfig        `toml:"forward"`
	ProfileMode    string                          `toml:"profile_mode"`
	AppConfig      AppConfig                       `toml:"app_config"`
	NodeConfig     NodeConfig                      `toml:"node_config"`
	Permissions    PermissionsConfig               `toml:"permissions"`
	AppBuilder     AppBuilderConfig                `toml:"app_builder"`
	BuilderAgent   map[string]BuilderAgentConfig   `toml:"builder_agent"`
	BuilderPublish map[string]BuilderPublishConfig `toml:"builder_publish"`
	BuilderPrompt  map[string]BuilderPromptConfig  `toml:"builder_prompt"`
	BuilderGit     map[string]BuilderGitConfig     `toml:"builder_git"`
}

// BuilderPromptConfig is one [builder_prompt.*] entry: a named prompt preset
// the user can pick when creating a builder app. Replace controls whether
// the preset replaces the system prompt or is appended to it
type BuilderPromptConfig struct {
	Prompt      string `toml:"prompt"`
	Replace     bool   `toml:"replace"`     // replace the system prompt instead of appending to it
	Description string `toml:"description"` // shown in the new-app form
	GitConfig   string `toml:"git_config"`  // [builder_git.*] entry sessions created with this preset publish to; empty = builder default
}

// BuilderGitConfig is one [builder_git.*] entry: a named git publish
// destination for builder apps. Empty branch/apps_file/source_dir default
// to main/apps.star/apps
type BuilderGitConfig struct {
	Repo      string `toml:"repo"`       // publish repo url
	Branch    string `toml:"branch"`     // branch for publish commits
	Auth      string `toml:"auth"`       // [git_auth.*] entry for the repo
	AppsFile  string `toml:"apps_file"`  // declarative file, relative to repo root
	SourceDir string `toml:"source_dir"` // repo directory for published app sources
}

// AppBuilderConfig configures the AI app builder (console Builder tab). Not
// supported when the container backend is Kubernetes: the agent sandbox needs
// a local docker/podman runtime with host directory volume mounts
type AppBuilderConfig struct {
	Enabled         bool   `toml:"enabled"`
	PreviewPath     string `toml:"preview_path"` // mount prefix for draft preview apps
	DefaultAgent    string `toml:"default_agent"`
	MaxSessions     int    `toml:"max_sessions"`
	SessionIdleMins int    `toml:"session_idle_mins"`
	WorkspaceDir    string `toml:"workspace_dir"` // default $OPENRUN_HOME/run/builder
	SystemPrompt    string `toml:"system_prompt"` // replaces the embedded base prompt when set
	PromptExtra     string `toml:"prompt_extra"`  // admin text appended to the system prompt

	// DefaultGitConfig names the [builder_git.*] entry used when the
	// session's prompt preset does not pick one. Empty (and no preset
	// choice) selects local publish mode ($OPENRUN_HOME/app_src)
	DefaultGitConfig string `toml:"default_git_config"`
}

// Defaults applied to empty [builder_git.*] entry fields
const (
	BuilderGitDefaultBranch    = "main"
	BuilderGitDefaultAppsFile  = "apps.star"
	BuilderGitDefaultSourceDir = "apps"
)

// ResolveBuilderGit returns the git publish destination for a builder
// session created with promptPreset: the preset's git_config if set, else
// app_builder.default_git_config. With neither set the result has an empty
// Repo, which selects local publish mode ($OPENRUN_HOME/app_src)
func (c *ServerConfig) ResolveBuilderGit(promptPreset string) (BuilderGitConfig, error) {
	name := ""
	if promptPreset != "" {
		preset, ok := c.BuilderPrompt[promptPreset]
		if !ok {
			return BuilderGitConfig{}, fmt.Errorf("no [builder_prompt.%s] config entry", promptPreset)
		}
		name = preset.GitConfig
	}
	if name == "" {
		name = c.AppBuilder.DefaultGitConfig
	}
	if name == "" {
		return BuilderGitConfig{AppsFile: BuilderGitDefaultAppsFile}, nil // local mode
	}

	entry, ok := c.BuilderGit[name]
	if !ok {
		return BuilderGitConfig{}, fmt.Errorf("no [builder_git.%s] config entry", name)
	}
	if entry.Branch == "" {
		entry.Branch = BuilderGitDefaultBranch
	}
	if entry.AppsFile == "" {
		entry.AppsFile = BuilderGitDefaultAppsFile
	}
	if entry.SourceDir == "" {
		entry.SourceDir = BuilderGitDefaultSourceDir
	}
	return entry, nil
}

// BuilderPublishConfig is one [builder_publish.*] entry: an app path glob
// users may publish builder apps to, with a description of the RBAC rules
// that apply there. No entries means any path is allowed (RBAC still gates)
type BuilderPublishConfig struct {
	Path        string `toml:"path"`        // app path glob, e.g. /teams/* or example.com:/**
	Description string `toml:"description"` // shown in the publish dialog: which RBAC rules apply
}

// BuilderAgentConfig is one agent profile for the app builder. The agent
// type is inferred from the entry name, like auth entries: opencode,
// opencode_dev, pi, ... use the embedded Dockerfile and ACP launch command
// for their type; custom_<name> entries must set Dockerfile and Command.
// The command must speak the Agent Client Protocol on stdio
type BuilderAgentConfig struct {
	Type        string            `toml:"type"`         // optional; must match the type inferred from the name
	Dockerfile  string            `toml:"dockerfile"`   // overrides the embedded Dockerfile
	Command     []string          `toml:"command"`      // overrides the embedded ACP command
	Env         map[string]string `toml:"env"`          // container env, {{secret ...}} resolved at launch
	ConfigFiles []string          `toml:"config_files"` // host:container[:ro] mounts
	Model       string            `toml:"model"`        // model passed to the agent at session start (agent's naming)
	Effort      string            `toml:"effort"`       // reasoning effort level passed to the agent at session start
}

// BuilderSessionStatus is the lifecycle state of a builder session
type BuilderSessionStatus string

const (
	BuilderSessionStarting  BuilderSessionStatus = "starting"  // sandbox launching / first turn running
	BuilderSessionReady     BuilderSessionStatus = "ready"     // agent idle, sandbox live
	BuilderSessionRunning   BuilderSessionStatus = "running"   // prompt turn in flight
	BuilderSessionDetached  BuilderSessionStatus = "detached"  // sandbox stopped, workspace persists
	BuilderSessionPublished BuilderSessionStatus = "published" // published at least once
	BuilderSessionError     BuilderSessionStatus = "error"     // failed to start / load
)

// BuilderSession is one app builder session (draft app + agent sandbox)
type BuilderSession struct {
	Id           string               `json:"id"`
	UserID       string               `json:"user_id"`
	Name         string               `json:"name"`
	Spec         string               `json:"spec"`
	Agent        string               `json:"agent"`        // [builder_agent.*] profile name
	Preset       string               `json:"preset"`       // [builder_prompt.*] preset chosen at creation; decides the git destination
	EditApp      string               `json:"edit_app"`     // app path this session edits (builder-published app); empty for create sessions
	EditVersion  int                  `json:"edit_version"` // app version the workspace was seeded from
	Status       BuilderSessionStatus `json:"status"`
	WorkspaceDir string               `json:"workspace_dir"`
	PreviewPath  string               `json:"preview_path"` // dev app path, once created
	PublishPath  string               `json:"publish_path"` // once published
	CreateTime   time.Time            `json:"create_time"`
	UpdateTime   time.Time            `json:"update_time"`
}

// BuilderActivity is one activity log row: prompts, agent messages, tool
// calls and lifecycle events for a builder session
type BuilderActivity struct {
	Id         string         `json:"id"`
	SessionId  string         `json:"session_id"`
	UserID     string         `json:"user_id"`
	CreateTime time.Time      `json:"create_time"`
	Kind       string         `json:"kind"` // prompt|agent_message|tool_call|lifecycle|approve|publish|unpublish|error
	Content    string         `json:"content"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type PluginSettings map[string]any
type SecretConfig map[string]any
type NodeConfig map[string]any

type AppConfig struct {
	CORS       CORS         `toml:"cors"`
	Action     ActionConfig `toml:"action"`
	Container  Container    `toml:"container"`
	Kubernetes Kubernetes   `toml:"kubernetes"`
	Proxy      Proxy        `toml:"proxy"`
	FS         FS           `toml:"fs"`
	Audit      Audit        `toml:"audit"`
	Security   Security     `toml:"security"`
	StarBase   string       `toml:"star_base"` // The base directory for starlark config files
}

type ActionConfig struct {
	MaxRequestBodyBytes int64 `toml:"max_request_body_bytes"`
}
type Security struct {
	DefaultSecretsProvider string `toml:"default_secrets_provider"`
	DisableCSRFProtection  bool   `toml:"disable_csrf_protection"`
	// HeadersLevel controls the set of security related HTTP response headers added to
	// app responses. Valid values are 0 to 10: 0 adds no extra headers and 10 adds the
	// strictest full set. Levels 0, 2, 5 and 10 are currently implemented; any other
	// value is rounded down to the nearest implemented level. Default is 2.
	HeadersLevel int `toml:"headers_level"`
}

type CORS struct {
	AllowOrigin      string `toml:"allow_origin"`
	AllowMethods     string `toml:"allow_methods"`
	AllowHeaders     string `toml:"allow_headers"`
	AllowCredentials string `toml:"allow_credentials"`
	MaxAge           string `toml:"max_age"`
}

type FS struct {
	FileAccess     []string `toml:"file_access"`
	RetainVersions int      `toml:"retain_versions"` // number of older versions to keep for each app
}

type Audit struct {
	RedactUrl      bool `toml:"redact_url"`
	SkipHttpEvents bool `toml:"skip_http_events"`
}

type Container struct {
	// Health check related config
	HealthUrl                  string `toml:"health_url"`
	HealthAttemptsAfterStartup int    `toml:"health_attempts_after_startup"`
	HealthTimeoutSecs          int    `toml:"health_timeout_secs"`
	DeployProbePeriodSecs      int    `toml:"deploy_probe_period_secs"`
	DeployHealthAttempts       int    `toml:"deploy_health_attempts"`
	// Overrides Kubernetes progressDeadlineSeconds when >0. Keep 0 unless tests
	// or operators deliberately want failed rollouts to be declared earlier.
	DeployProgressDeadlineSecs int `toml:"deploy_progress_deadline_secs"`

	LogLinesToShow     int  `toml:"log_lines_to_show"`
	ShowLogsForFailure bool `toml:"show_logs_for_failure"`

	// Idle shutdown related config
	IdleShutdownSecs       int  `toml:"idle_shutdown_secs"`
	IdleShutdownDevApps    bool `toml:"idle_shutdown_dev_apps"`
	IdleBytesHighWatermark int  `toml:"idle_bytes_high_watermark"`

	// Status check related config
	StatusCheckIntervalSecs int `toml:"status_check_interval_secs"`
	StatusHealthAttempts    int `toml:"status_health_attempts"`
}

// Kubernetes related settings in the App Config
type Kubernetes struct {
	DefaultVolumeSize   string `toml:"default_volume_size"`
	ScalingThresholdCPU int32  `toml:"scaling_threshold_cpu"` // CPU utilization threshold for HPA scaling
}

type Proxy struct {
	// Proxy related config
	MaxIdleConns        int  `toml:"max_idle_conns"`
	IdleConnTimeoutSecs int  `toml:"idle_conn_timeout_secs"`
	DisableCompression  bool `toml:"disable_compression"`
	RewriteLocation     bool `toml:"rewrite_location"`
}

type PluginContext struct {
	Logger    *Logger
	AppId     AppId
	StoreInfo *starlark_type.StoreInfo
	Config    PluginSettings
	AppConfig AppConfig
	AppPath   string
}

// HttpConfig is the configuration for the HTTP server
type HttpConfig struct {
	Host            string `toml:"host"`
	Port            int    `toml:"port"`
	RedirectToHttps bool   `toml:"redirect_to_https"`
}

// HttpsConfig is the configuration for the HTTPs server
type HttpsConfig struct {
	Host               string `toml:"host"`
	Port               int    `toml:"port"`
	EnableCertLookup   bool   `toml:"enable_cert_lookup"`
	MkcertPath         string `toml:"mkcert_path"`
	ServiceEmail       string `toml:"service_email"`
	UseStaging         bool   `toml:"use_staging"`
	StorageLocation    string `toml:"storage_location"`
	CertLocation       string `toml:"cert_location"`
	DisableClientCerts bool   `toml:"disable_client_certs"`
}

// SecurityConfig is the security related configuration
type SecurityConfig struct {
	UnsafeAdminOverTCP       bool              `toml:"unsafe_admin_over_tcp"`
	AdminPasswordBcrypt      string            `toml:"admin_password_bcrypt"`
	AppDefaultAuthType       string            `toml:"app_default_auth_type"`
	AuthRequired             bool              `toml:"auth_required"`
	SessionMaxAge            int               `toml:"session_max_age"`
	SessionHttpsOnly         bool              `toml:"session_https_only"`
	TrustedProxies           []string          `toml:"trusted_proxies"`
	CallbackUrl              string            `toml:"callback_url"`
	DefaultGitAuth           string            `toml:"default_git_auth"`
	StageEnableWriteAccess   bool              `toml:"stage_enable_write_access"`
	PreviewEnableWriteAccess bool              `toml:"preview_enable_write_access"`
	AllowedContainerArgs     map[string]string `toml:"allowed_container_args"` // the container args that are allowed to be used in the app config
	AllowedMounts            []string          `toml:"allowed_mounts"`         // the volume mounts paths that are allowed to be used in the app config

	// UnsafeAgentWithoutSandbox runs app builder agents as plain host
	// processes instead of container sandboxes. The sandbox is the safety
	// boundary for auto-approved agent tool calls, so this is not
	// recommended; dev-only escape hatch (e.g. codex using the host login
	// instead of an API key)
	UnsafeAgentWithoutSandbox bool `toml:"unsafe_agent_without_sandbox"`

	// UnsafeEnableTestUrlRbac allows _cl_perm= and _cl_role= URL path directives on
	// dev mode apps with none auth, simulating RBAC permissions/roles for
	// testing. Off by default.
	UnsafeEnableTestUrlRbac bool `toml:"unsafe_enable_testurl_rbac"`

	// UnsafeAllowSystemPluginsAnon allows anonymous (unauthenticated) callers to
	// invoke the privileged system plugins (openrun_admin, build). By default
	// these plugins require an authenticated user regardless of RBAC status, so
	// a console app accidentally served with none auth cannot perform admin or
	// builder operations. The read-only openrun plugin is never gated. Enabling
	// this is dev-only (e.g. the console running with none auth).
	UnsafeAllowSystemPluginsAnon bool `toml:"unsafe_allow_system_plugins_anon"`
}

// MetadataConfig is the configuration for the Metadata persistence layer
type MetadataConfig struct {
	DBConnection        string `toml:"db_connection"`
	AutoUpgrade         bool   `toml:"auto_upgrade"`
	AuditDBConnection   string `toml:"audit_db_connection"`
	IgnoreHigherVersion bool   `toml:"ignore_higher_version"` // If true, ignore higher version of the metadata schema
	FileCacheConnection string `toml:"file_cache_connection"` // The connection string for the file cache database

	// ConfigHistoryVersions is the number of dynamic config snapshots retained
	// in the config_history table. Every config change appends a snapshot
	ConfigHistoryVersions int `toml:"config_history_versions"`
}

// LogConfig is the configuration for the Logger
type LogConfig struct {
	Level         string `toml:"level"`
	MaxBackups    int    `toml:"max_backups"`
	MaxSizeMB     int    `toml:"max_size_mb"`
	Console       bool   `toml:"console"`
	File          bool   `toml:"file"`
	AccessLogging bool   `toml:"access_logging"`
}

// TelemetryConfig is the OpenTelemetry configuration.
type TelemetryConfig struct {
	Enabled     bool              `toml:"enabled"`
	ServiceName string            `toml:"service_name"`
	Environment string            `toml:"environment"`
	Endpoint    string            `toml:"endpoint"`
	Headers     map[string]string `toml:"headers"`
	Traces      bool              `toml:"traces"`
	Metrics     bool              `toml:"metrics"`
	// PluginSpans, when true, creates a span around each Starlark plugin
	// invocation. Off by default because data-heavy apps may issue many
	// plugin calls per request.
	PluginSpans bool `toml:"plugin_spans"`
}

const (
	TailwindVersionLegacy  = 3
	TailwindVersionCurrent = 4
	TailwindVersionDefault = TailwindVersionCurrent
	TailwindVersionMin     = TailwindVersionLegacy
)

// SystemConfig is the system level configuration
type SystemConfig struct {
	TailwindCSSCommand                  string   `toml:"tailwindcss_command"`
	TailwindVersion                     int      `toml:"tailwind_version"`
	DaisyUIURL                          string   `toml:"daisyui_url"`       // url for the prebundled daisyui plugin, used with tailwind_version 4
	DaisyUIThemeURL                     string   `toml:"daisyui_theme_url"` // url for the prebundled daisyui theme plugin, used for custom themes
	FileWatcherDebounceMillis           int      `toml:"file_watcher_debounce_millis"`
	WatchIgnorePatterns                 []string `toml:"watch_ignore_patterns"`
	NodePath                            string   `toml:"node_path"`
	ContainerCommand                    string   `toml:"container_command"`
	StaleContainerCleanupIntervalMins   int      `toml:"stale_container_cleanup_interval_mins"` // Interval for stale OpenRun container cleanup. Set <=0 to disable.
	ContainerBuilder                    string   `toml:"container_builder"`
	DefaultDomain                       string   `toml:"default_domain"`
	RootServeListApps                   string   `toml:"root_serve_list_apps"`
	EnableCompression                   bool     `toml:"enable_compression"`
	HttpEventRetentionDays              int      `toml:"http_event_retention_days"`
	NonHttpEventRetentionDays           int      `toml:"non_http_event_retention_days"`
	AllowedEnv                          []string `toml:"allowed_env"`                             // List of environment variables that are allowed to be used in the node config
	DefaultScheduleMins                 int      `toml:"default_schedule_mins"`                   // Default schedule time in minutes for scheduled sync
	MaxSyncFailureCount                 int      `toml:"max_sync_failure_count"`                  // Max failure count for sync jobs
	MaxConcurrentBuilds                 int      `toml:"max_concurrent_builds"`                   // Max concurrent container builds
	MaxBuildWaitSecs                    int      `toml:"max_build_wait_secs"`                     // Max wait time for a build lock
	UseImagePreBuildStep                bool     `toml:"use_image_pre_build_step"`                // Pre-build container images for verified reloads before the metadata transaction starts
	EarlyHints                          bool     `toml:"early_hints"`                             // enable early hints for HTML responses
	LeaderElectionLeaseSecs             int      `toml:"leader_election_lease_secs"`              // The lease time for the leader election
	LeaderElectionHeartbeatIntervalSecs int      `toml:"leader_election_heartbeat_interval_secs"` // The interval for the leader election heartbeat
	FileWorkers                         int      `toml:"file_workers"`                            // number of parallel workers for file compression during app version creation
	ListAppsTitle                       string   `toml:"list_apps_title"`                         // the title of the list apps page
	ShowHostedWith                      bool     `toml:"show_hosted_with"`                        // whether to show "Hosted with OpenRun" in the list apps page
	FallbackUnknownDomains              bool     `toml:"fallback_unknown_domains"`                // whether to fallback to default domain for unknown domains
	ForwardAuthTimeoutSecs              int      `toml:"forward_auth_timeout_secs"`               // timeout in seconds for forward auth requests. Defaults to 30 seconds.
	BuilderAuthToken                    string   `toml:"builder_auth_token"`                      // the token for the builder auth
	// StageAt is the default staging mode for new prod apps. "domain" stages at domain level,
	// "path" stages at path level, and any other value is treated as the staging domain.
	// Defaults to "domain".
	StageAt            string `toml:"stage_at"`
	DefaultStageDomain string `toml:"default_stage_domain"`
}

type RegistryConfig struct {
	URL            string `toml:"url"`
	Project        string `toml:"project"`
	Type           string `toml:"type"` // "", "ecr"
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	PasswordFile   string `toml:"password_file"`
	CAFile         string `toml:"ca_file"`
	ClientCertFile string `toml:"client_cert_file"`
	ClientKeyFile  string `toml:"client_key_file"`
	Insecure       bool   `toml:"insecure"`
	AWSRegion      string `toml:"aws_region"`
}

type KubernetesConfig struct {
	Namespace   string `toml:"namespace"`
	UseNodePort bool   `toml:"use_node_port"` // Use NodePort mode instead of default ClusterIP mode
	// Can be used with k3s for single node cluster where the OpenRun server is not running as a pod
}

type BuilderConfig struct {
	Mode            string `toml:"mode"` // "auto", "kaniko", "command", "delegate:<url>", "delegate_server"
	KanikoImage     string `toml:"kaniko_image"`
	KanikoCache     bool   `toml:"kaniko_cache"`      // enable kaniko layer caching in the registry
	KanikoCacheRepo string `toml:"kaniko_cache_repo"` // cache repo, defaults to <registry_url>[/<project>]/kaniko-cache
}

// GitAuth is a github auth config entry
type GitAuthEntry struct {
	UserID      string `toml:"user_id"`       // the user id of the user, defaults to "git" https://github.com/src-d/go-git/issues/637
	KeyFilePath string `toml:"key_file_path"` // the path to the private key file
	PrivateKey  string `toml:"private_key"`   // the private key contents (PEM), used instead of key_file_path; supports {{secret}} references
	Password    string `toml:"password"`      // the password for the private key file
}

// AuthConfig is the configuration for the Authentication provider
type AuthConfig struct {
	Key          string   `toml:"key"`           // the client id
	Secret       string   `toml:"secret"`        // the client secret
	OrgUrl       string   `toml:"org_url"`       // the org url, used for Okta
	Domain       string   `toml:"domain"`        // the domain, used for Auth0
	DiscoveryUrl string   `toml:"discovery_url"` // the discovery url, used for OIDC
	HostedDomain string   `toml:"hosted_domain"` // the hosted domain, used for Google
	Scopes       []string `toml:"scopes"`        // oauth scopes
}

type ForwardConfig struct {
	AuthUrl             string   `toml:"auth_url"`              // the auth url to send the GET request to
	ForwardHeaders      []string `toml:"forward_headers"`       // the headers to forward to the auth url. If empty, all headers are forwarded.
	CopyResponseHeaders []string `toml:"copy_response_headers"` // the headers to copy from the authserver response to app. Default is none
}

// PermissionsConfig is the permissions configuration for the server. This overrides the permissions configured in the app metadata.
type PermissionsConfig struct {
	Allow              []Permission `toml:"allow"`                // the permissions that are allowed for all apps, without requiring explicit approval
	BindingSourcePerms []string     `toml:"binding_source_perms"` // the binding sources that are allowed for all apps, without requiring explicit approval
	// supports a regex for the binding path, like "regex:/appdata/.*"
}

type ClientCertConfig struct {
	CACertFile string         `toml:"ca_cert_file"`
	RootCAs    *x509.CertPool `toml:"-"`
}

// ClientConfig is the configuration for the OpenRun Client
type ClientConfig struct {
	GlobalConfig
	Client ClientConfigStruct `toml:"client"`
}

// ClientConfigStruct is the configuration for the OpenRun Client
type ClientConfigStruct struct {
	SkipCertCheck bool   `toml:"skip_cert_check"`
	AdminPassword string `toml:"admin_password"`
	DefaultFormat string `toml:"default_format"` // the default format for the CLI output
}

// AppId is the identifier for an App
type AppId string

// AppPathDomain is a unique identifier for an app, consisting of the path and domain
type AppPathDomain struct {
	Path   string
	Domain string
}

func (a AppPathDomain) String() string {
	if a.Domain == "" {
		return a.Path
	} else {
		return a.Domain + ":" + a.Path
	}
}

// AppInfo is the basic info for an app
type AppInfo struct {
	AppPathDomain
	Name           string
	Id             AppId
	IsDev          bool
	MainApp        AppId
	LinkedAppPath  string
	Auth           AppAuthnType
	SourceUrl      string
	Spec           AppSpec
	Version        int
	GitSha         string
	GitMessage     string
	Branch         string
	StarBase       string
	UpdateTime     time.Time
	RetainVersions int
	AppliedSyncId  string
	UserID         string // user who created the app, used for RBAC owner checks
}

func CreateAppPathDomain(path, domain string) AppPathDomain {
	return AppPathDomain{
		Path:   path,
		Domain: domain,
	}
}

func CreateAppInfo(id AppId, name, path, domain string, isDev bool, mainApp AppId, linkedAppPath string,
	auth AppAuthnType, sourceUrl string, spec AppSpec,
	version int, gitSha, gitMessage, branch, starBase string, updatedAt time.Time, retainVersions int,
	appliedSyncId string, userId string) AppInfo {
	return AppInfo{
		AppPathDomain: AppPathDomain{
			Path:   path,
			Domain: domain,
		},
		Name:           name,
		Id:             id,
		IsDev:          isDev,
		MainApp:        mainApp,
		LinkedAppPath:  linkedAppPath,
		Auth:           auth,
		SourceUrl:      sourceUrl,
		Spec:           spec,
		Version:        version,
		GitSha:         gitSha,
		GitMessage:     gitMessage,
		Branch:         branch,
		StarBase:       starBase,
		UpdateTime:     updatedAt,
		RetainVersions: retainVersions,
		AppliedSyncId:  appliedSyncId,
		UserID:         userId,
	}
}

// Permission represents a permission granted to an app to run
// a plugin method with the given arguments
type Permission struct {
	Plugin    string   `json:"plugin" toml:"plugin"`
	Method    string   `json:"method" toml:"method"`
	Arguments []string `json:"arguments" toml:"arguments"`
	Permit    []string `json:"permit" toml:"permit"`                       // Custom RBAC permissions, any one of which allows the call.
	IsRead    *bool    `json:"is_read,omitempty" toml:"is_read,omitempty"` // Whether the call is a Read operation or Write operation.
	// nil value means go with the default as set in the plugin code
	Secrets [][]string `json:"secrets" toml:"secrets"` // The secrets that are allowed to be used in the call.
}

// AppAuthnType is the app level authentication type
type AppAuthnType string

const (
	AppAuthnNone    AppAuthnType = "none"    // No auth
	AppAuthnDefault AppAuthnType = "default" // Use whatever auth is the default for the system
	AppAuthnSystem  AppAuthnType = "system"  // Use the system admin user
)

type AppSpec string

const (
	StaticDiskSpec AppSpec = "static_disk"
)

// VersionMetadata contains the metadata for an app
type VersionMetadata struct {
	Version         int    `json:"version"`
	PreviousVersion int    `json:"previous_version"`
	GitBranch       string `json:"git_branch"`
	GitCommit       string `json:"git_commit"`
	GitMessage      string `json:"git_message"`
	ApplyInfo       []byte `json:"apply_info"`
	AppliedSyncId   string `json:"applied_sync_id"`
}

// AppEntry is the application configuration in the DB
type AppEntry struct {
	Id            AppId  `json:"id"`
	Path          string `json:"path"`
	Domain        string `json:"domain"`
	MainApp       AppId  `json:"main_app"`        // the id of the app that this app is linked to
	LinkedAppPath string `json:"linked_app_path"` // the path of the app that this app is linked to
	// for main app, points to the stage app. For stage app, points to the main app.
	// For preview apps, points to the base app. Not set for dev apps.
	SourceUrl  string      `json:"source_url"`
	IsDev      bool        `json:"is_dev"`
	UserID     string      `json:"user_id"`
	CreateTime *time.Time  `json:"create_time"`
	UpdateTime *time.Time  `json:"update_time"`
	Settings   AppSettings `json:"settings"` // settings are not version controlled
	Metadata   AppMetadata `json:"metadata"` // metadata is version controlled
}

func (ae *AppEntry) String() string {
	if ae.Domain == "" {
		return ae.Path
	} else {
		return ae.Domain + ":" + ae.Path
	}
}

func (ae *AppEntry) AppPathDomain() AppPathDomain {
	return AppPathDomain{
		Path:   ae.Path,
		Domain: ae.Domain,
	}
}

// AppMetadata contains the configuration for an app. App configurations are version controlled.
type AppMetadata struct {
	Name                       string            `json:"name"`
	VersionMetadata            VersionMetadata   `json:"version_metadata"`
	Loads                      []string          `json:"loads"`
	Permissions                []Permission      `json:"permissions"`
	Accounts                   []AccountLink     `json:"accounts"`
	BindingSourcePerms         []string          `json:"binding_source_perms"`          // the binding source permissions that are requested for the app
	ApprovedBindingSourcePerms []string          `json:"approved_binding_source_perms"` // the binding source permissions that are approved for the app
	ParamValues                map[string]string `json:"param_values"`
	Spec                       AppSpec           `json:"spec"`
	SpecFiles                  *SpecFiles        `json:"spec_files"`
	ContainerOptions           map[string]string `json:"container_options"`
	ContainerArgs              map[string]string `json:"container_args"`
	ContainerVolumes           []string          `json:"container_volumes"`
	AppConfig                  map[string]string `json:"appconfig"`
	AuthnType                  AppAuthnType      `json:"authn_type"`
	GitAuthName                string            `json:"git_auth_name"`
	Bindings                   []string          `json:"bindings"`
	AppliedSyncId              string            `json:"applied_sync_id"`             // id of the sync entry which last applied to this app, empty for imperative changes
	BuilderPublished           bool              `json:"builder_published,omitempty"` // app was published by the app builder; enables builder edit sessions
}

// AppSettings contains the settings for an app. Settings are not version controlled.
type AppSettings struct {
	//Deprecated: use AppMetadata.AuthnType instead
	AuthnType AppAuthnType `json:"authn_type"`
	//Deprecated: use AppMetadata.GitAuthName instead
	GitAuthName        string        `json:"git_auth_name"`
	StageWriteAccess   bool          `json:"stage_write_access"`
	PreviewWriteAccess bool          `json:"preview_write_access"`
	WebhookTokens      WebhookTokens `json:"webhook_tokens"`
	OrigSourceUrl      string        `json:"orig_source_url"` // the original source url of the app, used for git create in dev mode
}

type WebhookTokens struct {
	Reload        string `json:"reload"`
	ReloadPromote string `json:"reload_promote"`
	Promote       string `json:"promote"`
}

type WebhookType string

const (
	WebhookReload        WebhookType = "reload"
	WebhookReloadPromote WebhookType = "reload_promote"
	WebhookPromote       WebhookType = "promote"
)

// SpecFiles is a map of file names to file data. JSON encoding uses base 64 encoding of file text
type SpecFiles map[string]string

func (t *SpecFiles) UnmarshalJSON(data []byte) error {
	encodedData := map[string]string{}
	if err := json.Unmarshal(data, &encodedData); err != nil {
		return err
	}

	decoded := map[string]string{}
	for name, encodedData := range encodedData {
		decodedData, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			return err
		}
		decoded[name] = string(decodedData)
	}

	*t = SpecFiles(decoded)
	return nil
}

func (t *SpecFiles) MarshalJSON() ([]byte, error) {
	encoded := map[string]string{}
	for name, decodedData := range *t {
		encoded[name] = base64.StdEncoding.EncodeToString([]byte(decodedData))
	}

	return json.Marshal(encoded)
}

// AccountLink links the account to use for each plugin
type AccountLink struct {
	Plugin      string `json:"plugin"`
	AccountName string `json:"account_name"`
}

type BoolValue int

const (
	BoolValueUndefined BoolValue = iota
	BoolValueTrue
	BoolValueFalse
)

type StringValue string

const (
	StringValueUndefined StringValue = "<OPENRUN_UNDEFINED>"
)

type AppMetadataConfigType string

const (
	AppMetadataAppConfig        AppMetadataConfigType = "app_config"
	AppMetadataContainerOptions AppMetadataConfigType = "container_options"
	AppMetadataContainerArgs    AppMetadataConfigType = "container_args"
	AppMetadataContainerVolumes AppMetadataConfigType = "container_volumes"
	AppMetadataAuthnType        AppMetadataConfigType = "auth"
	AppMetadataGitAuthName      AppMetadataConfigType = "git_auth"
	AppMetadataBindings         AppMetadataConfigType = "bindings"
	AppMetadataBindingPerms     AppMetadataConfigType = "bind_perm"
)

type AppVersion struct {
	Active          bool
	AppId           AppId
	Version         int
	PreviousVersion int
	UserId          string
	Metadata        *AppMetadata
	CreateTime      time.Time
}

type AppFile struct {
	Name string
	Etag string
	Size int64
}

// Transaction is a wrapper around sql.Tx
type Transaction struct {
	*sql.Tx
}

func (t *Transaction) IsInitialized() bool {
	return t.Tx != nil
}

func StripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// StyleType is the type of style library used by the app
type StyleType string

type UserFile struct {
	Id           string
	AppId        string
	FilePath     string
	FileName     string
	MimeType     string
	CreateTime   time.Time
	ExpireAt     time.Time
	CreatedBy    string
	SingleAccess bool
	Visibility   string
	Metadata     map[string]any
}

type EventType string

const (
	EventTypeSystem EventType = "system"
	EventTypeHTTP   EventType = "http"
	EventTypeAction EventType = "action"
	EventTypeCustom EventType = "custom"
)

type AuditEvent struct {
	RequestId  string
	AppId      AppId
	CreateTime time.Time
	UserId     string
	EventType  EventType
	Operation  string
	Target     string
	Status     string
	Detail     string
}

type EventStatus string

const (
	EventStatusSuccess EventStatus = "Success"
	EventStatusFailure EventStatus = "Failed"
)

const REGEX_PREFIX = "regex:"

func RegexMatch(perm, entry string) (bool, error) {
	if len(perm) <= 6 || !strings.HasPrefix(perm, REGEX_PREFIX) {
		return false, nil
	}
	perm = perm[6:]
	return regexp.MatchString(perm, entry)
}

func GetAppUrl(appPathDomain AppPathDomain, serverConfig *ServerConfig) string {
	useHttps := serverConfig.Https.Port > 0
	domain := cmp.Or(appPathDomain.Domain, serverConfig.System.DefaultDomain)
	if useHttps {
		return fmt.Sprintf("https://%s:%d%s", domain, serverConfig.Https.Port, appPathDomain.Path)
	} else {
		return fmt.Sprintf("http://%s:%d%s", domain, serverConfig.Http.Port, appPathDomain.Path)
	}
}

type DryRun bool

const (
	DryRunTrue  DryRun = true
	DryRunFalse DryRun = false
)

type SyncEntry struct {
	Id          string        `json:"id"`
	Path        string        `json:"path"`
	IsScheduled bool          `json:"is_scheduled"` // whether this is a scheduled sync
	UserID      string        `json:"user_id"`
	CreateTime  *time.Time    `json:"create_time"`
	Metadata    SyncMetadata  `json:"metadata"`
	Status      SyncJobStatus `json:"status"`
}

// RBACSnapshot freezes the sync creator's RBAC authorization at sync create
// time: the grants whose Users matched the creator (group membership, including
// SSO context groups, resolved at create time), with role permissions flattened.
// Background sync runs are authorized against this snapshot, so later role,
// group or grant edits do not change what an existing sync entry may do. Nil
// when the create call was not RBAC enforced; such syncs run unrestricted.
type RBACSnapshot struct {
	UserId           string                      `json:"user_id"`
	Admin            bool                        `json:"admin,omitempty"` // creator held the admin super-user permission; Grants is empty
	Grants           []RBACSnapshotGrant         `json:"grants,omitempty"`
	OwnerPermissions map[string][]RBACPermission `json:"owner_permissions,omitempty"` // resource -> perms, for the owner virtual grant
}

// RBACSnapshotGrant is one grant that matched the creator, with the referenced
// roles flattened into their permission entries (exact permissions with
// implications expanded, glob and custom: entries preserved)
type RBACSnapshotGrant struct {
	Description string           `json:"description,omitempty"`
	Permissions []RBACPermission `json:"permissions"`
	Targets     []string         `json:"targets"`
}

type SyncMetadata struct {
	GitBranch string `json:"git_branch"` // the git branch to sync from
	GitAuth   string `json:"git_auth"`   // the git auth entry to use for the sync

	Promote     bool   `json:"promote"`      // whether this sync does a promote
	Approve     bool   `json:"approve"`      // whether this sync does an approve
	Verify      bool   `json:"verify"`       // whether this sync verifies container reloads
	Reload      string `json:"reload"`       // which apps to reload after the sync
	Clobber     bool   `json:"clobber"`      // whether to force update the sync, overwriting non-declarative changes
	ForceReload bool   `json:"force_reload"` // whether to force reload even if there is no new commit

	WebhookUrl        string `json:"webhook_url"`        // for webhook : the url to use
	WebhookSecret     string `json:"webhook_secret"`     // for webhook : the secret to use
	ScheduleFrequency int    `json:"schedule_frequency"` // for scheduled: the frequency of the sync, every N minutes

	RBAC *RBACSnapshot `json:"rbac,omitempty"` // creator authorization frozen at create time, nil means unrestricted
}

type SyncJobStatus struct {
	State             string           `json:"state"`               // the state of the sync job
	FailureCount      int              `json:"failure_count"`       // the number of times the sync job has failed recently
	LastExecutionTime time.Time        `json:"last_execution_time"` // the last time the sync job was executed
	Error             string           `json:"error"`               // the error message if the sync job failed
	CommitId          string           `json:"commit_id"`           // the commit id of the sync job
	IsApply           bool             `json:"is_apply"`            // whether this is an apply job
	ApplyResponse     AppApplyResponse `json:"app_apply_response"`  // the response of the apply job
}

// NotificationMessage is the message sent through the postgres listener
type NotificationMessage struct {
	MessageType string `json:"message_type"`
}

type ServerId string // the id of the server that sent the notification

var CurrentServerId ServerId // initialized in server.go init()

const MessageTypeAppUpdate = "app_update"
const MessageTypeConfigUpdate = "config_update"

type AppUpdatePayload struct {
	AppPathDomains []AppPathDomain `json:"app_path_domains"`
	ServerId       ServerId        `json:"server_id"`
}

type AppUpdateMessage struct {
	MessageType string           `json:"message_type"`
	Payload     AppUpdatePayload `json:"payload"`
}

type ConfigUpdatePayload struct {
	ServerId ServerId `json:"server_id"`
}

type ConfigUpdateMessage struct {
	MessageType string              `json:"message_type"`
	Payload     ConfigUpdatePayload `json:"payload"`
}

type LibraryType string

const (
	ESModule LibraryType = "ecmascript_module"
	Library  LibraryType = "library"
)

const (
	LIB_PATH = "static/gen/lib"
	ESM_PATH = "static/gen/esm"
)

// JSLibrary handles the downloading for JS libraries and esbuild based bundling for ESM libraries
type JSLibrary struct {
	LibType           LibraryType
	DirectUrl         string
	PackageName       string
	Version           string
	EsbuildArgs       [10]string // use an array so that the struct can be used as key in the jsCache map
	SanitizedFileName string
}

// DynamicConfig is the configuration which is settable through API and is persisted to metadata
type DynamicConfig struct {
	VersionId string     `json:"version_id"`
	RBAC      RBACConfig `json:"rbac"`

	// Entries holds the dynamically configured named entries: section name ->
	// entry name -> field values, mirroring the named-entry map sections of
	// openrun.toml ([git_auth.x], [auth.y], [saml.z], ...). Dynamic entries
	// take precedence over static entries with the same name. Unlike RBAC,
	// entry updates are not staged and take effect immediately
	Entries map[string]map[string]map[string]any `json:"entries,omitempty"`

	// Settings holds dynamically configured fields of the struct sections of
	// openrun.toml: section name -> dotted field key -> value (for example
	// security -> default_git_auth, app_config -> cors.allow_origin). A set
	// field takes precedence over the static config value. Like Entries,
	// settings updates are not staged and take effect immediately
	Settings map[string]map[string]any `json:"settings,omitempty"`
}

// ConfigDraft is the staged dynamic config edit, stored separately from the
// versioned config so draft edits do not pollute the config history.
// Enforcement always reads the live config; the draft goes live on publish
type ConfigDraft struct {
	RBAC         RBACConfig `json:"rbac"`          // the draft RBAC section
	BaseVersion  string     `json:"base_version"`  // live config version the draft was forked from
	DraftVersion string     `json:"draft_version"` // bumped on every draft edit, CAS for edits/discard
	CreatedBy    string     `json:"created_by"`
	CreateTime   time.Time  `json:"create_time"`
	UpdatedBy    string     `json:"updated_by"`
	UpdateTime   time.Time  `json:"update_time"`
}

// ConfigHistoryEntry describes one snapshot in the dynamic config history
type ConfigHistoryEntry struct {
	VersionId  string    `json:"version_id"`
	UserId     string    `json:"user_id"`
	UpdateTime time.Time `json:"update_time"`
}

type RBACConfig struct {
	Enabled bool                        `json:"enabled"` // whether rbac is enabled. When enabled, RBAC applies to every app
	Groups  map[string][]string         `json:"groups"`  // groups names to user ids. These groups are appended to the groups info from SAML
	Roles   map[string][]RBACPermission `json:"roles"`   // role names to permissions.
	Grants  []RBACGrant                 `json:"grants"`  // grants are used to grant permissions to users/groups for specific apps

	// OwnerPermissions overrides the default permissions granted to the creator of an
	// asset. Keys are resource names (app, sync); values are the permissions the owner
	// gets on assets they created. Missing key means the built-in default; an empty
	// list disables the owner rule for that resource. approve is not allowed.
	OwnerPermissions map[string][]RBACPermission `json:"owner_permissions,omitempty"`
}

type RBACGrant struct {
	Description string   `json:"description"`
	Users       []string `json:"users"`   // users/groups granted by this rule
	Roles       []string `json:"roles"`   // the roles granted by this rule
	Targets     []string `json:"targets"` // the app path globs for which this grant applies
}

type RBACPermission string

// Permissions are resource:verb strings. app:read gates both listing and reading app
// details (there is no separate list permission). approve is special: it is a global
// permission (granted with target "all"), never implied by app:manage, owner
// permissions or permission globs; it has to be granted by its literal name (or via
// the built-in admin role).
const (
	PermissionAccess      RBACPermission = "app:access"       // access the served app (checked for every app when RBAC is enabled)
	PermissionRead        RBACPermission = "app:read"         // list apps, get app details, list versions/files
	PermissionCreate      RBACPermission = "app:create"       // create app
	PermissionUpdate      RBACPermission = "app:update"       // settings/metadata/links/params/version switch
	PermissionReload      RBACPermission = "app:reload"       // reload apps
	PermissionApply       RBACPermission = "app:apply"        // declarative apply
	PermissionDelete      RBACPermission = "app:delete"       // delete apps
	PermissionPromote     RBACPermission = "app:promote"      // promote staging to prod
	PermissionPreview     RBACPermission = "app:preview"      // create preview apps
	PermissionTokenRead   RBACPermission = "app:token_read"   // list webhook tokens
	PermissionTokenManage RBACPermission = "app:token_manage" // create/delete webhook tokens
	PermissionAppManage   RBACPermission = "app:manage"       // all app permissions except approve

	PermissionSyncCreate RBACPermission = "sync:create"
	PermissionSyncRun    RBACPermission = "sync:run"
	PermissionSyncDelete RBACPermission = "sync:delete"
	PermissionSyncRead   RBACPermission = "sync:read"

	PermissionServiceCreate RBACPermission = "service:create"
	PermissionServiceUpdate RBACPermission = "service:update"
	PermissionServiceDelete RBACPermission = "service:delete"
	PermissionServiceRead   RBACPermission = "service:read"

	PermissionBindingCreate     RBACPermission = "binding:create"
	PermissionBindingUpdate     RBACPermission = "binding:update"
	PermissionBindingDelete     RBACPermission = "binding:delete"
	PermissionBindingRead       RBACPermission = "binding:read"
	PermissionBindingRunCommand RBACPermission = "binding:run_command"

	PermissionContainerRead   RBACPermission = "container:read"   // list containers, get container details/logs/stats
	PermissionContainerManage RBACPermission = "container:manage" // start/stop managed containers

	PermissionConfigBasicRead RBACPermission = "config:basic_read" // read non-sensitive config metadata (auth/git-auth entry names, specs, permission catalog); implied by config:read
	PermissionConfigRead      RBACPermission = "config:read"
	PermissionConfigUpdate    RBACPermission = "config:update"
	PermissionServerStop      RBACPermission = "server:stop"
	PermissionAuditRead       RBACPermission = "audit:read" // read the audit log across all apps

	PermissionSecretCreate RBACPermission = "secret:create" // create/update secrets, rekey the store
	PermissionSecretRead   RBACPermission = "secret:read"   // list secrets, get secret metadata (not values)
	PermissionSecretDelete RBACPermission = "secret:delete"
	PermissionSecretReveal RBACPermission = "secret:reveal" // read back a secret value

	PermissionBuilderList    RBACPermission = "builder:list"    // list and view one's own builder sessions (transcript, files, activity)
	PermissionBuilderCreate  RBACPermission = "builder:create"  // create sessions, message/stop/resume/delete one's own sessions
	PermissionBuilderPublish RBACPermission = "builder:publish" // publish/unpublish (also needs app:create on the path)

	// PermissionAdmin is the super-user permission: holders pass every RBAC
	// check (management APIs, app access, other users' builder sessions).
	// The "admin" user holds it implicitly; other users acquire it through a
	// grant of the literal permission (or the built-in admin role). Like
	// approve it is never matched by permission globs
	PermissionAdmin   RBACPermission = "admin"
	PermissionApprove RBACPermission = "approve" // approve plugin permissions (operator-only, global)
)

// RBACPermissionGroup lists the permissions for one resource type, in display order
type RBACPermissionGroup struct {
	Resource    string           `json:"resource"`
	Permissions []RBACPermission `json:"permissions"`
}

// RBACPermissionGroups is the canonical list of all RBAC permissions, grouped by
// resource type. UIs read this through the list_rbac_permissions plugin API;
// keep it in sync with the permission constants above
var RBACPermissionGroups = []RBACPermissionGroup{
	{Resource: "app", Permissions: []RBACPermission{
		PermissionAccess, PermissionRead, PermissionCreate, PermissionUpdate,
		PermissionReload, PermissionApply, PermissionDelete,
		PermissionPromote, PermissionPreview, PermissionTokenRead,
		PermissionTokenManage, PermissionAppManage}},
	{Resource: "sync", Permissions: []RBACPermission{
		PermissionSyncCreate, PermissionSyncRun, PermissionSyncDelete, PermissionSyncRead}},
	{Resource: "service", Permissions: []RBACPermission{
		PermissionServiceCreate, PermissionServiceUpdate, PermissionServiceDelete,
		PermissionServiceRead}},
	{Resource: "binding", Permissions: []RBACPermission{
		PermissionBindingCreate, PermissionBindingUpdate, PermissionBindingDelete,
		PermissionBindingRead, PermissionBindingRunCommand}},
	{Resource: "container", Permissions: []RBACPermission{
		PermissionContainerRead, PermissionContainerManage}},
	{Resource: "config", Permissions: []RBACPermission{
		PermissionConfigBasicRead, PermissionConfigRead, PermissionConfigUpdate}},
	{Resource: "secret", Permissions: []RBACPermission{
		PermissionSecretCreate, PermissionSecretRead, PermissionSecretDelete,
		PermissionSecretReveal}},
	{Resource: "builder", Permissions: []RBACPermission{
		PermissionBuilderList, PermissionBuilderCreate,
		PermissionBuilderPublish}},
	{Resource: "server", Permissions: []RBACPermission{PermissionServerStop}},
	{Resource: "audit", Permissions: []RBACPermission{PermissionAuditRead}},
	{Resource: "approve", Permissions: []RBACPermission{PermissionApprove}},
	{Resource: "admin", Permissions: []RBACPermission{PermissionAdmin}},
}

type AuthorizerFunc func(ctx context.Context, permissions []string) (bool, error)
type CustomPermsFunc func(ctx context.Context) ([]string, error)

type SAMLConfig struct {
	MetadataURL string `toml:"metadata_url"`
	GroupsAttr  string `toml:"groups_attr"`
	UsePost     bool   `toml:"use_post"`     // whether to use POST binding
	ForceAuthn  bool   `toml:"force_authn"`  // whether to force authn
	SPKeyFile   string `toml:"sp_key_file"`  // the SP key file to use
	SPCertFile  string `toml:"sp_cert_file"` // the SP cert file to use
}

const (
	SAML_SESSION_KV_PREFIX      = "saml_session:"
	OAUTH_SESSION_KV_PREFIX     = "oauth_session:"
	HTTP_SESSION_KV_PREFIX      = "http_session:"
	CONSTANT_KV_PREFIX          = "constant:"
	COOKIE_SESSION_SECRET_KV    = "cookie_session_secret"
	COOKIE_SESSION_BLOCK_KEY_KV = "cookie_session_block_key"
	OPENRUN_COOKIE_MARKER       = "_openrun_"
	GOTHIC_SESSION_COOKIE       = "_gothic_session"
	OAUTH_SESSION_COOKIE        = "openrun_session"
	SAML_SESSION_COOKIE         = "openrun_saml_session"
)

const (
	// OpenRun headers are used to pass information to the downstream service
	OPENRUN_HEADER_PREFIX           = "X-Openrun-"
	OPENRUN_HEADER_USER             = OPENRUN_HEADER_PREFIX + "User"
	OPENRUN_HEADER_USER_STRIPPED    = OPENRUN_HEADER_PREFIX + "User-Stripped" // the user ID stripped of the provider prefix
	OPENRUN_HEADER_USER_ID          = OPENRUN_HEADER_PREFIX + "User-Id"
	OPENRUN_HEADER_USER_EMAIL       = OPENRUN_HEADER_PREFIX + "User-Email"
	OPENRUN_HEADER_PERMS            = OPENRUN_HEADER_PREFIX + "Perms"
	OPENRUN_HEADER_APP_RBAC_ENABLED = OPENRUN_HEADER_PREFIX + "Rbac-Enabled"
)

// ErrSecretExists is returned when a secret with the given name already exists
var ErrSecretExists = errors.New("secret already exists")

// ErrSecretNotFound is returned when a secret with the given name does not exist
var ErrSecretNotFound = errors.New("secret not found")

// SecretMetadata is the non-sensitive metadata stored with an encrypted secret
type SecretMetadata struct {
	Description string `json:"description,omitempty"`
	SourceFile  string `json:"source_file,omitempty"` // original file name when created from a file
}

// SecretEntry is a row in the secrets table. Value is the AES-256-GCM
// ciphertext of the secret, sealed with the master key identified by KeyId
// and a per-write random Nonce
type SecretEntry struct {
	Name       string
	Value      []byte
	Nonce      []byte
	KeyId      string
	CreatedBy  string
	CreateTime time.Time
	UpdateTime time.Time
	Metadata   SecretMetadata
}

// Service is a service entry in the metadata database
// service is the admin level connection from which bindings are created
type Service struct {
	Id          string            `json:"id"`
	Name        string            `json:"name"`
	ServiceType string            `json:"service_type"`
	IsDefault   bool              `json:"is_default"`
	Staging     string            `json:"staging"`
	Config      map[string]string `json:"config"`
	CreateTime  time.Time         `json:"create_time"`
	UpdateTime  time.Time         `json:"update_time"`
}
