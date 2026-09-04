// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math"
	"net/http"
	"time"
)

// RequestError is the error returned by the API
type RequestError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func CreateRequestError(message string, code int) RequestError {
	return RequestError{
		Message: message,
		Code:    code,
	}
}

func (r RequestError) Error() string {
	if r.Message == "" {
		return fmt.Sprintf("status code %d", r.Code)
	} else {
		return r.Message
	}
}

// CreateAppRequest is the request body for creating an app
// This gets saved as ApplyInfo when doing declarative app creation
type CreateAppRequest struct {
	Path             string            `json:"path"`
	SourceUrl        string            `json:"source_url"`
	IsDev            bool              `json:"is_dev"`
	AppAuthn         AppAuthnType      `json:"app_authn"`
	GitBranch        string            `json:"git_branch"`
	GitCommit        string            `json:"git_commit"`
	GitAuthName      string            `json:"git_auth_name"`
	Spec             AppSpec           `json:"spec"`
	ParamValues      map[string]string `json:"param_values"`
	ContainerOptions map[string]string `json:"container_options"`
	ContainerArgs    map[string]string `json:"container_args"`
	ContainerVolumes []string          `json:"container_volumes"`
	Sidecars         []string          `json:"sidecars,omitempty,omitzero"` // JSON SidecarSpec documents
	Jobs             []string          `json:"jobs,omitempty,omitzero"`     // JSON JobSpec documents
	AppConfig        map[string]string `json:"appconfig"`
	Bindings         []string          `json:"bindings"`
	StageAt          string            `json:"stage_at"`
	Verify           bool              `json:"verify"`
	// fields supported by declarative apply must be merged in applyAppUpdate
}

// UpdateAppRequest is the request body for updating an app settings
type UpdateAppRequest struct {
	AuthnType          StringValue `json:"authn_type"`
	GitAuthName        StringValue `json:"git_auth_name"`
	StageWriteAccess   BoolValue   `json:"stage_write_access"`
	PreviewWriteAccess BoolValue   `json:"preview_write_access"`
	Spec               StringValue `json:"spec"`
}

func CreateUpdateAppRequest() UpdateAppRequest {
	return UpdateAppRequest{
		AuthnType:          StringValueUndefined,
		GitAuthName:        StringValueUndefined,
		StageWriteAccess:   BoolValueUndefined,
		PreviewWriteAccess: BoolValueUndefined,
		Spec:               StringValueUndefined,
	}
}

// UpdateAppMetadataRequest is the request body for updating an app metadata
type UpdateAppMetadataRequest struct {
	Spec          StringValue           `json:"spec"`
	ConfigType    AppMetadataConfigType `json:"config_type"`
	ConfigEntries []string              `json:"config_entries"`
}

func CreateUpdateAppMetadataRequest() UpdateAppMetadataRequest {
	return UpdateAppMetadataRequest{
		Spec:          StringValueUndefined,
		ConfigType:    AppMetadataConfigType(StringValueUndefined),
		ConfigEntries: []string{},
	}
}

// CreateBindingRequest is the request body for creating a binding.
type CreateBindingRequest struct {
	Path      string            `json:"path"`
	Source    string            `json:"source"`
	Grants    []string          `json:"grants"`
	Config    map[string]string `json:"config"`
	ApplyInfo []byte            `json:"-"`
}

// Export reference modes, controlling how server-level config references
// (service names, git auth entries) are written in the exported config
const (
	ExportRefDefault = "default" // reference the target instance's default entry
	ExportRefExact   = "exact"   // reference the exact entry name from this instance
)

// ExportOptions are the options for exporting app config declaratively
type ExportOptions struct {
	ServiceRef         string `json:"service_ref"`         // default: emit service type only; exact: emit type/name
	GitAuthRef         string `json:"git_auth_ref"`        // default: omit git_auth; exact: emit stored git auth name
	ExactCommit        bool   `json:"exact_commit"`        // pin git_commit to the currently deployed commit
	ExcludeDeclarative bool   `json:"exclude_declarative"` // skip apps and bindings already managed declaratively
}

// AppExportResponse is the response for the export and pretty-print APIs
type AppExportResponse struct {
	Config string `json:"config"`
}

// UpdateBindingRequest is the request body for updating a binding. Binding
// updates are limited to grant changes.
type UpdateBindingRequest struct {
	Path         string   `json:"path"`
	AddGrants    []string `json:"add_grants"`
	DeleteGrants []string `json:"delete_grants"`
}

// RunBindingCommandRequest is the request body for running a command through a
// service binding account.
type RunBindingCommandRequest struct {
	BindingName string `json:"binding_name"`
	UseStaging  bool   `json:"use_staging"`
	Command     string `json:"command"`
}

// ApproveResult represents the result of an app approval audit
type ApproveResult struct {
	Id                  AppId         `json:"id"`
	AppPathDomain       AppPathDomain `json:"app_path_domain"`
	NewLoads            []string      `json:"new_loads"`
	NewPermissions      []Permission  `json:"new_permissions"`
	ApprovedLoads       []string      `json:"approved_loads"`
	ApprovedPermissions []Permission  `json:"approved_permissions"`
	NeedsApproval       bool          `json:"needs_approval"`
}

type AppResponse struct {
	AppEntry
	StagedChanges bool `json:"staged_changes"`
}

type AppListResponse struct {
	Apps []AppResponse `json:"apps"`
}

type AppCreateResponse struct {
	AppPathDomain  AppPathDomain   `json:"app_path_domain"`
	DryRun         bool            `json:"dry_run"`
	HttpUrl        string          `json:"http_url"`
	HttpsUrl       string          `json:"https_url"`
	ApproveResults []ApproveResult `json:"approve_results"`
	OrigSourceUrl  string          `json:"orig_source_url"`
	SourceUrl      string          `json:"source_url"`
}

type AppDeleteResponse struct {
	DryRun  bool      `json:"dry_run"`
	AppInfo []AppInfo `json:"app_info"`
}

type AppStagedUpdateResponse struct {
	DryRun              bool            `json:"dry_run"`
	StagedUpdateResults any             `json:"staged_update_results"`
	PromoteResults      []AppPathDomain `json:"promote_results"`
}

type AppApproveResponse struct {
	DryRun              bool            `json:"dry_run"`
	StagedUpdateResults []ApproveResult `json:"staged_update_results"`
	PromoteResults      []AppPathDomain `json:"promote_results"`
}

type AppReloadResult struct {
	DryRun         bool            `json:"dry_run"`
	ReloadResults  []AppPathDomain `json:"reload_results"`
	ApproveResult  *ApproveResult  `json:"approve_result"`
	PromoteResults []AppPathDomain `json:"promote_results"`
	SkippedResults []AppPathDomain `json:"skipped_results"`
}

type AppReloadResponse struct {
	DryRun         bool            `json:"dry_run"`
	ReloadResults  []AppPathDomain `json:"reload_results"`
	ApproveResults []ApproveResult `json:"approve_results"`
	PromoteResults []AppPathDomain `json:"promote_results"`
	SkippedResults []AppPathDomain `json:"skipped_results"`
}

type AppApplyResult struct {
	DryRun        bool              `json:"dry_run"`
	CreateResult  AppCreateResponse `json:"create_result"`
	ApproveResult *ApproveResult    `json:"approve_result"`
	Updated       []AppPathDomain   `json:"updated"`
	Reloaded      []AppPathDomain   `json:"reloaded"`
	Skipped       []AppPathDomain   `json:"skipped"`
	Promoted      bool              `json:"promoted"`
}

type AppApplyResponse struct {
	DryRun                bool                `json:"dry_run"`
	CommitId              string              `json:"commit_id"`
	SkippedApply          bool                `json:"skipped_apply"`
	CreateResults         []AppCreateResponse `json:"create_results"`
	UpdateResults         []AppPathDomain     `json:"update_results"`
	ApproveResults        []ApproveResult     `json:"approve_results"`
	PromoteResults        []AppPathDomain     `json:"promote_results"`
	ReloadResults         []AppPathDomain     `json:"reload_results"`
	SkippedResults        []AppPathDomain     `json:"skipped_results"`
	FilteredApps          []AppPathDomain     `json:"filtered_apps"`
	FilteredBindings      []string            `json:"filtered_bindings"`
	CreateBindingResults  []string            `json:"create_binding_results"`
	UpdateBindingResults  []string            `json:"update_binding_results"`
	PromoteBindingResults []string            `json:"promote_binding_results"`
	// PrunedApps/PrunedBindings are the resources deleted by a prune-enabled
	// sync. Nil (null) when no prune ran; non-nil (possibly empty) when it did.
	PrunedApps     []AppPathDomain `json:"pruned_apps"`
	PrunedBindings []string        `json:"pruned_bindings"`
}

// ApplyDeleteResponse is the response of the declarative delete API: the apps
// and bindings declared in the apply file (and matching the glob) that were
// deleted, and the declared ones skipped because they do not exist.
type ApplyDeleteResponse struct {
	DryRun          bool            `json:"dry_run"`
	DeletedApps     []AppPathDomain `json:"deleted_apps"`
	DeletedBindings []string        `json:"deleted_bindings"`
	MissingApps     []AppPathDomain `json:"missing_apps"`
	MissingBindings []string        `json:"missing_bindings"`
}

type AppPromoteResponse struct {
	DryRun         bool            `json:"dry_run"`
	PromoteResults []AppPathDomain `json:"promote_results"`
}

type AppUpdateSettingsResponse struct {
	DryRun        bool            `json:"dry_run"`
	UpdateResults []AppPathDomain `json:"update_results"`
}

type AppPreviewResponse struct {
	DryRun        bool          `json:"dry_run"`
	HttpUrl       string        `json:"http_url"`
	HttpsUrl      string        `json:"https_url"`
	Success       bool          `json:"success"`
	ApproveResult ApproveResult `json:"approve_result"`
}

type AppLinkAccountResponse struct {
	DryRun              bool            `json:"dry_run"`
	StagedUpdateResults []AppPathDomain `json:"staged_update_results"`
	PromoteResults      []AppPathDomain `json:"promote_results"`
}

type AppUpdateMetadataResponse struct {
	DryRun              bool            `json:"dry_run"`
	StagedUpdateResults []AppPathDomain `json:"staged_update_results"`
	PromoteResults      []AppPathDomain `json:"promote_results"`
}

type AppGetResponse struct {
	AppEntry AppEntry `json:"app_entry"`
}

type AppVersionListResponse struct {
	Versions []AppVersion `json:"versions"`
}

type AppVersionFilesResponse struct {
	Files []AppFile `json:"files"`
}

type AppVersionSwitchResponse struct {
	DryRun      bool `json:"dry_run"`
	FromVersion int  `json:"from_version"`
	ToVersion   int  `json:"to_version"`
}

type AppToken struct {
	Type  WebhookType `json:"type"`
	Url   string      `json:"url"`
	Token string      `json:"token"`
}

type TokenListResponse struct {
	Tokens []AppToken `json:"tokens"`
}

type TokenCreateResponse struct {
	DryRun bool     `json:"dry_run"`
	Token  AppToken `json:"token"`
}

type TokenDeleteResponse struct {
	DryRun bool `json:"dry_run"`
}

type SyncCreateResponse struct {
	DryRun            bool          `json:"dry_run"`
	Id                string        `json:"id"`
	WebhookUrl        string        `json:"webhook_url"`
	WebhookSecret     string        `json:"webhook_secret"`
	ScheduleFrequency int           `json:"schedule_minutes"`
	SyncJobStatus     SyncJobStatus `json:"sync_job_status"`
}

type SyncDeleteResponse struct {
	DryRun bool   `json:"dry_run"`
	Id     string `json:"id"`
}

type SyncListResponse struct {
	Entries []*SyncEntry `json:"entries"`
}

type ConfigResponse struct {
	DynamicConfig DynamicConfig `json:"dynamic_config"`
}

// ServerStopResponse is the response of the server stop API. The PID lets a
// local client wait for the process to fully exit: the API responds when
// shutdown starts, and cleanup (final litestream sync) runs as the process
// exits, after the listeners are already closed
type ServerStopResponse struct {
	PID int `json:"pid"`
}

// ServerStatusResponse is the response of the server status API
type ServerStatusResponse struct {
	Status string `json:"status"`
}

// ServerVersionResponse is the response of the server version API
type ServerVersionResponse struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// DatabasePoolMetrics is the database/sql connection pool snapshot returned
// by the metadata health API. Durations are milliseconds.
type DatabasePoolMetrics struct {
	MaxOpenConnections int   `json:"max_open_connections"`
	OpenConnections    int   `json:"open_connections"`
	InUse              int   `json:"in_use"`
	Idle               int   `json:"idle"`
	WaitCount          int64 `json:"wait_count"`
	WaitDurationMillis int64 `json:"wait_duration_ms"`
	MaxIdleClosed      int64 `json:"max_idle_closed"`
	MaxIdleTimeClosed  int64 `json:"max_idle_time_closed"`
	MaxLifetimeClosed  int64 `json:"max_lifetime_closed"`
}

// SQLiteMetadataMetrics contains sqlite file and maintenance measurements.
type SQLiteMetadataMetrics struct {
	DatabasePath           string `json:"database_path"`
	DatabaseBytes          int64  `json:"database_bytes"`
	WALBytes               int64  `json:"wal_bytes"`
	SHMBytes               int64  `json:"shm_bytes"`
	MaintenanceEnabled     bool   `json:"maintenance_enabled"`
	LitestreamManaged      bool   `json:"litestream_managed"`
	CheckpointRuns         uint64 `json:"checkpoint_runs"`
	CheckpointErrors       uint64 `json:"checkpoint_errors"`
	TruncateRuns           uint64 `json:"truncate_runs"`
	TruncateBlocked        uint64 `json:"truncate_blocked"`
	VacuumRuns             uint64 `json:"vacuum_runs"`
	VacuumSkippedRuns      uint64 `json:"vacuum_skipped_runs"`
	LastCheckpointAt       string `json:"last_checkpoint_at,omitempty"`
	LastCheckpointMode     string `json:"last_checkpoint_mode,omitempty"`
	LastCheckpointBusy     int    `json:"last_checkpoint_busy"`
	LastWALFrames          int    `json:"last_wal_frames"`
	LastCheckpointedFrames int    `json:"last_checkpointed_frames"`
	LastCheckpointBacklog  int    `json:"last_checkpoint_backlog_frames"`
	LastCheckpointError    string `json:"last_checkpoint_error,omitempty"`
	LastVacuumAt           string `json:"last_vacuum_at,omitempty"`
	LastVacuumError        string `json:"last_vacuum_error,omitempty"`
}

// MetadataHealthResponse reports metadata connectivity and pool metrics. The
// SQLite section is present only for sqlite; postgres uses the common pool and
// ping measurements.
type MetadataHealthResponse struct {
	Status            string                 `json:"status"`
	DatabaseType      string                 `json:"database_type"`
	PingLatencyMillis int64                  `json:"ping_latency_ms"`
	PingError         string                 `json:"ping_error,omitempty"`
	Pool              DatabasePoolMetrics    `json:"pool"`
	SQLite            *SQLiteMetadataMetrics `json:"sqlite,omitempty"`
}

// CreateSecretRequest is the request body for storing a secret in a writable
// secret provider. Either Name (explicit name) or Prefix (a unique name is
// generated with the prefix) must be set. Encoding "base64" is used to pass
// binary values (file contents); the decoded bytes are stored
type CreateSecretRequest struct {
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	Value       string `json:"value"`
	Encoding    string `json:"encoding"` // "" for plain string, "base64" for binary values
	Description string `json:"description"`
	Provider    string `json:"provider"` // secret provider name, default "db"
	SourceFile  string `json:"source_file"`
}

// SecretCreateResponse returns the stored secret name and the template
// reference to use in app params/config values
type SecretCreateResponse struct {
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	SecretRef string `json:"secret_ref"` // ready to use {{secret ...}} reference
	Updated   bool   `json:"updated"`    // true if an existing secret was updated
}

// SecretInfo is the non-sensitive info about a stored secret
type SecretInfo struct {
	Name        string    `json:"name"`
	KeyId       string    `json:"key_id"`
	CreatedBy   string    `json:"created_by"`
	CreateTime  time.Time `json:"create_time"`
	UpdateTime  time.Time `json:"update_time"`
	Description string    `json:"description"`
	SourceFile  string    `json:"source_file"`
}

type SecretListResponse struct {
	Secrets []SecretInfo `json:"secrets"`
}

// SecretGetResponse is the response for getting a secret. Value is set only
// when reveal is requested; binary values are base64 encoded with Encoding
// set to "base64"
type SecretGetResponse struct {
	SecretInfo
	Value    string `json:"value,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type SecretDeleteResponse struct {
	Name string `json:"name"`
}

// UserUpdateRequest is the request to create or update one builtin auth user
// as a dynamic config entry. Password carries the bcrypt hash of the password
// (hashed on the client side); an empty Password on an update keeps the
// stored hash. Groups nil on an update keeps the stored groups; an empty
// (non-nil) list clears them
type UserUpdateRequest struct {
	Password string   `json:"password"` // bcrypt hash of the password
	Groups   []string `json:"groups"`
}

// MarshalJSONTo preserves the distinction between nil groups (keep the
// existing groups on update) and an empty group list (clear the groups).
func (r UserUpdateRequest) MarshalJSONTo(out *jsontext.Encoder) error {
	type wireUserUpdateRequest UserUpdateRequest
	return json.MarshalEncode(out, wireUserUpdateRequest(r), json.FormatNilSliceAsNull(true))
}

type UserUpdateResponse struct {
	Username string `json:"username"`
	Updated  bool   `json:"updated"` // true if an existing user entry was updated
}

// BuiltinUserInfo is the non-sensitive info about one builtin auth user
type BuiltinUserInfo struct {
	Username   string   `json:"username"`
	Groups     []string `json:"groups"`
	Source     string   `json:"source"`     // "static" (openrun.toml) or "dynamic"
	Overridden bool     `json:"overridden"` // static entry shadowed by a dynamic entry of the same name
}

type UserListResponse struct {
	Users []BuiltinUserInfo `json:"users"`
}

type UserDeleteResponse struct {
	Username string `json:"username"`
}

// SecretRekeyResponse reports the result of re-encrypting stored secrets with
// the active master key. Skipped counts rows sealed with a key id that is not
// configured for the provider
type SecretRekeyResponse struct {
	Rekeyed int `json:"rekeyed"`
	Skipped int `json:"skipped"`
}

type AppReloadOption string

const (
	AppReloadOptionNone    AppReloadOption = "none"
	AppReloadOptionUpdated AppReloadOption = "updated"
	AppReloadOptionMatched AppReloadOption = "matched"
)

// Replication status states, most severe first: misconfigured (the service
// references an undefined litestream config), sidecar_down (the replication
// companion container is not running), pending (no data replicated yet),
// idle (replica is reachable but has not advanced recently; healthy for a
// quiet app, stale for a busy one), healthy.
const (
	ReplicationStateHealthy       = "healthy"
	ReplicationStateIdle          = "idle"
	ReplicationStatePending       = "pending"
	ReplicationStateSidecarDown   = "sidecar_down"
	ReplicationStateMisconfigured = "misconfigured"
	ReplicationStateSyncing       = "syncing"
	ReplicationStateError         = "error"
)

// ReplicationFileStatus is the replica state of one database file within a
// binding's replica location.
type ReplicationFileStatus struct {
	Path        string    `json:"path"` // relative to the binding data dir, e.g. data.db
	LastSync    time.Time `json:"last_sync,omitzero"`
	ReplicaTXID uint64    `json:"replica_txid,omitempty,omitzero"`
	Size        int64     `json:"size"`
}

// ReplicationStatusEntry is the replication state of one target: a server
// metadata database (kind "metadata") or one sqlite binding environment
// (kind "app", one row per binding per staged/prod environment in use).
type ReplicationStatusEntry struct {
	Kind             string    `json:"kind"` // metadata | app
	Target           string    `json:"target"`
	AppPaths         []string  `json:"app_paths,omitempty"`
	Env              string    `json:"env,omitempty"` // prod | staged (kind app)
	LitestreamConfig string    `json:"litestream_config"`
	Enabled          bool      `json:"enabled"`
	State            string    `json:"state"`
	SidecarRunning   *bool     `json:"sidecar_running,omitempty"` // nil when not determinable (kubernetes)
	LastSync         time.Time `json:"last_sync,omitzero"`
	ReplicaSize      int64     `json:"replica_size,omitempty,omitzero"`
	LocalTXID        uint64    `json:"local_txid,omitempty,omitzero"`   // metadata only
	ReplicaTXID      uint64    `json:"replica_txid,omitempty,omitzero"` // highest replicated TXID
	// Files is the per-database breakdown for app targets: with directory
	// watching a binding can replicate several database files
	Files []ReplicationFileStatus `json:"files,omitempty"`
	Error string                  `json:"error,omitempty"`
}

// ServerInfo is the openrun.in server_info API response: identity and
// runtime facts about this server. Everything here is readable from memory
// (no DB or external calls), so the API is safe on hot paths. The metadata
// replication entries come from the in-process litestream manager (kind
// "metadata" only); per-binding replication needs the full
// replication_status API.
type ServerInfo struct {
	Version             string                   `json:"version"`
	Commit              string                   `json:"commit"`
	StartTime           time.Time                `json:"start_time"`
	UptimeSecs          int64                    `json:"uptime_secs"`
	MetadataDBType      string                   `json:"metadata_db_type"` // sqlite | postgres
	AuditDBType         string                   `json:"audit_db_type"`
	ContainerCommand    string                   `json:"container_command"` // configured value: "", auto, docker, ...
	ContainerRuntime    string                   `json:"container_runtime"` // resolved: docker | podman | kubernetes | ""
	IsLeader            bool                     `json:"is_leader"`
	MetadataReplication []ReplicationStatusEntry `json:"metadata_replication"`
}

// Credential types stored in the credentials table
const (
	CredentialTypePAT          = "pat"
	CredentialTypeOAuthAccess  = "oauth_access"
	CredentialTypeOAuthRefresh = "oauth_refresh"
)

// Identity is a principal that credentials map to. PrincipalName is the
// provider:username string RBAC grants match; StableSubject is the provider's
// stable id (equals the username for builtin/admin). Groups is the provider
// group snapshot for federated identities (builtin groups are re-resolved
// live from config on every request instead)
type Identity struct {
	Id               string     `json:"id"`
	Provider         string     `json:"provider"`
	StableSubject    string     `json:"stable_subject"`
	PrincipalName    string     `json:"principal_name"`
	Groups           []string   `json:"groups"`
	GroupsObservedAt *time.Time `json:"groups_observed_at,omitempty"`
	DisabledAt       *time.Time `json:"disabled_at,omitempty"`
	CreateTime       time.Time  `json:"create_time"`
}

// Credential is one stored bearer credential (API key / OAuth token). The
// secret is stored only as a SHA-256 hash. Scopes nil means unscoped (RBAC
// alone governs); non-nil is the ceiling
type Credential struct {
	Id               string     `json:"id"`
	SecretHash       string     `json:"-"`
	Type             string     `json:"type"`
	IdentityId       string     `json:"identity_id"`
	Scopes           []string   `json:"scopes,omitempty"`
	Resources        []string   `json:"resources,omitempty"`
	Description      string     `json:"description,omitempty"`
	OAuthClientId    string     `json:"oauth_client_id,omitempty"`
	GrantId          string     `json:"grant_id,omitempty"`
	FamilyId         string     `json:"family_id,omitempty"`
	ReplacedById     string     `json:"replaced_by_id,omitempty"`
	ConsumedAt       *time.Time `json:"consumed_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"` // nil = never expires
	CreatedBy        string     `json:"created_by"`
	CreateTime       time.Time  `json:"create_time"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
}

// ApiKeyCreateRequest is the request to create an API key (PAT). User names
// the key's identity (provider:username, like builtin:alice); empty means the
// caller's own identity. Creating a key for another user requires the admin
// permission and audits as create_apikey_other
type ApiKeyCreateRequest struct {
	User        string   `json:"user"`
	ExpiresIn   string   `json:"expires_in"`  // Go duration, "never", or "" for the configured default (90d)
	Scopes      []string `json:"scopes"`      // permission globs; empty = unscoped (RBAC alone governs)
	Resources   []string `json:"resources"`   // "rest", "mcp"; empty = rest
	Description string   `json:"description"` //nolint:misspell
}

// ApiKeyCreateResponse carries the one-time plaintext key. The secret is
// never stored or shown again
type ApiKeyCreateResponse struct {
	Id        string     `json:"id"`
	Key       string     `json:"key"` // orun_pat_<id>_<secret>, shown once
	User      string     `json:"user"`
	Scopes    []string   `json:"scopes,omitempty"`     // applied scope ceiling; empty = unscoped
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = never expires
}

// ApiKeyInfo is one API key's metadata (no secret material)
type ApiKeyInfo struct {
	Id          string     `json:"id"`
	User        string     `json:"user"`
	Type        string     `json:"type"` // pat | oauth_access | oauth_refresh
	Scopes      []string   `json:"scopes,omitempty"`
	Resources   []string   `json:"resources,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreateTime  time.Time  `json:"create_time"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// ApiKeyListResponse lists API keys: the caller's own, or all with --all (admin)
type ApiKeyListResponse struct {
	Keys []ApiKeyInfo `json:"keys"`
}

// ApiKeyDeleteResponse confirms an API key deletion
type ApiKeyDeleteResponse struct {
	Id   string `json:"id"`
	User string `json:"user"`
}

// GetHTTPHeader returns the first value of the header with the given key.
// The key has to be a HTTP Canonical Header Key (case is important)
func GetHTTPHeader(header http.Header, key string) string {
	val := header[key]
	if len(val) > 0 {
		return val[0]
	}
	return ""
}

// Int64ToInt32 converts an int64 to an int32, returning an error if the value is out of range
func Int64ToInt32(v int64) (int32, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("value %d overflows int32", v)
	}
	return int32(v), nil
}
