// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
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
	CreateBindingResults  []string            `json:"create_binding_results"`
	UpdateBindingResults  []string            `json:"update_binding_results"`
	PromoteBindingResults []string            `json:"promote_binding_results"`
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
