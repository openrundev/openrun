// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// API_NAME identifies one management API operation: the audit operation
// name, the MCP tool name and the [api.mcp]/[api.rest] config key
type API_NAME string

const (
	API_STOP_SERVER          API_NAME = "stop_server"
	API_RESTART_SERVER       API_NAME = "restart_server"
	API_SERVER_STATUS        API_NAME = "server_status"
	API_SERVER_VERSION       API_NAME = "server_version"
	API_METADATA_HEALTH      API_NAME = "metadata_health"
	API_LIST_APPS            API_NAME = "list_apps"
	API_GET_APP              API_NAME = "get_app"
	API_CREATE_APP           API_NAME = "create_app"
	API_DELETE_APPS          API_NAME = "delete_apps"
	API_APPROVE_APPS         API_NAME = "approve_apps"
	API_RELOAD_APPS          API_NAME = "reload_apps"
	API_PROMOTE_APPS         API_NAME = "promote_apps"
	API_CREATE_PREVIEW       API_NAME = "create_preview"
	API_UPDATE_SETTINGS      API_NAME = "update_settings"
	API_UPDATE_METADATA      API_NAME = "update_metadata"
	API_UPDATE_LINKS         API_NAME = "update_links"
	API_UPDATE_PARAMS        API_NAME = "update_params"
	API_LIST_VERSIONS        API_NAME = "list_versions"
	API_LIST_FILES           API_NAME = "list_files"
	API_VERSION_SWITCH       API_NAME = "version_switch"
	API_LIST_WEBHOOKS        API_NAME = "list_webhooks"
	API_TOKEN_CREATE         API_NAME = "token_create"
	API_TOKEN_DELETE         API_NAME = "token_delete"
	API_APPLY                API_NAME = "apply"
	API_APPLY_DELETE         API_NAME = "apply_delete"
	API_EXPORT_APPS          API_NAME = "export_apps"
	API_PRETTY_PRINT         API_NAME = "pretty_print"
	API_SYNC_CREATE          API_NAME = "sync_create"
	API_SYNC_RUN             API_NAME = "sync_run"
	API_SYNC_DELETE          API_NAME = "sync_delete"
	API_LIST_SYNC            API_NAME = "list_sync"
	API_SERVICE_CREATE       API_NAME = "service_create"
	API_SERVICE_UPDATE       API_NAME = "service_update"
	API_SERVICE_DELETE       API_NAME = "service_delete"
	API_LIST_SERVICES        API_NAME = "list_services"
	API_SERVICE_HEALTH       API_NAME = "service_health"
	API_PROVIDER_INSTALL     API_NAME = "provider_install"
	API_PROVIDER_UNINSTALL   API_NAME = "provider_uninstall"
	API_LIST_PROVIDERS       API_NAME = "list_providers"
	API_BINDING_CREATE       API_NAME = "binding_create"
	API_BINDING_UPDATE       API_NAME = "binding_update"
	API_BINDING_DELETE       API_NAME = "binding_delete"
	API_BINDING_GET          API_NAME = "binding_get"
	API_LIST_BINDINGS        API_NAME = "list_bindings"
	API_BINDING_SHOW_ACCOUNT API_NAME = "binding_show_account"
	API_BINDING_RUN_COMMAND  API_NAME = "binding_run_command"
	API_BINDING_HEALTH       API_NAME = "binding_health"
	API_REPLICATION_STATUS   API_NAME = "replication_status"
	API_SECRET_CREATE        API_NAME = "secret_create"
	API_SECRET_GET           API_NAME = "secret_get"
	API_SECRET_REVEAL        API_NAME = "secret_reveal"
	API_SECRET_DELETE        API_NAME = "secret_delete"
	API_LIST_SECRETS         API_NAME = "list_secrets"
	API_SECRET_REKEY         API_NAME = "secret_rekey"
	API_USER_ADD             API_NAME = "user_add"
	API_USER_DELETE          API_NAME = "user_delete"
	API_USER_LIST            API_NAME = "user_list"
	API_CONFIG_GET           API_NAME = "config_get"
	API_CONFIG_UPDATE        API_NAME = "config_update"
	API_CREATE_APIKEY        API_NAME = "create_apikey"
	API_CREATE_APIKEY_OTHER  API_NAME = "create_apikey_other"
	API_LIST_APIKEYS         API_NAME = "list_apikeys"
	API_DELETE_APIKEY        API_NAME = "delete_apikey"
	API_DELETE_APIKEY_OTHER  API_NAME = "delete_apikey_other"
)

// The operation registry: every management API operation declared once, with
// its primary permission (used as the credential scope for MCP tool metadata),
// read-only/destructive flags (MCP tool annotations) and per-invoker default
// availability. Operation names are the audit operation vocabulary
// (create_app, list_apps, ...) and are the keys accepted in the
// [api.mcp]/[api.rest] enable_apis/disable_apis config lists.
//
// Dangerous request variants are separate logical operations (secret_reveal
// vs secret_get, create_apikey_other vs create_apikey): the REST adapters
// resolve to the logical op after request validation, so invoker policy and
// audit key on the logical op.

// Invoker type markers stored in the request context (types.API_INVOKER)
const (
	InvokerPlugin = "plugin"
	InvokerUDS    = "uds"
	InvokerRest   = "rest"
	InvokerMCP    = "mcp"
)

type apiOperation struct {
	Scope       types.RBACPermission // primary permission; "" for connectivity ops
	ReadOnly    bool                 // MCP ReadOnlyHint
	Destructive bool                 // MCP DestructiveHint
	MCPDisabled bool                 // disabled by default for the MCP invoker

	// Description documents the operation for consumers of the catalog; it
	// is the MCP tool description
	Description string

	// MCPExcluded, when non-empty, is the reason this operation has no MCP
	// tool (CLI-oriented output, logical resolution of another op, ...).
	// The catalog parity test enforces that every op either registers a
	// tool or carries a reason here
	MCPExcluded string

	// REST route. serveInternal builds the management router from these
	// fields; an entry with an empty Path is a logical operation (resolved
	// inside a handler after request validation, like secret_reveal) and
	// gets no route of its own
	Method            string                                         // http method
	Path              string                                         // route under /_openrun
	ApiFunc           func(h *Handler, r *http.Request) (any, error) // method expression, (*Handler).getApps
	RunVersionCleanup bool                                           // run app version cleanup after success
	MaxBodyBytes      int64                                          // request body cap; 0 = default
}

var apiRegistry map[API_NAME]apiOperation

// Populated in init: several handler methods referenced here transitively
// consult apiRegistry themselves (checkApiOpEnabled), which the compiler
// conservatively reports as an initialization cycle for a direct var literal
func init() {
	apiRegistry = map[API_NAME]apiOperation{
		// Server lifecycle: default-disabled for MCP
		API_STOP_SERVER: {Description: "Stop the OpenRun server (disabled for MCP by default)",
			Scope: types.PermissionServerStop, Destructive: true, MCPDisabled: true,
			Method: http.MethodPost, Path: "/stop", ApiFunc: (*Handler).stopServer},
		API_RESTART_SERVER: {Description: "Zero downtime in-place restart (disabled for MCP by default)",
			Scope: types.PermissionServerStop, Destructive: true, MCPDisabled: true,
			Method: http.MethodPost, Path: "/restart", ApiFunc: (*Handler).restartServer},
		API_SERVER_STATUS: {Description: "Check server connectivity",
			ReadOnly: true,
			Method:   http.MethodGet, Path: "/server_status", ApiFunc: (*Handler).serverStatus},
		API_SERVER_VERSION: {Description: "Get the OpenRun server version",
			ReadOnly: true,
			Method:   http.MethodGet, Path: "/server_version", ApiFunc: (*Handler).serverVersion},
		API_METADATA_HEALTH: {MCPExcluded: "handler-level DB diagnostics, use server_status",
			ReadOnly: true,
			Method:   http.MethodGet, Path: "/metadata_health", ApiFunc: (*Handler).metadataHealth},

		// Apps
		API_LIST_APPS: {Description: "List apps, optionally filtered by a path glob. Returns app metadata including staging/prod state",
			Scope: types.PermissionRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/apps", ApiFunc: (*Handler).getApps},
		API_GET_APP: {Description: "Get one app's details by path",
			Scope: types.PermissionRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/app", ApiFunc: (*Handler).getApp},
		API_CREATE_APP: {Description: "Create a new app from a source url at the given path. The app starts in staging; promote_apps pushes it to prod",
			Scope:  types.PermissionCreate,
			Method: http.MethodPost, Path: "/app", ApiFunc: (*Handler).createApp},
		API_DELETE_APPS: {Description: "Delete the apps matching a path glob",
			Scope: types.PermissionDelete, Destructive: true,
			Method: http.MethodDelete, Path: "/app", ApiFunc: (*Handler).deleteApps, RunVersionCleanup: true},
		API_APPROVE_APPS: {Description: "Approve the plugin permissions of the apps matching a path glob",
			Scope:  types.PermissionApprove,
			Method: http.MethodPost, Path: "/approve", ApiFunc: (*Handler).approveApps},
		API_RELOAD_APPS: {Description: "Reload the apps matching a path glob from their source",
			Scope:  types.PermissionReload,
			Method: http.MethodPost, Path: "/reload", ApiFunc: (*Handler).reloadApps, RunVersionCleanup: true},
		API_PROMOTE_APPS: {Description: "Promote staging to prod for the apps matching a path glob",
			Scope: types.PermissionPromote, Destructive: true,
			Method: http.MethodPost, Path: "/promote", ApiFunc: (*Handler).promoteApps, RunVersionCleanup: true},
		API_CREATE_PREVIEW: {Description: "Create a preview app for a git commit",
			Scope:  types.PermissionPreview,
			Method: http.MethodPost, Path: "/preview", ApiFunc: (*Handler).previewApp},
		API_UPDATE_SETTINGS: {Description: "Update app settings (auth type, git auth, spec, write access). Empty/omitted fields are left unchanged",
			Scope:  types.PermissionUpdate,
			Method: http.MethodPost, Path: "/app_settings", ApiFunc: (*Handler).updateAppSettings},
		API_UPDATE_METADATA: {Description: "Update app metadata (spec, app config, container options) on the staging version",
			Scope:  types.PermissionUpdate,
			Method: http.MethodPost, Path: "/app_metadata", ApiFunc: (*Handler).updateAppMetadata, RunVersionCleanup: true},
		API_UPDATE_LINKS: {Description: "Link a plugin to an account for the matched apps",
			Scope:  types.PermissionUpdate,
			Method: http.MethodPost, Path: "/link_account", ApiFunc: (*Handler).accountLink, RunVersionCleanup: true},
		API_UPDATE_PARAMS: {Description: "Set or delete one app parameter value on the staging version",
			Scope:  types.PermissionUpdate,
			Method: http.MethodPost, Path: "/update_param", ApiFunc: (*Handler).updateParam, RunVersionCleanup: true},
		API_LIST_VERSIONS: {Description: "List the versions of an app",
			Scope: types.PermissionRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/version", ApiFunc: (*Handler).versionList},
		API_LIST_FILES: {Description: "List the files in an app version",
			Scope: types.PermissionRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/version/files", ApiFunc: (*Handler).versionFiles},
		API_VERSION_SWITCH: {Description: "Switch an app to a different version (rollback/rollforward)",
			Scope: types.PermissionUpdate, Destructive: true,
			Method: http.MethodPost, Path: "/version", ApiFunc: (*Handler).versionSwitch},
		API_LIST_WEBHOOKS: {Description: "List an app's webhook tokens",
			Scope: types.PermissionTokenRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/app_webhook_token", ApiFunc: (*Handler).tokenList},
		API_TOKEN_CREATE: {Description: "Create a webhook token for an app",
			Scope:  types.PermissionTokenManage,
			Method: http.MethodPost, Path: "/app_webhook_token", ApiFunc: (*Handler).tokenCreate},
		API_TOKEN_DELETE: {Description: "Delete a webhook token from an app",
			Scope:  types.PermissionTokenManage,
			Method: http.MethodDelete, Path: "/app_webhook_token", ApiFunc: (*Handler).tokenDelete},
		API_APPLY: {Description: "Declaratively apply an app configuration file (server-local path or git url)",
			Scope:  types.PermissionApply,
			Method: http.MethodPost, Path: "/apply", ApiFunc: (*Handler).apply, RunVersionCleanup: true},
		API_APPLY_DELETE: {Description: "Delete the apps declared in an apply file",
			Scope: types.PermissionApply, Destructive: true,
			Method: http.MethodDelete, Path: "/apply", ApiFunc: (*Handler).applyDelete, RunVersionCleanup: true},
		API_EXPORT_APPS: {MCPExcluded: "produces server-side export files, CLI oriented",
			Scope: types.PermissionRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/export", ApiFunc: (*Handler).export},
		API_PRETTY_PRINT: {MCPExcluded: "CLI formatting helper for apply files",
			ReadOnly: true,
			Method:   http.MethodGet, Path: "/pretty_print", ApiFunc: (*Handler).prettyPrint},

		// Sync
		API_SYNC_CREATE: {Description: "Create a sync entry keeping apps in sync with an apply file",
			Scope:  types.PermissionSyncCreate,
			Method: http.MethodPost, Path: "/sync", ApiFunc: (*Handler).createSyncEntry, RunVersionCleanup: true},
		API_SYNC_RUN: {Description: "Run a sync entry now",
			Scope:  types.PermissionSyncRun,
			Method: http.MethodPost, Path: "/sync/run", ApiFunc: (*Handler).runSyncEntry, RunVersionCleanup: true},
		API_SYNC_DELETE: {Description: "Delete a sync entry",
			Scope: types.PermissionSyncDelete, Destructive: true,
			Method: http.MethodDelete, Path: "/sync", ApiFunc: (*Handler).deleteSyncEntry},
		API_LIST_SYNC: {Description: "List the sync entries (declarative git sync schedules)",
			Scope: types.PermissionSyncRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/sync", ApiFunc: (*Handler).listSyncEntries},

		// Services
		API_SERVICE_CREATE: {Description: "Create a managed service (postgres, redis, ...)",
			Scope:  types.PermissionServiceCreate,
			Method: http.MethodPost, Path: "/service", ApiFunc: (*Handler).createService},
		API_SERVICE_UPDATE: {Description: "Update a managed service's configuration",
			Scope:  types.PermissionServiceUpdate,
			Method: http.MethodPut, Path: "/service", ApiFunc: (*Handler).updateService},
		API_SERVICE_DELETE: {Description: "Delete a managed service",
			Scope: types.PermissionServiceDelete, Destructive: true,
			Method: http.MethodDelete, Path: "/service", ApiFunc: (*Handler).deleteService},
		API_LIST_SERVICES: {Description: "List the services (managed backends like postgres, redis)",
			Scope: types.PermissionServiceRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/services", ApiFunc: (*Handler).listServices},
		API_SERVICE_HEALTH: {Description: "Check a service's health (admin connection + no-op operation)",
			Scope: types.PermissionServiceRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/service/health", ApiFunc: (*Handler).serviceHealth},

		// Providers: install/uninstall are RCE-equivalent, MCP default-disabled
		API_PROVIDER_INSTALL: {Description: "Install a binding provider binary (RCE-equivalent, disabled for MCP by default)",
			Scope: types.PermissionProviderManage, MCPDisabled: true,
			Method: http.MethodPost, Path: "/provider", ApiFunc: (*Handler).installProvider},
		API_PROVIDER_UNINSTALL: {Description: "Uninstall a binding provider (disabled for MCP by default)",
			Scope: types.PermissionProviderManage, Destructive: true, MCPDisabled: true,
			Method: http.MethodDelete, Path: "/provider", ApiFunc: (*Handler).uninstallProvider},
		API_LIST_PROVIDERS: {Description: "List the installed binding providers",
			Scope: types.PermissionProviderRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/providers", ApiFunc: (*Handler).listProviders},

		// Bindings; binding_show_account reveals credentials, MCP default-disabled
		API_BINDING_CREATE: {Description: "Create a binding (app to service connection)",
			Scope:  types.PermissionBindingCreate,
			Method: http.MethodPost, Path: "/binding", ApiFunc: (*Handler).createBinding},
		API_BINDING_UPDATE: {Description: "Update a binding's grants",
			Scope:  types.PermissionBindingUpdate,
			Method: http.MethodPut, Path: "/binding", ApiFunc: (*Handler).updateBinding},
		API_BINDING_DELETE: {Description: "Delete a binding",
			Scope: types.PermissionBindingDelete, Destructive: true,
			Method: http.MethodDelete, Path: "/binding", ApiFunc: (*Handler).deleteBinding},
		API_BINDING_GET: {Description: "Get one binding's details",
			Scope: types.PermissionBindingRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/binding", ApiFunc: (*Handler).getBinding},
		API_LIST_BINDINGS: {Description: "List the bindings (app to service connections)",
			Scope: types.PermissionBindingRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/bindings", ApiFunc: (*Handler).listBindings},
		API_BINDING_SHOW_ACCOUNT: {Description: "Reveal a binding's account credentials (disabled for MCP by default)",
			Scope: types.PermissionBindingReveal, ReadOnly: true, MCPDisabled: true,
			Method: http.MethodGet, Path: "/binding/account", ApiFunc: (*Handler).getBindingAccount},
		API_BINDING_RUN_COMMAND: {Description: "Run a provider command through a binding account",
			Scope:  types.PermissionBindingRunCommand,
			Method: http.MethodPost, Path: "/binding/run-command", ApiFunc: (*Handler).runBindingCommand},
		API_BINDING_HEALTH: {Description: "Check a binding account's health",
			Scope: types.PermissionBindingRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/binding/health", ApiFunc: (*Handler).bindingHealth},

		API_REPLICATION_STATUS: {Description: "Get the metadata replication status",
			Scope: types.PermissionConfigBasicRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/replication/status", ApiFunc: (*Handler).replicationStatus},

		// Secrets: reveal and rekey are MCP default-disabled; secret_get is
		// metadata only (the reveal request variant resolves to secret_reveal)
		API_SECRET_CREATE: {Description: "Create or update a secret",
			Scope:  types.PermissionSecretCreate,
			Method: http.MethodPost, Path: "/secret", ApiFunc: (*Handler).createSecret, MaxBodyBytes: MAX_SECRET_UPLOAD_SIZE},
		API_SECRET_GET: {Description: "Get one secret's metadata (never the value; value reveal is a separate operation, disabled for MCP by default)",
			Scope: types.PermissionSecretRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/secret", ApiFunc: (*Handler).getSecret},
		API_SECRET_REVEAL: {Description: "Reveal a secret's value (disabled for MCP by default)",
			Scope: types.PermissionSecretReveal, ReadOnly: true, MCPDisabled: true},
		API_SECRET_DELETE: {Description: "Delete a secret",
			Scope: types.PermissionSecretDelete, Destructive: true,
			Method: http.MethodDelete, Path: "/secret", ApiFunc: (*Handler).deleteSecret},
		API_LIST_SECRETS: {Description: "List secret names and metadata (never values)",
			Scope: types.PermissionSecretRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/secrets", ApiFunc: (*Handler).listSecrets},
		API_SECRET_REKEY: {Description: "Re-encrypt stored secrets with the active master key (disabled for MCP by default)",
			Scope: types.PermissionSecretCreate, MCPDisabled: true,
			Method: http.MethodPost, Path: "/secret/rekey", ApiFunc: (*Handler).rekeySecrets},

		// Builtin auth user management: MCP default-disabled
		API_USER_ADD: {Description: "Create or update a builtin auth user (disabled for MCP by default)",
			Scope: types.PermissionConfigUpdate, MCPDisabled: true,
			Method: http.MethodPost, Path: "/user", ApiFunc: (*Handler).userUpdate},
		API_USER_DELETE: {Description: "Delete a builtin auth user (disabled for MCP by default)",
			Scope: types.PermissionConfigUpdate, Destructive: true, MCPDisabled: true,
			Method: http.MethodDelete, Path: "/user", ApiFunc: (*Handler).userDelete},
		API_USER_LIST: {Description: "List the builtin auth users (no passwords)",
			Scope: types.PermissionConfigRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/users", ApiFunc: (*Handler).userList},

		// Config: config_update can grant everything else, MCP default-disabled
		API_CONFIG_GET: {Description: "Get the dynamic server configuration (RBAC, config entries)",
			Scope: types.PermissionConfigRead, ReadOnly: true,
			Method: http.MethodGet, Path: "/config", ApiFunc: (*Handler).configGet},
		API_CONFIG_UPDATE: {Description: "Update the dynamic server config (RBAC, entries; disabled for MCP by default)",
			Scope: types.PermissionConfigUpdate, MCPDisabled: true,
			Method: http.MethodPost, Path: "/config", ApiFunc: (*Handler).configUpdate},

		// API keys: creating/deleting another user's key is a separate,
		// prominently audited logical op, MCP default-disabled
		API_CREATE_APIKEY: {Description: "Create an API key. The key is returned once and never stored",
			Scope:  types.PermissionApiKeyManageSelf,
			Method: http.MethodPost, Path: "/apikey", ApiFunc: (*Handler).createApiKey},
		API_CREATE_APIKEY_OTHER: {MCPExcluded: "logical resolution of create_apikey (user != caller)",
			Scope: types.PermissionAdmin, MCPDisabled: true},
		API_LIST_APIKEYS: {Description: "List the caller's API keys (metadata only)",
			Scope: types.PermissionApiKeyManageSelf, ReadOnly: true,
			Method: http.MethodGet, Path: "/apikey", ApiFunc: (*Handler).listApiKeys},
		API_DELETE_APIKEY: {Description: "Delete an API key by id",
			Scope: types.PermissionApiKeyManageSelf, Destructive: true,
			Method: http.MethodDelete, Path: "/apikey", ApiFunc: (*Handler).deleteApiKey},
		API_DELETE_APIKEY_OTHER: {MCPExcluded: "logical resolution of delete_apikey (owner != caller)",
			Scope: types.PermissionAdmin, Destructive: true, MCPDisabled: true},
	}
}

// apiSurfaceEnabled reports whether the surface ("rest"/"mcp") is enabled
// ([api.<surface>] enable)
func apiSurfaceEnabled(config *types.ServerConfig, surface string) bool {
	surfaceConfig, ok := config.Api.Surface(surface)
	return ok && surfaceConfig.Enabled()
}

// apiOpEnabled reports whether the operation is enabled for the invoker,
// combining the registry defaults with the [api.<surface>] enable_apis /
// disable_apis overrides. The uds and plugin invokers are always fully
// enabled: UDS is the recovery path, and the console's in-process plugin
// calls carry the session identity with RBAC as the gate
func (s *Server) apiOpEnabled(invoker string, operation API_NAME) bool {
	var surface types.ApiSurfaceConfig
	var defaultDisabled bool
	switch invoker {
	case InvokerMCP:
		surface = s.Config().Api.MCP
		entry, known := apiRegistry[operation]
		defaultDisabled = known && entry.MCPDisabled
	case InvokerRest:
		surface = s.Config().Api.Rest
	default:
		return true
	}
	if slices.Contains(surface.DisableApis, string(operation)) {
		return false
	}
	if defaultDisabled {
		return slices.Contains(surface.EnableApis, string(operation))
	}
	return true
}

// checkApiOpEnabled returns a RequestError when the operation is disabled
// for the context's invoker. Called at dispatch and again by handlers that
// resolve a request to a more specific logical operation (secret_reveal,
// create_apikey_other)
func (s *Server) checkApiOpEnabled(ctx context.Context, operation API_NAME) error {
	invoker := system.GetContextApiInvoker(ctx)
	if invoker == "" {
		return nil
	}
	if !s.apiOpEnabled(invoker, operation) {
		return types.CreateRequestError(
			fmt.Sprintf("operation %s is disabled for the %s API surface", operation, invoker), http.StatusForbidden)
	}
	return nil
}

// validateApiSurfaceConfig fully validates the [api] section: schema
// (validateApiConfig) plus, when a surface is enabled, the RBAC and transport
// prerequisites and the external url shape. Runs at startup on the static
// config and again on every dynamic config update against the effective
// config (the [api] section is dynamically settable)
func validateApiSurfaceConfig(config *types.ServerConfig) error {
	if err := validateApiConfig(config); err != nil {
		return err
	}
	if !apiSurfaceEnabled(config, string(types.ApiSurfaceRest)) && !apiSurfaceEnabled(config, string(types.ApiSurfaceMCP)) {
		return nil
	}
	if config.Security.UnsafeDisableRBAC {
		return fmt.Errorf("an enabled remote API surface (api.rest / api.mcp enable) requires RBAC enforcement: unset security.unsafe_disable_rbac to use it")
	}
	if config.Https.Port == -1 && len(config.Security.TrustedProxies) == 0 {
		return fmt.Errorf("an enabled remote API surface (api.rest / api.mcp enable) requires an HTTPS listener or security.trusted_proxies for a TLS-terminating proxy")
	}
	// The external url backs token resource URIs and the OAuth metadata; a
	// config that would 404 discovery or fail login only after credentials
	// are typed must be rejected
	external := strings.TrimSuffix(cmp.Or(config.Api.ExternalUrl, config.Security.CallbackUrl), "/")
	if external == "" {
		return fmt.Errorf("an enabled remote API surface (api.rest / api.mcp enable) requires api.external_url (or security.callback_url): the canonical https origin for API tokens and OAuth metadata")
	}
	// OAuth endpoints and resource identifiers are built from this value by
	// concatenation: it must be a plain https origin, or the discovery
	// metadata comes out invalid
	parsed, err := url.Parse(external)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("api.external_url must be a plain https origin (https://host[:port], no path/query/fragment/userinfo), got %q", external)
	}
	for section, surface := range map[string]types.ApiSurfaceConfig{"api.mcp": config.Api.MCP, "api.rest": config.Api.Rest} {
		for _, mechanism := range surface.Auth {
			switch mechanism {
			case "builtin", "admin":
			default:
				_, isOAuth := config.Auth[mechanism]
				_, isSAML := config.SAML[mechanism]
				if !isOAuth && !isSAML {
					return fmt.Errorf("%s auth: unknown login mechanism %q (valid: builtin, admin, or an [auth.*]/[saml.*] entry name)", section, mechanism)
				}
			}
		}
	}
	return nil
}

// validateApiConfig checks the [api] section schema: every surface names
// at least one login mechanism (the default is admin), and the
// enable_apis / disable_apis op names are known
func validateApiConfig(config *types.ServerConfig) error {
	for section, surface := range map[string]types.ApiSurfaceConfig{"api.mcp": config.Api.MCP, "api.rest": config.Api.Rest} {
		if len(surface.Auth) == 0 {
			return fmt.Errorf("%s auth: at least one login mechanism is required (builtin, admin, or an [auth.*]/[saml.*] entry name; the default is admin)", section)
		}
		for _, op := range append(append([]string{}, surface.EnableApis...), surface.DisableApis...) {
			if _, ok := apiRegistry[API_NAME(op)]; !ok {
				return fmt.Errorf("%s: unknown operation %q in enable_apis/disable_apis", section, op)
			}
		}
	}
	if config.Api.Rest.SkipDestructiveConfirm {
		return fmt.Errorf("api.rest: skip_destructive_confirm applies to the mcp surface only")
	}
	return nil
}
