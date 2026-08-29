// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The MCP surface: management operations exposed as MCP tools over Streamable
// HTTP at /_openrun/mcp. Tools are thin typed wrappers over the same Server
// methods the CLI and console use; RBAC (and the credential scope ceiling)
// are enforced inside those methods from the request context identity, which
// the bearer middleware attaches to the HTTP request context (stateless mode
// propagates it into tool handlers).
//
// Tool annotations (ReadOnlyHint/DestructiveHint) inform client UX only; the
// security model is invoker policy + scopes + RBAC, never annotations.

const mcpServerInstructions = `OpenRun is an app deployment platform. Apps deploy from git or local
sources to a path (like /myapp) with a staging version (path_cl_stage) that
promote pushes to prod. Apps may use services (postgres, redis, ...) through
bindings. Sync entries keep apps in sync with git declaratively. Operations
run as the authenticated user; RBAC decides what is allowed. Destructive
tools (delete_apps, promote_apps, version_switch) support dry_run=true to
preview the outcome first.`

// getMCPServer returns the lazily built *mcp.Server; tools not enabled for
// the MCP invoker (registry defaults + [api.mcp] config) are not registered,
// and every tool re-checks invocation-time policy anyway
func (s *Server) getMCPServer() *mcp.Server {
	s.mcpOnce.Do(func() {
		s.mcpServer = s.buildMCPServer()
	})
	return s.mcpServer
}

// mcpHTTPHandler authenticates the bearer credential for the mcp surface and
// serves the streamable HTTP transport (stateless: no session state, safe
// across zero downtime restarts)
func (s *Server) mcpHTTPHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return s.getMCPServer()
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The identity context is attached to the HTTP request context; the
		// stateless streamable transport propagates it into tool handlers
		ctx, _, ok := s.authenticateApiRequest(w, r, ApiResourceMCP, "mcp")
		if !ok {
			return
		}
		streamable.ServeHTTP(w, r.WithContext(ctx))
	})
}

// mcpServerState holds the lazily built MCP server, embedded in Server
type mcpServerState struct {
	mcpOnce   sync.Once
	mcpServer *mcp.Server
}

// addMCPTool registers one typed tool wrapping a management operation. The
// registry is authoritative: the operation must exist there (name,
// description and annotations come from its entry - a mismatch panics at
// server build, like chi does for a bad route). The bridge enforces
// invocation-time invoker policy and writes the audit event (RBAC runs
// inside the Server method)
func addMCPTool[In any](s *Server, srv *mcp.Server, operation API_NAME,
	handler func(ctx context.Context, in In) (any, error)) {
	entry, known := apiRegistry[operation]
	if !known {
		panic("addMCPTool: operation " + string(operation) + " is not in the api registry")
	}
	if entry.MCPExcluded != "" {
		panic("addMCPTool: operation " + string(operation) + " is marked MCP-excluded: " + entry.MCPExcluded)
	}
	if !s.apiOpEnabled(InvokerMCP, operation) {
		return
	}
	destructive := entry.Destructive
	tool := &mcp.Tool{
		Name:        string(operation),
		Description: entry.Description,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    entry.ReadOnly,
			DestructiveHint: &destructive,
		},
	}
	mcp.AddTool(srv, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		event := types.AuditEvent{
			RequestId:  system.GetContextRequestId(ctx),
			CreateTime: time.Now(),
			UserId:     apiCallerPrincipal(ctx),
			EventType:  types.EventTypeSystem,
			Operation:  string(operation),
			Target:     mcpInputTarget(in),
			Status:     string(types.EventStatusFailure),
			Detail:     apiAuditDetail(ctx),
		}
		// Invocation-time policy is authoritative regardless of the cached
		// tool list a client may hold. Refused attempts are audited: "what
		// did MCP try and get refused" is a first-class audit query
		if err := s.checkApiOpEnabled(ctx, operation); err != nil {
			event.Detail += " refused=op_disabled"
			if auditErr := s.InsertAuditEvent(&event); auditErr != nil {
				s.Error().Err(auditErr).Msg("error inserting audit event for refused MCP call")
			}
			return nil, nil, err
		}
		// Attach a ContextShared so the Server methods' logical-op renames
		// (create_apikey_other, secret_reveal) and target updates reach the
		// audit event, matching the REST path
		cs := &ContextShared{}
		ctx = context.WithValue(ctx, types.SHARED, cs)
		out, err := handler(ctx, in)
		if err == nil {
			event.Status = string(types.EventStatusSuccess)
		}
		if cs.Operation != "" {
			event.Operation = cs.Operation
		}
		if cs.Target != "" {
			event.Target = cs.Target
		}
		if cs.DryRun || mcpInputDryRun(in) {
			event.Operation += "_dryrun"
		}
		if auditErr := s.InsertAuditEvent(&event); auditErr != nil {
			s.Error().Err(auditErr).Msg("error inserting audit event for MCP call")
		}
		if err != nil {
			return nil, nil, err
		}
		// Normalize through json/v2 so the API types' custom marshalers
		// apply, matching the REST responses byte for byte; Out is any, so
		// the SDK skips schema inference (the rich DTOs use conditional
		// fields and custom encodings that make poor generated schemas)
		generic, err := toJSONValue(out)
		return nil, generic, err
	})
}

// MCP tool input types. Dedicated slim DTOs: the REST request types lean on
// query params and conditional fields that make poor tool schemas
type (
	mcpAppGlobIn struct {
		PathGlob string `json:"path_glob,omitzero" jsonschema:"app path glob to match, like /myapp, example.com:/**, or all. Empty matches all apps across all domains"`
	}
	mcpAppPathIn struct {
		Path string `json:"path" jsonschema:"the app path, like /myapp or example.com:/myapp"`
	}
	mcpCreateAppIn struct {
		Path      string            `json:"path" jsonschema:"the app path to create, like /myapp"`
		SourceUrl string            `json:"source_url" jsonschema:"app source: git url, github shorthand like github.com/org/repo/folder, or server-local directory path"`
		Spec      string            `json:"spec,omitzero" jsonschema:"app spec name, like image or python-streamlit. Empty auto-detects for known frameworks"`
		Approve   bool              `json:"approve,omitzero" jsonschema:"approve the app's plugin permissions immediately (requires app:approve)"`
		Params    map[string]string `json:"params,omitzero" jsonschema:"app parameter values"`
		DryRun    bool              `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpDeleteAppsIn struct {
		PathGlob string `json:"path_glob" jsonschema:"app path glob to delete"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpStagedUpdateIn struct {
		PathGlob string `json:"path_glob" jsonschema:"app path glob to operate on"`
		Promote  bool   `json:"promote,omitzero" jsonschema:"also promote the staging change to prod"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpReloadAppsIn struct {
		PathGlob string `json:"path_glob" jsonschema:"app path glob to reload"`
		Approve  bool   `json:"approve,omitzero" jsonschema:"approve any new plugin permissions (requires app:approve)"`
		Promote  bool   `json:"promote,omitzero" jsonschema:"promote to prod after reload (requires app:promote)"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpVersionSwitchIn struct {
		Path    string `json:"path" jsonschema:"the app path"`
		Version string `json:"version" jsonschema:"target version number, or previous/next"`
		DryRun  bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpListServicesIn struct {
		Type string `json:"type,omitzero" jsonschema:"filter by service type, like postgres"`
		Name string `json:"name,omitzero" jsonschema:"filter by service name"`
	}
	mcpListBindingsIn struct {
		Source string `json:"source,omitzero" jsonschema:"filter by binding source"`
	}
	mcpListSecretsIn struct {
		Provider string `json:"provider,omitzero" jsonschema:"secret provider name, empty for the default"`
		NameGlob string `json:"name_glob,omitzero" jsonschema:"secret name glob"`
	}
	mcpSecretGetIn struct {
		Provider string `json:"provider,omitzero" jsonschema:"secret provider name, empty for the default"`
		Name     string `json:"name" jsonschema:"the secret name"`
	}
	mcpEmptyIn        struct{}
	mcpUpdateParamsIn struct {
		PathGlob string `json:"path_glob" jsonschema:"app path glob to update"`
		Name     string `json:"name" jsonschema:"the parameter name"`
		Value    string `json:"value" jsonschema:"the parameter value; use - to delete the parameter"`
		Promote  bool   `json:"promote,omitzero" jsonschema:"promote to prod after the update"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpPreviewIn struct {
		Path    string `json:"path" jsonschema:"the app path"`
		Commit  string `json:"commit" jsonschema:"the git commit id to preview"`
		Approve bool   `json:"approve,omitzero" jsonschema:"approve the preview app's plugin permissions"`
		DryRun  bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpListFilesIn struct {
		Path    string `json:"path" jsonschema:"the app path"`
		Version string `json:"version,omitzero" jsonschema:"the version to list files of; empty for current"`
	}
	mcpWebhookIn struct {
		Path   string `json:"path" jsonschema:"the app path"`
		Type   string `json:"type" jsonschema:"webhook type: reload, reload_promote or promote"`
		DryRun bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpApplyIn struct {
		Path     string `json:"path" jsonschema:"apply file location: server-local path or git url"`
		PathGlob string `json:"path_glob,omitzero" jsonschema:"app path glob to apply, default all"`
		Approve  bool   `json:"approve,omitzero" jsonschema:"approve plugin permissions (requires app:approve)"`
		Promote  bool   `json:"promote,omitzero" jsonschema:"promote changes to prod"`
		Reload   string `json:"reload,omitzero" jsonschema:"which apps to reload: none, updated or matched (default updated)"`
		Clobber  bool   `json:"clobber,omitzero" jsonschema:"overwrite non-declarative changes"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpApplyDeleteIn struct {
		Path     string `json:"path" jsonschema:"apply file location: server-local path or git url"`
		PathGlob string `json:"path_glob,omitzero" jsonschema:"app path glob to delete, default all"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpSyncCreateIn struct {
		Path              string `json:"path" jsonschema:"apply file location: server-local path or git url"`
		ScheduleFrequency int    `json:"schedule_frequency,omitzero" jsonschema:"run every N minutes (scheduled sync)"`
		Approve           bool   `json:"approve,omitzero" jsonschema:"syncs approve plugin permissions"`
		Promote           bool   `json:"promote,omitzero" jsonschema:"syncs promote to prod"`
		DryRun            bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpSyncIdIn struct {
		Id     string `json:"id" jsonschema:"the sync entry id"`
		DryRun bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpServiceIn struct {
		Name   string            `json:"name" jsonschema:"the service name"`
		Type   string            `json:"type" jsonschema:"the service type, like postgres"`
		Config map[string]string `json:"config,omitzero" jsonschema:"service configuration values"`
		DryRun bool              `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpServiceRefIn struct {
		Name   string `json:"name" jsonschema:"the service name"`
		Type   string `json:"type" jsonschema:"the service type"`
		DryRun bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpProviderInstallIn struct {
		Name      string `json:"name" jsonschema:"the provider name"`
		SourceUrl string `json:"source_url" jsonschema:"http(s) url ({os}/{arch} placeholders allowed) or server-local path of the provider binary"`
		Version   string `json:"version,omitzero" jsonschema:"provider version"`
		Sha256    string `json:"sha256,omitzero" jsonschema:"expected sha256 of the binary"`
	}
	mcpProviderUninstallIn struct {
		Name  string `json:"name" jsonschema:"the provider name"`
		Force bool   `json:"force,omitzero" jsonschema:"force uninstall even when in use"`
	}
	mcpBindingCreateIn struct {
		Path   string            `json:"path" jsonschema:"the binding path, like /myapp/db"`
		Source string            `json:"source" jsonschema:"the binding source, like a service id (postgres/main)"`
		Grants []string          `json:"grants,omitzero" jsonschema:"grant entries for the binding"`
		Config map[string]string `json:"config,omitzero" jsonschema:"binding configuration values"`
		DryRun bool              `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpBindingUpdateIn struct {
		Path         string   `json:"path" jsonschema:"the binding path"`
		AddGrants    []string `json:"add_grants,omitzero" jsonschema:"grant entries to add"`
		DeleteGrants []string `json:"delete_grants,omitzero" jsonschema:"grant entries to delete"`
		Promote      bool     `json:"promote,omitzero" jsonschema:"promote dependent apps"`
		DryRun       bool     `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpBindingPathIn struct {
		Path   string `json:"path" jsonschema:"the binding path"`
		DryRun bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpBindingNameIn struct {
		Name    string `json:"name" jsonschema:"the binding name/path"`
		Staging bool   `json:"staging,omitzero" jsonschema:"use the staging account"`
	}
	mcpBindingCommandIn struct {
		Name    string `json:"name" jsonschema:"the binding name/path"`
		Staging bool   `json:"staging,omitzero" jsonschema:"use the staging account"`
		Command string `json:"command" jsonschema:"the provider command to run"`
	}
	mcpSecretCreateIn struct {
		Name        string `json:"name" jsonschema:"the secret name"`
		Value       string `json:"value" jsonschema:"the secret value"`
		Provider    string `json:"provider,omitzero" jsonschema:"secret provider name, empty for the default"`
		Description string `json:"description,omitzero" jsonschema:"description for the secret"`
		Update      bool   `json:"update,omitzero" jsonschema:"update an existing secret instead of creating"`
	}
	mcpSecretRefIn struct {
		Provider string `json:"provider,omitzero" jsonschema:"secret provider name, empty for the default"`
		Name     string `json:"name" jsonschema:"the secret name"`
	}
	mcpProviderOnlyIn struct {
		Provider string `json:"provider,omitzero" jsonschema:"secret provider name, empty for the default"`
	}
	mcpUserAddIn struct {
		Username     string   `json:"username" jsonschema:"the builtin auth username"`
		PasswordHash string   `json:"password_hash" jsonschema:"bcrypt hash of the user's password"`
		Groups       []string `json:"groups,omitzero" jsonschema:"RBAC groups for the user"`
		Update       bool     `json:"update,omitzero" jsonschema:"update an existing user instead of creating"`
	}
	mcpUsernameIn struct {
		Username string `json:"username" jsonschema:"the builtin auth username"`
	}
	mcpConfigUpdateIn struct {
		ConfigJson string `json:"config_json" jsonschema:"the full dynamic config document as JSON (same shape as config_get returns)"`
		Force      bool   `json:"force,omitzero" jsonschema:"skip the version conflict check"`
	}
	mcpApiKeyCreateIn struct {
		User        string   `json:"user,omitzero" jsonschema:"the key's user identity; empty for the caller. Another user requires admin"`
		ExpiresIn   string   `json:"expires_in,omitzero" jsonschema:"lifetime: Go duration, <N>d, or never. Default 90d"`
		Scopes      []string `json:"scopes,omitzero" jsonschema:"permission glob scopes limiting the key"`
		Resources   []string `json:"resources,omitzero" jsonschema:"surfaces the key is valid for: rest and/or mcp"`
		Description string   `json:"description,omitzero" jsonschema:"description for the key"`
	}
	mcpApiKeyIdIn struct {
		Id string `json:"id" jsonschema:"the api key id"`
	}
	mcpUpdateSettingsIn struct {
		PathGlob           string `json:"path_glob" jsonschema:"app path glob to update"`
		AuthnType          string `json:"authn_type,omitzero" jsonschema:"app auth type (system, none, or an auth entry name); empty leaves unchanged"`
		GitAuthName        string `json:"git_auth_name,omitzero" jsonschema:"git auth entry name; empty leaves unchanged"`
		Spec               string `json:"spec,omitzero" jsonschema:"app spec name; empty leaves unchanged"`
		StageWriteAccess   *bool  `json:"stage_write_access,omitzero" jsonschema:"staging write plugin access; omit to leave unchanged"`
		PreviewWriteAccess *bool  `json:"preview_write_access,omitzero" jsonschema:"preview write plugin access; omit to leave unchanged"`
		DryRun             bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpUpdateMetadataIn struct {
		PathGlob      string   `json:"path_glob" jsonschema:"app path glob to update"`
		Spec          string   `json:"spec,omitzero" jsonschema:"app spec name; empty leaves unchanged"`
		ConfigType    string   `json:"config_type,omitzero" jsonschema:"metadata config to update: app_config, container_options, container_args, container_volumes, sidecars, auth, git_auth or bindings"`
		ConfigEntries []string `json:"config_entries,omitzero" jsonschema:"entries for the config type, each formatted as key=value"`
		Promote       bool     `json:"promote,omitzero" jsonschema:"promote to prod after the update"`
		DryRun        bool     `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpUpdateLinksIn struct {
		PathGlob string `json:"path_glob" jsonschema:"app path glob to update"`
		Plugin   string `json:"plugin" jsonschema:"the plugin to link, like store.in"`
		Account  string `json:"account" jsonschema:"the account name to link the plugin to"`
		Promote  bool   `json:"promote,omitzero" jsonschema:"promote to prod after the update"`
		DryRun   bool   `json:"dry_run,omitzero" jsonschema:"preview without applying"`
	}
	mcpReplicationIn struct {
		Refresh bool `json:"refresh,omitzero" jsonschema:"refresh the replication status"`
	}
)

// buildMCPServer registers the tool set. Ops disabled for the MCP invoker
// (registry defaults like stop_server/secret_reveal, minus [api.mcp] enable,
// plus [api.mcp] disable) are not registered at all
func (s *Server) buildMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "openrun", Version: types.GetVersion()},
		&mcp.ServerOptions{Instructions: mcpServerInstructions})

	addMCPTool(s, srv, API_SERVER_VERSION,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.ServerVersion(ctx)
		})

	addMCPTool(s, srv, API_LIST_APPS,
		func(ctx context.Context, in mcpAppGlobIn) (any, error) {
			// "all" (like "" and *:**) matches every app on every domain;
			// a bare * would match only root-level default-domain paths
			return s.GetApps(ctx, cmp.Or(in.PathGlob, "all"), false)
		})

	addMCPTool(s, srv, API_GET_APP,
		func(ctx context.Context, in mcpAppPathIn) (any, error) {
			return s.GetAppApi(ctx, in.Path)
		})

	addMCPTool(s, srv, API_LIST_VERSIONS,
		func(ctx context.Context, in mcpAppPathIn) (any, error) {
			return s.VersionList(ctx, in.Path)
		})

	addMCPTool(s, srv, API_CREATE_APP,
		func(ctx context.Context, in mcpCreateAppIn) (any, error) {
			req := &types.CreateAppRequest{
				Path:        in.Path,
				SourceUrl:   in.SourceUrl,
				Spec:        types.AppSpec(in.Spec),
				ParamValues: in.Params,
			}
			return s.CreateApp(ctx, in.Path, in.Approve, in.DryRun, req)
		})

	addMCPTool(s, srv, API_DELETE_APPS,
		func(ctx context.Context, in mcpDeleteAppsIn) (any, error) {
			return s.DeleteApps(ctx, in.PathGlob, in.DryRun)
		})

	addMCPTool(s, srv, API_APPROVE_APPS,
		func(ctx context.Context, in mcpStagedUpdateIn) (any, error) {
			return s.ApproveApps(ctx, in.PathGlob, in.DryRun, in.Promote)
		})

	addMCPTool(s, srv, API_RELOAD_APPS,
		func(ctx context.Context, in mcpReloadAppsIn) (any, error) {
			return s.ReloadApps(ctx, in.PathGlob, in.Approve, in.DryRun, in.Promote, "", "", "", false, false)
		})

	addMCPTool(s, srv, API_PROMOTE_APPS,
		func(ctx context.Context, in mcpDeleteAppsIn) (any, error) {
			return s.PromoteApps(ctx, in.PathGlob, in.DryRun)
		})

	addMCPTool(s, srv, API_VERSION_SWITCH,
		func(ctx context.Context, in mcpVersionSwitchIn) (any, error) {
			return s.VersionSwitch(ctx, in.Path, in.DryRun, in.Version)
		})

	addMCPTool(s, srv, API_LIST_SERVICES,
		func(ctx context.Context, in mcpListServicesIn) (any, error) {
			return s.ListServices(ctx, in.Type, in.Name)
		})

	addMCPTool(s, srv, API_LIST_BINDINGS,
		func(ctx context.Context, in mcpListBindingsIn) (any, error) {
			return s.ListBindings(ctx, in.Source)
		})

	addMCPTool(s, srv, API_LIST_SYNC,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.ListSyncEntries(ctx)
		})

	addMCPTool(s, srv, API_LIST_SECRETS,
		func(ctx context.Context, in mcpListSecretsIn) (any, error) {
			return s.ListSecrets(ctx, in.Provider, in.NameGlob)
		})

	addMCPTool(s, srv, API_SECRET_GET,
		func(ctx context.Context, in mcpSecretGetIn) (any, error) {
			return s.GetSecret(ctx, in.Provider, in.Name, false)
		})

	addMCPTool(s, srv, API_CONFIG_GET,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.GetConfigResponse(ctx)
		})

	addMCPTool(s, srv, API_LIST_APIKEYS,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.ListApiKeys(ctx, false)
		})

	addMCPTool(s, srv, API_SERVER_STATUS,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return types.ServerStatusResponse{Status: "ok"}, nil
		})

	addMCPTool(s, srv, API_STOP_SERVER,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.StopServer(ctx)
		})

	addMCPTool(s, srv, API_RESTART_SERVER,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.RestartServer(ctx)
		})

	addMCPTool(s, srv, API_UPDATE_PARAMS,
		func(ctx context.Context, in mcpUpdateParamsIn) (any, error) {
			return s.UpdateAppParams(ctx, in.PathGlob, in.DryRun, in.Promote, in.Name, in.Value)
		})

	addMCPTool(s, srv, API_CREATE_PREVIEW,
		func(ctx context.Context, in mcpPreviewIn) (any, error) {
			return s.PreviewApp(ctx, in.Path, in.Commit, in.Approve, in.DryRun)
		})

	addMCPTool(s, srv, API_LIST_FILES,
		func(ctx context.Context, in mcpListFilesIn) (any, error) {
			return s.VersionFiles(ctx, in.Path, in.Version)
		})

	addMCPTool(s, srv, API_LIST_WEBHOOKS,
		func(ctx context.Context, in mcpAppPathIn) (any, error) {
			return s.TokenList(ctx, in.Path)
		})

	addMCPTool(s, srv, API_TOKEN_CREATE,
		func(ctx context.Context, in mcpWebhookIn) (any, error) {
			return s.TokenCreate(ctx, in.Path, types.WebhookType(in.Type), in.DryRun)
		})

	addMCPTool(s, srv, API_TOKEN_DELETE,
		func(ctx context.Context, in mcpWebhookIn) (any, error) {
			return s.TokenDelete(ctx, in.Path, types.WebhookType(in.Type), in.DryRun)
		})

	addMCPTool(s, srv, API_APPLY,
		func(ctx context.Context, in mcpApplyIn) (any, error) {
			glob := cmp.Or(in.PathGlob, "all")
			reload := types.AppReloadOption(cmp.Or(in.Reload, string(types.AppReloadOptionUpdated)))
			result, _, err := s.Apply(ctx, types.Transaction{}, in.Path, glob, in.Approve, in.DryRun, in.Promote,
				reload, "", "", "", in.Clobber, false, false, "", nil, false)
			return result, err
		})

	addMCPTool(s, srv, API_APPLY_DELETE,
		func(ctx context.Context, in mcpApplyDeleteIn) (any, error) {
			return s.ApplyDelete(ctx, in.Path, cmp.Or(in.PathGlob, "all"), in.DryRun, "", "", "")
		})

	addMCPTool(s, srv, API_SYNC_CREATE,
		func(ctx context.Context, in mcpSyncCreateIn) (any, error) {
			sync := &types.SyncMetadata{
				Approve:           in.Approve,
				Promote:           in.Promote,
				ScheduleFrequency: in.ScheduleFrequency,
			}
			return s.CreateSyncEntry(ctx, in.Path, in.ScheduleFrequency > 0, in.DryRun, sync)
		})

	addMCPTool(s, srv, API_SYNC_RUN,
		func(ctx context.Context, in mcpSyncIdIn) (any, error) {
			return s.RunSync(ctx, in.Id, in.DryRun)
		})

	addMCPTool(s, srv, API_SYNC_DELETE,
		func(ctx context.Context, in mcpSyncIdIn) (any, error) {
			return s.DeleteSyncEntry(ctx, in.Id, in.DryRun)
		})

	addMCPTool(s, srv, API_SERVICE_CREATE,
		func(ctx context.Context, in mcpServiceIn) (any, error) {
			service := &types.Service{Name: in.Name, ServiceType: in.Type, Config: in.Config}
			if err := s.CreateService(ctx, service, in.DryRun); err != nil {
				return nil, err
			}
			return service, nil
		})

	addMCPTool(s, srv, API_SERVICE_UPDATE,
		func(ctx context.Context, in mcpServiceIn) (any, error) {
			service := &types.Service{Name: in.Name, ServiceType: in.Type, Config: in.Config}
			if err := s.UpdateService(ctx, service, in.DryRun); err != nil {
				return nil, err
			}
			return service, nil
		})

	addMCPTool(s, srv, API_SERVICE_DELETE,
		func(ctx context.Context, in mcpServiceRefIn) (any, error) {
			if err := s.DeleteService(ctx, in.Name, in.Type, in.DryRun); err != nil {
				return nil, err
			}
			return map[string]any{"name": in.Name, "service_type": in.Type, "status": "deleted"}, nil
		})

	addMCPTool(s, srv, API_SERVICE_HEALTH,
		func(ctx context.Context, in mcpServiceRefIn) (any, error) {
			if err := s.ServiceHealth(ctx, in.Type, in.Name); err != nil {
				return nil, err
			}
			return map[string]any{"name": in.Name, "service_type": in.Type, "status": "healthy"}, nil
		})

	addMCPTool(s, srv, API_PROVIDER_INSTALL,
		func(ctx context.Context, in mcpProviderInstallIn) (any, error) {
			return s.InstallProvider(ctx, &types.ProviderInstallRequest{
				Name: in.Name, SourceURL: in.SourceUrl, Version: in.Version, Sha256: in.Sha256})
		})

	addMCPTool(s, srv, API_PROVIDER_UNINSTALL,
		func(ctx context.Context, in mcpProviderUninstallIn) (any, error) {
			if err := s.UninstallProvider(ctx, in.Name, in.Force); err != nil {
				return nil, err
			}
			return map[string]any{"name": in.Name, "status": "uninstalled"}, nil
		})

	addMCPTool(s, srv, API_LIST_PROVIDERS,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			return s.ListProviders(ctx)
		})

	addMCPTool(s, srv, API_BINDING_CREATE,
		func(ctx context.Context, in mcpBindingCreateIn) (any, error) {
			binding, err := s.CreateBinding(ctx, &types.CreateBindingRequest{
				Path: in.Path, Source: in.Source, Grants: in.Grants, Config: in.Config}, in.DryRun)
			if err != nil {
				return nil, err
			}
			// Account credentials need binding:reveal (binding_show_account),
			// matching the REST handlers' redaction
			return redactBindingAccount(binding), nil
		})

	addMCPTool(s, srv, API_BINDING_UPDATE,
		func(ctx context.Context, in mcpBindingUpdateIn) (any, error) {
			binding, err := s.UpdateBinding(ctx, types.UpdateBindingRequest{
				Path: in.Path, AddGrants: in.AddGrants, DeleteGrants: in.DeleteGrants}, in.DryRun, in.Promote, false)
			if err != nil {
				return nil, err
			}
			return redactBindingAccount(binding), nil
		})

	addMCPTool(s, srv, API_BINDING_DELETE,
		func(ctx context.Context, in mcpBindingPathIn) (any, error) {
			if err := s.DeleteBinding(ctx, in.Path, in.DryRun); err != nil {
				return nil, err
			}
			return map[string]any{"path": in.Path, "status": "deleted"}, nil
		})

	addMCPTool(s, srv, API_BINDING_GET,
		func(ctx context.Context, in mcpBindingPathIn) (any, error) {
			return s.GetBinding(ctx, in.Path)
		})

	addMCPTool(s, srv, API_BINDING_HEALTH,
		func(ctx context.Context, in mcpBindingNameIn) (any, error) {
			if err := s.BindingHealth(ctx, in.Name, in.Staging); err != nil {
				return nil, err
			}
			return map[string]any{"name": in.Name, "staging": in.Staging, "status": "healthy"}, nil
		})

	addMCPTool(s, srv, API_BINDING_RUN_COMMAND,
		func(ctx context.Context, in mcpBindingCommandIn) (any, error) {
			return s.RunBindingCommand(ctx, in.Name, in.Staging, in.Command)
		})

	addMCPTool(s, srv, API_BINDING_SHOW_ACCOUNT,
		func(ctx context.Context, in mcpBindingNameIn) (any, error) {
			return s.GetBindingAccount(ctx, in.Name, in.Staging)
		})

	addMCPTool(s, srv, API_UPDATE_SETTINGS,
		func(ctx context.Context, in mcpUpdateSettingsIn) (any, error) {
			req := types.CreateUpdateAppRequest()
			if in.AuthnType != "" {
				req.AuthnType = types.StringValue(in.AuthnType)
			}
			if in.GitAuthName != "" {
				req.GitAuthName = types.StringValue(in.GitAuthName)
			}
			if in.Spec != "" {
				req.Spec = types.StringValue(in.Spec)
			}
			if in.StageWriteAccess != nil {
				req.StageWriteAccess = boolToBoolValue(*in.StageWriteAccess)
			}
			if in.PreviewWriteAccess != nil {
				req.PreviewWriteAccess = boolToBoolValue(*in.PreviewWriteAccess)
			}
			return s.UpdateAppSettings(ctx, in.PathGlob, in.DryRun, req)
		})

	addMCPTool(s, srv, API_UPDATE_METADATA,
		func(ctx context.Context, in mcpUpdateMetadataIn) (any, error) {
			req := types.CreateUpdateAppMetadataRequest()
			if in.Spec != "" {
				req.Spec = types.StringValue(in.Spec)
			}
			if in.ConfigType != "" {
				req.ConfigType = types.AppMetadataConfigType(in.ConfigType)
				req.ConfigEntries = in.ConfigEntries
			}
			args := map[string]any{"metadata": req, "dryRun": in.DryRun}
			return s.StagedUpdate(ctx, in.PathGlob, in.DryRun, in.Promote, s.updateMetadataHandler, args, "update_metadata")
		})

	addMCPTool(s, srv, API_UPDATE_LINKS,
		func(ctx context.Context, in mcpUpdateLinksIn) (any, error) {
			args := map[string]any{"plugin": in.Plugin, "account": in.Account}
			return s.StagedUpdate(ctx, in.PathGlob, in.DryRun, in.Promote, s.accountLinkHandler, args, "account-link")
		})

	addMCPTool(s, srv, API_REPLICATION_STATUS,
		func(ctx context.Context, in mcpReplicationIn) (any, error) {
			return s.ReplicationStatus(ctx, in.Refresh)
		})

	addMCPTool(s, srv, API_SECRET_CREATE,
		func(ctx context.Context, in mcpSecretCreateIn) (any, error) {
			return s.CreateSecret(ctx, &types.CreateSecretRequest{
				Name: in.Name, Value: in.Value, Provider: in.Provider, Description: in.Description}, in.Update)
		})

	addMCPTool(s, srv, API_SECRET_REVEAL,
		func(ctx context.Context, in mcpSecretRefIn) (any, error) {
			return s.GetSecret(ctx, in.Provider, in.Name, true)
		})

	addMCPTool(s, srv, API_SECRET_DELETE,
		func(ctx context.Context, in mcpSecretRefIn) (any, error) {
			if err := s.DeleteSecret(ctx, in.Provider, in.Name); err != nil {
				return nil, err
			}
			return map[string]any{"name": in.Name, "status": "deleted"}, nil
		})

	addMCPTool(s, srv, API_SECRET_REKEY,
		func(ctx context.Context, in mcpProviderOnlyIn) (any, error) {
			return s.RekeySecrets(ctx, in.Provider)
		})

	addMCPTool(s, srv, API_USER_ADD,
		func(ctx context.Context, in mcpUserAddIn) (any, error) {
			updated, err := s.CreateUpdateUser(ctx, in.Username, in.PasswordHash, in.Groups, in.Update)
			if err != nil {
				return nil, err
			}
			return map[string]any{"username": in.Username, "updated": updated}, nil
		})

	addMCPTool(s, srv, API_USER_DELETE,
		func(ctx context.Context, in mcpUsernameIn) (any, error) {
			if err := s.DeleteUser(ctx, in.Username); err != nil {
				return nil, err
			}
			return map[string]any{"username": in.Username, "status": "deleted"}, nil
		})

	addMCPTool(s, srv, API_USER_LIST,
		func(ctx context.Context, _ mcpEmptyIn) (any, error) {
			// ListUsers enforces config:read internally (via GetConfigEntries)
			return s.ListUsers(ctx)
		})

	addMCPTool(s, srv, API_CONFIG_UPDATE,
		func(ctx context.Context, in mcpConfigUpdateIn) (any, error) {
			var dynamicConfig types.DynamicConfig
			if err := json.Unmarshal([]byte(in.ConfigJson), &dynamicConfig); err != nil {
				return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
			}
			newConfig, err := s.UpdateDynamicConfig(ctx, &dynamicConfig, in.Force)
			if err != nil {
				return nil, err
			}
			return types.ConfigResponse{DynamicConfig: *newConfig}, nil
		})

	addMCPTool(s, srv, API_CREATE_APIKEY,
		func(ctx context.Context, in mcpApiKeyCreateIn) (any, error) {
			return s.CreateApiKey(ctx, &types.ApiKeyCreateRequest{
				User: in.User, ExpiresIn: in.ExpiresIn, Scopes: in.Scopes,
				Resources: in.Resources, Description: in.Description})
		})

	addMCPTool(s, srv, API_DELETE_APIKEY,
		func(ctx context.Context, in mcpApiKeyIdIn) (any, error) {
			return s.DeleteApiKey(ctx, in.Id)
		})

	return srv
}

// toJSONValue round-trips a value through json/v2 into generic JSON values,
// so custom marshalers on the API types apply before the MCP layer encodes
// the result
func toJSONValue(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, err
	}
	return generic, nil
}

// mcpInputTarget extracts a best-effort audit target from a tool's input:
// the first non-empty of the conventional identifying fields
func mcpInputTarget(in any) string {
	value := reflect.ValueOf(in)
	if value.Kind() != reflect.Struct {
		return ""
	}
	for _, name := range []string{"Path", "PathGlob", "Name", "Id", "Username", "User"} {
		field := value.FieldByName(name)
		if field.IsValid() && field.Kind() == reflect.String && field.String() != "" {
			return field.String()
		}
	}
	return ""
}

// mcpInputDryRun reports whether the tool input carries DryRun=true, so
// dry-run MCP calls audit with the _dryrun suffix like the REST path
func mcpInputDryRun(in any) bool {
	value := reflect.ValueOf(in)
	if value.Kind() != reflect.Struct {
		return false
	}
	field := value.FieldByName("DryRun")
	return field.IsValid() && field.Kind() == reflect.Bool && field.Bool()
}

func boolToBoolValue(value bool) types.BoolValue {
	if value {
		return types.BoolValueTrue
	}
	return types.BoolValueFalse
}
