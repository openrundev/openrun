// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// App actions through the management API: the transport of the openrun action
// CLI commands and of the list_actions/get_action/run_action/suggest_action
// MCP tools. The calls dispatch in-process to the served app's actions
// (action.Invoke), under the checks a browser user of the app gets, all
// evaluated for the caller's principal:
//  1. the principal is one the app's auth would have produced (provider match)
//  2. app:access on the app
//  3. the action's permit list (custom permissions)
// Design: arch/docs/actions-cli-mcp.md

const (
	actionRequestField   = "request" // multipart field holding the ActionRunRequest document
	actionMultipartBytes = 10 << 20  // in-memory part of a multipart run request
	actionMaxBodyBytes   = 32 << 20  // run/suggest request cap, the actions REST API default
	actionSelectorSep    = ":"       // audit target is <appPath>:<tool>
	actionLoginHint      = `run "openrun login --auth %s"`
	actionAdminOnlyError = "app %s uses %s auth, its actions can be run through the management API by the admin user only"
)

// actionTarget is what the authorization of an action call needs to know of
// the app: available from the app metadata (types.AppInfo) without loading the
// app, and from a loaded app
type actionTarget struct {
	id         types.AppId
	pathDomain types.AppPathDomain
	grantPath  types.AppPathDomain // the main app path for stage and preview apps, RBAC grants are on it
	authn      types.AppAuthnType
	owner      string
}

func actionTargetOfApp(application *app.App) actionTarget {
	return actionTarget{
		id:         application.Id,
		pathDomain: application.AppPathDomain(),
		grantPath:  mainAppPathDomain(application.AppPathDomain(), application.MainApp, application.LinkedAppPath),
		authn:      application.Metadata.AuthnType,
		owner:      application.UserID,
	}
}

func actionTargetOfInfo(info types.AppInfo) actionTarget {
	return actionTarget{
		id:         info.Id,
		pathDomain: info.AppPathDomain,
		grantPath:  mainAppPathDomain(info.AppPathDomain, info.MainApp, info.LinkedAppPath),
		authn:      info.Auth,
		owner:      info.UserID,
	}
}

// actionProviderMatch checks that the caller's principal is one the app's
// auth setting would have produced: a builtin:bob token does not run the
// actions of an app whose users log in through saml_okta, even when a group
// grant would let it through RBAC. Not checked for trusted calls (the unix
// socket without --as), for the admin user and for callers holding the admin
// permission; apps with auth none accept any principal
func (s *Server) actionProviderMatch(ctx context.Context, target actionTarget) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	principal := apiCallerPrincipal(ctx)
	if principal == types.ADMIN_USER {
		return nil
	}

	coreAuth, _, err := s.checkAuthModifiers(resolveAppAuth(target.authn, s.Config()))
	if err != nil {
		return err
	}
	coreAuth = strings.TrimPrefix(coreAuth, rbac.RBAC_AUTH_PREFIX)
	if coreAuth == string(types.AppAuthnNone) {
		return nil
	}

	if isAdmin, adminErr := s.rbacManager.AuthorizeAPI(ctx, types.PermissionAdmin, target.grantPath, target.owner); adminErr == nil && isAdmin {
		return nil
	}

	switch {
	case coreAuth == string(types.AppAuthnSystem):
		return types.CreateRequestError(fmt.Sprintf(actionAdminOnlyError, target.pathDomain, "system"), http.StatusForbidden)
	case coreAuth == "cert" || strings.HasPrefix(coreAuth, "cert_"):
		return types.CreateRequestError(fmt.Sprintf(actionAdminOnlyError, target.pathDomain, "client certificate"), http.StatusForbidden)
	}

	provider, _, _ := strings.Cut(principal, ":")
	if provider != coreAuth {
		return types.CreateRequestError(fmt.Sprintf("app %s uses login %s, you are logged in as %s: "+actionLoginHint,
			target.pathDomain, coreAuth, principal, coreAuth), http.StatusForbidden)
	}
	return nil
}

// actionAppContext builds the app request context the action runs with: the
// identity values the permit check, the plugins and the audit events read,
// as authenticateAndServeApp and serveMCPApp set them for a served request
func (s *Server) actionAppContext(ctx context.Context, target actionTarget) (context.Context, error) {
	authCtx := &authContext{
		Context: ctx,
		userId:  apiCallerPrincipal(ctx),
		// authContext answers these keys itself: carry the subject and email
		// of a federated caller over, plugins and proxied requests see the
		// identity a browser session of the user has
		userSubject: system.GetContextUserSubject(ctx),
		userEmail:   system.GetContextUserEmail(ctx),
		appId:       string(target.id),
		pathDomain:  target.grantPath,
		appAuth:     target.authn,
		groups:      system.GetContextGroups(ctx),
		customPerms: make([]string, 0),
	}
	if authCtx.groups == nil {
		authCtx.groups = []string{}
	}
	// Trusted calls (the unix socket without --as) are the admin user, who
	// passes every permit check; enforcement follows the config otherwise
	authCtx.rbacEnabled = s.rbacManager.IsAppRBACEnabled(authCtx)
	if authCtx.rbacEnabled {
		var err error
		authCtx.customPerms, err = s.rbacManager.GetCustomPermissions(authCtx)
		if err != nil {
			return nil, err
		}
	}
	return authCtx, nil
}

func actionTargetOfEntry(entry *types.AppEntry) actionTarget {
	return actionTarget{
		id:         entry.Id,
		pathDomain: entry.AppPathDomain(),
		grantPath:  mainAppPathDomain(entry.AppPathDomain(), entry.MainApp, entry.LinkedAppPath),
		authn:      entry.Metadata.AuthnType,
		owner:      entry.UserID,
	}
}

// definitionApp returns an app with its definition loaded, without
// initializing it: what listing and describing actions need. Initializing a
// container app builds and starts its container, which only running an action
// is a reason for. The app loaded on this node is used when there is one;
// otherwise the definition alone is loaded (no container, the load job runs
// use) into an app which release closes
func (s *Server) definitionApp(ctx context.Context, entry *types.AppEntry) (*app.App, func(), error) {
	if loadedApp, err := s.apps.GetApp(entry.AppPathDomain()); err == nil {
		if _, loaded := loadedApp.LoadedActions(); loaded {
			return loadedApp, func() {}, nil
		}
	}
	application, err := s.setupApp(ctx, entry, types.Transaction{})
	if err != nil {
		return nil, nil, err
	}
	if _, err := application.Reload(ctx, true, true, types.DryRunFalse, app.ReloadOptions{SkipContainer: true}); err != nil {
		application.Close() //nolint:errcheck
		return nil, nil, err
	}
	return application, func() { application.Close() }, nil //nolint:errcheck
}

// actionApp resolves the app instance for an app path (the staging instance
// with stage) for a caller who passes the provider match and app:access
// checks. The checks work from the app metadata and come first: nothing is
// loaded, let alone started, for a caller who may not use the app. With
// initialize the served app is returned, initialized so that its actions can
// run; without, an app with its definition loaded (definitionApp). release
// has to be called when done with the app
func (s *Server) actionApp(ctx context.Context, appPath string, stage, initialize bool) (*app.App, context.Context, func(), error) {
	entry, err := s.resolveJobInstance(ctx, appPath, stage)
	if err != nil {
		return nil, nil, nil, err
	}
	target := actionTargetOfEntry(entry)
	if err := s.actionProviderMatch(ctx, target); err != nil {
		return nil, nil, nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionAccess, entry); err != nil {
		return nil, nil, nil, err
	}
	appCtx, err := s.actionAppContext(ctx, target)
	if err != nil {
		return nil, nil, nil, err
	}

	var application *app.App
	release := func() {}
	if initialize {
		application, err = s.GetApp(ctx, entry.AppPathDomain(), true)
	} else {
		application, release, err = s.definitionApp(ctx, entry)
	}
	if err != nil {
		return nil, nil, nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	return application, appCtx, release, nil
}

// resolvedAction is an action selected by a caller who passed all the checks
type resolvedAction struct {
	app     *app.App
	action  *action.Action
	tool    string
	ctx     context.Context // the app request context, see actionAppContext
	release func()          // to be called when done with the app, see actionApp
}

// resolveAction selects an action of an app and authorizes the caller for it.
// A caller without the permit gets the same not found error as for an action
// which does not exist
func (s *Server) resolveAction(ctx context.Context, appPath, selector string, stage, initialize bool) (resolved *resolvedAction, err error) {
	if appPath == "" {
		return nil, types.CreateRequestError("app path is required", http.StatusBadRequest)
	}
	application, appCtx, release, err := s.actionApp(ctx, appPath, stage, initialize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resolved == nil {
			release()
		}
	}()
	actions := application.Actions()
	if len(actions) == 0 {
		return nil, types.CreateRequestError(fmt.Sprintf("app %s has no actions", appPath), http.StatusNotFound)
	}
	act, err := action.FindAction(actions, selector)
	if err != nil {
		code := http.StatusNotFound
		if selector == "" {
			code = http.StatusBadRequest
		}
		return nil, types.CreateRequestError(err.Error(), code)
	}
	authorized, err := act.Authorized(appCtx)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, types.CreateRequestError(fmt.Sprintf("action %q not found", cmp.Or(selector, act.Name())), http.StatusNotFound)
	}
	return &resolvedAction{app: application, action: act, tool: action.ToolNames(actions)[act], ctx: appCtx, release: release}, nil
}

func actionInfo(application *app.App, act *action.Action, tool string) types.ActionInfo {
	return types.ActionInfo{
		AppPath:     application.AppPathDomain().String(),
		Name:        act.Name(),
		Tool:        tool,
		Path:        act.Path(),
		Description: act.Description(),
		Suggest:     act.HasSuggest(),
	}
}

// listedAction is an action as the list shows it, with the permit the caller
// is checked against
type listedAction struct {
	info   types.ActionInfo
	permit []string
}

// actionListEntry is the in-memory action list of one app version, for the
// versions which have no DefinitionActions in their metadata
type actionListEntry struct {
	version int
	actions []listedAction
}

func listedActions(appPath string, actions []*action.Action) []listedAction {
	return listedActionDefs(appPath, action.Defs(actions))
}

// listedActionDefs is the list form of action definitions: the persisted ones
// of the app metadata, or those of a loaded app. The tool names are derived
// here, they are not stored
func listedActionDefs(appPath string, defs []types.ActionDef) []listedAction {
	names := action.ToolNamesOfDefs(defs)
	listed := make([]listedAction, 0, len(defs))
	for i, def := range defs {
		listed = append(listed, listedAction{permit: def.Permit, info: types.ActionInfo{
			AppPath:     appPath,
			Name:        def.Name,
			Tool:        names[i],
			Path:        def.Path,
			Description: def.Description,
			Suggest:     def.Suggest,
		}})
	}
	return listed
}

// appActionList returns the actions an app defines, without loading the app
// where that can be avoided and never initializing it (for a container app
// that builds and starts the container).
//
// The actions of a prod or stage app come from its version metadata
// (DefinitionActions), persisted by the deploy transactions when the
// definition loads: a database read, as for jobs. A version stored before the
// field existed, or whose definition never loaded, has none (nil): for it, and
// for dev apps (their source changes without a deploy, the stored list can be
// stale), the actions are read from the app loaded on this node, else from the
// in-memory list of that app version, else from a load of the definition alone
// (definitionApp). Reading a loaded app takes no app lock, a list does not wait
// behind a reload in progress
func (s *Server) appActionList(ctx context.Context, info types.AppInfo) ([]listedAction, error) {
	appPath := info.String()
	appEntry, err := s.db.GetAppEntry(ctx, info.AppPathDomain)
	if err != nil {
		return nil, err
	}
	if !appEntry.IsDev && appEntry.Metadata.DefinitionActions != nil {
		return listedActionDefs(appPath, appEntry.Metadata.DefinitionActions), nil
	}

	if loadedApp, err := s.apps.GetApp(info.AppPathDomain); err == nil {
		if actions, loaded := loadedApp.LoadedActions(); loaded {
			return listedActions(appPath, actions), nil
		}
	}
	version := appEntry.Metadata.VersionMetadata.Version
	if cached, ok := s.actionLists.Load(appEntry.Id); ok && !appEntry.IsDev {
		if entry := cached.(*actionListEntry); entry.version == version {
			return entry.actions, nil
		}
	}

	application, release, err := s.definitionApp(ctx, appEntry)
	if err != nil {
		return nil, err
	}
	defer release()
	listed := listedActions(appPath, application.Actions())
	if !appEntry.IsDev {
		s.actionLists.Store(appEntry.Id, &actionListEntry{version: version, actions: listed})
	}
	return listed, nil
}

// ListActions lists the actions the caller can run, for the apps matching the
// glob. Apps the caller fails the provider match or app:access check on and
// actions the caller lacks the permit for are left out, not flagged. Both app
// checks work from the app metadata and come first: nothing is loaded for an
// app the caller cannot use, and no app is initialized to be listed
func (s *Server) ListActions(ctx context.Context, appPathGlob string) (*types.ActionListResponse, error) {
	filteredApps, err := s.FilterApps(cmp.Or(appPathGlob, "all"), false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	ret := &types.ActionListResponse{Actions: []types.ActionInfo{}}
	for _, appInfo := range filteredApps {
		target := actionTargetOfInfo(appInfo)
		if s.rbacManager.APIEnforced(ctx) {
			authorized, err := s.rbacManager.AuthorizeAPI(ctx, types.PermissionAccess, target.grantPath, target.owner)
			if err != nil {
				return nil, err
			}
			if !authorized {
				continue
			}
		}
		if s.actionProviderMatch(ctx, target) != nil {
			continue
		}

		listed, err := s.appActionList(ctx, appInfo)
		if err != nil {
			ret.Warnings = append(ret.Warnings, fmt.Sprintf("%s: %s", appInfo.AppPathDomain, err))
			continue
		}
		if len(listed) == 0 {
			continue
		}
		appCtx, err := s.actionAppContext(ctx, target)
		if err != nil {
			return nil, err
		}
		for _, act := range listed {
			authorized := len(act.permit) == 0
			if !authorized {
				if authorized, err = s.rbacManager.AuthorizeAny(appCtx, act.permit); err != nil {
					return nil, err
				}
			}
			if authorized {
				ret.Actions = append(ret.Actions, act.info)
			}
		}
	}
	// By app path; the actions of an app stay in their declared order
	slices.SortStableFunc(ret.Actions, func(a, b types.ActionInfo) int {
		return strings.Compare(a.AppPath, b.AppPath)
	})
	return ret, nil
}

// GetAction returns the param definitions of an action
func (s *Server) GetAction(ctx context.Context, appPath, selector string, stage bool) (*types.ActionDetailResponse, error) {
	resolved, err := s.resolveAction(ctx, appPath, selector, stage, false)
	if err != nil {
		return nil, err
	}
	defer resolved.release()
	schema, err := resolved.action.Schema()
	if err != nil {
		return nil, err
	}
	inputSchema, err := resolved.action.InputJSONSchema(false)
	if err != nil {
		return nil, err
	}
	appUrl := strings.TrimSuffix(types.GetAppUrl(resolved.app.AppPathDomain(), s.Config()), "/")
	return &types.ActionDetailResponse{
		ActionInfo:  actionInfo(resolved.app, resolved.action, resolved.tool),
		Url:         appUrl + strings.TrimSuffix(resolved.action.Path(), "/"),
		Params:      schema.Params,
		InputSchema: inputSchema,
	}, nil
}

// ActionsOpenAPI returns the OpenAPI spec of the app's actions REST API, as
// the app serves it to the caller (the actions the caller lacks the permit
// for are not included)
func (s *Server) ActionsOpenAPI(ctx context.Context, appPath string, stage bool) (any, error) {
	if appPath == "" {
		return nil, types.CreateRequestError("app path is required", http.StatusBadRequest)
	}
	application, appCtx, release, err := s.actionApp(ctx, appPath, stage, false)
	if err != nil {
		return nil, err
	}
	defer release()
	actions := application.Actions()
	if len(actions) == 0 {
		return nil, types.CreateRequestError(fmt.Sprintf("app %s has no actions", appPath), http.StatusNotFound)
	}
	return action.OpenAPISpec(appCtx, application.Name, application.Path, actions)
}

// actionInvocation is an authorized, completed invocation. The caller renders
// the outcome and closes it
type actionInvocation struct {
	*resolvedAction
	outcome *action.Outcome
	op      action.Op
}

// InvokeAction runs (or validates, with DryRun) an action, or its suggest
// handler. source is the audit operation prefix (action.SourceMgmt / SourceMCP)
func (s *Server) InvokeAction(ctx context.Context, req *types.ActionRunRequest, suggest bool, source string,
	files map[string]action.UploadedFile) (*actionInvocation, error) {
	resolved, err := s.resolveAction(ctx, req.AppPath, req.Action, req.Stage, true)
	if err != nil {
		return nil, err
	}
	op := action.OpRun
	if suggest {
		op = action.OpSuggest
	} else if req.DryRun {
		op = action.OpValidate
	}
	// The call does not pass through App.ServeHTTP: count it as app activity,
	// or the idle shutdown stops the container of an app which is in use
	resolved.app.RecordActivity()
	outcome, invErr := resolved.action.Invoke(resolved.ctx, action.Invocation{
		Op:       op,
		AuditOp:  action.AuditOp(source, op),
		JSONArgs: req.Args,
		Files:    files,
	})
	if invErr != nil {
		return nil, types.CreateRequestError(invErr.Msg, invErr.Code)
	}
	return &actionInvocation{resolvedAction: resolved, outcome: outcome, op: op}, nil
}

// rawAPIResponse is an API response which writes itself, for the responses
// the JSON encoding of apiHandler does not fit: a stream, a non 200 status
type rawAPIResponse interface {
	writeResponse(w http.ResponseWriter, r *http.Request)
}

// actionResponse writes an action outcome the way the actions REST API does:
// JSON (422 for param errors), or chunked text/plain for a stream result
type actionResponse struct {
	invocation *actionInvocation
}

func (a *actionResponse) writeResponse(w http.ResponseWriter, r *http.Request) {
	inv := a.invocation
	defer inv.outcome.Close()
	if inv.outcome.IsStream() {
		inv.action.WriteStreamText(w, r, inv.outcome)
		return
	}
	var response map[string]any
	code := http.StatusOK
	if inv.op == action.OpSuggest {
		var invErr *action.InvokeError
		if response, invErr = inv.action.SuggestResult(inv.outcome.Suggest); invErr != nil {
			response, code = map[string]any{"error": invErr.Msg}, invErr.Code
		}
	} else {
		response, code = inv.action.APIResult(inv.outcome, inv.op == action.OpValidate)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.MarshalWrite(w, response) // response is already committed
}

// parseActionRunRequest reads the run/suggest request: a JSON document, or a
// multipart form with the document in the request field and the uploads for
// the file params in file parts named after the param
func parseActionRunRequest(r *http.Request) (*types.ActionRunRequest, map[string]action.UploadedFile, error) {
	var req types.ActionRunRequest
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "multipart/form-data" {
		if err := json.UnmarshalRead(r.Body, &req); err != nil {
			return nil, nil, types.CreateRequestError("invalid request: "+err.Error(), http.StatusBadRequest)
		}
		return &req, nil, nil
	}

	if err := r.ParseMultipartForm(actionMultipartBytes); err != nil {
		return nil, nil, types.CreateRequestError("invalid multipart request: "+err.Error(), http.StatusBadRequest)
	}
	docs := r.MultipartForm.Value[actionRequestField]
	if len(docs) != 1 {
		return nil, nil, types.CreateRequestError("multipart request needs one "+actionRequestField+" field with the request document", http.StatusBadRequest)
	}
	if err := json.Unmarshal([]byte(docs[0]), &req); err != nil {
		return nil, nil, types.CreateRequestError("invalid request field: "+err.Error(), http.StatusBadRequest)
	}
	files := map[string]action.UploadedFile{}
	for name, headers := range r.MultipartForm.File {
		if len(headers) == 0 {
			continue
		}
		files[name] = uploadedFile(headers[0])
	}
	return &req, files, nil
}

func uploadedFile(fh *multipart.FileHeader) action.UploadedFile {
	return action.UploadedFile{
		Filename: fh.Filename,
		Open:     func() (io.ReadCloser, error) { return fh.Open() },
	}
}

func (h *Handler) listActions(r *http.Request) (any, error) {
	appPathGlob := r.URL.Query().Get("appPathGlob")
	updateTargetInContext(r, appPathGlob, false)
	return h.server.ListActions(r.Context(), appPathGlob)
}

func (h *Handler) getAction(r *http.Request) (any, error) {
	query := r.URL.Query()
	stage, err := parseBoolArg(query.Get("stage"), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, query.Get("appPath")+actionSelectorSep+query.Get("action"), false)
	return h.server.GetAction(r.Context(), query.Get("appPath"), query.Get("action"), stage)
}

func (h *Handler) actionsOpenAPI(r *http.Request) (any, error) {
	query := r.URL.Query()
	stage, err := parseBoolArg(query.Get("stage"), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, query.Get("appPath"), false)
	return h.server.ActionsOpenAPI(r.Context(), query.Get("appPath"), stage)
}

// actionFileResponse serves a result file of an action through the app router
type actionFileResponse struct {
	resolved *resolvedAction
	localURL string
}

func (a *actionFileResponse) writeResponse(w http.ResponseWriter, _ *http.Request) {
	a.resolved.app.ServeLocal(a.resolved.ctx, w, a.localURL)
}

// ActionFile returns the file at the url of a DOWNLOAD or IMAGE result row of
// an action, for callers which have no app session to fetch it with. The url
// is resolved as the action page would resolve it and has to be within the
// app; it is served by the app's own router as the calling user, who passed
// the same checks as for running the action: the app's rules for the url
// (the visibility and single access of fs.serve_tmp_file files) apply
func (s *Server) ActionFile(ctx context.Context, appPath, selector, fileURL string, stage bool) (*actionFileResponse, error) {
	resolved, err := s.resolveAction(ctx, appPath, selector, stage, true)
	if err != nil {
		return nil, err
	}
	localURL, external, err := resolved.action.ResolveResultURL(fileURL)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if external {
		return nil, types.CreateRequestError(fmt.Sprintf("url %s is not within app %s, fetch it directly", fileURL, appPath), http.StatusBadRequest)
	}
	localPath, _, _ := strings.Cut(localURL, "?")
	if mcp := resolved.app.Metadata.MCP; mcp != nil && inMCPRegion(path.Clean(localPath), appMCPRegion(resolved.app.Path, mcp)) {
		// The MCP region accepts only bearer credentials bound to the app,
		// it is not reachable through this route
		return nil, types.CreateRequestError(fmt.Sprintf("url %s is in the MCP endpoint of app %s", fileURL, appPath), http.StatusBadRequest)
	}
	return &actionFileResponse{resolved: resolved, localURL: localURL}, nil
}

func (h *Handler) actionFile(r *http.Request) (any, error) {
	query := r.URL.Query()
	stage, err := parseBoolArg(query.Get("stage"), false)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, query.Get("appPath")+actionSelectorSep+query.Get("action"), false)
	return h.server.ActionFile(r.Context(), query.Get("appPath"), query.Get("action"), query.Get("url"), stage)
}

func (h *Handler) invokeAction(r *http.Request, suggest bool) (any, error) {
	req, files, err := parseActionRunRequest(r)
	if err != nil {
		return nil, err
	}
	updateTargetInContext(r, req.AppPath+actionSelectorSep+req.Action, req.DryRun)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll() //nolint:errcheck
	}
	invocation, err := h.server.InvokeAction(r.Context(), req, suggest, action.SourceMgmt, files)
	if err != nil {
		return nil, err
	}
	return &actionResponse{invocation: invocation}, nil
}

func (h *Handler) runAction(r *http.Request) (any, error) {
	return h.invokeAction(r, false)
}

func (h *Handler) suggestAction(r *http.Request) (any, error) {
	return h.invokeAction(r, true)
}

// mcpInvokeAction is the run_action/suggest_action MCP tool: the result
// document of the action (status, report, values, param_errors). A stream
// result is consumed to completion and reported as its output tail and exit
// status. Param errors and failed commands are results, not tool failures:
// the caller can read them and correct the call
func (s *Server) mcpInvokeAction(ctx context.Context, appPath, selector string, stage, dryRun, suggest bool,
	args map[string]any) (any, error) {
	req := &types.ActionRunRequest{AppPath: appPath, Action: selector, Stage: stage, DryRun: dryRun}
	if len(args) > 0 {
		req.Args = make(map[string]jsontext.Value, len(args))
		for name, value := range args {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, types.CreateRequestError(fmt.Sprintf("invalid value for %s: %s", name, err), http.StatusBadRequest)
			}
			req.Args[name] = encoded
		}
	}
	invocation, err := s.InvokeAction(ctx, req, suggest, action.SourceMCP, nil)
	if err != nil {
		return nil, err
	}
	defer invocation.outcome.Close()
	doc, _, _ := invocation.action.ResultDocument(ctx, invocation.outcome, invocation.op, nil)
	return doc, nil
}
