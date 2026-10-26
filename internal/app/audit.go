// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"reflect"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func (a *App) Audit() (*types.ApproveResult, error) {
	buf, err := a.sourceFS.ReadFile(a.getStarPath(apptype.APP_FILE_NAME))
	if err != nil {
		return nil, fmt.Errorf("error reading %s file: %w", a.getStarPath(apptype.APP_FILE_NAME), err)
	}

	// Plugin loads are collected across all starlark files: statically from
	// app.star and via the audit loader for files loaded with .star loads.
	// Loads of app starlark files are not plugin loads and are not recorded
	loads := []string{}
	addLoad := func(module string) {
		if strings.HasSuffix(module, apptype.STARLARK_FILE_SUFFIX) {
			return
		}
		if !slices.Contains(loads, module) {
			loads = append(loads, module)
		}
	}

	starlarkCache := map[string]*starlarkCacheEntry{}
	auditLoader := func(thread *starlark.Thread, moduleFullPath string) (starlark.StringDict, error) {
		addLoad(moduleFullPath)

		if strings.HasSuffix(moduleFullPath, apptype.STARLARK_FILE_SUFFIX) {
			// Load the starlark file rather than the plugin
			return a.loadStarlark(thread, moduleFullPath, starlarkCache)
		}

		// The loader in audit mode is used to track the modules that are loaded.
		// A copy of the real loader's response is returned, with builtins replaced with dummy methods,
		// so that the audit can be run without any side effects

		modulePath, moduleName, _ := parseModulePath(moduleFullPath)

		pluginMap, err := a.pluginLookup(thread, modulePath)
		if err != nil {
			return nil, err
		}

		// Replace all the builtins with dummy methods
		dummyDict := make(starlark.StringDict)
		for name, pluginInfo := range pluginMap {
			if pluginInfo.HandlerName == "" {
				dummyDict[name] = pluginInfo.ConstantValue
			} else {
				dummyDict[name] = starlark.NewBuiltin(name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
					a.Info().Msgf("Plugin called during audit: %s.%s", modulePath, name)
					return starlarkstruct.FromStringDict(starlarkstruct.Default, make(starlark.StringDict)), nil
				})
			}
		}

		ret := make(starlark.StringDict)
		ret[moduleName] = starlarkstruct.FromStringDict(starlarkstruct.Default, dummyDict)

		return ret, nil
	}

	thread := &starlark.Thread{
		Name:  a.Path,
		Print: func(_ *starlark.Thread, msg string) { a.Info().Msg(msg) },
		Load:  auditLoader,
	}
	thread.SetLocal(types.TL_APP_URL, a.appUrl)

	err = a.loadSchemaInfo(a.sourceFS)
	if err != nil {
		return nil, err
	}

	err = a.loadParamsInfo(a.sourceFS)
	if err != nil {
		return nil, err
	}

	err = a.loadActionParamsInfo(a.sourceFS)
	if err != nil {
		return nil, err
	}

	builtin, err := a.createBuiltin()
	if err != nil {
		return nil, err
	}

	_, prog, err := starlark.SourceProgramOptions(AppFileOptions(), a.getStarPath(apptype.APP_FILE_NAME), buf, builtin.Has)
	if err != nil {
		return nil, fmt.Errorf("parsing source failed %v", err)
	}

	for i := 0; i < prog.NumLoads(); i++ {
		p, _ := prog.Load(i)
		addLoad(p)
	}

	// This runs the starlark script, with dummy plugin methods
	// The intent is to load the permissions from the app definition while trying
	// to avoid any potential side effects from script
	globals, err := prog.Init(thread, builtin)
	if err != nil {
		return nil, fmt.Errorf("source init failed: %v", err)
	}

	appDef, err := verifyConfig(globals)
	if err != nil {
		return nil, err
	}
	// actions.star runs on the audit thread too, so its plugin loads are
	// recorded and its permissions are part of the approval
	appDef, err = a.mergeActionsFile(thread, appDef, starlarkCache)
	if err != nil {
		return nil, err
	}

	name, err := apptype.GetStringAttr(appDef, "name")
	if err != nil {
		return nil, err
	}

	a.Metadata.Name = name
	if err := a.auditActionsMCP(appDef); err != nil {
		return nil, err
	}
	if err := a.auditActions(appDef); err != nil {
		return nil, err
	}
	return a.createApproveResponse(loads, appDef)
}

// auditActions applies the action definition checks of the app load
// (addAction) at audit time, so that app create and update fail instead of
// the first request: hidden names outside action_params.star, and a root
// action beside a root proxy route (which would conflict on the router)
func (a *App) auditActions(appDef *starlarkstruct.Struct) error {
	actions, err := appDef.Attr("actions")
	if err != nil || actions == nil {
		return nil
	}
	actionList, ok := actions.(*starlark.List)
	if !ok {
		return nil
	}
	rootProxy := false
	if routes, err := appDef.Attr("routes"); err == nil {
		if routeList, ok := routes.(*starlark.List); ok {
			iter := routeList.Iterate()
			var val starlark.Value
			for iter.Next(&val) {
				routeDef, ok := val.(*starlarkstruct.Struct)
				if !ok {
					continue
				}
				if _, err := routeDef.Attr("config"); err != nil {
					continue // not a proxy route
				}
				if p, err := apptype.GetStringAttr(routeDef, "path"); err == nil && p == "/" {
					rootProxy = true
				}
			}
			iter.Done()
		}
	}
	iter := actionList.Iterate()
	defer iter.Done()
	var val starlark.Value
	for iter.Next(&val) {
		actionDef, ok := val.(*starlarkstruct.Struct)
		if !ok {
			continue
		}
		name, _ := apptype.GetStringAttr(actionDef, "name")
		actionPath, _ := apptype.GetStringAttr(actionDef, "path")
		if !strings.HasPrefix(actionPath, "/") {
			actionPath = "/" + actionPath
		}
		if actionPath == "/" && rootProxy {
			return fmt.Errorf("action %s: a root action cannot share the app root with the proxy route at /, use a sub path", name)
		}
		hidden, err := apptype.GetListStringAttr(actionDef, "hidden", true)
		if err != nil {
			return err
		}
		if err := a.checkActionHidden(name, hidden); err != nil {
			return err
		}
	}
	return nil
}

// checkActionHidden verifies, when action_params.star sets the visible param
// set, that the hidden names of an action are in it: a name outside it is a
// stale reference (typically to a params.star param)
func (a *App) checkActionHidden(name string, hidden []string) error {
	if a.actionParamInfo == nil {
		return nil
	}
	for _, h := range hidden {
		if _, ok := a.actionParamInfo[h]; !ok {
			return fmt.Errorf("action %s: hidden param %s is not defined in %s", name, h, apptype.ACTION_PARAMS_FILE_NAME)
		}
	}
	return nil
}

// auditActionsMCP checks, for an app with mcp source "actions", that the app
// definition has actions and that none of them sits at the MCP endpoint path.
// The same rules are enforced when the app is loaded (mountActionsMCP); the
// check here makes app create and update fail instead of the first request
func (a *App) auditActionsMCP(appDef *starlarkstruct.Struct) error {
	mcp := a.Metadata.MCP
	if !mcp.ServesActions() {
		return nil
	}
	count := 0
	if actions, err := appDef.Attr("actions"); err == nil && actions != nil {
		if actionList, ok := actions.(*starlark.List); ok {
			iter := actionList.Iterate()
			defer iter.Done()
			var val starlark.Value
			for iter.Next(&val) {
				count++
				actionDef, ok := val.(*starlarkstruct.Struct)
				if !ok {
					continue
				}
				actionPath, err := apptype.GetStringAttr(actionDef, "path")
				if err != nil {
					continue
				}
				if !strings.HasPrefix(actionPath, "/") {
					actionPath = "/" + actionPath
				}
				if actionPath == mcp.Path || strings.HasPrefix(actionPath, mcp.Path+"/") {
					return fmt.Errorf("action path %s is not allowed, %s is the MCP endpoint of the app", actionPath, mcp.Path)
				}
			}
		}
	}
	if count == 0 {
		return fmt.Errorf("mcp source %s needs the app to define actions", types.MCPSourceActions)
	}
	return nil
}

func needsApproval(a *types.ApproveResult) bool {
	// Loads are a set (reordering the load statements in app.star is not a
	// change which needs a new approval). Permissions are compared in their
	// declared order: checkPermissions uses the first matching entry, so with
	// overlapping entries the order changes what is enforced (which is_read
	// value or secrets apply to a call) and a reorder needs a new approval
	if !slices.Equal(slices.Sorted(slices.Values(a.NewLoads)), slices.Sorted(slices.Values(a.ApprovedLoads))) {
		return true
	}

	permEquals := func(a, b types.Permission) bool {
		if a.Plugin != b.Plugin || a.Method != b.Method {
			return false
		}

		if a.IsRead == nil && b.IsRead != nil || a.IsRead != nil && b.IsRead == nil {
			return false
		}

		if a.IsRead != nil && b.IsRead != nil && *a.IsRead != *b.IsRead {
			return false
		}

		if !slices.Equal(a.Arguments, b.Arguments) {
			return false
		}

		if !slices.Equal(a.Permit, b.Permit) {
			return false
		}

		if !reflect.DeepEqual(a.Secrets, b.Secrets) {
			return false
		}

		return true
	}

	return !slices.EqualFunc(a.NewPermissions, a.ApprovedPermissions, permEquals)
}

// needsApprovalWithServerConfig re-evaluates whether approval is needed after accounting
// for loads and permissions that are already covered by the server config.
func needsApprovalWithServerConfig(a *types.ApproveResult, serverPerms []types.Permission) bool {
	serverPlugins := make(map[string]bool)
	for _, sp := range serverPerms {
		serverPlugins[sp.Plugin] = true
	}

	// Filter new loads: remove any that are covered by server config or already approved
	approvedSet := make(map[string]bool)
	for _, l := range a.ApprovedLoads {
		approvedSet[l] = true
	}
	for _, l := range a.NewLoads {
		if !approvedSet[l] && !serverPlugins[l] {
			return true
		}
	}

	// Filter new permissions: remove any that are covered by server config or already approved
	for _, p := range a.NewPermissions {
		if permissionCoveredByServerConfig(p, serverPerms) {
			continue
		}
		// Check if it's in the approved list
		found := false
		for _, ap := range a.ApprovedPermissions {
			if ap.Plugin == p.Plugin && ap.Method == p.Method &&
				slices.Equal(ap.Arguments, p.Arguments) &&
				slices.Equal(ap.Permit, p.Permit) &&
				reflect.DeepEqual(ap.Secrets, p.Secrets) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	return false
}

// patternCovers reports whether a permission pattern (the server config's or
// an approved entry's method or argument, exact or regex:) covers a pattern
// declared by the app. A plain declared value is covered when the pattern
// matches it the way the runtime check matches a call. A declared regex: is
// never matched as text, since a regex matching the text of another regex
// says nothing about the values the two accept (regex:get|head matches the
// text of regex:get|post although it does not permit post): it is covered
// only by the identical pattern or by a pattern proven to accept every value
func patternCovers(pattern, declared string) bool {
	if pattern == declared {
		return true
	}
	if strings.HasPrefix(declared, types.REGEX_PREFIX) {
		return regexUniversal(pattern)
	}
	match, err := types.RegexMatch(pattern, declared)
	return err == nil && match
}

// regexUniversal reports whether a regex: pattern accepts every value under
// the unanchored match the runtime uses. Without empty-width assertions
// (^, $, \b and the like) a pattern that matches the empty string matches a
// substring of every input, and a pattern that matches every input matches
// the empty one, so the two are the same. With assertions the shortcut does
// not hold (^(get|head)?$ matches the empty string but not post), so such a
// pattern is never taken as universal
func regexUniversal(pattern string) bool {
	if !strings.HasPrefix(pattern, types.REGEX_PREFIX) {
		return false
	}
	expr := pattern[len(types.REGEX_PREFIX):]
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil || hasEmptyWidthOp(re) {
		return false
	}
	match, err := types.RegexMatch(pattern, "")
	return err == nil && match
}

func hasEmptyWidthOp(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	return slices.ContainsFunc(re.Sub, hasEmptyWidthOp)
}

// permissionCoveredByServerConfig checks if a permission declared by an app is already
// covered by a server config permission entry. Server config permissions can use regex
// for arguments, so this does regex-aware matching.
func permissionCoveredByServerConfig(perm types.Permission, serverPerms []types.Permission) bool {
	for _, sp := range serverPerms {
		if sp.Plugin != perm.Plugin {
			continue
		}
		if !patternCovers(sp.Method, perm.Method) {
			continue
		}

		if len(sp.Arguments) == 0 {
			if !slices.Equal(sp.Permit, perm.Permit) {
				continue
			}
			return true
		}

		if len(sp.Arguments) > len(perm.Arguments) {
			continue
		}

		argMatch := true
		for i, serverArg := range sp.Arguments {
			if !patternCovers(serverArg, perm.Arguments[i]) {
				argMatch = false
				break
			}
		}

		if argMatch {
			if !slices.Equal(sp.Permit, perm.Permit) {
				continue
			}
			return true
		}
	}
	return false
}

func (a *App) createApproveResponse(loads []string, appDef *starlarkstruct.Struct) (*types.ApproveResult, error) {
	// the App entry should not get updated during the audit call, since there
	// can be audit calls when the app is running.
	var err error
	perms := []types.Permission{}
	results := types.ApproveResult{
		AppPathDomain:       a.AppPathDomain(),
		MainAppPath:         a.mainAppPath(),
		Id:                  a.Id,
		NewLoads:            loads,
		NewPermissions:      perms,
		ApprovedLoads:       a.Metadata.Loads,
		ApprovedPermissions: a.Metadata.Permissions,
	}
	permissions, err := appDef.Attr("permissions")
	if err != nil {
		a.setApprovalState(&results)
		return &results, nil
	}

	var ok bool
	var permList *starlark.List
	if permList, ok = permissions.(*starlark.List); !ok {
		return nil, fmt.Errorf("permissions is not a list")
	}
	iter := permList.Iterate()
	var val starlark.Value
	count := -1
	for iter.Next(&val) {
		count++
		var permStruct *starlarkstruct.Struct
		if permStruct, ok = val.(*starlarkstruct.Struct); !ok {
			return nil, fmt.Errorf("permissions entry %d is not a struct", count)
		}
		var pluginStr, methodStr string
		var args, permit []string
		var secrets [][]string
		if pluginStr, err = apptype.GetStringAttr(permStruct, "plugin"); err != nil {
			return nil, err
		}
		if methodStr, err = apptype.GetStringAttr(permStruct, "method"); err != nil {
			return nil, err
		}
		if args, err = apptype.GetListStringAttr(permStruct, "arguments", true); err != nil {
			return nil, err
		}
		if secrets, err = apptype.GetListListStringAttr(permStruct, "secrets", true); err != nil {
			return nil, err
		}
		if permit, err = apptype.GetListStringAttr(permStruct, "permit", true); err != nil {
			return nil, err
		}

		perm := types.Permission{
			Plugin:    pluginStr,
			Method:    methodStr,
			Arguments: args,
			Permit:    permit,
			Secrets:   secrets,
		}

		if slices.Contains(permStruct.AttrNames(), "is_read") {
			isRead, err := apptype.GetBoolAttr(permStruct, "is_read")
			if err != nil {
				return nil, err
			}
			perm.IsRead = &isRead
		}

		perms = append(perms, perm)

	}
	results.NewPermissions = perms
	a.setApprovalState(&results)
	return &results, nil
}

// setApprovalState fills in the audit verdict: Changed when the declared
// loads/permissions differ from the approved ones (permission order needs to
// match for now), NeedsApproval when the difference is not allowed by the
// server config either, and UngrantedSecrets for the declared secret access
// the app would not have at runtime
func (a *App) setApprovalState(results *types.ApproveResult) {
	serverPerms := a.serverConfig.Permissions.Allow
	results.Changed = needsApproval(results)
	results.NeedsApproval = results.Changed
	if results.NeedsApproval && len(serverPerms) > 0 {
		results.NeedsApproval = needsApprovalWithServerConfig(results, serverPerms)
	}
	results.UngrantedSecrets = ungrantedSecrets(results.NewPermissions, results.ApprovedPermissions, serverPerms)
}

// ungrantedSecrets returns the declared permissions asking for secrets the
// app cannot resolve at runtime. The secrets a plugin call may use are the
// union of the secrets on the app's approved permissions and on the server
// config entries for the same plugin method (see allowedSecrets), so a
// declared secret pattern is granted when one of those patterns covers it.
// The server config allowing the plugin call does not by itself grant the
// secrets: an app whose only uncovered request is its secrets deploys without
// approval, with the secrets unresolved until it is approved
func ungrantedSecrets(declared, approved, serverPerms []types.Permission) []types.Permission {
	var ret []types.Permission
	for _, p := range declared {
		if len(p.Secrets) == 0 {
			continue
		}
		allowed := allowedSecrets(p.Plugin, p.Method, approved, serverPerms)
		if !secretsCovered(p.Secrets, allowed) {
			ret = append(ret, p)
		}
	}
	return ret
}

// allowedSecrets returns the secret patterns the given plugin method may
// resolve: the union over the permission lists of the secrets on the entries
// for that plugin method. This is the runtime allowlist, so the audit's
// view of granted secrets is the one enforcement uses
func allowedSecrets(plugin, method string, permLists ...[]types.Permission) [][]string {
	ret := [][]string{}
	for _, perms := range permLists {
		for _, p := range perms {
			if p.Plugin != plugin {
				continue
			}
			if patternCovers(p.Method, method) {
				ret = append(ret, p.Secrets...)
			}
		}
	}
	return ret
}

// secretsCovered reports whether every requested secret (a pattern an app
// declares, or a key list a call resolved) is matched by an allowed one. An
// allowed pattern is matched against a requested one the way the runtime
// check matches a secret name (patternCovers per entry, the allowed entries
// as a prefix of the requested ones, never longer), so an allowed regex:.*
// covers any request while a requested regex is covered only by the same
// regex or by a universal one
func secretsCovered(requested, allowed [][]string) bool {
	for _, req := range requested {
		if !slices.ContainsFunc(allowed, func(a []string) bool { return secretPatternCovers(a, req) }) {
			return false
		}
	}
	return true
}

func secretPatternCovers(allowed, requested []string) bool {
	if len(requested) == 0 || len(allowed) > len(requested) {
		return false
	}
	for i, entry := range requested {
		if i >= len(allowed) {
			continue
		}
		if !patternCovers(allowed[i], entry) {
			return false
		}
	}
	return true
}
