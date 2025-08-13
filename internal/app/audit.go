// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"reflect"
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

	starlarkCache := map[string]*starlarkCacheEntry{}
	auditLoader := func(thread *starlark.Thread, moduleFullPath string) (starlark.StringDict, error) {

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
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) }, // TODO use logger
		Load:  auditLoader,
	}

	err = a.loadSchemaInfo(a.sourceFS)
	if err != nil {
		return nil, err
	}

	err = a.loadParamsInfo(a.sourceFS)
	if err != nil {
		return nil, err
	}

	builtin, err := a.createBuiltin()
	if err != nil {
		return nil, err
	}

	_, prog, err := starlark.SourceProgram(a.getStarPath(apptype.APP_FILE_NAME), buf, builtin.Has)
	if err != nil {
		return nil, fmt.Errorf("parsing source failed %v", err)
	}

	loads := []string{}
	for i := 0; i < prog.NumLoads(); i++ {
		p, _ := prog.Load(i)
		if !slices.Contains(loads, p) {
			loads = append(loads, p)
		}
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

	name, err := apptype.GetStringAttr(appDef, "name")
	if err != nil {
		return nil, err
	}

	a.Metadata.Name = name
	return a.createApproveResponse(loads, globals)
}

func needsApproval(a *types.ApproveResult) bool {
	if !slices.Equal(a.NewLoads, a.ApprovedLoads) {
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

		if !reflect.DeepEqual(a.Secrets, b.Secrets) {
			return false
		}

		return true
	}

	//TODO: sort slices before checking equality
	return !slices.EqualFunc(a.NewPermissions, a.ApprovedPermissions, permEquals)
}

func (a *App) createApproveResponse(loads []string, globals starlark.StringDict) (*types.ApproveResult, error) {
	// the App entry should not get updated during the audit call, since there
	// can be audit calls when the app is running.
	appDef, err := verifyConfig(globals)
	if err != nil {
		return nil, err
	}

	perms := []types.Permission{}
	results := types.ApproveResult{
		AppPathDomain:       a.AppEntry.AppPathDomain(),
		Id:                  a.Id,
		NewLoads:            loads,
		NewPermissions:      perms,
		ApprovedLoads:       a.Metadata.Loads,
		ApprovedPermissions: a.Metadata.Permissions,
	}
	permissions, err := appDef.Attr("permissions")
	if err != nil {
		// permission order needs to match for now
		results.NeedsApproval = needsApproval(&results)
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
		var args []string
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

		perm := types.Permission{
			Plugin:    pluginStr,
			Method:    methodStr,
			Arguments: args,
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
	results.NeedsApproval = needsApproval(&results)
	return &results, nil
}
