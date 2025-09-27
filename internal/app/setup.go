// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/dev"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func (a *App) loadStarlarkConfig(dryRun types.DryRun) error {
	a.Info().Str("path", a.Path).Str("domain", a.Domain).Msg("Loading app")

	buf, err := a.sourceFS.ReadFile(a.getStarPath(apptype.APP_FILE_NAME))
	if err != nil {
		return fmt.Errorf("error reading %s: %w", a.getStarPath(apptype.APP_FILE_NAME), err)
	}

	thread := &starlark.Thread{
		Name:  a.Path,
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) }, // TODO use logger
		Load:  a.loader,
	}
	thread.SetLocal(types.TL_APP_URL, types.GetAppUrl(a.AppPathDomain(), a.serverConfig))

	builtin, err := a.createBuiltin()
	if err != nil {
		return err
	}

	a.globals, err = starlark.ExecFileOptions(AppFileOptions(), thread, a.getStarPath(apptype.APP_FILE_NAME), buf, builtin)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			a.Error().Err(err).Str("trace", evalErr.Backtrace()).Msg("Error loading app")
		} else {
			a.Error().Err(err).Msg("Error loading app")
		}
		return err
	}

	a.appDef, err = verifyConfig(a.globals)
	if err != nil {
		return err
	}

	a.Name, err = apptype.GetStringAttr(a.appDef, "name")
	if err != nil {
		return err
	}
	a.CustomLayout, err = apptype.GetBoolAttr(a.appDef, "custom_layout")
	if err != nil {
		return err
	}
	a.staticOnly, err = apptype.GetBoolAttr(a.appDef, "static_only")
	if err != nil {
		return err
	}
	a.redirectBarePath, err = apptype.GetBoolAttr(a.appDef, "redirect_bare_path")
	if err != nil {
		return err
	}

	a.jsLibs, err = a.loadLibraryInfo()
	if err != nil {
		return err
	}

	if a.IsDev {
		a.appDev.CustomLayout = a.CustomLayout
		a.appDev.JsLibs = a.jsLibs
	}

	var settingsMap map[string]interface{}
	settings, err := a.appDef.Attr("settings")
	if err == nil {
		var dict *starlark.Dict
		var ok bool
		if dict, ok = settings.(*starlark.Dict); !ok {
			return errors.New("settings is not a starlark dict")
		}
		var converted any
		if converted, err = starlark_type.UnmarshalStarlark(dict); err != nil {
			return err
		}
		if settingsMap, ok = converted.(map[string]interface{}); !ok {
			return errors.New("settings is not a map")
		}
	} else {
		settingsMap = make(map[string]interface{})
	}

	// Update the app config with entries loaded from the settings map
	var jsonBuf bytes.Buffer
	if err = json.NewEncoder(&jsonBuf).Encode(settingsMap); err != nil {
		return err
	}
	if err = json.Unmarshal(jsonBuf.Bytes(), a.codeConfig); err != nil {
		return err
	}

	var stripAppPath bool
	if stripAppPath, err = a.checkAppPathStripping(); err != nil {
		return err
	}

	// Load container config. The proxy config in routes depends on this being loaded first
	if err = a.loadContainerManager(stripAppPath); err != nil {
		return err
	}

	if a.containerManager != nil {
		// Container manager is present, reload the container
		if a.IsDev {
			if err = a.containerManager.DevReload(bool(dryRun)); err != nil {
				return err
			}
		} else {
			if err := a.containerManager.ProdReload(bool(dryRun)); err != nil {
				return err
			}
		}
	}

	// Initialize the router configuration
	err = a.initRouter()
	if err != nil {
		return err
	}

	return nil
}

func (a *App) createBuiltin() (starlark.StringDict, error) {
	builtin := apptype.CreateBuiltin(a.serverConfig.NodeConfig, a.systemConfig.AllowedEnv)
	if builtin == nil {
		return nil, errors.New("error creating builtin")
	}

	var err error
	if builtin, err = a.addSchemaTypes(builtin); err != nil {
		return nil, err
	}

	if builtin, err = a.addParams(builtin); err != nil {
		return nil, err
	}

	return builtin, nil
}

func (a *App) addSchemaTypes(builtin starlark.StringDict) (starlark.StringDict, error) {
	if a.storeInfo == nil || len(a.storeInfo.Types) == 0 {
		return builtin, nil
	}

	// Create a copy of the builtins, don't modify the original
	newBuiltins := starlark.StringDict{}
	for k, v := range builtin {
		newBuiltins[k] = v
	}

	// Add type module for referencing type names
	typeDict := starlark.StringDict{}
	for _, t := range a.storeInfo.Types {
		tb := starlark_type.TypeBuilder{Name: t.Name, Fields: t.Fields}
		typeDict[t.Name] = starlark.NewBuiltin(t.Name, tb.CreateType)
	}

	docModule := starlarkstruct.Module{
		Name:    apptype.DOC_MODULE,
		Members: typeDict,
	}
	newBuiltins[apptype.DOC_MODULE] = &docModule

	// Add table module for referencing table names
	tableDict := starlark.StringDict{}
	for _, t := range a.storeInfo.Types {
		tableDict[t.Name] = starlark.String(t.Name)
	}

	tableModule := starlarkstruct.Module{
		Name:    apptype.TABLE_MODULE,
		Members: tableDict,
	}
	newBuiltins[apptype.TABLE_MODULE] = &tableModule

	return newBuiltins, nil
}

func (a *App) addParams(builtin starlark.StringDict) (starlark.StringDict, error) {
	a.paramValuesStr = make(map[string]string)

	// Create a copy of the builtins, don't modify the original
	newBuiltins := starlark.StringDict{}
	for k, v := range builtin {
		newBuiltins[k] = v
	}

	// Add param module for referencing param values
	a.paramDict = starlark.StringDict{}
	for _, p := range a.paramInfo {
		a.paramDict[p.Name] = p.DefaultValue

		if p.DefaultValue != starlark.None {
			switch p.Type {
			// Set the default value in the paramMap (in the string format)
			case starlark_type.STRING:
				a.paramValuesStr[p.Name] = string(p.DefaultValue.(starlark.String))
			case starlark_type.INT:
				intVal, ok := p.DefaultValue.(starlark.Int).Int64()
				if !ok {
					return nil, fmt.Errorf("param %s is not an int", p.Name)
				}
				a.paramValuesStr[p.Name] = fmt.Sprintf("%d", intVal)
			case starlark_type.BOOLEAN:
				a.paramValuesStr[p.Name] = strconv.FormatBool(bool(p.DefaultValue.(starlark.Bool)))
			case starlark_type.DICT, starlark_type.LIST:
				val, err := starlark_type.UnmarshalStarlark(p.DefaultValue)
				if err != nil {
					return nil, err
				}
				jsonVal, err := json.Marshal(val)
				if err != nil {
					return nil, err
				}
				a.paramValuesStr[p.Name] = string(jsonVal)
			}
		}

		valueStr, ok := a.Metadata.ParamValues[p.Name]
		if !ok {
			// no custom value specified
			if p.Required && p.DefaultValue == starlark.None {
				return nil, fmt.Errorf("param %s is a required param, a value has to be provided", p.Name)
			}
			continue
		}

		a.paramValuesStr[p.Name] = valueStr
		value, err := apptype.ParamStringToType(p.Name, p.Type, valueStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing param %s: %w", p.Name, err)
		}
		a.paramDict[p.Name] = value

		if p.Type == starlark_type.STRING && p.Required && valueStr == "" {
			return nil, fmt.Errorf("param %s is a required param, value cannot be empty", p.Name)
		}
	}

	paramModule := starlarkstruct.Module{
		Name:    apptype.PARAM_MODULE,
		Members: a.paramDict,
	}

	newBuiltins[apptype.PARAM_MODULE] = &paramModule

	for k, v := range a.Metadata.ParamValues {
		if _, ok := a.paramDict[k]; !ok {
			a.paramValuesStr[k] = v // add additional param values to paramMap
		}
	}
	return newBuiltins, nil
}

func verifyConfig(globals starlark.StringDict) (*starlarkstruct.Struct, error) {
	if !globals.Has(apptype.APP_CONFIG_KEY) {
		return nil, fmt.Errorf("%s not defined, check %s, add '%s = ace.app(...)'", apptype.APP_CONFIG_KEY, apptype.APP_FILE_NAME, apptype.APP_CONFIG_KEY)
	}
	appDef, ok := globals[apptype.APP_CONFIG_KEY].(*starlarkstruct.Struct)
	if !ok {
		return nil, fmt.Errorf("%s not of type ace.app in %s", apptype.APP_CONFIG_KEY, apptype.APP_FILE_NAME)
	}
	return appDef, nil
}

// checkAppPathStripping checks if the app path should be stripped from the request path for container proxying
// This is required for container health checks.
func (a *App) checkAppPathStripping() (bool, error) {
	appPathStripping := true
	// Iterate through all the routes
	routes, err := a.appDef.Attr("routes")
	if err != nil {
		return false, err
	}

	var ok bool
	var routeList *starlark.List
	if routeList, ok = routes.(*starlark.List); !ok {
		return false, fmt.Errorf("routes is not a list")
	}

	iter := routeList.Iterate()
	var val starlark.Value
	var count int

	for iter.Next(&val) {
		count += 1
		var pageDef *starlarkstruct.Struct
		if pageDef, ok = val.(*starlarkstruct.Struct); !ok {
			return false, fmt.Errorf("routes entry %d is not a struct", count)
		}

		_, err := pageDef.Attr("config")
		if err == nil {
			// "config" is defined, this must be a proxy config instead of a page definition
			var configAttr starlark.HasAttrs
			if configAttr, err = getProxyConfig(count, pageDef); err != nil {
				return false, err
			}

			var urlValue starlark.Value
			if urlValue, err = configAttr.Attr("url"); err != nil {
				return false, err
			}

			if urlValue.(starlark.String).GoString() != apptype.CONTAINER_URL {
				// Not proxying to container url, ignore
				continue
			}

			var stripAppValue starlark.Value
			if stripAppValue, err = configAttr.Attr("strip_app"); err != nil {
				return false, err
			}

			return bool(stripAppValue.(starlark.Bool)), nil
		}
	}

	return appPathStripping, nil
}

func fileExists(fs appfs.ReadableFS, name string) bool {
	_, err := fs.Stat(name)
	return err == nil
}

func (a *App) initRouter() error {
	var defaultHandler starlark.Callable
	if a.globals.Has(apptype.DEFAULT_HANDLER) {
		var ok bool
		defaultHandler, ok = a.globals[apptype.DEFAULT_HANDLER].(starlark.Callable)
		if !ok {
			return fmt.Errorf("%s is not a function", apptype.DEFAULT_HANDLER)
		}
	}

	if a.globals.Has(apptype.ERROR_HANDLER) {
		var ok bool
		a.errorHandler, ok = a.globals[apptype.ERROR_HANDLER].(starlark.Callable)
		if !ok {
			return fmt.Errorf("%s is not a function", apptype.ERROR_HANDLER)
		}
	}

	router := chi.NewRouter()
	if err := a.createInternalRoutes(router); err != nil {
		return err
	}

	// Iterate through all the routes
	routes, err := a.appDef.Attr("routes")
	if err != nil {
		return err
	}

	var ok bool
	var routeList *starlark.List
	if routeList, ok = routes.(*starlark.List); !ok {
		return fmt.Errorf("routes is not a list")
	}
	iter := routeList.Iterate()
	var val starlark.Value
	count := 0
	rootWildcard := false
	for iter.Next(&val) {
		count++

		var rootWildcardSet bool
		if rootWildcardSet, err = a.addRoute(count, router, val, defaultHandler); err != nil {
			return err
		}

		if rootWildcardSet {
			rootWildcard = true // Root wildcard path, static files are not served
		}
	}

	if a.staticOnly && rootWildcard {
		return fmt.Errorf("static_only app cannot have root level wildcard path for proxy")
	}

	if a.staticOnly {
		singleFile, err := apptype.GetBoolAttr(a.appDef, "single_file")
		if err != nil {
			return err
		}

		indexPage, err := apptype.GetStringAttr(a.appDef, "index")
		if err != nil {
			return err
		}

		if indexPage == "" {
			if fileExists(a.sourceFS, "index.html") {
				indexPage = "index.html"
			} else if fileExists(a.sourceFS, "index.htm") {
				indexPage = "index.htm"
			}
		}

		if singleFile && indexPage == "" {
			return fmt.Errorf("single_file static app must have index_page attribute set")
		}

		staticPattern := path.Join("/", "*")
		if singleFile {
			// Single file app
			router.Handle(staticPattern, http.StripPrefix(a.Path, appfs.FileServerSingle(a.sourceFS, indexPage)))
		} else {
			// All app files are served at the root level
			router.Handle(staticPattern, http.StripPrefix(a.Path, appfs.FileServer(a.sourceFS, indexPage)))
		}
	} else {
		// Mount static dir
		if !rootWildcard {
			staticPattern := path.Join("/", "static", "*")
			router.Handle(staticPattern, http.StripPrefix(a.Path, appfs.FileServer(a.sourceFS, "")))
		}

		err = a.addStaticRoot(router)
		if err != nil {
			return fmt.Errorf("error adding static root : %w ", err)
		}
	}

	err = a.initActions(router)
	if err != nil {
		return err
	}

	a.appRouter = chi.NewRouter()
	a.Trace().Msgf("Mounting app %s at %s", a.Name, a.Path)
	a.appRouter.Mount(a.Path, router)

	return nil
}

func (a *App) initActions(router *chi.Mux) error {
	actions, err := a.appDef.Attr("actions")
	if err != nil {
		return err
	}

	a.actions = make([]*action.Action, 0)
	if actions == nil {
		return nil
	}

	var ok bool
	var actionList *starlark.List
	if actionList, ok = actions.(*starlark.List); !ok {
		return fmt.Errorf("actions is not a list")
	}

	iter := actionList.Iterate()
	var val starlark.Value
	count := 0
	for iter.Next(&val) {
		count++

		if err = a.addAction(count, val, router); err != nil {
			return err
		}
	}

	// Set the links for all actions
	allLinks := make([]action.ActionLink, 0, len(a.actions))
	for _, action := range a.actions {
		allLinks = append(allLinks, action.GetLink())
	}
	for _, action := range a.actions {
		action.Links = allLinks
	}

	return nil
}

func (a *App) addAction(count int, val starlark.Value, router *chi.Mux) (err error) {
	var ok bool
	var actionDef *starlarkstruct.Struct

	if actionDef, ok = val.(*starlarkstruct.Struct); !ok {
		return fmt.Errorf("actions entry %d is not a struct", count)
	}

	var name, path, description string
	var run, suggest starlark.Callable
	var hidden, permit []string
	var showValidate bool
	if name, err = apptype.GetStringAttr(actionDef, "name"); err != nil {
		return err
	}
	if path, err = apptype.GetStringAttr(actionDef, "path"); err != nil {
		return err
	}
	if description, err = apptype.GetStringAttr(actionDef, "description"); err != nil {
		return err
	}
	if run, err = apptype.GetCallableAttr(actionDef, "run"); err != nil {
		return err
	}
	if hidden, err = apptype.GetListStringAttr(actionDef, "hidden", true); err != nil {
		return err
	}

	if permit, err = apptype.GetListStringAttr(actionDef, "permit", true); err != nil {
		return err
	}

	if showValidate, err = apptype.GetBoolAttr(actionDef, "show_validate"); err != nil {
		return err
	}
	sa, _ := actionDef.Attr("suggest")
	if sa != nil {
		if suggest, err = apptype.GetCallableAttr(actionDef, "suggest"); err != nil {
			return err
		}
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	containerProxyUrl := ""
	if a.containerManager != nil {
		containerProxyUrl = a.containerManager.GetProxyUrl()
	}
	action, err := action.NewAction(a.Logger, a.sourceFS, a.IsDev, name, description, path, run, suggest,
		slices.Collect(maps.Values(a.paramInfo)), a.paramValuesStr, a.paramDict, a.Path, a.appStyle.GetStyleType(),
		containerProxyUrl, hidden, showValidate, a.auditInsert, a.containerManager, a.jsLibs, a.AppPathDomain(), a.serverConfig, permit, a.authorizer)
	if err != nil {
		return fmt.Errorf("error creating action %s: %w", name, err)
	}

	r, err := action.BuildRouter()
	if err != nil {
		return fmt.Errorf("error building router for action %s: %w", name, err)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error adding action at path %s: %v", path, r)
		}
	}()
	router.Mount(path, r)
	a.actions = append(a.actions, action)
	return nil
}

// addStaticRoot adds the static root directory contents to the router
// Files can be referenced by /<filename>, without /static or /static_root
func (a *App) addStaticRoot(router *chi.Mux) error {
	staticFiles := a.sourceFS.StaticFiles()
	for _, rootFile := range staticFiles {
		if !strings.HasPrefix(rootFile, "static_root/") {
			continue
		}
		rootFile := rootFile
		fileName := rootFile[len("static_root/"):]
		router.Get("/"+fileName, func(w http.ResponseWriter, r *http.Request) {
			f, err := a.sourceFS.Open(rootFile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			seeker, ok := f.(io.ReadSeeker)
			if !ok {
				http.Error(w, "500 Filesystem does not implement Seek interface", http.StatusInternalServerError)
				return
			}

			fi, err := f.Stat()
			if err != nil {
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			} else if fi.IsDir() {
				http.Error(w, "Directory not supported in static root", http.StatusInternalServerError)
				return
			}

			http.ServeContent(w, r, fileName, fi.ModTime(), seeker)
		})

	}
	return nil
}

func (a *App) addRoute(count int, router *chi.Mux, routeVal starlark.Value, defaultHandler starlark.Callable) (bool, error) {
	var ok bool
	var err error
	var pageDef *starlarkstruct.Struct
	rootWildcard := false

	if pageDef, ok = routeVal.(*starlarkstruct.Struct); !ok {
		return rootWildcard, fmt.Errorf("routes entry %d is not a struct", count)
	}

	var pathStr, htmlFile, blockStr, methodStr string
	_, err = pageDef.Attr("config")
	if err == nil {
		// "config" is defined, this must be a proxy config instead of a page definition
		return a.addProxyConfig(count, router, pageDef)
	}

	_, err = pageDef.Attr("full")
	if err != nil {
		// "full" is not defined, this must be a API route instead of a html route
		return rootWildcard, a.addAPIRoute("", router, pageDef, defaultHandler)
	}

	if pathStr, err = apptype.GetStringAttr(pageDef, "path"); err != nil {
		return rootWildcard, err
	}
	if methodStr, err = apptype.GetStringAttr(pageDef, "method"); err != nil {
		return rootWildcard, err
	}
	if htmlFile, err = apptype.GetStringAttr(pageDef, "full"); err != nil {
		return rootWildcard, err
	}
	if blockStr, err = apptype.GetStringAttr(pageDef, "partial"); err != nil {
		return rootWildcard, err
	}

	if a.staticOnly {
		return rootWildcard, fmt.Errorf("static_only app cannot have HTML routes")
	}

	a.usesHtmlTemplate = true
	if htmlFile == "" {
		if a.CustomLayout {
			htmlFile = apptype.INDEX_FILE
		} else {
			htmlFile = apptype.INDEX_GEN_FILE
		}
	}

	handler := defaultHandler // Use app level default handler, which could also be nil
	handlerAttr, _ := pageDef.Attr("handler")
	if handlerAttr != nil {
		if handler, ok = handlerAttr.(starlark.Callable); !ok {
			return rootWildcard, fmt.Errorf("handler for page %s is not a function", pathStr)
		}
	}

	handlerFunc := a.createHandlerFunc(htmlFile, blockStr, handler, apptype.HTML_TYPE)
	if err = a.handleFragments(router, pathStr, count, htmlFile, blockStr, pageDef, handler); err != nil {
		return rootWildcard, err
	}
	a.Trace().Msgf("Adding page route %s <%s>", methodStr, pathStr)
	router.Method(methodStr, pathStr, handlerFunc)
	return rootWildcard, nil
}

// getProxyConfig extracts the proxy config from the proxy definition
func getProxyConfig(count int, proxyDef *starlarkstruct.Struct) (starlark.HasAttrs, error) {
	var err error
	var pathStr string

	if pathStr, err = apptype.GetStringAttr(proxyDef, "path"); err != nil {
		return nil, err
	}

	var ok bool
	var responseAttr starlark.HasAttrs
	pluginResponse, err := proxyDef.Attr("config")
	if err != nil {
		return nil, err
	}
	if responseAttr, ok = pluginResponse.(starlark.HasAttrs); !ok {
		return nil, fmt.Errorf("proxy entry %d:%s is not a proxy response", count, pathStr)
	}

	errorValue, err := responseAttr.Attr("error")
	if err != nil {
		return nil, fmt.Errorf("error in proxy config: %w", err)
	}

	if errorValue != nil && errorValue != starlark.None {
		var errorString starlark.String
		if errorString, ok = errorValue.(starlark.String); !ok {
			return nil, fmt.Errorf("error in proxy config: %w", err)
		}

		if errorString.GoString() != "" {
			return nil, fmt.Errorf("error in proxy config: %s", errorString.GoString())
		}
	}

	config, err := responseAttr.Attr("value")
	if err != nil {
		return nil, err
	}

	/*
		if config.String() != "ProxyConfig" {
			return nil, fmt.Errorf("proxy entry %d:%s is not a proxy config", count, pathStr)
		}*/

	var configAttr starlark.HasAttrs
	if configAttr, ok = config.(starlark.HasAttrs); !ok {
		return nil, fmt.Errorf("proxy entry %d:%s is not a proxy config attr", count, pathStr)
	}

	return configAttr, nil
}

func (a *App) addProxyConfig(count int, router *chi.Mux, proxyDef *starlarkstruct.Struct) (bool, error) {
	var err error
	var pathStr string
	rootWildcard := false

	if pathStr, err = apptype.GetStringAttr(proxyDef, "path"); err != nil {
		return rootWildcard, err
	}

	if pathStr == "/" {
		rootWildcard = true // Root wildcard path, static files are not served
	}

	var configAttr starlark.HasAttrs
	if configAttr, err = getProxyConfig(count, proxyDef); err != nil {
		return rootWildcard, err
	}

	urlStr, err := apptype.GetStringAttr(configAttr, "url")
	if err != nil {
		return rootWildcard, err
	}

	preserveHost, err := apptype.GetBoolAttr(configAttr, "preserve_host")
	if err != nil {
		return rootWildcard, err
	}

	stripApp, err := apptype.GetBoolAttr(configAttr, "strip_app")
	if err != nil {
		return rootWildcard, err
	}
	stripPath, err := apptype.GetStringAttr(configAttr, "strip_path")
	if err != nil {
		return rootWildcard, err
	}

	responseHeaders, err := apptype.GetDictAttr(configAttr, "response_headers", true)
	if err != nil {
		return rootWildcard, err
	}

	if urlStr == apptype.CONTAINER_URL {
		// proxying to container url
		if a.containerManager == nil {
			return rootWildcard, fmt.Errorf("container manager not initialized")
		}

		urlStr = a.containerManager.GetProxyUrl()
	}

	urlParsed, err := url.Parse(urlStr)
	if err != nil {
		return rootWildcard, fmt.Errorf("error parsing url %s: %w", urlStr, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(urlParsed)

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	maxIdleConnCount := a.AppConfig.Proxy.MaxIdleConns
	customTransport.MaxConnsPerHost = maxIdleConnCount * 2
	customTransport.MaxIdleConns = maxIdleConnCount
	customTransport.MaxIdleConnsPerHost = maxIdleConnCount
	customTransport.IdleConnTimeout = time.Duration(a.AppConfig.Proxy.IdleConnTimeoutSecs) * time.Second
	customTransport.DisableCompression = a.AppConfig.Proxy.DisableCompression
	proxy.Transport = customTransport

	defaultDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		defaultDirector(req)
		// To support WebSockets, we need to ensure that the `Connection`, `Upgrade`
		// and `Host` headers are forwarded as-is and not modified.
		if req.Header.Get("Upgrade") == "websocket" {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		} else if !preserveHost {
			// Set the Host header to target url for non-WebSocket requests, unless
			// disabled in proxy config
			req.Host = urlParsed.Host
		}
	}

	permsHandler := func(p *httputil.ReverseProxy) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If write API, check if preview/stage app is allowed access
			isWriteRequest := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete
			if isWriteRequest {
				if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_PREVIEW) && !a.Settings.PreviewWriteAccess {
					http.Error(w, "Preview app does not have access to proxy write APIs", http.StatusInternalServerError)
					return
				} else if strings.HasPrefix(string(a.Id), types.ID_PREFIX_APP_STAGE) && !a.Settings.StageWriteAccess {
					http.Error(w, "Stage app does not have access to proxy write APIs", http.StatusInternalServerError)
					return
				}
			}

			r.Header.Set("X-Forwarded-Host", strings.SplitN(r.Host, ":", 2)[0])
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
			if a.Path != "" && a.Path != "/" {
				r.Header.Set("X-Forwarded-Prefix", a.Path)
			}

			// Set the response headers
			for key, value := range responseHeaders {
				if value == nil {
					continue
				}

				valueStr, ok := value.(string)
				if !ok {
					a.Error().Msgf("response header %s is not a string", key)
					continue
				}
				valueStr = strings.ReplaceAll(valueStr, "$url", r.URL.Path)
				w.Header().Set(key, valueStr)
			}

			// use the reverse proxy to handle the request
			p.ServeHTTP(w, r)
		})
	}
	if stripApp {
		stripPath = path.Join(a.Path, stripPath)
	}
	router.Mount(pathStr, http.StripPrefix(stripPath, permsHandler(proxy)))
	return rootWildcard, nil
}

func (a *App) addAPIRoute(basePath string, router *chi.Mux, apiDef *starlarkstruct.Struct, defaultHandler starlark.Callable) error {
	var err error
	var pathStr, method, rtype string
	if pathStr, err = apptype.GetStringAttr(apiDef, "path"); err != nil {
		return err
	}

	if method, err = apptype.GetStringAttr(apiDef, "method"); err != nil {
		return err
	}

	if rtype, err = apptype.GetStringAttr(apiDef, "type"); err != nil {
		return err
	}

	var ok bool
	handler := defaultHandler // Use app level default handler, which could also be nil
	handlerAttr, _ := apiDef.Attr("handler")
	if handlerAttr != nil {
		if handler, ok = handlerAttr.(starlark.Callable); !ok {
			return fmt.Errorf("handler for API %s is not a function", pathStr)
		}
	}

	handlerFunc := a.createHandlerFunc("", "", handler, rtype)

	fullPath := pathStr
	if basePath != "" {
		fullPath = path.Join(basePath, pathStr)
	}
	router.Method(method, fullPath, handlerFunc)
	return nil
}

func (a *App) handleFragments(router *chi.Mux, pagePath string, pageCount int, htmlFile string, block string, page *starlarkstruct.Struct, handlerCallable starlark.Callable) error {
	// Iterate through all the pages
	var err error
	fragmentAttr, err := page.Attr("fragments")
	if err != nil {
		// No fragments defined
		return nil
	}

	var ok bool
	var fragmentList *starlark.List
	if fragmentList, ok = fragmentAttr.(*starlark.List); !ok {
		return fmt.Errorf("fragments attribute in page %d is not a list", pageCount)
	}
	iter := fragmentList.Iterate()
	var val starlark.Value
	count := 0
	for iter.Next(&val) {
		count++

		var fragmentDef *starlarkstruct.Struct
		if fragmentDef, ok = val.(*starlarkstruct.Struct); !ok {
			return fmt.Errorf("page %d fragment %d is not a struct", pageCount, count)
		}

		_, err = fragmentDef.Attr("partial")
		if err != nil {
			// "partial" is not defined, this must be a API route instead of a html route
			if err = a.addAPIRoute(pagePath, router, fragmentDef, handlerCallable); err != nil {
				return err
			}
			continue
		}

		var pathStr, blockStr, methodStr string
		if pathStr, err = apptype.GetStringAttr(fragmentDef, "path"); err != nil {
			return err
		}
		if methodStr, err = apptype.GetStringAttr(fragmentDef, "method"); err != nil {
			return err
		}
		if blockStr, err = apptype.GetStringAttr(fragmentDef, "partial"); err != nil {
			return err
		}

		if blockStr == "" {
			// Inherit page level block setting
			blockStr = block
		}

		fragmentCallback := handlerCallable
		handler, _ := fragmentDef.Attr("handler")
		if handler != nil {
			// If new handler is defined at fragment level, that is verified. Otherwise the
			// page level handler is used
			if fragmentCallback, ok = handler.(starlark.Callable); !ok {
				return fmt.Errorf("handler for page %d fragment %d is not a function", pageCount, count)
			}
		}
		handlerFunc := a.createHandlerFunc(htmlFile, blockStr, fragmentCallback, apptype.HTML_TYPE)

		fragmentPath := path.Join(pagePath, pathStr)
		a.Trace().Msgf("Adding fragment route %s <%s>", methodStr, fragmentPath)
		router.Method(methodStr, fragmentPath, handlerFunc)
	}

	return nil
}

func (a *App) createInternalRoutes(router *chi.Mux) error {
	if a.IsDev || a.codeConfig.Routing.PushEvents {
		router.Get(types.APP_INTERNAL_URL_PREFIX+"/sse", a.sseHandler)
	}

	router.Get(types.APP_INTERNAL_URL_PREFIX+"/file/{file_id}", a.userFileHandler)
	return nil
}

func (a *App) userFileHandler(w http.ResponseWriter, r *http.Request) {
	connectString := a.plugins.pluginConfig["fs.in"]["db_connection"] // this cannot be overridden at the app level
	csStr, ok := connectString.(string)
	if !ok {
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	err := InitFileStore(r.Context(), csStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fileID := chi.URLParam(r, "file_id")
	fileEntry, err := GetUserFile(r.Context(), fileID)
	if err != nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	if fileEntry.Visibility == "private" && fileEntry.CreatedBy != types.ANONYMOUS_USER {
		// Check if the user is authorized to access the file
		reqUser := r.Context().Value(types.USER_ID)
		if reqUser == nil {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		userStr, ok := reqUser.(string)
		if !ok {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		if userStr != fileEntry.CreatedBy {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
	}
	// For app level visibility, the file is accessible if the API is accessible

	if !strings.HasPrefix(fileEntry.FilePath, "file://") {
		http.Error(w, "500 Unknown file type", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", fileEntry.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileEntry.FileName))

	filePath := fileEntry.FilePath[len("file://"):]
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer file.Close() //nolint:errcheck

	// Copy the file content to the response writer
	// This streams the content and uses chunked transfer encoding
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Error while copying file. "+err.Error(), http.StatusInternalServerError)
		return
	}

	if fileEntry.SingleAccess {
		if strings.HasPrefix(fileEntry.FilePath, "file://") {
			err := os.Remove(strings.TrimPrefix(fileEntry.FilePath, "file://"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error deleting file %s: %s", fileEntry.FilePath, err)
			}
		}

		err = DeleteUserFile(r.Context(), fileID)
		if err != nil {
			a.Error().Err(err).Msgf("Error deleting file %s %s", fileID, fileEntry.FilePath)
		}
	}
}

func (a *App) loadLibraryInfo() ([]types.JSLibrary, error) {
	lib, err := a.appDef.Attr("libraries")
	if err != nil {
		return nil, err
	}

	if lib == nil {
		// No libraries defined
		return nil, nil
	}

	var ok bool
	var libList *starlark.List
	if libList, ok = lib.(*starlark.List); !ok {
		return nil, fmt.Errorf("libraries is not a list")
	}

	libraries := []types.JSLibrary{}
	iter := libList.Iterate()
	var libValue starlark.Value
	count := 0
	for iter.Next(&libValue) {
		count++
		libStruct, ok := libValue.(*starlarkstruct.Struct)
		if ok {
			var name, version string
			var esbuildArgs []string
			if name, err = apptype.GetStringAttr(libStruct, "name"); err != nil {
				return nil, err
			}
			if version, err = apptype.GetStringAttr(libStruct, "version"); err != nil {
				return nil, err
			}
			if esbuildArgs, err = apptype.GetListStringAttr(libStruct, "args", true); err != nil {
				return nil, err
			}
			jsLib := dev.NewLibraryESM(name, version, esbuildArgs)
			libraries = append(libraries, *jsLib)
		} else {
			libStr, ok := libValue.(starlark.String)
			if !ok {
				return nil, fmt.Errorf("libraries entry %d is not a string or library", count)
			}
			jsLib := dev.NewLibrary(string(libStr))
			libraries = append(libraries, *jsLib)
		}
	}

	return libraries, nil
}
