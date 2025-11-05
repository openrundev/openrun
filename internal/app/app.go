// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/fsnotify/fsnotify"
	"github.com/go-chi/chi"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/dev"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// App is the main object that represents a OpenRun app. It is created when the app is loaded
type App struct {
	*types.Logger
	*types.AppEntry
	Name         string
	CustomLayout bool
	notifyClose  chan<- types.AppPathDomain // Channel to notify server to close the app

	codeConfig       *apptype.CodeConfig
	sourceFS         *appfs.SourceFs
	initMutex        sync.Mutex
	initialized      bool
	reloadError      error
	reloadStartTime  time.Time
	appDev           *dev.AppDev
	appStyle         *dev.AppStyle
	systemConfig     *types.SystemConfig
	storeInfo        *starlark_type.StoreInfo
	paramInfo        map[string]apptype.AppParam
	paramValuesStr   map[string]string   // the param values for the app, from metadata and defaults
	paramDict        starlark.StringDict // the Starlark param values for the app
	plugins          *AppPlugins
	containerManager *ContainerHandler
	serverConfig     *types.ServerConfig

	globals      starlark.StringDict    // global variables defined in starlark code
	appDef       *starlarkstruct.Struct // app starlark definition
	errorHandler starlark.Callable      // error handler function
	appRouter    *chi.Mux               // router for the app
	actions      []*action.Action       // actions defined for the app

	usesHtmlTemplate bool                          // Whether the app uses HTML templates, false if only JSON APIs
	template         *template.Template            // unstructured templates, no base_templates defined
	templateMap      map[string]*template.Template // structured templates, base_templates defined
	staticOnly       bool                          // app has only static files, no HTML routes
	redirectBarePath bool                          // whether to redirect bare path requests to the full path with trailing slash
	jsLibs           []types.JSLibrary             // JS libraries used by the app

	watcher       *fsnotify.Watcher
	sseListeners  []chan SSEMessage
	funcMap       template.FuncMap
	starlarkCache map[string]*starlarkCacheEntry

	// App config that takes default values from toml config, overridden with app level metadata.
	// It is important that this property is used instead of reading from app metadata config, so that toml
	// config defaults are applied.
	AppConfig types.AppConfig

	lastRequestTime atomic.Int64
	secretEvalFunc  func([][]string, string, string) (string, error)
	auditInsert     func(*types.AuditEvent) error
	AppRunPath      string       // path to the app run directory
	rbacApi         rbac.RBACAPI // the rbac api to use
}

type starlarkCacheEntry struct {
	globals starlark.StringDict
	err     error
}

type SSEMessage struct {
	event string
	data  string
}

func NewApp(sourceFS *appfs.SourceFs, workFS *appfs.WorkFs, logger *types.Logger,
	appEntry *types.AppEntry, systemConfig *types.SystemConfig,
	plugins map[string]types.PluginSettings, appConfig types.AppConfig, notifyClose chan<- types.AppPathDomain,
	secretEvalFunc func([][]string, string, string) (string, error),
	auditInsert func(*types.AuditEvent) error, serverConfig *types.ServerConfig,
	rbacApi rbac.RBACAPI) (*App, error) {
	newApp := &App{
		sourceFS:       sourceFS,
		Logger:         logger,
		AppEntry:       appEntry,
		systemConfig:   systemConfig,
		starlarkCache:  map[string]*starlarkCacheEntry{},
		notifyClose:    notifyClose,
		secretEvalFunc: secretEvalFunc,
		appStyle:       &dev.AppStyle{},
		auditInsert:    auditInsert,
		serverConfig:   serverConfig,
		rbacApi:        rbacApi,
	}
	newApp.plugins = NewAppPlugins(newApp, plugins, appEntry.Metadata.Accounts)
	newApp.AppConfig = appConfig
	if err := newApp.updateAppConfig(); err != nil {
		return nil, err
	}

	if appEntry.IsDev {
		newApp.appDev = dev.NewAppDev(logger, &appfs.WritableSourceFs{SourceFs: sourceFS}, workFS, newApp.appStyle, systemConfig)
	}

	funcMap := system.GetFuncMap()
	funcMap["static"] = func(name string) string {
		staticPath := path.Join("static", name)
		fullPath := path.Join(newApp.Path, sourceFS.HashName(staticPath))
		return fullPath
	}
	funcMap["fileNonEmpty"] = func(name string) bool {
		staticPath := path.Join("static", name)
		fi, err := sourceFS.Stat(staticPath)
		if err != nil {
			return false
		}
		return fi.Size() > 0
	}

	newApp.funcMap = funcMap

	clHome := cmp.Or(os.Getenv("OPENRUN_HOME"), "./")
	newApp.AppRunPath = fmt.Sprintf("%s/run/app/%s", clHome, appEntry.Id)
	if err := os.MkdirAll(newApp.AppRunPath, 0700); err != nil {
		return nil, err
	}
	return newApp, nil
}

func (a *App) Initialize(dryRun types.DryRun) error {
	var reloaded bool
	var err error
	if reloaded, err = a.Reload(false, true, dryRun); err != nil {
		return err
	}

	if reloaded && a.IsDev {
		if err := a.startWatcher(); err != nil {
			a.Info().Msgf("error starting watcher: %s", err)
			return err
		}
	}
	return nil
}

func (a *App) Close() error {
	a.initMutex.Lock()
	defer a.initMutex.Unlock()
	if a.watcher != nil {
		if err := a.watcher.Close(); err != nil {
			return err
		}
	}

	if a.appDev != nil {
		_ = a.appDev.Close()
	}

	if a.containerManager != nil {
		if err := a.containerManager.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) ResetFS() {
	a.sourceFS.Reset()
}

func (a *App) Reload(force, immediate bool, dryRun types.DryRun) (bool, error) {
	requestTime := time.Now()

	a.initMutex.Lock()
	defer a.initMutex.Unlock()
	if a.initialized && !force {
		return false, nil
	}

	if requestTime.Compare(a.reloadStartTime) == -1 {
		// Current request is older than the last reloaded request, ignore
		a.Info().Msg("Ignoring reload request since it is older than the last reload request")
		return false, nil
	}

	if !immediate {
		// Sleep to allow for multiple file changes to be processed together
		// For slower machines, this can be increased, default is 300ms. The tailwind watcher
		// especially might need a higher value
		time.Sleep(time.Duration(a.systemConfig.FileWatcherDebounceMillis) * time.Millisecond)
	}
	a.reloadStartTime = time.Now()

	var err error
	a.Info().Msg("Reloading app definition")

	// Clear any cached data
	a.sourceFS.ClearCache()
	clear(a.starlarkCache)

	err = a.loadSchemaInfo(a.sourceFS)
	if err != nil {
		return false, err
	}

	err = a.loadParamsInfo(a.sourceFS)
	if err != nil {
		return false, err
	}

	configData, err := a.sourceFS.ReadFile(apptype.CONFIG_LOCK_FILE_NAME)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}

		// Config lock is not present, use default config
		a.Debug().Msg("No config lock file found, using default config")
		a.codeConfig = apptype.NewCodeConfig()
		if a.IsDev {
			a.appDev.Config = a.codeConfig
			err = a.appDev.SaveConfigLockFile()
			if err != nil {
				return false, err
			}
		}
	} else {
		// Config lock file is present, read defaults from that
		a.Debug().Msg("Config lock file found, using config from lock file")
		a.codeConfig = apptype.NewCompatibleCodeConfig()
		if err := json.Unmarshal(configData, a.codeConfig); err != nil {
			return false, err
		}
	}

	// Load Starlark config, AppConfig is updated with the settings contents
	if err = a.loadStarlarkConfig(dryRun); err != nil {
		return false, fmt.Errorf("error loading starlark config: %w", err)
	}
	a.Metadata.Name = a.Name

	// Initialize style configuration
	if err := a.appStyle.Init(a.Id, a.appDef); err != nil {
		return false, err
	}

	if a.IsDev {
		// Copy settings into appdev
		a.appDev.Config = a.codeConfig
		a.appDev.CustomLayout = a.CustomLayout
		a.appDev.AppStyle = a.appStyle

		// Setup the CSS files
		if err = a.appDev.AppStyle.Setup(a.appDev); err != nil {
			return false, err
		}

		// Start the watcher for CSS files unless disabled
		if !a.appDev.AppStyle.DisableWatcher {
			if err = a.appDev.AppStyle.StartWatcher(a.appDev); err != nil {
				a.Warn().Err(err).Msg("Error starting tailwind watcher")
				fmt.Printf("Error: %s\n", err)
				// Allow the app to start even if the watcher fails
			}
		} else if err := a.appDev.AppStyle.StopWatcher(); err != nil {
			return false, err
		}

		if a.usesHtmlTemplate || len(a.actions) > 0 {
			// Setup the JS libraries
			if err := a.appDev.SetupJsLibs(); err != nil {
				return false, err
			}
		}

		if a.usesHtmlTemplate {
			// Create the generated HTML
			if err = a.appDev.GenerateHTML(); err != nil {
				return false, err
			}
		}
	}

	// Parse HTML templates if there are HTML routes or action uses HTML templates
	baseFiles, err := a.sourceFS.Glob(path.Join(a.codeConfig.Routing.BaseTemplates, "*.go.html"))
	if err != nil {
		return false, err
	}

	if len(baseFiles) == 0 {
		// No base templates found, use the default unstructured templates
		if a.template, err = a.sourceFS.ParseFS(a.funcMap, a.codeConfig.Routing.TemplateLocations...); err != nil {
			if strings.Contains(err.Error(), "pattern matches no files") {
				if a.usesHtmlTemplate {
					// No html templates found, but app has html routes
					return false, err
				}
				// no html templates, ignore error
			} else {
				// Some other error parsing templates, report
				return false, err
			}
		}
	} else {
		// Base templates found, using structured templates
		base, err := a.sourceFS.ParseFS(a.funcMap, baseFiles...)
		if err != nil {
			return false, err
		}

		a.templateMap = make(map[string]*template.Template)
		for _, paths := range a.codeConfig.Routing.TemplateLocations {
			files, err := a.sourceFS.Glob(paths)
			if err != nil {
				return false, err
			}

			for _, file := range files {
				tmpl, err := base.Clone()
				if err != nil {
					return false, err
				}

				a.templateMap[file], err = tmpl.ParseFS(a.sourceFS.ReadableFS, file)
				if err != nil {
					return false, err
				}
			}
		}
	}
	for _, action := range a.actions {
		// structured templates are not supported for actions currently
		action.AppTemplate = a.template
		action.StyleType = a.appStyle.GetStyleType()
		action.LightTheme = cmp.Or(a.appStyle.Light, apptype.DEFAULT_DAISYUI_LIGHT_THEME)
		action.DarkTheme = cmp.Or(a.appStyle.Dark, apptype.DEFAULT_DAISYUI_DARK_THEME)
	}
	a.initialized = true

	if a.IsDev {
		a.notifyClients()
	}
	return true, nil
}

const (
	CONTAINERFILE = "Containerfile"
	DOCKERFILE    = "Dockerfile"
)

func (a *App) loadContainerManager(stripAppPath bool) error {
	containerConfig, err := a.appDef.Attr("container")
	if err != nil || containerConfig == starlark.None {
		// Plugin not authorized, skip any container files
		return nil
	}

	if a.systemConfig.ContainerCommand == "" {
		return fmt.Errorf("app requires container support. Container management is not enabled in OpenRun server config. " +
			"Install Docker/Podman and set the container_command in system config or set to auto (default) and ensure that " +
			"the container manager command is in the PATH")
	}

	var ok bool
	var responseAttr starlark.HasAttrs
	if responseAttr, ok = containerConfig.(starlark.HasAttrs); !ok {
		return fmt.Errorf("container config is not valid type")
	}

	errorValue, err := responseAttr.Attr("error")
	if err != nil {
		return fmt.Errorf("error in container config: %w", err)
	}

	if errorValue != nil && errorValue != starlark.None {
		var errorString starlark.String
		if errorString, ok = errorValue.(starlark.String); !ok {
			return fmt.Errorf("error in container config: %w", err)
		}

		if errorString.GoString() != "" {
			return fmt.Errorf("error in container config: %s", errorString.GoString())
		}
	}

	config, err := responseAttr.Attr("value")
	if err != nil {
		return err
	}

	var configAttr starlark.HasAttrs
	if configAttr, ok = config.(starlark.HasAttrs); !ok {
		return fmt.Errorf("container config is not valid type")
	}

	src, err := apptype.GetStringAttr(configAttr, "source")
	if err != nil {
		return fmt.Errorf("error reading source: %w", err)
	}

	port, err := apptype.GetIntAttr(configAttr, "port")
	if err != nil {
		return fmt.Errorf("error reading port: %w", err)
	}
	lifetime, err := apptype.GetStringAttr(configAttr, "lifetime")
	if err != nil {
		return fmt.Errorf("error reading lifetime: %w", err)
	}

	scheme, err := apptype.GetStringAttr(configAttr, "scheme")
	if err != nil {
		return fmt.Errorf("error reading scheme: %w", err)
	}

	health, err := apptype.GetStringAttr(configAttr, "health")
	if err != nil {
		return fmt.Errorf("error reading health: %w", err)
	}

	buildDir, err := apptype.GetStringAttr(configAttr, "build_dir")
	if err != nil {
		return fmt.Errorf("error reading build_dir: %w", err)
	}

	volumesConfig, err := apptype.GetListStringAttr(configAttr, "volumes", true)
	if err != nil {
		return fmt.Errorf("error reading volumes: %w", err)
	}

	volumes := a.Metadata.ContainerVolumes
	volumes = append(volumes, volumesConfig...)

	cargs, err := apptype.GetDictAttr(configAttr, "cargs", true)
	if err != nil {
		return fmt.Errorf("error reading cargs: %w", err)
	}

	// Parse the source file specification
	var fileName string
	switch src {
	case types.CONTAINER_SOURCE_AUTO:
		// Look for a file in the source fs (ignoring spec). If not found,
		// look in spec files also.
		if _, err := a.sourceFS.StatNoSpec(CONTAINERFILE); err == nil {
			fileName = CONTAINERFILE
		} else {
			if _, err := a.sourceFS.StatNoSpec(DOCKERFILE); err == nil {
				fileName = DOCKERFILE
			}
		}

		if fileName == "" {
			// Containerfile/Dockerfile not found in source, check in spec files also
			if _, err := a.sourceFS.Stat(CONTAINERFILE); err == nil {
				fileName = CONTAINERFILE
			} else {
				if _, err := a.sourceFS.Stat(DOCKERFILE); err == nil {
					fileName = DOCKERFILE
				}
			}
		}
	case types.CONTAINER_SOURCE_NIXPACKS:
		return fmt.Errorf("nixpacks container source not supported yet")
	default:
		// Custom container file (or image name prefixed with image:)
		fileName = src
	}

	if fileName == "" {
		return fmt.Errorf("no container file found, source is set to %s", src)
	}

	if a.containerManager != nil {
		if err := a.containerManager.Close(); err != nil {
			return fmt.Errorf("error shutting down previous container manager: %w", err)
		}
	}

	a.containerManager, err = NewContainerManager(a.Logger, a,
		fileName, a.systemConfig, port, lifetime, scheme, health, buildDir,
		a.sourceFS, a.paramValuesStr, a.AppConfig.Container, stripAppPath, volumes,
		a.getSecretsAllowed("container.in", "config"), cargs)
	if err != nil {
		return fmt.Errorf("error creating container manager: %w", err)
	}

	return nil
}

func (a *App) executeTemplate(w io.Writer, template, partial string, data any) error {
	var err error
	if a.template != nil {
		exec := partial
		if partial == "" {
			exec = template
		}
		if err = a.template.ExecuteTemplate(w, exec, data); err != nil {
			return err
		}
	} else {
		if template == "" {
			if _, ok := a.templateMap[partial]; ok {
				template = partial
			} else {
				template = "index.go.html"
			}
		}

		t, ok := a.templateMap[template]
		if !ok {
			return fmt.Errorf("template %s not found", template)
		}
		exec := partial
		if partial == "" {
			exec = template
		}
		if err = t.ExecuteTemplate(w, exec, data); err != nil {
			return err
		}
	}
	return err
}

func (a *App) loadSchemaInfo(sourceFS *appfs.SourceFs) error {
	// Load the schema info
	schemaInfoData, err := sourceFS.ReadFile(a.getStarPath(apptype.SCHEMA_FILE_NAME))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil // Ignore absence of schema file
	}

	a.storeInfo, err = apptype.ReadStoreInfo(a.getStarPath(apptype.SCHEMA_FILE_NAME), schemaInfoData)
	if err != nil {
		return fmt.Errorf("error reading schema info: %w", err)
	}

	return nil

}

func (a *App) loadParamsInfo(sourceFS *appfs.SourceFs) error {
	// Load the params info
	paramsInfoData, err := sourceFS.ReadFile(a.getStarPath(apptype.PARAMS_FILE_NAME))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil // Ignore absence of params file
	}

	a.paramInfo, err = apptype.ReadParamInfo(a.getStarPath(apptype.PARAMS_FILE_NAME), paramsInfoData, a.serverConfig)
	if err != nil {
		return fmt.Errorf("error reading params info: %w", err)
	}

	return nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Info().Enabled() {
		a.Info().Str("method", r.Method).Str("url", r.URL.String()).Msg("App Received request")
	}
	if a.reloadError != nil {
		a.Warn().Err(a.reloadError).Msg("Last reload had failed")
		http.Error(w, a.reloadError.Error(), http.StatusInternalServerError)
		return
	}

	if a.redirectBarePath && r.URL.Path == a.Path && !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, a.Path+"/", http.StatusTemporaryRedirect) // some apps like gradio need redirect to the full path with trailing slash
		return
	}

	if a.AppConfig.CORS.AllowOrigin != "" {
		origin := a.AppConfig.CORS.AllowOrigin
		if a.AppConfig.CORS.AllowOrigin == "origin" {
			origin = getRequestUrl(r)
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", a.AppConfig.CORS.AllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", a.AppConfig.CORS.AllowHeaders)
			w.Header().Set("Access-Control-Allow-Credentials", a.AppConfig.CORS.AllowCredentials)
			w.Header().Set("Access-Control-Max-Age", a.AppConfig.CORS.MaxAge)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", a.AppConfig.CORS.AllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", a.AppConfig.CORS.AllowHeaders)
		}
	}

	a.lastRequestTime.Store(time.Now().Unix()) // new api call, update last request time
	a.appRouter.ServeHTTP(w, r)
}

func (a *App) startWatcher() error {
	a.initMutex.Lock()
	defer a.initMutex.Unlock()
	if a.watcher != nil {
		_ = a.watcher.Close()
	}

	var err error
	a.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Start listening for events.
	a.Trace().Msg("Start waiting for file changes")
	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.Error().Msgf("Recovered from panic in watcher: %s", r)
			}
		}()

		inReload := atomic.Bool{}
		reloadEndTime := atomic.Int64{}
		inReload.Store(false)
		reloadEndTime.Store(0)

		for {
			select {
			case event, ok := <-a.watcher.Events:
				if !ok {
					return
				}

				if inReload.Load() {
					// If a reload is in progress, ignore the event
					a.Trace().Str("event", fmt.Sprint(event)).Msg("Ignoring event since reload is in progress")
					continue
				}
				endTime := reloadEndTime.Load()
				diff := time.Now().UnixMilli() - endTime
				a.Trace().Int64("diff", diff).Msg("Time since last reload")
				if endTime > 0 && (time.Now().UnixMilli()-endTime) < int64(a.systemConfig.FileWatcherDebounceMillis)*5 {
					// If a reload has happened recently, ignore the event
					a.Trace().Str("event", fmt.Sprint(event)).Msg("Ignoring event since reload happened recently")
					continue
				}
				if !(event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)) { //nolint:staticcheck
					// ignore chmod events
					a.Trace().Str("event", fmt.Sprint(event)).Msg("Ignoring event")
					continue
				}

				foundIgnoreMatch := false
				for _, pattern := range a.systemConfig.WatchIgnorePatterns {
					if match, err := doublestar.Match(pattern, event.Name); err == nil && match {
						a.Trace().Str("event", fmt.Sprint(event)).
							Msgf("Ignoring event on %s since it matches ignore pattern %s", event.Name, pattern)
						foundIgnoreMatch = true
						break
					}
				}
				if foundIgnoreMatch {
					continue
				}

				a.Trace().Str("event", fmt.Sprint(event)).Msg("Received event")

				go func() {
					defer func() {
						if r := recover(); r != nil {
							a.Error().Msgf("Recovered from panic in watcher: %s", r)
						}
					}()

					inReload.Store(true)
					defer inReload.Store(false)
					_, err := a.Reload(true, false, types.DryRun(false))
					a.reloadError = err
					if err != nil {
						a.Error().Err(err).Msg("Error reloading app")
						if a.IsDev {
							a.notifyClients() // Force clients to refresh if reload failed
						}
					}
					a.Trace().Msg("Reloaded app after file changes")
					reloadEndTime.Store(time.Now().UnixMilli())
				}()
			case err, ok := <-a.watcher.Errors:
				a.Error().Err(err).Msgf("Error in watcher error receiver")
				if !ok {
					return
				}
			}
		}
	}()

	// Add watcher path.
	return filepath.WalkDir(a.SourceUrl, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			a.Trace().Str("path", path).Msg("Adding path to watcher")
			return a.watcher.Add(path)
		}
		return nil
	})
}

func (a *App) addSSEClient(newChan chan SSEMessage) {
	a.initMutex.Lock()
	defer a.initMutex.Unlock()
	a.sseListeners = append(a.sseListeners, newChan)
}

func (a *App) removeSSEClient(chanRemove chan SSEMessage) {
	a.initMutex.Lock()
	defer a.initMutex.Unlock()
	for i, ch := range a.sseListeners {
		if ch == chanRemove {
			a.sseListeners = append(a.sseListeners[:i], a.sseListeners[i+1:]...)
			break
		}
	}
}

func (a *App) notifyClients() {
	a.Trace().Msg("Notifying clients for reload")
	reloadMessage := SSEMessage{
		event: "openrun_reload",
		data:  "App reloaded after file updates",
	}
	for _, ch := range a.sseListeners {
		ch <- reloadMessage
	}
}

func (a *App) sseHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	messageChan := make(chan SSEMessage)
	a.addSSEClient(messageChan)

	//keeping the connection alive with keep-alive protocol
	keepAliveTickler := time.NewTicker(15 * time.Second)
	notify := r.Context().Done()

	//listen to signal to close and unregister
	go func() {
		<-notify
		a.Trace().Msg("Closing SSE connection")
		a.removeSSEClient(messageChan)
		keepAliveTickler.Stop()
	}()

	for {
		select {
		case appMessage := <-messageChan:
			fmt.Fprintf(w, "event: %s\n", appMessage.event) //nolint:errcheck
			fmt.Fprintf(w, "data: %s\n\n", appMessage.data) //nolint:errcheck
			flusher.Flush()
		case <-keepAliveTickler.C:
			a.Trace().Msg("Sending keepalive")
			fmt.Fprintf(w, "event:keepalive\n\n") //nolint:errcheck
			flusher.Flush()
		}
	}
}

// loadStarlark loads a starlark file. The main app.star, if it calls load on a file with .star suffix, then
// this function is used to load the starlark file.
func (a *App) loadStarlark(thread *starlark.Thread, module string, cache map[string]*starlarkCacheEntry) (starlark.StringDict, error) {
	cacheEntry, ok := cache[module]
	if cacheEntry == nil {
		if ok {
			// request for package whose loading is in progress
			return nil, fmt.Errorf("cycle in starlark load graph during load of %s", module)
		}
		// Add a placeholder to indicate "load in progress".
		cache[module] = nil

		buf, err := a.sourceFS.ReadFile(a.getStarPath(module))
		if err != nil {
			return nil, err
		}

		builtin, err := a.createBuiltin()
		if err != nil {
			return nil, err
		}
		globals, err := starlark.ExecFileOptions(AppFileOptions(), thread, module, buf, builtin)
		cacheEntry = &starlarkCacheEntry{globals, err}
		// Update the cache.
		cache[module] = cacheEntry
	}
	return cacheEntry.globals, cacheEntry.err
}

func AppFileOptions() *syntax.FileOptions {
	return &syntax.FileOptions{
		While:     true,
		Recursion: true,
	}
}

// updateAppConfig updates the app defaults from the metadata
// It creates a TOML intermediate string so that the TOML parsing can be used
func (a *App) updateAppConfig() error {
	if len(a.Metadata.AppConfig) == 0 {
		return nil
	}

	buf := strings.Builder{}
	for key, value := range a.Metadata.AppConfig {
		buf.WriteString(fmt.Sprintf("%s=%s\n", key, value))
	}

	_, err := toml.Decode(buf.String(), &a.AppConfig)
	return err
}

func (a *App) getSecretsAllowed(plugin, function string) [][]string {
	ret := [][]string{}
	for _, p := range a.Metadata.Permissions {
		if p.Plugin == plugin && p.Method == function {
			ret = append(ret, p.Secrets...)
		}
	}

	return ret
}

func (a *App) getStarPath(name string) string {
	if a.AppConfig.StarBase == "" {
		return name
	}
	return path.Join(a.AppConfig.StarBase, name)
}
