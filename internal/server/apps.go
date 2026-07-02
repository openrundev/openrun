// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// AppStore is a store of apps. List of apps is stored in memory. Apps are initialized lazily,
// AddApp has to be called before GetApp to initialize the app
type AppStore struct {
	*types.Logger
	server     *Server
	allApps    []types.AppInfo
	idToInfo   map[types.AppId]types.AppInfo
	allDomains map[string]bool
	// domainApps indexes allApps by effective domain (app domain or the
	// default domain) so request matching scans only the apps installed on
	// the request's domain. Entries preserve allApps order (newest first).
	domainApps map[string][]types.AppInfo

	mu     sync.RWMutex
	appMap map[types.AppPathDomain]*app.App
	// generation increments whenever apps are removed from the store (an
	// update committed, an app was deleted, ...). GetApp reads it before
	// loading an app entry from the DB and re-checks it when inserting the
	// built App, so an App built from a read that a concurrent clear made
	// stale is never cached.
	generation uint64
}

func NewAppStore(logger *types.Logger, server *Server) *AppStore {
	return &AppStore{
		Logger: logger,
		server: server,
		appMap: make(map[types.AppPathDomain]*app.App),
	}
}

// GetAppsFullInfo returns the apps indexed by effective domain and the set of
// all configured domains, for request matching.
func (a *AppStore) GetAppsFullInfo() (map[string][]types.AppInfo, map[string]bool, error) {
	a.mu.RLock()
	if a.allApps != nil {
		a.mu.RUnlock()
		return a.domainApps, a.allDomains, nil
	}
	a.mu.RUnlock()

	// Get exclusive lock
	a.mu.Lock()
	defer a.mu.Unlock()

	err := a.reloadAppInfo()
	if err != nil {
		return nil, nil, err
	}
	return a.domainApps, a.allDomains, nil
}

func (a *AppStore) GetAllAppsInfo() ([]types.AppInfo, error) {
	a.mu.RLock()
	if a.allApps != nil {
		a.mu.RUnlock()
		return a.allApps, nil
	}
	a.mu.RUnlock()

	// Get exclusive lock
	a.mu.Lock()
	defer a.mu.Unlock()

	err := a.reloadAppInfo()
	if err != nil {
		return nil, err
	}
	return a.allApps, nil
}

func (a *AppStore) GetAppInfo(appId types.AppId) (types.AppInfo, bool) {
	a.mu.RLock()
	if a.idToInfo != nil {
		a.mu.RUnlock()
		info, ok := a.idToInfo[appId]
		return info, ok
	}
	a.mu.RUnlock()

	// Get exclusive lock
	a.mu.Lock()
	defer a.mu.Unlock()

	err := a.reloadAppInfo()
	if err != nil {
		return types.AppInfo{}, false
	}
	info, ok := a.idToInfo[appId]
	return info, ok
}

func (a *AppStore) GetAllDomains() (map[string]bool, error) {
	a.mu.RLock()
	if a.allDomains != nil {
		a.mu.RUnlock()
		return a.allDomains, nil
	}
	a.mu.RUnlock()

	// Get exclusive lock
	a.mu.Lock()
	defer a.mu.Unlock()

	err := a.reloadAppInfo()
	if err != nil {
		return nil, err
	}
	return a.allDomains, nil
}

func (a *AppStore) reloadAppInfo() error {
	var err error
	a.allApps, err = a.server.db.GetAllApps(true)
	if err != nil {
		return err
	}

	a.idToInfo = make(map[types.AppId]types.AppInfo)
	for _, appInfo := range a.allApps {
		a.idToInfo[appInfo.Id] = appInfo
	}

	a.allDomains = make(map[string]bool)
	a.allDomains[a.server.config.System.DefaultDomain] = true
	for _, appInfo := range a.allApps {
		if appInfo.Domain != "" {
			a.allDomains[appInfo.Domain] = true
		}
	}
	a.domainApps = buildDomainApps(a.allApps, a.server.config.System.DefaultDomain)
	return nil
}

// buildDomainApps indexes apps by their effective domain, preserving input order.
func buildDomainApps(apps []types.AppInfo, defaultDomain string) map[string][]types.AppInfo {
	domainApps := make(map[string][]types.AppInfo)
	for _, appInfo := range apps {
		domain := cmp.Or(appInfo.Domain, defaultDomain)
		domainApps[domain] = append(domainApps[domain], appInfo)
	}
	return domainApps
}

func (a *AppStore) ResetAllAppCache() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetAllAppCache()
}

func (a *AppStore) resetAllAppCache() {
	a.allApps = nil
	a.allDomains = nil
	a.idToInfo = nil
	a.domainApps = nil
}

func (a *AppStore) GetApp(pathDomain types.AppPathDomain) (*app.App, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	app, ok := a.appMap[pathDomain]
	if !ok {
		return nil, fmt.Errorf("app not found: %s", pathDomain)
	}
	return app, nil
}

// ActiveContainerNames returns the container names currently referenced by loaded apps.
func (a *AppStore) ActiveContainerNames() map[container.ContainerName]bool {
	a.mu.RLock()
	apps := make([]*app.App, 0, len(a.appMap))
	for _, application := range a.appMap {
		apps = append(apps, application)
	}
	a.mu.RUnlock()

	names := make(map[container.ContainerName]bool)
	for _, application := range apps {
		name, ok := application.ActiveContainerName()
		if ok {
			names[name] = true
		}
	}
	return names
}

// Generation returns the current store generation. Read it before loading app
// state from the DB and pass it to AddAppIfUnchanged.
func (a *AppStore) Generation() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.generation
}

// AddAppIfUnchanged adds the app to the store only if no apps have been
// removed from the store since the given generation was read. It returns false
// without adding when the store changed: the DB state the app was built from
// may have been superseded (e.g. a reload committed in between), so the caller
// must discard the app and rebuild from a fresh read.
func (a *AppStore) AddAppIfUnchanged(app *app.App, generation uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.generation != generation {
		return false
	}
	a.appMap[types.CreateAppPathDomain(app.Path, app.Domain)] = app
	a.resetAllAppCache()
	return true
}

func (a *AppStore) ClearLinkedApps(pathDomain types.AppPathDomain) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	appPaths := []types.AppPathDomain{}
	appPaths = append(appPaths, pathDomain)

	for key, app := range a.appMap {
		// Clear stage/preview apps that point back to the app being cleared. Apps without a
		// (parseable) linked app path are skipped rather than aborting the whole clear.
		linkedPathDomain, err := parseLinkedAppPathDomain(app.LinkedAppPath)
		if err != nil {
			continue
		}
		if linkedPathDomain == pathDomain {
			a.clearApp(key)
			appPaths = append(appPaths, key)
		}
	}

	a.clearApp(pathDomain)
	a.resetAllAppCache()
	return a.server.db.NotifyAppUpdate(appPaths)
}

func (a *AppStore) clearApp(pathDomain types.AppPathDomain) {
	// Invalidate in-progress GetApp loads even when this path is not cached:
	// the app being cleared may be exactly the one a concurrent GetApp is
	// building from a now-stale DB read.
	a.generation++
	app, ok := a.appMap[pathDomain]
	if ok {
		app.Close() //nolint:errcheck
		delete(a.appMap, pathDomain)
	}
}

// ClearApps removes the specified apps from the in memory App cache
// Also clears the app info cache for all apps (so that it is reloaded on next request)
func (a *AppStore) ClearApps(pathDomains []types.AppPathDomain) {
	if len(pathDomains) == 0 {
		return
	}

	a.mu.Lock()
	for _, pd := range pathDomains {
		a.clearApp(pd)
	}
	a.resetAllAppCache()
	a.mu.Unlock()

	err := a.server.db.NotifyAppUpdate(pathDomains)
	if err != nil {
		a.Error().Err(err).Msg("error sending app update notification")
	}
}

// ClearApps removes the specified apps from the in memory App cache
// Also clears the app info cache for all apps (so that it is reloaded on next request)
// This does not notify other servers of the app update (intended for use from the listener)
func (a *AppStore) ClearAppsNoNotify(pathDomains []types.AppPathDomain) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, pd := range pathDomains {
		a.clearApp(pd)
	}
	a.resetAllAppCache()
}

// ClearApps removes the specified apps from the in memory App cache and creates an audit entry.
// Also clears the app info cache for all apps (so that it is reloaded on next request)
func (a *AppStore) ClearAppsAudit(ctx context.Context, pathDomains []types.AppPathDomain, op string) error {
	if len(pathDomains) == 0 {
		return nil
	}
	defer a.ClearApps(pathDomains)

	appInfo, error := a.GetAllAppsInfo()
	if error != nil {
		return error
	}
	appMap := getAppInfoMap(appInfo)

	event := types.AuditEvent{
		RequestId: system.GetContextRequestId(ctx),
		UserId:    system.GetContextUserId(ctx),
		EventType: types.EventTypeSystem,
		Operation: op,
		Status:    string(types.EventStatusSuccess),
	}

	for _, pd := range pathDomains {
		appInfo, ok := appMap[pd.String()]
		if !ok {
			a.Warn().Msgf("audit event skipped for %s, app info not found", pd)
			continue
		}

		event.Target = pd.String()
		event.AppId = appInfo.Id
		event.CreateTime = time.Now()

		if err := a.server.InsertAuditEvent(&event); err != nil {
			return err
		}
	}

	return nil
}

func getAppInfoMap(appInfo []types.AppInfo) map[string]types.AppInfo {
	ret := make(map[string]types.AppInfo)
	for _, info := range appInfo {
		ret[info.AppPathDomain.String()] = info //nolint:staticcheck
	}
	return ret
}
