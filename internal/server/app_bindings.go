// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
)

const autoBindingPathPrefix = "/auto"

func autoBindingPathForAppID(appID types.AppId, serviceType string) string {
	return autoBindingPathPrefix + "/" + string(appID) + "/" + serviceType
}

func autoBindingAppID(appEntry *types.AppEntry) types.AppId {
	if appEntry.IsDev {
		return appEntry.Id
	}
	if appEntry.MainApp != "" {
		return appEntry.MainApp
	}
	return appEntry.Id
}

func isDevAutoBindingPath(bindingPath string) bool {
	return strings.HasPrefix(bindingPath, autoBindingPathPrefix+"/"+types.ID_PREFIX_APP_DEV)
}

func useStagedBindingMetadata(binding *types.Binding, useStaging bool) bool {
	return useStaging || isDevAutoBindingPath(binding.Path)
}

// resolveAppBindings resolves the binding references on an app. A reference that
// starts with "/" is an existing binding path. Any other reference is a service
// source (serviceType or serviceType/name) for which an auto binding is created.
// Auto binding accounts are tracked on the operation's account manager, so they
// are removed from the service if the operation's transaction is rolled back.
//
// Attaching a binding hands its credentials to the app, so newly attached
// references are RBAC checked: an existing binding path needs binding:use on it,
// a service source needs service:bind on the service (which covers creating and
// attaching the auto binding). References already attached to the app
// (existingBindings) are kept without a check, so a caller who cannot use a
// previously attached binding can still update the app.
func (s *Server) resolveAppBindings(ctx context.Context, tx types.Transaction, appID types.AppId,
	bindingRefs, existingBindings []string, dryRun bool, accounts *bindingAccountManager) ([]string, error) {
	resolved := make([]string, 0, len(bindingRefs))
	seen := make(map[string]bool, len(bindingRefs))
	addResolved := func(path string) {
		if !seen[path] {
			resolved = append(resolved, path)
			seen[path] = true
		}
	}
	existing := make(map[string]bool, len(existingBindings))
	for _, path := range existingBindings {
		existing[path] = true
	}

	// Sqlite databases are single-writer files on one per-binding volume; one
	// sqlite binding per app keeps the volume, env and replication mapping
	// unambiguous
	sqliteBindings := 0
	countSqlite := func(path string) error {
		if seen[path] {
			return nil
		}
		sqliteBindings++
		if sqliteBindings > 1 {
			return fmt.Errorf("an app can have at most one sqlite binding")
		}
		return nil
	}

	for _, bindingRef := range bindingRefs {
		if bindingRef == "" {
			return nil, fmt.Errorf("binding path cannot be empty")
		}
		if strings.HasPrefix(bindingRef, "/") {
			// Auto bindings are owned by one app and deleted with it, so
			// another app may not attach them (an app's own auto binding
			// paths pass, e.g. when stored refs are re-resolved on update)
			if strings.HasPrefix(bindingRef, autoBindingPathPrefix+"/") &&
				!strings.HasPrefix(bindingRef, autoBindingPathForAppID(appID, "")) {
				return nil, fmt.Errorf("binding %s is an auto binding owned by another app and cannot be attached", bindingRef)
			}
			binding, err := s.db.GetBinding(ctx, tx, bindingRef)
			if err != nil {
				return nil, fmt.Errorf("binding %s not found: %w", bindingRef, err)
			}
			if binding.ServiceType == bindings.SqliteServiceType {
				if err := countSqlite(bindingRef); err != nil {
					return nil, err
				}
			}
			if !existing[bindingRef] {
				if err := s.enforceBindingPerm(ctx, types.PermissionBindingUse, binding.Path, binding.CreatedBy); err != nil {
					return nil, err
				}
				if binding.ServiceType == bindings.SqliteServiceType {
					if err := s.enforceSqliteSingleAttach(ctx, tx, appID, binding.Path); err != nil {
						return nil, err
					}
				}
			}
			addResolved(bindingRef)
			continue
		}

		source, bindingConfig, err := parseBindingSourceParams(bindingRef)
		if err != nil {
			return nil, err
		}
		service, err := s.serviceForBindingSource(ctx, tx, source)
		if err != nil {
			return nil, err
		}
		autoPath := autoBindingPathForAppID(appID, service.ServiceType)
		if service.ServiceType == bindings.SqliteServiceType {
			if err := countSqlite(autoPath); err != nil {
				return nil, err
			}
		}
		if !existing[autoPath] {
			if err := s.enforceServiceBind(ctx, tx, service); err != nil {
				return nil, err
			}
		}
		if err := s.ensureAutoBinding(ctx, tx, autoPath, source, bindingConfig, service, accounts); err != nil {
			return nil, err
		}
		addResolved(autoPath)
	}
	return resolved, nil
}

// parseBindingSourceParams splits an auto binding reference into the service
// source and its optional binding config params. The syntax is generic for
// any service type: "sqlite;path=/mydata,example=val2" creates the auto
// binding with config {path: /mydata, example: val2}, exactly like binding
// create --config. Values must not contain commas.
func parseBindingSourceParams(bindingRef string) (string, map[string]string, error) {
	source, paramStr, found := strings.Cut(bindingRef, ";")
	if !found {
		return source, nil, nil
	}
	params := map[string]string{}
	for part := range strings.SplitSeq(paramStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return "", nil, fmt.Errorf("invalid binding param %q in %s: expected source;key=value,key2=value2", part, bindingRef)
		}
		params[key] = value
	}
	if len(params) == 0 {
		return source, nil, nil
	}
	return source, params, nil
}

// enforceSqliteSingleAttach rejects attaching a sqlite binding to a second
// app. Sqlite databases are single-writer files on a per-app volume
// (ReadWriteOnce on kubernetes): a second app would either corrupt the
// database or silently get its own empty volume. Auto bindings are per-app by
// construction; only explicitly created base bindings can hit this.
func (s *Server) enforceSqliteSingleAttach(ctx context.Context, tx types.Transaction, appID types.AppId, bindingPath string) error {
	users, err := s.db.AppsUsingBinding(ctx, tx, bindingPath)
	if err != nil {
		return fmt.Errorf("error checking apps using binding %s: %w", bindingPath, err)
	}
	for _, use := range users {
		if use.MainApp != appID {
			return fmt.Errorf("sqlite binding %s is already attached to app %s: sqlite databases are "+
				"single-writer, a binding can be attached to only one app", bindingPath, use.PathDomain)
		}
	}
	return nil
}

func (s *Server) ensureAutoBinding(ctx context.Context, tx types.Transaction, bindingPath, source string,
	bindingConfig map[string]string, service *types.Service, accounts *bindingAccountManager) error {
	binding, err := s.db.GetBinding(ctx, tx, bindingPath)
	if err == nil {
		if binding.ServiceType != service.ServiceType || binding.ServiceName != service.Name {
			return fmt.Errorf("auto binding %s already exists with source %s, cannot use source %s", bindingPath, binding.Source, source)
		}
		// The auto binding's config was applied when it was created (the
		// account may depend on it); a differing config on a later reference
		// is a conflict, not an update
		if len(bindingConfig) > 0 && !equalStringMaps(binding.StagedMetadata.Config, bindingConfig) {
			return fmt.Errorf("auto binding %s already exists with config %v, cannot change it to %v; "+
				"delete the binding to recreate it with the new config", bindingPath, binding.StagedMetadata.Config, bindingConfig)
		}
		return nil
	}
	if !strings.HasPrefix(err.Error(), "binding not found with path: ") {
		return err
	}

	createRequest := &types.CreateBindingRequest{
		Path:   bindingPath,
		Source: source,
		Config: bindingConfig,
	}
	// The auto binding row and its service account share the operation's fate: the
	// row is written on the operation's transaction and the account is tracked on
	// the operation's account manager, which deletes it if the operation rolls back.
	if _, err := s.createBindingTx(ctx, tx, createRequest, accounts, true); err != nil {
		return fmt.Errorf("error creating auto binding %s for service %s: %w", bindingPath, source, err)
	}
	return nil
}

// equalStringMaps compares two config maps, treating nil and empty as equal.
func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (s *Server) serviceForBindingSource(ctx context.Context, tx types.Transaction, source string) (*types.Service, error) {
	serviceType, name, ok := strings.Cut(source, "/")
	if !ok {
		service, err := s.db.GetDefaultService(ctx, tx, source)
		if err != nil {
			return nil, fmt.Errorf("service %s not found", source)
		}
		return service, nil
	}

	service, err := s.db.GetService(ctx, tx, serviceType, name)
	if err != nil {
		return nil, fmt.Errorf("service %s not found", source)
	}
	return service, nil
}
