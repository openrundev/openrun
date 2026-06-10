// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"

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
func (s *Server) resolveAppBindings(ctx context.Context, tx types.Transaction, appID types.AppId,
	bindingRefs []string, dryRun bool) ([]string, error) {
	resolved := make([]string, 0, len(bindingRefs))
	seen := make(map[string]bool, len(bindingRefs))
	addResolved := func(path string) {
		if !seen[path] {
			resolved = append(resolved, path)
			seen[path] = true
		}
	}

	for _, bindingRef := range bindingRefs {
		if bindingRef == "" {
			return nil, fmt.Errorf("binding path cannot be empty")
		}
		if strings.HasPrefix(bindingRef, "/") {
			if _, err := s.db.GetBinding(ctx, tx, bindingRef); err != nil {
				return nil, fmt.Errorf("binding %s not found: %w", bindingRef, err)
			}
			addResolved(bindingRef)
			continue
		}

		service, err := s.serviceForBindingSource(ctx, tx, bindingRef)
		if err != nil {
			return nil, err
		}
		autoPath := autoBindingPathForAppID(appID, service.ServiceType)
		if err := s.ensureAutoBinding(ctx, tx, autoPath, bindingRef, service, dryRun); err != nil {
			return nil, err
		}
		addResolved(autoPath)
	}
	return resolved, nil
}

func (s *Server) ensureAutoBinding(ctx context.Context, tx types.Transaction, bindingPath, source string, service *types.Service, dryRun bool) error {
	binding, err := s.db.GetBinding(ctx, tx, bindingPath)
	if err == nil {
		if binding.ServiceType != service.ServiceType || binding.ServiceName != service.Name {
			return fmt.Errorf("auto binding %s already exists with source %s, cannot use source %s", bindingPath, binding.Source, source)
		}
		return nil
	}
	if !strings.HasPrefix(err.Error(), "binding not found with path: ") {
		return err
	}

	createRequest := &types.CreateBindingRequest{
		Path:   bindingPath,
		Source: source,
	}
	accounts := s.newBindingAccountManager(dryRun)
	defer accounts.rollbackAndClose(ctx)
	if _, err := s.createBindingTx(ctx, tx, createRequest, accounts, true); err != nil {
		return fmt.Errorf("error creating auto binding %s for service %s: %w", bindingPath, source, err)
	}
	// The auto binding account is kept once created; it is not removed if the
	// caller's metadata transaction is rolled back.
	accounts.commit()
	return nil
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
