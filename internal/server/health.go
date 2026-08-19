// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

const (
	// healthCheckTimeout bounds one backend dial: a hung backend must not pin
	// the aggregate call (and its HTTP request) indefinitely
	healthCheckTimeout = 10 * time.Second
	// healthCheckConcurrency caps concurrent backend dials per aggregate call
	healthCheckConcurrency = 5
	// healthCacheTTL is how long a check result is served from the cache. The
	// console fires the aggregate calls on every bindings page render (and
	// re-render), so repeat calls within the TTL must not re-dial backends.
	// The cache is per target and SHARED across callers (a health status is
	// not caller-specific); per-caller visibility is applied on the listing
	// before the cache is consulted.
	healthCacheTTL = 2 * time.Minute
)

// ServiceHealthResult is one service's aggregate health check outcome
type ServiceHealthResult struct {
	Id      string `json:"id"` // <service_type>/<name>
	Healthy bool   `json:"healthy"`
	Error   string `json:"error"`
}

// BindingHealthResult is one binding's aggregate health check outcome. The
// prod and staging accounts are separate accounts on the backend (and the
// staging account may live on a linked staging service), so both are checked.
type BindingHealthResult struct {
	Path           string `json:"path"`
	Healthy        bool   `json:"healthy"` // the prod account
	Error          string `json:"error"`
	StagingHealthy bool   `json:"staging_healthy"`
	StagingError   string `json:"staging_error"`
}

// healthCacheEntry caches one target's check result. An entry is valid while
// updateKey matches the target's current update times (a service or binding
// config edit invalidates immediately) and checkedAt is within healthCacheTTL.
type healthCacheEntry struct {
	updateKey string
	checkedAt time.Time
	result    any
}

func (s *Server) healthCacheGet(key, updateKey string) (any, bool) {
	val, ok := s.healthCache.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(healthCacheEntry)
	if entry.updateKey != updateKey || time.Since(entry.checkedAt) > healthCacheTTL {
		return nil, false
	}
	return entry.result, true
}

func (s *Server) healthCachePut(key, updateKey string, result any) {
	s.healthCache.Store(key, healthCacheEntry{updateKey: updateKey, checkedAt: time.Now(), result: result})
}

// healthErrString formats a check error, mapping a deadline hit to a readable
// timeout message
func healthErrString(ctx context.Context, err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
		return fmt.Sprintf("health check timed out after %s", healthCheckTimeout)
	}
	return err.Error()
}

// runHealthChecks runs the check funcs concurrently, capped at
// healthCheckConcurrency, each under its own healthCheckTimeout context
func runHealthChecks(ctx context.Context, checks []func(ctx context.Context)) {
	sem := make(chan struct{}, healthCheckConcurrency)
	var wg sync.WaitGroup
	for _, check := range checks {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			tctx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
			defer cancel()
			check(tctx)
		})
	}
	wg.Wait()
}

// ServicesHealth checks the health of every service the caller holds
// service:read on (the ListServices visibility rule) and reports per-service
// status. Checks run concurrently with a per-check timeout; results are
// cached for healthCacheTTL, keyed on the service's update time so a config
// edit invalidates immediately.
func (s *Server) ServicesHealth(ctx context.Context) ([]ServiceHealthResult, error) {
	services, err := s.ListServices(ctx, "", "")
	if err != nil {
		return nil, err
	}

	results := make([]ServiceHealthResult, len(services))
	checks := make([]func(ctx context.Context), 0, len(services))
	for i, service := range services {
		id := service.ServiceType + "/" + service.Name
		cacheKey := "service:" + id
		updateKey := service.UpdateTime.UTC().Format(time.RFC3339Nano)
		if cached, ok := s.healthCacheGet(cacheKey, updateKey); ok {
			results[i] = cached.(ServiceHealthResult)
			continue
		}
		checks = append(checks, func(ctx context.Context) {
			checkErr := s.dialServiceHealth(ctx, service)
			results[i] = ServiceHealthResult{Id: id, Healthy: checkErr == nil, Error: healthErrString(ctx, checkErr)}
			s.healthCachePut(cacheKey, updateKey, results[i])
		})
	}
	runHealthChecks(ctx, checks)

	sort.Slice(results, func(i, j int) bool { return results[i].Id < results[j].Id })
	return results, nil
}

// bindingHealthKind filters BindingsHealth to one bindings table: "base"
// (non-derived, non-auto), "derived", "auto" (/auto/... app bindings) or ""
// for all bindings
func bindingHealthKindMatch(kind string, binding *types.Binding) (bool, error) {
	isAuto := strings.HasPrefix(binding.Path, autoBindingPathPrefix+"/")
	switch kind {
	case "":
		return true, nil
	case "base":
		return !isAuto && binding.DerivedFrom == "", nil
	case "derived":
		return !isAuto && binding.DerivedFrom != "", nil
	case "auto":
		return isAuto, nil
	default:
		return false, fmt.Errorf("invalid binding health kind %q: use base, derived or auto", kind)
	}
}

// BindingsHealth checks the health of every binding the caller holds
// binding:read on (the ListBindings visibility rule), filtered by kind, and
// reports per-binding status for both the prod and the staging account (the
// staging account is checked against the linked staging service when the
// binding's service sets one). Checks run concurrently with a per-check
// timeout; results are cached for healthCacheTTL, keyed on the binding's and
// its services' update times so a config edit invalidates immediately.
func (s *Server) BindingsHealth(ctx context.Context, kind string) ([]BindingHealthResult, error) {
	if _, err := bindingHealthKindMatch(kind, &types.Binding{}); err != nil {
		return nil, err
	}

	// The bindings are read unredacted: the check connects to the backend AS
	// the binding account, which needs the account credentials. The results
	// carry no credentials. The transaction is released before any backend is
	// dialed (a slow or unavailable service must not hold one open).
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	allBindings, err := s.db.ListBindings(ctx, tx, "")
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return nil, err
	}
	allServices, err := s.db.ListServices(ctx, tx, "", "")
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return nil, err
	}
	tx.Rollback() //nolint:errcheck

	// Service lookup is unfiltered: checking a binding needs binding:read
	// only, not service:read on its service (same rule as bindingBackendTarget)
	serviceMap := make(map[string]*types.Service, len(allServices))
	for _, service := range allServices {
		serviceMap[service.ServiceType+"/"+service.Name] = service
	}

	rbacEnforced := s.rbacManager.APIEnforced(ctx)
	selected := make([]*types.Binding, 0, len(allBindings))
	for _, binding := range allBindings {
		match, _ := bindingHealthKindMatch(kind, binding)
		if !match {
			continue
		}
		if rbacEnforced {
			// Visibility mirrors ListBindings: only bindings the caller holds
			// binding:read on are checked and reported
			authorized, err := s.rbacManager.AuthorizeResourceAPI(ctx,
				types.PermissionBindingRead, binding.Path, binding.CreatedBy)
			if err != nil {
				return nil, err
			}
			if !authorized {
				continue
			}
		}
		selected = append(selected, binding)
	}

	results := make([]BindingHealthResult, len(selected))
	checks := make([]func(ctx context.Context), 0, len(selected))
	for i, binding := range selected {
		prodService := serviceMap[binding.ServiceType+"/"+binding.ServiceName]
		if prodService == nil {
			errStr := fmt.Sprintf("no service found with name %s and service_type %s",
				binding.ServiceName, binding.ServiceType)
			results[i] = BindingHealthResult{Path: binding.Path, Error: errStr, StagingError: errStr}
			continue
		}
		// A missing staging service is reported on the staging side; prod is
		// still checkable against the binding's own service
		stagingService := prodService
		stagingMissing := false
		if prodService.Staging != "" {
			stagingService = serviceMap[prodService.ServiceType+"/"+prodService.Staging]
			if stagingService == nil {
				stagingMissing = true
				stagingService = prodService
			}
		}

		// Dev auto bindings only carry a staged account; check it as both envs
		prodMetadata := binding.Metadata
		if useStagedBindingMetadata(binding, false) {
			prodMetadata = binding.StagedMetadata
		}
		stagingMetadata := binding.StagedMetadata

		updateKey := binding.UpdateTime.UTC().Format(time.RFC3339Nano) + "|" +
			prodService.UpdateTime.UTC().Format(time.RFC3339Nano) + "|" +
			stagingService.UpdateTime.UTC().Format(time.RFC3339Nano)
		cacheKey := "binding:" + binding.Path
		if cached, ok := s.healthCacheGet(cacheKey, updateKey); ok {
			results[i] = cached.(BindingHealthResult)
			continue
		}

		checks = append(checks, func(ctx context.Context) {
			result := BindingHealthResult{Path: binding.Path}
			prodErr := s.dialBindingHealth(ctx, prodService, prodMetadata)
			result.Healthy = prodErr == nil
			result.Error = healthErrString(ctx, prodErr)
			if stagingMissing {
				result.StagingError = fmt.Sprintf("no staging service found with name %s and service_type %s",
					prodService.Staging, prodService.ServiceType)
			} else {
				stagingErr := s.dialBindingHealth(ctx, stagingService, stagingMetadata)
				result.StagingHealthy = stagingErr == nil
				result.StagingError = healthErrString(ctx, stagingErr)
			}
			results[i] = result
			s.healthCachePut(cacheKey, updateKey, result)
		})
	}
	runHealthChecks(ctx, checks)

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}

// dialServiceHealth connects to the service with the admin credentials and
// runs its no-op health operation
func (s *Server) dialServiceHealth(ctx context.Context, service *types.Service) error {
	serviceBinding, err := s.getServiceBinding(ctx, service)
	if err != nil {
		return fmt.Errorf("error connecting to service: %w", err)
	}
	defer serviceBinding.CloseService(ctx) //nolint:errcheck

	return serviceBinding.CheckHealth(ctx)
}

// dialBindingHealth connects to the service AS the binding account described
// by metadata and runs its no-op health operation
func (s *Server) dialBindingHealth(ctx context.Context, service *types.Service, metadata types.BindingMetadata) error {
	serviceBinding, err := s.getServiceBinding(ctx, service)
	if err != nil {
		return fmt.Errorf("error connecting to service: %w", err)
	}
	defer serviceBinding.CloseService(ctx) //nolint:errcheck

	return serviceBinding.CheckBindingHealth(ctx, metadata)
}
