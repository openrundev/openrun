// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

func newPrefixedId(prefix string) (string, error) {
	genId, err := ksuid.NewRandom()
	if err != nil {
		return "", err
	}
	return prefix + strings.ToLower(genId.String()), nil
}

func (s *Server) validateStagingService(ctx context.Context, tx types.Transaction, service *types.Service) error {
	if service.Staging == "" {
		return nil
	}
	if service.Staging == service.Name {
		return fmt.Errorf("staging service %s/%s cannot refer to itself", service.ServiceType, service.Name)
	}

	exists, err := s.db.ServiceExists(ctx, tx, service.ServiceType, service.Staging)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("staging service %s/%s not found", service.ServiceType, service.Staging)
	}
	return nil
}

func (s *Server) CreateService(ctx context.Context, service *types.Service, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	service.Id, err = newPrefixedId(types.ID_PREFIX_SERVICE)
	if err != nil {
		return err
	}

	builder, ok := bindings.ServiceBindings[service.ServiceType]
	if !ok {
		return fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	serviceBinding := builder()
	if err := serviceBinding.InitializeService(ctx, s.Logger, service.Config); err != nil {
		return fmt.Errorf("error initializing service binding: %w", err)
	}

	count, err := s.db.CountServices(ctx, tx, service.ServiceType)
	if err != nil {
		return err
	}
	if count == 0 {
		// First service of this type automatically becomes the default
		service.IsDefault = true
	} else if service.IsDefault {
		// Clear any existing default for this service_type
		if err := s.db.ClearServiceDefault(ctx, tx, service.ServiceType, ""); err != nil {
			return err
		}
	}

	if err := s.validateStagingService(ctx, tx, service); err != nil {
		return err
	}

	if err := s.db.CreateService(ctx, tx, service); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	return tx.Commit()
}

func (s *Server) UpdateService(ctx context.Context, service *types.Service, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if service.IsDefault {
		// Clear default flag on any other service of this type
		if err := s.db.ClearServiceDefault(ctx, tx, service.ServiceType, service.Name); err != nil {
			return err
		}
	}

	if err := s.validateStagingService(ctx, tx, service); err != nil {
		return err
	}

	if err := s.db.UpdateService(ctx, tx, service); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	return tx.Commit()
}

func (s *Server) DeleteService(ctx context.Context, name, serviceType string, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := s.db.DeleteService(ctx, tx, name, serviceType); err != nil {
		return err
	}
	if err := s.db.ClearServiceStaging(ctx, tx, serviceType, name); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	return tx.Commit()
}

func (s *Server) ListServices(ctx context.Context, serviceType, name string) ([]*types.Service, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	return s.db.ListServices(ctx, tx, serviceType, name)
}

func (s *Server) CreateBinding(ctx context.Context, binding *types.Binding, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	binding.Id, err = newPrefixedId(types.ID_PREFIX_BINDING)
	if err != nil {
		return err
	}

	_, err = s.db.GetBinding(ctx, tx, binding.Path)
	if err == nil {
		return fmt.Errorf("binding already exists: %s", binding.Path)
	}

	if binding.Source == "" {
		return fmt.Errorf("binding source is required")
	}
	binding.StagedMetadata.Grants = normalizeGrantList(binding.StagedMetadata.Grants)

	var service *types.Service
	var derivedFrom *types.Binding
	if strings.HasPrefix(binding.Source, "/") {
		// Reference another binding by path - derived binding
		derivedFrom, err = s.db.GetBinding(ctx, tx, binding.Source)
		if err != nil {
			return fmt.Errorf("binding source %s not found", binding.Source)
		}

		// Reject multi-level nesting. A derived binding must be derived from a
		// base binding (one whose Source points at a service, not at another
		// binding). Allowing derived-of-derived would make ALTER DEFAULT
		// PRIVILEGES reference the wrong creator role
		if derivedFrom.DerivedFrom != "" {
			return fmt.Errorf(
				"cannot derive binding %s from another derived binding %s; "+
					"derive from the base binding %s instead",
				binding.Path, derivedFrom.Path, derivedFrom.DerivedFrom)
		}

		binding.ServiceType = derivedFrom.ServiceType
		binding.ServiceName = derivedFrom.ServiceName
		binding.DerivedFrom = binding.Source

		service, err = s.db.GetService(ctx, tx, derivedFrom.ServiceType, derivedFrom.ServiceName)
		if err != nil {
			return fmt.Errorf("error getting base binding service: %w", err)
		}
	} else {
		// Base binding
		if len(binding.StagedMetadata.Grants) > 0 {
			return fmt.Errorf("grants are not supported for base bindings, only derived bindings can have grants")
		}
		serviceType, name, ok := strings.Cut(binding.Source, "/")
		if !ok {
			// Reference a service by type alone
			service, err = s.db.GetDefaultService(ctx, tx, binding.Source)
			if err != nil {
				return fmt.Errorf("service %s not found", binding.Source)
			}
		} else {
			// Reference a service by type and name
			service, err = s.db.GetService(ctx, tx, serviceType, name)
			if err != nil {
				return fmt.Errorf("service %s not found", binding.Source)
			}
		}

		binding.ServiceType = service.ServiceType
		binding.ServiceName = service.Name
		binding.DerivedFrom = ""
	}
	binding.Metadata = binding.StagedMetadata

	if err := s.db.CreateBinding(ctx, tx, binding); err != nil {
		return err
	}

	stagingService := service
	if service.Staging != "" {
		stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
		if err != nil {
			return fmt.Errorf("error getting staging service: %w", err)
		}
	}

	// Not dry run, generate the account info
	// Generate the staging account info, either against the staging service if set or against the main service
	binding.StagedMetadata.Account, binding.StagedMetadata.GrantsApplied, err = s.generateAccount(ctx, dryRun, stagingService, binding, derivedFrom, true, true)
	if err != nil {
		return fmt.Errorf("error generating staging account: %w", err)
	}

	// Generate the production account info
	// This runs as a separate transaction, since it might not be against same database as the metadata database
	binding.Metadata.Account, binding.Metadata.GrantsApplied, err = s.generateAccount(ctx, dryRun, service, binding, derivedFrom, false, true)
	if err != nil {
		return err
	}
	if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
		return err
	}

	if dryRun {
		return nil
	}

	return tx.Commit()
}

func (s *Server) generateAccount(ctx context.Context, dryRun bool, service *types.Service, binding *types.Binding, derivedFrom *types.Binding, isStaging, reapplyAll bool) (map[string]string, []types.BindingGrant, error) {
	builder, ok := bindings.ServiceBindings[service.ServiceType]
	if !ok {
		return nil, nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	var err error
	serviceBinding := builder()
	if err = serviceBinding.InitializeService(ctx, s.Logger, service.Config); err != nil {
		return nil, nil, fmt.Errorf("error initializing service: %w", err)
	}

	metadata := binding.Metadata
	if isStaging {
		metadata = binding.StagedMetadata
	}

	var derivedFromMetadata *types.BindingMetadata
	if derivedFrom != nil {
		derivedFromMetadata = &derivedFrom.Metadata
		if isStaging {
			derivedFromMetadata = &derivedFrom.StagedMetadata
		}
	}

	ctx, err = serviceBinding.BeginTransaction(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error beginning transaction: %w", err)
	}
	defer serviceBinding.RollbackTransaction(ctx) //nolint:errcheck

	account, err := serviceBinding.GenerateAccount(ctx, binding.Id, binding.Path, metadata, derivedFromMetadata, isStaging)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating account: %w", err)
	}

	grantsApplied := []types.BindingGrant{}
	if derivedFrom != nil {
		grantsApplied, err = serviceBinding.ApplyGrants(ctx, account, metadata, *derivedFromMetadata, reapplyAll)
		if err != nil {
			return nil, nil, fmt.Errorf("error applying grants: %w", err)
		}
	}

	if !dryRun {
		if err := serviceBinding.CommitTransaction(ctx); err != nil {
			return nil, nil, fmt.Errorf("error committing transaction: %w", err)
		}
	}

	return account, grantsApplied, nil
}

func (s *Server) applyBindingGrants(ctx context.Context, dryRun bool, service *types.Service,
	binding *types.Binding, derivedFrom *types.Binding, isStaging bool, reapplyAll bool) ([]types.BindingGrant, error) {
	builder, ok := bindings.ServiceBindings[service.ServiceType]
	if !ok {
		return nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	serviceBinding := builder()
	if err := serviceBinding.InitializeService(ctx, s.Logger, service.Config); err != nil {
		return nil, fmt.Errorf("error initializing service: %w", err)
	}

	metadata := binding.Metadata
	if isStaging {
		metadata = binding.StagedMetadata
	}

	derivedFromMetadata := derivedFrom.Metadata
	if isStaging {
		derivedFromMetadata = derivedFrom.StagedMetadata
	}

	ctx, err := serviceBinding.BeginTransaction(ctx)
	if err != nil {
		return nil, fmt.Errorf("error beginning transaction: %w", err)
	}
	defer serviceBinding.RollbackTransaction(ctx) //nolint:errcheck

	grantsApplied, err := serviceBinding.ApplyGrants(ctx, metadata.Account, metadata, derivedFromMetadata, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error applying grants: %w", err)
	}

	if !dryRun {
		if err := serviceBinding.CommitTransaction(ctx); err != nil {
			return nil, fmt.Errorf("error committing transaction: %w", err)
		}
	}

	return grantsApplied, nil
}

func normalizeGrantForStorage(grant string) string {
	grantType, grantTarget, ok := strings.Cut(grant, ":")
	if !ok {
		return strings.TrimSpace(grant)
	}
	return strings.ToLower(strings.TrimSpace(grantType)) + ":" + strings.TrimSpace(grantTarget)
}

func normalizeGrantList(grants []string) []string {
	normalized := make([]string, 0, len(grants))
	for _, grant := range grants {
		normalizedGrant := normalizeGrantForStorage(grant)
		if !slices.Contains(normalized, normalizedGrant) {
			normalized = append(normalized, normalizedGrant)
		}
	}
	return normalized
}

func mergeGrantUpdates(current, addGrants, deleteGrants []string) []string {
	merged := normalizeGrantList(current)
	for _, grant := range normalizeGrantList(deleteGrants) {
		for {
			index := slices.Index(merged, grant)
			if index == -1 {
				break
			}
			merged = slices.Delete(merged, index, index+1)
		}
	}
	for _, grant := range normalizeGrantList(addGrants) {
		if !slices.Contains(merged, grant) {
			merged = append(merged, grant)
		}
	}
	return merged
}

func (s *Server) UpdateBinding(ctx context.Context, updateRequest types.UpdateBindingRequest, dryRun, promote bool) (*types.Binding, error) {
	if len(updateRequest.AddGrants) == 0 && len(updateRequest.DeleteGrants) == 0 && !promote {
		return nil, fmt.Errorf("expected at least one grant update or promote")
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, updateRequest.Path)
	if err != nil {
		return nil, err
	}
	if binding.DerivedFrom == "" {
		return nil, fmt.Errorf("grants are not supported for base bindings, only derived bindings can have grants")
	}

	derivedFrom, err := s.db.GetBinding(ctx, tx, binding.DerivedFrom)
	if err != nil {
		return nil, fmt.Errorf("base binding %s not found: %w", binding.DerivedFrom, err)
	}

	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return nil, fmt.Errorf("error getting binding service: %w", err)
	}

	binding.StagedMetadata.Grants = mergeGrantUpdates(binding.StagedMetadata.Grants, updateRequest.AddGrants, updateRequest.DeleteGrants)

	stagingService := service
	if service.Staging != "" {
		stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
		if err != nil {
			return nil, fmt.Errorf("error getting staging service: %w", err)
		}
	}
	binding.StagedMetadata.GrantsApplied, err = s.applyBindingGrants(ctx, dryRun, stagingService, binding, derivedFrom, true, false)
	if err != nil {
		return nil, fmt.Errorf("error applying staging grants: %w", err)
	}

	if promote {
		binding.Metadata.Grants = binding.StagedMetadata.Grants
		binding.Metadata.GrantsApplied, err = s.applyBindingGrants(ctx, dryRun, service, binding, derivedFrom, false, false)
		if err != nil {
			return nil, err
		}
	}

	if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
		return nil, err
	}

	if dryRun {
		return binding, nil
	}
	return binding, tx.Commit()
}

func (s *Server) DeleteBinding(ctx context.Context, path string, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := s.db.DeleteBinding(ctx, tx, path); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	return tx.Commit()
}

func (s *Server) GetBinding(ctx context.Context, path string) (*types.Binding, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	return s.db.GetBinding(ctx, tx, path)
}

func (s *Server) ListBindings(ctx context.Context, source string) ([]*types.Binding, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	return s.db.ListBindings(ctx, tx, source)
}
