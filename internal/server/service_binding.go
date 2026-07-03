// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
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
	if err := s.enforceGlobalPerm(ctx, types.PermissionServiceCreate, ""); err != nil {
		return err
	}

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
	if err := serviceBinding.InitializeService(ctx, s.Logger, service.Config, s.serviceBindingRuntime()); err != nil {
		return fmt.Errorf("error initializing service binding: %w", err)
	}
	defer serviceBinding.CloseService(ctx) //nolint:errcheck

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
	if err := s.enforceGlobalPerm(ctx, types.PermissionServiceUpdate, ""); err != nil {
		return err
	}

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
	if err := s.enforceGlobalPerm(ctx, types.PermissionServiceDelete, ""); err != nil {
		return err
	}

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
	if err := s.enforceGlobalPerm(ctx, types.PermissionServiceRead, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	return s.db.ListServices(ctx, tx, serviceType, name)
}

func (s *Server) CreateBinding(ctx context.Context, createRequest *types.CreateBindingRequest, dryRun bool) (*types.Binding, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingCreate, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	accounts := s.newBindingAccountManager(dryRun)
	defer accounts.rollbackAndClose(ctx)

	binding, err := s.createBindingTx(ctx, tx, createRequest, accounts, false)
	if err != nil {
		return nil, err
	}

	if dryRun {
		return binding, nil
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	accounts.commit()

	return binding, nil
}

func (s *Server) createBindingTx(ctx context.Context, tx types.Transaction, createRequest *types.CreateBindingRequest,
	accounts *bindingAccountManager, allowAutoPath bool) (*types.Binding, error) {
	var err error
	binding := types.Binding{
		Path:   createRequest.Path,
		Source: createRequest.Source,
		StagedMetadata: types.BindingMetadata{
			Grants:    normalizeGrantList(createRequest.Grants),
			Config:    createRequest.Config,
			ApplyInfo: createRequest.ApplyInfo,
		},
	}
	if err := validateBindingCreatePath(binding.Path, allowAutoPath); err != nil {
		return nil, err
	}
	binding.Id, err = newPrefixedId(types.ID_PREFIX_BINDING)
	if err != nil {
		return nil, err
	}

	_, err = s.db.GetBinding(ctx, tx, binding.Path)
	if err == nil {
		return nil, fmt.Errorf("binding already exists: %s", binding.Path)
	}

	if binding.Source == "" {
		return nil, fmt.Errorf("binding source is required")
	}

	var service *types.Service
	var derivedFrom *types.Binding
	if strings.HasPrefix(binding.Source, "/") {
		// Reference another binding by path - derived binding
		derivedFrom, err = s.db.GetBinding(ctx, tx, binding.Source)
		if err != nil {
			return nil, fmt.Errorf("binding source %s not found", binding.Source)
		}

		// Reject multi-level nesting. A derived binding must be derived from a
		// base binding (one whose Source points at a service, not at another
		// binding). Allowing derived-of-derived would make ALTER DEFAULT
		// PRIVILEGES reference the wrong creator role
		if derivedFrom.DerivedFrom != "" {
			return nil, fmt.Errorf(
				"cannot derive binding %s from another derived binding %s; "+
					"derive from the base binding %s instead",
				binding.Path, derivedFrom.Path, derivedFrom.DerivedFrom)
		}

		binding.ServiceType = derivedFrom.ServiceType
		binding.ServiceName = derivedFrom.ServiceName
		binding.DerivedFrom = binding.Source

		service, err = s.db.GetService(ctx, tx, derivedFrom.ServiceType, derivedFrom.ServiceName)
		if err != nil {
			return nil, fmt.Errorf("error getting base binding service: %w", err)
		}
	} else {
		// Base binding
		if len(binding.StagedMetadata.Grants) > 0 {
			return nil, fmt.Errorf("grants are not supported for base bindings, only derived bindings can have grants")
		}
		service, err = s.serviceForBindingSource(ctx, tx, binding.Source)
		if err != nil {
			return nil, err
		}

		binding.ServiceType = service.ServiceType
		binding.ServiceName = service.Name
		binding.DerivedFrom = ""
	}
	binding.Metadata = binding.StagedMetadata

	if err := s.db.CreateBinding(ctx, tx, &binding); err != nil {
		return nil, err
	}

	stagingService := service
	if service.Staging != "" {
		stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
		if err != nil {
			return nil, fmt.Errorf("error getting staging service: %w", err)
		}
	}

	// Generate the staging account info, either against the staging service if set or against the main service.
	// The account artifacts are persisted on the service immediately (outside the metadata transaction);
	// the account manager deletes them if the operation is rolled back. Skipped on dry run.
	binding.StagedMetadata.Account, binding.StagedMetadata.GrantsApplied, err = accounts.generateAccount(ctx, stagingService, &binding, derivedFrom, true, true)
	if err != nil {
		return nil, fmt.Errorf("error generating staging account: %w", err)
	}

	// Generate the production account info
	binding.Metadata.Account, binding.Metadata.GrantsApplied, err = accounts.generateAccount(ctx, service, &binding, derivedFrom, false, true)
	if err != nil {
		return nil, err
	}
	if err := s.db.UpdateBinding(ctx, tx, &binding); err != nil {
		return nil, err
	}

	return &binding, nil
}

func validateBindingCreatePath(bindingPath string, allowAutoPath bool) error {
	if !allowAutoPath && (bindingPath == autoBindingPathPrefix || strings.HasPrefix(bindingPath, autoBindingPathPrefix+"/")) {
		return fmt.Errorf("binding path cannot start with /auto; /auto is reserved for autobindings")
	}
	return nil
}

func (s *Server) getServiceBinding(ctx context.Context, service *types.Service, binding *types.Binding) (bindings.ServiceBinding, error) {
	builder, ok := bindings.ServiceBindings[service.ServiceType]
	if !ok {
		return nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	var err error
	serviceBinding := builder()
	if err = serviceBinding.InitializeService(ctx, s.Logger, service.Config, s.serviceBindingRuntime()); err != nil {
		return nil, fmt.Errorf("error initializing service: %w", err)
	}

	return serviceBinding, nil
}

func (s *Server) serviceBindingRuntime() bindings.ServiceBindingRuntime {
	containerCommand := ""
	if s.config != nil {
		containerCommand = s.config.System.ContainerCommand
	}
	return bindings.ServiceBindingRuntime{
		LocalhostBindingHostname: container.LocalhostBindingHostname(containerCommand),
	}
}

// bindingAccountManager caches service binding connections and tracks the artifacts
// (roles, schemas, users, databases) created on external services. Artifacts are
// persisted on the service as soon as they are created, so apps using the binding
// (e.g. during verify) see them right away. If the metadata transaction is rolled
// back, rollbackAndClose deletes the artifacts created since the last commit. Only
// artifacts reported as created by GenerateAccount during this manager's lifetime are
// ever deleted; pre-existing objects on the service are never touched.
// On dry run no service connections are opened and no artifacts are created.
type bindingAccountManager struct {
	server   *Server
	dryRun   bool
	services map[string]bindings.ServiceBinding
	created  []createdArtifact
}

type createdArtifact struct {
	serviceBinding bindings.ServiceBinding
	artifact       bindings.Artifact
}

func (s *Server) newBindingAccountManager(dryRun bool) *bindingAccountManager {
	return &bindingAccountManager{
		server:   s,
		dryRun:   dryRun,
		services: map[string]bindings.ServiceBinding{},
	}
}

func bindingServiceKey(service *types.Service) string {
	return service.ServiceType + "/" + service.Name
}

func (m *bindingAccountManager) getServiceBinding(ctx context.Context, service *types.Service, binding *types.Binding) (bindings.ServiceBinding, error) {
	key := bindingServiceKey(service)
	if serviceBinding, ok := m.services[key]; ok {
		return serviceBinding, nil
	}

	serviceBinding, err := m.server.getServiceBinding(ctx, service, binding)
	if err != nil {
		return nil, err
	}
	m.services[key] = serviceBinding
	return serviceBinding, nil
}

// generateAccount creates the binding account on the service and applies the grants for
// derived bindings. The created account is tracked so rollbackAndClose can delete it.
// On dry run nothing is created and an empty account is returned.
func (m *bindingAccountManager) generateAccount(ctx context.Context, service *types.Service, binding *types.Binding, derivedFrom *types.Binding,
	isStaging, reapplyAll bool) (map[string]string, []types.BindingGrant, error) {
	if _, ok := bindings.ServiceBindings[service.ServiceType]; !ok {
		return nil, nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}
	if m.dryRun {
		return nil, nil, nil
	}

	serviceBinding, err := m.getServiceBinding(ctx, service, binding)
	if err != nil {
		return nil, nil, err
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

	// Track the created artifacts before checking the error: on a partial failure the
	// artifacts that were already created are returned with the error, and the
	// deferred rollbackAndClose deletes them.
	account, createdArtifacts, err := serviceBinding.GenerateAccount(ctx, binding.Id, binding.Path, metadata, derivedFromMetadata, isStaging)
	for _, artifact := range createdArtifacts {
		m.created = append(m.created, createdArtifact{serviceBinding: serviceBinding, artifact: artifact})
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error generating account: %w", err)
	}

	grantsApplied := []types.BindingGrant{}
	if derivedFromMetadata != nil {
		grantsApplied, err = serviceBinding.ApplyGrants(ctx, account, metadata, *derivedFromMetadata, reapplyAll)
		if err != nil {
			return nil, nil, fmt.Errorf("error applying grants: %w", err)
		}
	}

	return account, grantsApplied, nil
}

// applyGrants applies the grants for a derived binding. Grant changes are persisted
// on the service immediately. On dry run nothing is changed and the currently
// applied grants are returned.
func (m *bindingAccountManager) applyGrants(ctx context.Context, service *types.Service, binding *types.Binding, derivedFrom *types.Binding,
	isStaging bool, reapplyAll bool) ([]types.BindingGrant, error) {
	if _, ok := bindings.ServiceBindings[service.ServiceType]; !ok {
		return nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	metadata := binding.Metadata
	if isStaging {
		metadata = binding.StagedMetadata
	}
	if m.dryRun {
		return metadata.GrantsApplied, nil
	}

	serviceBinding, err := m.getServiceBinding(ctx, service, binding)
	if err != nil {
		return nil, err
	}

	derivedFromMetadata := derivedFrom.Metadata
	if isStaging {
		derivedFromMetadata = derivedFrom.StagedMetadata
	}

	grantsApplied, err := serviceBinding.ApplyGrants(ctx, metadata.Account, metadata, derivedFromMetadata, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error applying grants: %w", err)
	}
	return grantsApplied, nil
}

// commit keeps the created artifacts. Call after the metadata transaction has committed;
// the artifacts are already persisted on the services, this just stops rollbackAndClose
// from deleting them.
func (m *bindingAccountManager) commit() {
	if m == nil {
		return
	}
	m.created = nil
}

// rollbackAndClose deletes the artifacts created since the last commit, in reverse
// creation order, and closes the service connections. Deletes are best-effort;
// failures are logged.
func (m *bindingAccountManager) rollbackAndClose(ctx context.Context) {
	if m == nil {
		return
	}
	// Use a non-cancelable context so cleanup still runs when rolling back due to
	// cancellation of the original context.
	cleanupCtx := context.WithoutCancel(ctx)
	for i := len(m.created) - 1; i >= 0; i-- {
		created := m.created[i]
		if err := created.serviceBinding.DeleteArtifact(cleanupCtx, created.artifact); err != nil {
			m.server.Warn().Err(err).Str("type", string(created.artifact.Type)).Str("name", created.artifact.Name).
				Msg("error deleting binding artifact during rollback")
		}
	}
	m.created = nil
	for _, serviceBinding := range m.services {
		serviceBinding.CloseService(cleanupCtx) //nolint:errcheck
	}
	m.services = map[string]bindings.ServiceBinding{}
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

func (s *Server) UpdateBinding(ctx context.Context, updateRequest types.UpdateBindingRequest, dryRun, promote, reapplyAll bool) (*types.Binding, error) {
	if len(updateRequest.AddGrants) == 0 && len(updateRequest.DeleteGrants) == 0 && !promote && !reapplyAll {
		return nil, fmt.Errorf("expected at least one grant update, promote, or reapply-all")
	}

	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingUpdate, ""); err != nil {
		return nil, err
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

	accounts := s.newBindingAccountManager(dryRun)
	defer accounts.rollbackAndClose(ctx)

	binding.StagedMetadata.GrantsApplied, err = accounts.applyGrants(ctx, stagingService, binding, derivedFrom, true, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error applying staging grants: %w", err)
	}

	if promote {
		binding.Metadata.Grants = binding.StagedMetadata.Grants
		binding.Metadata.GrantsApplied, err = accounts.applyGrants(ctx, service, binding, derivedFrom, false, reapplyAll)
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
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingDelete, ""); err != nil {
		return err
	}

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
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingRead, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		return nil, err
	}
	return redactBindingAccount(binding), nil
}

// GetBindingWithAccount gets the binding with the account info un-redacted.
func (s *Server) GetBindingWithAccount(ctx context.Context, tx types.Transaction, path string) (*types.Binding, error) {
	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		return nil, err
	}
	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return nil, fmt.Errorf("error getting binding service: %w", err)
	}
	binding.ServiceIsDefault = service.IsDefault
	return binding, nil
}

func (s *Server) ListBindings(ctx context.Context, source string) ([]*types.Binding, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	bindings, err := s.db.ListBindings(ctx, tx, source)
	if err != nil {
		return nil, err
	}
	for i, binding := range bindings {
		bindings[i] = redactBindingAccount(binding)
	}
	return bindings, nil
}

func redactBindingAccount(binding *types.Binding) *types.Binding {
	if binding == nil {
		return nil
	}
	redacted := *binding
	redacted.Metadata.Account = nil
	redacted.StagedMetadata.Account = nil
	return &redacted
}

func (s *Server) GetBindingAccount(ctx context.Context, path string, useStaging bool) (map[string]string, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingRead, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		return nil, err
	}
	if useStagedBindingMetadata(binding, useStaging) {
		return binding.StagedMetadata.Account, nil
	}
	return binding.Metadata.Account, nil
}

func (s *Server) RunBindingCommand(ctx context.Context, bindingName string, useStaging bool, command string) (map[string]any, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingRunCommand, ""); err != nil {
		return nil, err
	}

	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("sql is required")
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, bindingName)
	if err != nil {
		return nil, err
	}

	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return nil, fmt.Errorf("error getting binding service: %w", err)
	}

	metadata := binding.Metadata
	if useStagedBindingMetadata(binding, useStaging) {
		metadata = binding.StagedMetadata
		if service.Staging != "" {
			service, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
			if err != nil {
				return nil, fmt.Errorf("error getting staging service: %w", err)
			}
		}
	}

	serviceBinding, err := s.getServiceBinding(ctx, service, binding)
	if err != nil {
		return nil, fmt.Errorf("error getting service binding: %w", err)
	}

	defer serviceBinding.CloseService(ctx) //nolint:errcheck

	return serviceBinding.RunCommand(ctx, metadata, command)
}
