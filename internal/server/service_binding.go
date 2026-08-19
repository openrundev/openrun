// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
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

// serviceRBACId is the service identity RBAC target globs are matched
// against: <type>/<name>, like postgres/main
func serviceRBACId(serviceType, name string) string {
	return serviceType + "/" + name
}

// enforceDefaultDisplacement authorizes making a service the default of its
// type: displacing the current default modifies THAT service (bare-type
// binding sources start resolving elsewhere), so it needs service:update on
// the current default, not just on the service being promoted
func (s *Server) enforceDefaultDisplacement(ctx context.Context, tx types.Transaction, serviceType, newDefaultName string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	current, err := s.db.GetDefaultService(ctx, tx, serviceType)
	if err != nil {
		return nil // no current default to displace
	}
	if current.Name == newDefaultName {
		return nil
	}
	return s.enforceServicePerm(ctx, types.PermissionServiceUpdate,
		serviceRBACId(current.ServiceType, current.Name), current.CreatedBy)
}

func (s *Server) CreateService(ctx context.Context, service *types.Service, dryRun bool) error {
	if err := s.enforceServicePerm(ctx, types.PermissionServiceCreate,
		serviceRBACId(service.ServiceType, service.Name), ""); err != nil {
		return err
	}
	if err := s.enforceServiceSecretRefs(ctx, service.Config); err != nil {
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
	service.CreatedBy = system.GetContextUserId(ctx)

	builder, err := s.resolveServiceBinding(ctx, service.ServiceType)
	if err != nil {
		return err
	}

	resolvedConfig, err := s.resolveServiceConfig(service.Config)
	if err != nil {
		return err
	}
	serviceBinding := builder()
	if err := serviceBinding.InitializeService(ctx, s.Logger, resolvedConfig, s.serviceBindingRuntime()); err != nil {
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
		if err := s.enforceDefaultDisplacement(ctx, tx, service.ServiceType, service.Name); err != nil {
			return err
		}
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

	existing, err := s.db.GetService(ctx, tx, service.ServiceType, service.Name)
	if err != nil {
		return fmt.Errorf("service %s not found", serviceRBACId(service.ServiceType, service.Name))
	}
	if err := s.enforceServicePerm(ctx, types.PermissionServiceUpdate,
		serviceRBACId(service.ServiceType, service.Name), existing.CreatedBy); err != nil {
		return err
	}
	if err := s.enforceServiceSecretRefs(ctx, service.Config); err != nil {
		return err
	}

	if service.IsDefault {
		if err := s.enforceDefaultDisplacement(ctx, tx, service.ServiceType, service.Name); err != nil {
			return err
		}
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

	existing, err := s.db.GetService(ctx, tx, serviceType, name)
	if err != nil {
		// Keep the delete operation's established error message (asserted by
		// the CLI e2e tests) instead of the lookup's phrasing
		return fmt.Errorf("no service found with name %s and service_type %s", name, serviceType)
	}
	if err := s.enforceServicePerm(ctx, types.PermissionServiceDelete,
		serviceRBACId(serviceType, name), existing.CreatedBy); err != nil {
		return err
	}

	// A service cannot be deleted while bindings provisioned from it exist;
	// nothing is changed on the backend service itself
	bindingPathList, err := s.db.GetBindingPathsForService(ctx, tx, serviceType, name)
	if err != nil {
		return err
	}
	if len(bindingPathList) > 0 {
		return fmt.Errorf("service %s/%s is used by bindings (%s), delete the bindings first",
			serviceType, name, strings.Join(bindingPathList, ", "))
	}

	// The service may be the staging service of other services: their bindings'
	// staged accounts are provisioned on it, so those bindings block the delete
	// too. Staging links from services without bindings are cleared below.
	stagingUsers, err := s.db.GetServiceNamesUsingStaging(ctx, tx, serviceType, name)
	if err != nil {
		return err
	}
	for _, stagingUser := range stagingUsers {
		userBindingPaths, err := s.db.GetBindingPathsForService(ctx, tx, serviceType, stagingUser)
		if err != nil {
			return err
		}
		if len(userBindingPaths) > 0 {
			return fmt.Errorf("service %s/%s is the staging service for %s/%s which has bindings (%s), delete the bindings first",
				serviceType, name, serviceType, stagingUser, strings.Join(userBindingPaths, ", "))
		}
	}

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

	services, err := s.db.ListServices(ctx, tx, serviceType, name)
	if err != nil {
		return nil, err
	}

	if !s.rbacManager.APIEnforced(ctx) {
		return services, nil
	}
	// Under RBAC enforcement, the listing is filtered to the services the user
	// holds service:read on (through grants or the owner rule)
	filtered := make([]*types.Service, 0, len(services))
	for _, service := range services {
		authorized, err := s.rbacManager.AuthorizeResourceAPI(ctx, types.PermissionServiceRead,
			serviceRBACId(service.ServiceType, service.Name), service.CreatedBy)
		if err != nil {
			return nil, err
		}
		if authorized {
			filtered = append(filtered, service)
		}
	}
	return filtered, nil
}

func (s *Server) CreateBinding(ctx context.Context, createRequest *types.CreateBindingRequest, dryRun bool) (_ *types.Binding, retErr error) {
	if err := s.enforceBindingPerm(ctx, types.PermissionBindingCreate, createRequest.Path, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Creating a binding also needs authority over its source: provisioning an
	// account on a service needs service:bind, deriving from a base binding
	// needs binding:use on it
	if err := s.enforceBindingSource(ctx, tx, createRequest.Source); err != nil {
		return nil, err
	}

	ctx, deployScope := s.beginDeployScope(ctx, true, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()

	binding, err := s.createBindingTx(ctx, tx, createRequest, deployScope.accounts, false)
	if err != nil {
		return nil, err
	}

	if dryRun {
		return binding, nil
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.approvalCacheGen.Add(1)
	if err := deployScope.commit(ctx); err != nil {
		return nil, err
	}

	return binding, nil
}

func (s *Server) createBindingTx(ctx context.Context, tx types.Transaction, createRequest *types.CreateBindingRequest,
	accounts *bindingAccountManager, allowAutoPath bool) (*types.Binding, error) {
	var err error
	binding := types.Binding{
		Path:      createRequest.Path,
		Source:    createRequest.Source,
		CreatedBy: system.GetContextUserId(ctx),
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

		// Sqlite has no accounts or grants, so the derived binding
		// least-privilege model cannot be enforced on it
		if derivedFrom.ServiceType == bindings.SqliteServiceType {
			return nil, fmt.Errorf("sqlite bindings do not support derived bindings; "+
				"bind %s directly instead of deriving from it", derivedFrom.Path)
		}

		// Auto bindings are owned by their app and are deleted (with their
		// backend accounts) when the app is deleted, so nothing may derive
		// from them
		if strings.HasPrefix(derivedFrom.Path, autoBindingPathPrefix+"/") {
			return nil, fmt.Errorf("cannot derive binding %s from %s: auto bindings are owned by their app and cannot be shared",
				binding.Path, derivedFrom.Path)
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
		if derivedFrom == nil {
			// The linked staging service hosts the staged account artifacts,
			// so provisioning a base/auto binding needs service:bind on it
			// too, not just on the source service (derived bindings need
			// binding:use on the base instead, whose creator authorized both
			// services when the base was created)
			if err := s.enforceServicePerm(ctx, types.PermissionServiceBind,
				serviceRBACId(stagingService.ServiceType, stagingService.Name), stagingService.CreatedBy); err != nil {
				return nil, err
			}
		}
	}

	// Generate the staging account info, either against the staging service if set or against the main service.
	// The account artifacts are persisted on the service immediately (outside the metadata transaction);
	// the account manager deletes them if the operation is rolled back. The artifacts are also recorded in
	// the binding metadata, so deleting the binding later can drop them. Skipped on dry run.
	binding.StagedMetadata.Account, binding.StagedMetadata.GrantsApplied, binding.StagedMetadata.Artifacts, err = accounts.generateAccount(ctx, stagingService, &binding, derivedFrom, true, true)
	if err != nil {
		return nil, fmt.Errorf("error generating staging account: %w", err)
	}

	// Generate the production account info
	binding.Metadata.Account, binding.Metadata.GrantsApplied, binding.Metadata.Artifacts, err = accounts.generateAccount(ctx, service, &binding, derivedFrom, false, true)
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

// enforceBindingSource authorizes using source as a credential source: a
// binding path needs binding:use on it (deriving a new binding from it, or
// attaching it to an app), a service source needs service:bind on the service
// (base/auto bindings). Shared by binding create, apply, builder publish and
// preview creation so the attach rule cannot diverge between them
func (s *Server) enforceBindingSource(ctx context.Context, tx types.Transaction, source string) error {
	if !s.rbacManager.APIEnforced(ctx) {
		// Skip the source lookups when there is no check to make: the create
		// path validates the source itself, with its own error ordering
		// (e.g. grants-on-base-binding errors before a missing source)
		return nil
	}
	if source == "" {
		return nil // createBindingTx rejects the empty source
	}
	if strings.HasPrefix(source, "/") {
		sourceBinding, err := s.db.GetBinding(ctx, tx, source)
		if err != nil {
			return fmt.Errorf("binding source %s not found", source)
		}
		return s.enforceBindingPerm(ctx, types.PermissionBindingUse, sourceBinding.Path, sourceBinding.CreatedBy)
	}
	service, err := s.serviceForBindingSource(ctx, tx, source)
	if err != nil {
		return err
	}
	return s.enforceServiceBind(ctx, tx, service)
}

// enforceServiceBind authorizes provisioning a binding from service:
// service:bind on the service itself and, when a staging service is linked,
// on the staging service too — the staged account artifacts are provisioned
// on it (createBindingTx keeps the staging check as a backstop, but preflights
// like the builder publish never reach createBindingTx before mutating state)
func (s *Server) enforceServiceBind(ctx context.Context, tx types.Transaction, service *types.Service) error {
	if !s.rbacManager.APIEnforced(ctx) {
		return nil
	}
	if err := s.enforceServicePerm(ctx, types.PermissionServiceBind,
		serviceRBACId(service.ServiceType, service.Name), service.CreatedBy); err != nil {
		return err
	}
	if service.Staging == "" {
		return nil
	}
	stagingService, err := s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
	if err != nil {
		return fmt.Errorf("error getting staging service: %w", err)
	}
	return s.enforceServicePerm(ctx, types.PermissionServiceBind,
		serviceRBACId(stagingService.ServiceType, stagingService.Name), stagingService.CreatedBy)
}

func (s *Server) getServiceBinding(ctx context.Context, service *types.Service) (bindings.ServiceBinding, error) {
	builder, err := s.resolveServiceBinding(ctx, service.ServiceType)
	if err != nil {
		return nil, err
	}

	resolvedConfig, err := s.resolveServiceConfig(service.Config)
	if err != nil {
		return nil, err
	}
	serviceBinding := builder()
	if err = serviceBinding.InitializeService(ctx, s.Logger, resolvedConfig, s.serviceBindingRuntime()); err != nil {
		return nil, fmt.Errorf("error initializing service: %w", err)
	}

	return serviceBinding, nil
}

// enforceServiceSecretRefs requires the secret:read permission when a
// service config value references a secret. Referenced values flow resolved
// to the service's binding provider, so selecting which secrets a service
// uses must be limited to callers who are allowed to use the secret store,
// not implied by service:manage alone
func (s *Server) enforceServiceSecretRefs(ctx context.Context, config map[string]string) error {
	mgr := s.secretsMgr()
	if mgr == nil {
		return nil
	}
	for key, value := range config {
		if mgr.ReferencesSecrets(value) {
			if err := s.enforceGlobalPerm(ctx, types.PermissionSecretRead, ""); err != nil {
				return fmt.Errorf("service config key %s references a secret: %w", key, err)
			}
			return nil
		}
	}
	return nil
}

// resolveServiceConfig returns a copy of the service config with {{secret}}
// and {{secret_from}} references resolved through the current secrets
// manager. The stored service config keeps the references; resolution happens
// each time the config is handed to a binding or an app, so a rotated secret
// value is picked up on the next operation without a service update. Values
// that do not reference secrets pass through unchanged
func (s *Server) resolveServiceConfig(config map[string]string) (map[string]string, error) {
	if len(config) == 0 {
		return config, nil
	}
	mgr := s.secretsMgr()
	if mgr == nil {
		return config, nil
	}
	resolved := make(map[string]string, len(config))
	for key, value := range config {
		evaled, err := mgr.ServiceEvalTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("error resolving secret reference in service config key %s: %w", key, err)
		}
		resolved[key] = evaled
	}
	return resolved, nil
}

func (s *Server) serviceBindingRuntime() bindings.ServiceBindingRuntime {
	containerCommand := ""
	var litestreamNames, litestreamFileNames []string
	if s.Config() != nil {
		containerCommand = s.Config().System.ContainerCommand
		litestreamNames = slices.Sorted(maps.Keys(s.Config().Litestream))
		for _, name := range litestreamNames {
			if s.Config().Litestream[name].Type == system.LitestreamReplicaTypeFile {
				litestreamFileNames = append(litestreamFileNames, name)
			}
		}
	}
	return bindings.ServiceBindingRuntime{
		LocalhostBindingHostname:  container.LocalhostBindingHostname(containerCommand),
		LitestreamConfigNames:     litestreamNames,
		LitestreamFileConfigNames: litestreamFileNames,
	}
}

// bindingAccountManager caches service binding connections and tracks the side effects
// of the operation on external services: the artifacts (roles, schemas, users,
// databases) created by GenerateAccount and the grant changes made by ApplyGrants.
// Artifacts and new grants are persisted on the service as soon as they are created,
// so apps using the binding (e.g. during verify) see them right away. Grant removals
// are never executed while the operation is in flight: they are queued as pending
// revokes and run by finalizeRevokes only after the metadata transaction commits, so
// a running app never loses a grant because of an operation that is rolled back.
// Deleting a binding's artifacts is deferred the same way: the drops are recorded as
// pending deletes and run by finalizeDeletes after the commit, so the metadata
// transaction is never held open across a call to the backend service.
// If the metadata transaction is rolled back, rollbackAndClose revokes the grants
// applied and deletes the artifacts created since the last commit. Only side effects
// recorded during this manager's lifetime are ever undone; pre-existing objects and
// grants on the service are never touched.
// The manager is created by beginDeployScope and shared by nested scopes;
// operationScope.commit and operationScope.finish drive the commit/finalize and rollback.
// On dry run no service connections are opened and nothing is changed on the services.
type bindingAccountManager struct {
	server   *Server
	dryRun   bool
	services map[string]bindings.ServiceBinding
	created  []createdArtifact
	// granted tracks grants newly applied on existing accounts; on rollback they
	// are revoked to compensate. Grants applied on accounts created by this same
	// operation are not tracked: deleting the account's artifacts covers them.
	granted []grantDelta
	// pendingRevokes are grant removals computed by ApplyGrants but not executed;
	// finalizeRevokes runs them after the metadata transaction has committed.
	pendingRevokes []grantDelta
	// pendingDeletes are the backend objects of deleted bindings, recorded while
	// the metadata transaction is open and dropped by finalizeDeletes after it
	// has committed.
	pendingDeletes []artifactDelete
}

type createdArtifact struct {
	serviceBinding bindings.ServiceBinding
	artifact       bindings.Artifact
}

// artifactDelete is the set of recorded artifacts to drop for one deleted
// binding on one service. The service is the row read inside the metadata
// transaction; the connection to it is opened only when the delete is executed,
// so recording a delete does no network work.
type artifactDelete struct {
	service     *types.Service
	bindingPath string
	artifacts   []types.BindingArtifact
}

// grantDelta is a set of grant changes for one binding account on one service.
type grantDelta struct {
	serviceBinding bindings.ServiceBinding
	bindingPath    string
	isStaging      bool
	account        map[string]string
	derivedFrom    types.BindingMetadata
	grants         []types.BindingGrant
	// regrants are the grants that must remain in effect after the grants above are
	// revoked; RevokeGrants re-applies them so an overlapping revoke does not remove
	// privileges the remaining grants still need.
	regrants []types.BindingGrant
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

func (m *bindingAccountManager) getServiceBinding(ctx context.Context, service *types.Service) (bindings.ServiceBinding, error) {
	key := bindingServiceKey(service)
	if serviceBinding, ok := m.services[key]; ok {
		return serviceBinding, nil
	}

	serviceBinding, err := m.server.getServiceBinding(ctx, service)
	if err != nil {
		return nil, err
	}
	m.services[key] = serviceBinding
	return serviceBinding, nil
}

// generateAccount creates the binding account on the service and applies the grants for
// derived bindings. The created account is tracked so rollbackAndClose can delete it.
// The created artifacts are also returned, in creation order, so the caller can record
// them in the binding metadata for deletion when the binding is deleted.
// On dry run nothing is created and an empty account is returned.
func (m *bindingAccountManager) generateAccount(ctx context.Context, service *types.Service, binding *types.Binding, derivedFrom *types.Binding,
	isStaging, reapplyAll bool) (map[string]string, []types.BindingGrant, []types.BindingArtifact, error) {
	if _, err := m.server.resolveServiceBinding(ctx, service.ServiceType); err != nil {
		return nil, nil, nil, err
	}
	if m.dryRun {
		return nil, nil, nil, nil
	}

	serviceBinding, err := m.getServiceBinding(ctx, service)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, fmt.Errorf("error generating account: %w", err)
	}

	grantsApplied := []types.BindingGrant{}
	if derivedFromMetadata != nil {
		// The account was created by this operation, so grants applied on it need
		// no compensation tracking: rolling back deletes the account's artifacts.
		// A new account has no applied grants yet, so there are no revokes either.
		result, err := serviceBinding.ApplyGrants(ctx, account, metadata, *derivedFromMetadata, reapplyAll)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error applying grants: %w", err)
		}
		grantsApplied = result.GrantsApplied
	}

	return account, grantsApplied, artifactRecords(createdArtifacts), nil
}

// artifactRecords converts service binding artifacts to the form stored in the
// binding metadata.
func artifactRecords(artifacts []bindings.Artifact) []types.BindingArtifact {
	if len(artifacts) == 0 {
		return nil
	}
	records := make([]types.BindingArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		records = append(records, types.BindingArtifact{Type: string(artifact.Type), Name: artifact.Name})
	}
	return records
}

// applyGrants applies the grant changes for a derived binding. New grants are
// persisted on the service immediately and recorded so they can be revoked if the
// operation is rolled back. Grant removals are not executed here: they are queued
// as pending revokes and only run by finalizeRevokes after the metadata transaction
// commits. The returned list is what to record in the binding's GrantsApplied; it
// still includes the pending revokes since they are still in effect on the service.
// On dry run nothing is changed and the currently applied grants are returned.
func (m *bindingAccountManager) applyGrants(ctx context.Context, service *types.Service, binding *types.Binding, derivedFrom *types.Binding,
	isStaging bool, reapplyAll bool) ([]types.BindingGrant, error) {
	if _, err := m.server.resolveServiceBinding(ctx, service.ServiceType); err != nil {
		return nil, err
	}

	metadata := binding.Metadata
	if isStaging {
		metadata = binding.StagedMetadata
	}
	if m.dryRun {
		return metadata.GrantsApplied, nil
	}

	serviceBinding, err := m.getServiceBinding(ctx, service)
	if err != nil {
		return nil, err
	}

	derivedFromMetadata := derivedFrom.Metadata
	if isStaging {
		derivedFromMetadata = derivedFrom.StagedMetadata
	}

	result, err := serviceBinding.ApplyGrants(ctx, metadata.Account, metadata, derivedFromMetadata, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error applying grants: %w", err)
	}

	if len(result.Granted) > 0 {
		// Compensation: if the operation rolls back, revoke what was just granted
		// and restore the grants that were applied before the operation
		m.granted = append(m.granted, grantDelta{
			serviceBinding: serviceBinding,
			bindingPath:    binding.Path,
			isStaging:      isStaging,
			account:        metadata.Account,
			derivedFrom:    derivedFromMetadata,
			grants:         result.Granted,
			regrants:       append([]types.BindingGrant{}, metadata.GrantsApplied...),
		})
	}
	if len(result.PendingRevokes) > 0 {
		// After commit: revoke what is no longer desired, keeping the rest applied
		m.recordPendingRevokes(grantDelta{
			serviceBinding: serviceBinding,
			bindingPath:    binding.Path,
			isStaging:      isStaging,
			account:        metadata.Account,
			derivedFrom:    derivedFromMetadata,
			grants:         result.PendingRevokes,
			regrants:       subtractBindingGrants(result.GrantsApplied, result.PendingRevokes),
		})
	}
	return result.GrantsApplied, nil
}

// subtractBindingGrants returns the grants in list that are not in remove.
func subtractBindingGrants(list, remove []types.BindingGrant) []types.BindingGrant {
	ret := make([]types.BindingGrant, 0, len(list))
	for _, grant := range list {
		if !slices.Contains(remove, grant) {
			ret = append(ret, grant)
		}
	}
	return ret
}

// recordPendingRevokes queues grants for revocation after commit, merging with an
// existing entry for the same account (applyGrants can run more than once for a
// binding within one operation, e.g. update followed by the verify reconcile pass).
// The latest call's regrants win: they reflect the most recent applied state.
func (m *bindingAccountManager) recordPendingRevokes(delta grantDelta) {
	for i := range m.pendingRevokes {
		existing := &m.pendingRevokes[i]
		if existing.bindingPath == delta.bindingPath && existing.isStaging == delta.isStaging {
			for _, grant := range delta.grants {
				if !slices.Contains(existing.grants, grant) {
					existing.grants = append(existing.grants, grant)
				}
			}
			existing.regrants = delta.regrants
			return
		}
	}
	m.pendingRevokes = append(m.pendingRevokes, delta)
}

// commit keeps the created artifacts and applied grants. operationScope.commit calls
// this after the metadata transaction has committed; the artifacts and grants are
// already persisted on the services, this just stops rollbackAndClose from undoing
// them. The pending revokes and deletes are kept: finalizeRevokes and finalizeDeletes
// execute them afterwards.
func (m *bindingAccountManager) commit() {
	if m == nil {
		return
	}
	m.created = nil
	m.granted = nil
}

// closeServices closes the cached service connections. operationScope.commit calls
// this once the post-commit work is done; rollbackAndClose closes on the rollback
// path.
func (m *bindingAccountManager) closeServices(ctx context.Context) {
	if m == nil {
		return
	}
	for _, serviceBinding := range m.services {
		serviceBinding.CloseService(ctx) //nolint:errcheck
	}
	m.services = map[string]bindings.ServiceBinding{}
}

// finalizeRevokes executes the grant revokes that were deferred until after the
// metadata commit, then removes the revoked grants from the bindings' GrantsApplied
// metadata in a small follow-up transaction. Each delta is rechecked against the
// currently committed binding state first: a concurrent operation may have re-added
// a grant since this operation's transaction computed the delta, and such grants
// must not be revoked. Call only after commit, with a context that is detached from
// the request cancellation and bounded by the operation timeout (operationScope.commit
// passes one). A failed revoke leaves the grant both on the service and in
// GrantsApplied, so a later apply/sync that processes the binding recomputes and
// retries it (use --force-reload if the apply would otherwise be skipped as already
// applied).
func (m *bindingAccountManager) finalizeRevokes(ctx context.Context) error {
	if m == nil || m.dryRun || len(m.pendingRevokes) == 0 {
		return nil
	}

	var errs []error
	revoked := make([]grantDelta, 0, len(m.pendingRevokes))
	for _, delta := range m.pendingRevokes {
		// Skip revoking grants that the committed desired state contains again:
		// they were re-added by a concurrent operation after this delta was
		// computed. The next processing of the binding reconciles GrantsApplied.
		if desired, _, ok := m.server.committedBindingGrants(ctx, delta.bindingPath, delta.isStaging); ok {
			delta = filterRevokeDelta(delta, desired)
		}
		if len(delta.grants) == 0 {
			continue
		}
		if err := delta.serviceBinding.RevokeGrants(ctx, delta.account, delta.derivedFrom, delta.grants, delta.regrants); err != nil {
			m.server.Warn().Err(err).Str("binding", delta.bindingPath).Bool("staging", delta.isStaging).
				Msg("error revoking grants after commit; the extra grants remain until a later apply retries")
			errs = append(errs, fmt.Errorf("binding %s: %w", delta.bindingPath, err))
			continue
		}
		revoked = append(revoked, delta)
	}
	m.pendingRevokes = nil

	if len(revoked) > 0 {
		if err := m.server.removeRevokedGrants(ctx, revoked); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("bindings were updated, but deferred grant revokes did not complete: %w", errors.Join(errs...))
	}
	return nil
}

// recordArtifactDeletes queues the recorded artifacts of a deleted binding for
// dropping on the service. Nothing is contacted on the service here: the service
// row is read from the caller's metadata transaction and the drops run in
// finalizeDeletes, after that transaction has committed.
func (m *bindingAccountManager) recordArtifactDeletes(service *types.Service, binding *types.Binding, artifacts []types.BindingArtifact) {
	if m == nil || m.dryRun || len(artifacts) == 0 {
		return
	}
	m.pendingDeletes = append(m.pendingDeletes, artifactDelete{
		service:     service,
		bindingPath: binding.Path,
		artifacts:   artifacts,
	})
}

// finalizeDeletes drops the backend objects of the bindings deleted by the
// operation, after the metadata transaction that removed the binding rows has
// committed. Deferring the drops keeps the metadata transaction off the network:
// a slow or unavailable service cannot hold it open. The cost is that a failed
// drop leaves the objects on the service after the binding row is gone; the
// failure is logged and returned so the objects can be dropped manually (the
// artifact names are derived from the binding id, so a binding recreated at the
// same path never collides with them). Call only after commit, with a context
// detached from the request cancellation and bounded by a timeout.
func (m *bindingAccountManager) finalizeDeletes(ctx context.Context) error {
	if m == nil || m.dryRun || len(m.pendingDeletes) == 0 {
		return nil
	}
	pending := m.pendingDeletes
	m.pendingDeletes = nil

	var errs []error
	for _, pendingDelete := range pending {
		if err := m.deleteArtifacts(ctx, pendingDelete); err != nil {
			m.server.Warn().Err(err).Str("binding", pendingDelete.bindingPath).
				Msg("error dropping the backend objects of a deleted binding; drop them on the service manually")
			errs = append(errs, fmt.Errorf("binding %s: %w", pendingDelete.bindingPath, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("bindings were deleted, but their objects on the backend services were not all dropped: %w", errors.Join(errs...))
	}
	return nil
}

// deleteArtifacts drops one binding's recorded artifacts on its service, in
// reverse creation order.
func (m *bindingAccountManager) deleteArtifacts(ctx context.Context, pendingDelete artifactDelete) error {
	serviceBinding, err := m.getServiceBinding(ctx, pendingDelete.service)
	if err != nil {
		return err
	}
	artifacts := pendingDelete.artifacts
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := bindings.Artifact{Type: bindings.ArtifactType(artifacts[i].Type), Name: artifacts[i].Name}
		if err := serviceBinding.DeleteArtifact(ctx, artifact); err != nil {
			return fmt.Errorf("error deleting %s %s: %w", artifacts[i].Type, artifacts[i].Name, err)
		}
	}
	return nil
}

// committedBindingGrants reads the currently committed grant state (desired grants
// and applied grants) for a binding, for rechecking a revoke delta that was computed
// in an earlier transaction against changes committed by concurrent operations.
// ok is false when the state could not be read (binding deleted or read failure);
// the caller then proceeds with the unfiltered delta.
func (s *Server) committedBindingGrants(ctx context.Context, bindingPath string, isStaging bool) (desired, applied []types.BindingGrant, ok bool) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		s.Warn().Err(err).Str("binding", bindingPath).Msg("error reading committed binding state before revoke")
		return nil, nil, false
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, bindingPath)
	if err != nil {
		return nil, nil, false
	}
	metadata := binding.Metadata
	if isStaging {
		metadata = binding.StagedMetadata
	}
	for _, grantStr := range metadata.Grants {
		grant, err := types.ParseGrant(grantStr, []types.GrantType{types.GrantTypeRead, types.GrantTypeCreate, types.GrantTypeFull})
		if err != nil {
			continue
		}
		desired = append(desired, grant)
	}
	return desired, metadata.GrantsApplied, true
}

// filterRevokeDelta drops from the delta the grants present in keep (grants the
// committed binding state now owns). The dropped grants move to the regrants, so a
// revoke that is still executed for an overlapping grant (e.g. read:* while a kept
// read:t1 remains) does not remove privileges the kept grants need.
func filterRevokeDelta(delta grantDelta, keep []types.BindingGrant) grantDelta {
	remaining := make([]types.BindingGrant, 0, len(delta.grants))
	skipped := []types.BindingGrant{}
	for _, grant := range delta.grants {
		if slices.Contains(keep, grant) {
			skipped = append(skipped, grant)
		} else {
			remaining = append(remaining, grant)
		}
	}
	if len(skipped) == 0 {
		return delta
	}
	filtered := delta
	filtered.grants = remaining
	filtered.regrants = append([]types.BindingGrant{}, delta.regrants...)
	for _, grant := range skipped {
		if !slices.Contains(filtered.regrants, grant) {
			filtered.regrants = append(filtered.regrants, grant)
		}
	}
	return filtered
}

// removeRevokedGrants clears the finalized revokes from the bindings' GrantsApplied
// metadata. Runs in its own transaction, after the operation's transaction committed
// and the revokes were executed on the services.
func (s *Server) removeRevokedGrants(ctx context.Context, revoked []grantDelta) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, delta := range revoked {
		binding, err := s.db.GetBinding(ctx, tx, delta.bindingPath)
		if err != nil {
			// The binding may have been deleted since the commit; the revoke on the
			// service was still the right thing to do, nothing to record.
			s.Warn().Err(err).Str("binding", delta.bindingPath).Msg("binding not found while recording finalized revokes")
			continue
		}
		metadata := &binding.Metadata
		if delta.isStaging {
			metadata = &binding.StagedMetadata
		}
		remaining := make([]types.BindingGrant, 0, len(metadata.GrantsApplied))
		for _, grant := range metadata.GrantsApplied {
			if !slices.Contains(delta.grants, grant) {
				remaining = append(remaining, grant)
			}
		}
		metadata.GrantsApplied = remaining
		if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
			return fmt.Errorf("error recording finalized revokes for binding %s: %w", delta.bindingPath, err)
		}
	}
	return tx.Commit()
}

// rollbackAndClose undoes the service side effects recorded since the last commit
// and closes the service connections: grants applied by the operation are revoked
// and created artifacts are deleted (in reverse creation order). Each compensation
// is rechecked against the currently committed binding state first: a grant that a
// concurrent operation committed as applied while this one was in flight is owned
// by that operation and must not be revoked. Pending revokes and pending artifact
// deletes are dropped without being executed, so a rolled-back operation never
// removes a grant a running app may depend on, and never drops the backend objects
// of a binding whose row survived the rollback.
// Undo is best-effort; failures are logged. The caller passes a
// context that is detached from the request cancellation and bounded by the
// operation timeout (operationScope.finish passes one), so cleanup runs even when
// rolling back due to cancellation but cannot block the cluster rollback
// indefinitely.
func (m *bindingAccountManager) rollbackAndClose(ctx context.Context) {
	if m == nil {
		return
	}

	// Revoke the compensable grants before dropping artifacts: a grant's schema or
	// base role may be among the artifacts about to be deleted.
	for i := len(m.granted) - 1; i >= 0; i-- {
		delta := m.granted[i]
		// This operation's writes are rolled back, so any grant the committed
		// GrantsApplied contains belongs to a concurrent operation; skip it
		if _, applied, ok := m.server.committedBindingGrants(ctx, delta.bindingPath, delta.isStaging); ok {
			delta = filterRevokeDelta(delta, applied)
		}
		if len(delta.grants) == 0 {
			continue
		}
		if err := delta.serviceBinding.RevokeGrants(ctx, delta.account, delta.derivedFrom, delta.grants, delta.regrants); err != nil {
			m.server.Warn().Err(err).Str("binding", delta.bindingPath).Bool("staging", delta.isStaging).
				Msg("error revoking grants during rollback")
		}
	}
	m.granted = nil
	m.pendingRevokes = nil
	// The binding rows the deletes were computed for are still there, since the
	// metadata transaction was rolled back; their backend objects must stay too
	m.pendingDeletes = nil

	for i := len(m.created) - 1; i >= 0; i-- {
		created := m.created[i]
		if err := created.serviceBinding.DeleteArtifact(ctx, created.artifact); err != nil {
			m.server.Warn().Err(err).Str("type", string(created.artifact.Type)).Str("name", created.artifact.Name).
				Msg("error deleting binding artifact during rollback")
		}
	}
	m.created = nil
	m.closeServices(ctx)
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

func (s *Server) UpdateBinding(ctx context.Context, updateRequest types.UpdateBindingRequest, dryRun, promote, reapplyAll bool) (_ *types.Binding, retErr error) {
	if len(updateRequest.AddGrants) == 0 && len(updateRequest.DeleteGrants) == 0 && !promote && !reapplyAll {
		return nil, fmt.Errorf("expected at least one grant update, promote, or reapply-all")
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
	if err := s.enforceBindingPerm(ctx, types.PermissionBindingUpdate, binding.Path, binding.CreatedBy); err != nil {
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

	ctx, deployScope := s.beginDeployScope(ctx, true, dryRun)
	defer func() { retErr = deployScope.finish(ctx, retErr) }()

	binding.StagedMetadata.GrantsApplied, err = deployScope.accounts.applyGrants(ctx, stagingService, binding, derivedFrom, true, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error applying staging grants: %w", err)
	}

	if promote {
		binding.Metadata.Grants = binding.StagedMetadata.Grants
		binding.Metadata.GrantsApplied, err = deployScope.accounts.applyGrants(ctx, service, binding, derivedFrom, false, reapplyAll)
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
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.approvalCacheGen.Add(1)
	if err := deployScope.commit(ctx); err != nil {
		// The binding update is committed; only the deferred revokes failed
		return binding, err
	}
	return binding, nil
}

func (s *Server) DeleteBinding(ctx context.Context, path string, dryRun bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		if strings.HasPrefix(err.Error(), "binding not found with path: ") {
			// Keep the delete operation's established error message
			return fmt.Errorf("no binding found with path %s", path)
		}
		return err
	}
	if err := s.enforceBindingPerm(ctx, types.PermissionBindingDelete, binding.Path, binding.CreatedBy); err != nil {
		return err
	}

	// A base binding cannot be deleted while bindings derived from it exist:
	// their accounts live in the base binding's schema/database
	derived, err := s.db.ListBindings(ctx, tx, path)
	if err != nil {
		return err
	}
	if len(derived) > 0 {
		return fmt.Errorf("binding %s has derived bindings (%s), delete the derived bindings first",
			path, strings.Join(bindingPaths(derived), ", "))
	}

	accounts := s.newBindingAccountManager(dryRun)
	cleanupCtx, cancel := bindingCleanupContext(ctx)
	defer cancel()
	defer accounts.closeServices(cleanupCtx)

	if err := s.db.DeleteBinding(ctx, tx, path); err != nil {
		return err
	}
	// Only record what to drop on the backend service here; the drops run after
	// the metadata commit, so the transaction is not held open across them
	if err := s.recordBindingArtifactDeletes(ctx, tx, accounts, binding); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.approvalCacheGen.Add(1)

	// The binding is deleted; a failure here only means its backend objects were
	// left behind, which is reported to the caller
	return accounts.finalizeDeletes(cleanupCtx)
}

// bindingCleanupTimeout bounds the post-commit work on the backend services
// (dropping the objects of deleted bindings) so an unresponsive service cannot
// block the request indefinitely.
const bindingCleanupTimeout = 2 * time.Minute

// bindingCleanupContext returns the context for post-commit backend cleanup: it
// is detached from the request cancellation, so the drops still run when the
// client goes away after the metadata commit, and is bounded by
// bindingCleanupTimeout.
func bindingCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), bindingCleanupTimeout)
}

func bindingPaths(bindingList []*types.Binding) []string {
	paths := make([]string, 0, len(bindingList))
	for _, binding := range bindingList {
		paths = append(paths, binding.Path)
	}
	return paths
}

// recordBindingArtifactDeletes records the backend service objects to drop for a
// binding being deleted: the artifacts noted when its accounts were generated,
// the staged ones on the staging service (when the binding's service has one
// linked) and the production ones on the main service. Only the service rows are
// read here, from the caller's transaction; accounts.finalizeDeletes drops the
// objects once that transaction has committed.
// Bindings without recorded artifacts (created by an older version or a dry
// run) leave their backend objects in place with a warning. No-op on dry run.
func (s *Server) recordBindingArtifactDeletes(ctx context.Context, tx types.Transaction, accounts *bindingAccountManager, binding *types.Binding) error {
	if accounts.dryRun {
		return nil
	}
	if len(binding.StagedMetadata.Artifacts) == 0 && len(binding.Metadata.Artifacts) == 0 {
		// Sqlite accounts are computed, not provisioned: no artifacts is the
		// normal state, not a sign of a legacy binding
		if binding.ServiceType != bindings.SqliteServiceType &&
			(len(binding.StagedMetadata.Account) > 0 || len(binding.Metadata.Account) > 0) {
			s.Warn().Str("binding", binding.Path).
				Msg("binding has no recorded artifacts; backend service objects are not dropped")
		}
		return nil
	}

	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return fmt.Errorf("error getting binding service: %w", err)
	}
	stagingService := service
	if service.Staging != "" {
		stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
		if err != nil {
			return fmt.Errorf("error getting staging service: %w", err)
		}
	}

	accounts.recordArtifactDeletes(stagingService, binding, binding.StagedMetadata.Artifacts)
	accounts.recordArtifactDeletes(service, binding, binding.Metadata.Artifacts)
	return nil
}

func (s *Server) GetBinding(ctx context.Context, path string) (*types.Binding, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		return nil, err
	}
	if err := s.enforceBindingPerm(ctx, types.PermissionBindingRead, binding.Path, binding.CreatedBy); err != nil {
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
	binding.ServiceConfig, err = s.resolveServiceConfig(service.Config)
	if err != nil {
		return nil, err
	}
	if service.Staging != "" {
		// Staged apps follow the linked staging service's config; a missing
		// staging service (deleted since) falls back to the primary config
		if stagingService, err := s.db.GetService(ctx, tx, service.ServiceType, service.Staging); err == nil {
			binding.StagingServiceConfig, err = s.resolveServiceConfig(stagingService.Config)
			if err != nil {
				return nil, err
			}
		}
	}
	return binding, nil
}

// ListBindings returns the bindings the caller can read: under RBAC
// enforcement the listing is filtered to the bindings the user holds
// binding:read on (through grants or the owner rule). Account credentials
// are redacted. Exposed through the REST API and the openrun.in plugin
func (s *Server) ListBindings(ctx context.Context, source string) ([]*types.Binding, error) {
	bindings, err := s.listBindingsInternal(ctx, source)
	if err != nil {
		return nil, err
	}
	if !s.rbacManager.APIEnforced(ctx) {
		return bindings, nil
	}
	filtered := make([]*types.Binding, 0, len(bindings))
	for _, binding := range bindings {
		authorized, err := s.rbacManager.AuthorizeResourceAPI(ctx,
			types.PermissionBindingRead, binding.Path, binding.CreatedBy)
		if err != nil {
			return nil, err
		}
		if authorized {
			filtered = append(filtered, binding)
		}
	}
	return filtered, nil
}

// listBindingsInternal is the unfiltered listing (accounts still redacted),
// for internal flows like apply that diff against every binding and enforce
// per-binding permissions themselves. Never expose it to a caller directly
func (s *Server) listBindingsInternal(ctx context.Context, source string) ([]*types.Binding, error) {
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

// GetBindingAccount returns the binding's account credentials (show-account).
// Revealing credentials needs binding:reveal, which is never implied by
// binding:manage (so binding owners do not hold it by default; operators can
// opt owners in via owner_permissions.binding)
func (s *Server) GetBindingAccount(ctx context.Context, path string, useStaging bool) (map[string]string, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, path)
	if err != nil {
		return nil, err
	}
	if err := s.enforceBindingPerm(ctx, types.PermissionBindingReveal, binding.Path, binding.CreatedBy); err != nil {
		return nil, err
	}
	if useStagedBindingMetadata(binding, useStaging) {
		return binding.StagedMetadata.Account, nil
	}
	return binding.Metadata.Account, nil
}

func (s *Server) RunBindingCommand(ctx context.Context, bindingName string, useStaging bool, command string) (map[string]any, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("sql is required")
	}

	// The metadata transaction is released before the backend is contacted: the
	// command runs as the binding account and can take arbitrarily long, which
	// must not hold a metadata transaction open
	service, metadata, err := s.bindingBackendTarget(ctx, bindingName, useStaging, types.PermissionBindingRunCommand)
	if err != nil {
		return nil, err
	}

	serviceBinding, err := s.getServiceBinding(ctx, service)
	if err != nil {
		return nil, fmt.Errorf("error getting service binding: %w", err)
	}

	defer serviceBinding.CloseService(ctx) //nolint:errcheck

	return serviceBinding.RunCommand(ctx, metadata, command)
}

// ServiceHealth verifies the service is healthy: the admin connection is
// established from the (secret-resolved) service config and a no-op operation
// runs on the backend. A nil return means healthy.
func (s *Server) ServiceHealth(ctx context.Context, serviceType, name string) error {
	// The metadata transaction is released before the backend is contacted: a
	// slow or unavailable service must not hold one open for the length of the
	// health check
	service, err := s.serviceBackendTarget(ctx, serviceType, name)
	if err != nil {
		return err
	}

	return s.dialServiceHealth(ctx, service)
}

// BindingHealth verifies the binding account is healthy: the backend is
// contacted AS the binding account (staged account and staging service with
// useStaging) and a no-op operation runs. A nil return means healthy.
func (s *Server) BindingHealth(ctx context.Context, bindingName string, useStaging bool) error {
	// The metadata transaction is released before the backend is contacted: a
	// slow or unavailable service must not hold one open for the length of the
	// health check
	service, metadata, err := s.bindingBackendTarget(ctx, bindingName, useStaging, types.PermissionBindingRead)
	if err != nil {
		return err
	}

	return s.dialBindingHealth(ctx, service, metadata)
}

// serviceBackendTarget loads the service to connect to and enforces the caller's
// permission on it, in a read-only transaction that is released before
// returning, so the caller contacts the backend with no metadata transaction
// open.
func (s *Server) serviceBackendTarget(ctx context.Context, serviceType, name string) (*types.Service, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	service, err := s.db.GetService(ctx, tx, serviceType, name)
	if err != nil {
		return nil, fmt.Errorf("no service found with name %s and service_type %s", name, serviceType)
	}
	if err := s.enforceServicePerm(ctx, types.PermissionServiceRead,
		serviceRBACId(service.ServiceType, service.Name), service.CreatedBy); err != nil {
		return nil, err
	}
	return service, nil
}

// bindingBackendTarget loads the service to connect to and the account metadata
// to act as for a binding (the staged account on the staging service with
// useStaging), and enforces the given permission on the binding. Like
// serviceBackendTarget, the transaction is released before returning.
func (s *Server) bindingBackendTarget(ctx context.Context, bindingName string, useStaging bool,
	perm types.RBACPermission) (*types.Service, types.BindingMetadata, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, types.BindingMetadata{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	binding, err := s.db.GetBinding(ctx, tx, bindingName)
	if err != nil {
		if strings.HasPrefix(err.Error(), "binding not found with path: ") {
			return nil, types.BindingMetadata{}, fmt.Errorf("no binding found with path %s", bindingName)
		}
		return nil, types.BindingMetadata{}, err
	}
	if err := s.enforceBindingPerm(ctx, perm, binding.Path, binding.CreatedBy); err != nil {
		return nil, types.BindingMetadata{}, err
	}

	service, err := s.db.GetService(ctx, tx, binding.ServiceType, binding.ServiceName)
	if err != nil {
		return nil, types.BindingMetadata{}, fmt.Errorf("error getting binding service: %w", err)
	}

	metadata := binding.Metadata
	if useStagedBindingMetadata(binding, useStaging) {
		metadata = binding.StagedMetadata
		if service.Staging != "" {
			service, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
			if err != nil {
				return nil, types.BindingMetadata{}, fmt.Errorf("error getting staging service: %w", err)
			}
		}
	}
	return service, metadata, nil
}
