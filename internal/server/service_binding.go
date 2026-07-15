// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

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

func (s *Server) CreateBinding(ctx context.Context, createRequest *types.CreateBindingRequest, dryRun bool) (_ *types.Binding, retErr error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionBindingCreate, ""); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

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
	if s.Config() != nil {
		containerCommand = s.Config().System.ContainerCommand
	}
	return bindings.ServiceBindingRuntime{
		LocalhostBindingHostname: container.LocalhostBindingHostname(containerCommand),
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
}

type createdArtifact struct {
	serviceBinding bindings.ServiceBinding
	artifact       bindings.Artifact
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
		// The account was created by this operation, so grants applied on it need
		// no compensation tracking: rolling back deletes the account's artifacts.
		// A new account has no applied grants yet, so there are no revokes either.
		result, err := serviceBinding.ApplyGrants(ctx, account, metadata, *derivedFromMetadata, reapplyAll)
		if err != nil {
			return nil, nil, fmt.Errorf("error applying grants: %w", err)
		}
		grantsApplied = result.GrantsApplied
	}

	return account, grantsApplied, nil
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
// them. The pending revokes are kept: finalizeRevokes executes them afterwards.
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
// by that operation and must not be revoked. Pending revokes are dropped without
// being executed, so a rolled-back operation never removes a grant a running app
// may depend on. Undo is best-effort; failures are logged. The caller passes a
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
	if err := tx.Commit(); err != nil {
		return err
	}
	s.approvalCacheGen.Add(1)
	return nil
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
