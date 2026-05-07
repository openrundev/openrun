// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
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
	if err := serviceBinding.InitService(ctx, service.Config); err != nil {
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

	var service *types.Service
	if strings.HasPrefix(binding.Source, "/") {
		// Reference another binding by path - derived binding
		baseBinding, err := s.db.GetBinding(ctx, tx, binding.Source)
		if err != nil {
			return fmt.Errorf("binding source %s not found", binding.Source)
		}

		binding.ServiceType = baseBinding.ServiceType
		binding.ServiceName = baseBinding.ServiceName
		binding.BaseBinding = binding.Source
		// TODO: Implement derived binding initialization
	} else {
		// Base binding
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
		binding.BaseBinding = ""
	}
	binding.Metadata = binding.StagedMetadata

	if err := s.db.CreateBinding(ctx, tx, binding); err != nil {
		return err
	}

	if dryRun {
		return nil
	}

	// Not dry run, generate the account info
	if binding.BaseBinding == "" {
		// Generate the base binding
		stagingService := service
		if service.Staging != "" {
			stagingService, err = s.db.GetService(ctx, tx, service.ServiceType, service.Staging)
			if err != nil {
				return fmt.Errorf("error getting staging service: %w", err)
			}
		}

		// Generate the staging account info, either against the staging service if set or against the main service
		stagingAccount, err := s.generateBaseBindingAccount(ctx, stagingService, binding.Id, binding.Metadata.Config, true)
		if err != nil {
			return fmt.Errorf("error generating staging account: %w", err)
		}
		binding.StagedMetadata.Account = stagingAccount

		// Generate the production account info
		// This runs as a separate transaction, since it might not be against same database as the metadata database
		account, err := s.generateBaseBindingAccount(ctx, service, binding.Id, binding.Metadata.Config, false)
		if err != nil {
			return err
		}
		binding.Metadata.Account = account
		if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
			return err
		}
	} else {
		// TODO: Implement derived binding account generation
	}

	return tx.Commit()
}

func (s *Server) generateBaseBindingAccount(ctx context.Context, service *types.Service, bindingId string, bindingConfig map[string]string, isStaging bool) (map[string]string, error) {
	builder, ok := bindings.ServiceBindings[service.ServiceType]
	if !ok {
		return nil, fmt.Errorf("unknown service type: %s", service.ServiceType)
	}

	serviceBinding := builder()
	if err := serviceBinding.InitService(ctx, service.Config); err != nil {
		return nil, fmt.Errorf("error initializing service: %w", err)
	}
	if err := serviceBinding.InitBaseBinding(ctx, bindingConfig); err != nil {
		return nil, fmt.Errorf("error initializing base binding: %w", err)
	}

	return serviceBinding.GenerateAccount(ctx, bindingId, isStaging)
}

func (s *Server) UpdateBinding(ctx context.Context, binding *types.Binding, dryRun, promote bool) error {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if promote {
		binding.Metadata = binding.StagedMetadata
	}
	if err := s.db.UpdateBinding(ctx, tx, binding); err != nil {
		return err
	}

	if dryRun {
		return nil
	}
	return tx.Commit()
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
