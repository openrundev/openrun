// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"

	"github.com/openrundev/openrun/internal/types"
)

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
