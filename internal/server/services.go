// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/openrundev/openrun/internal/types"
)

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
