// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// CreateSecret stores a secret value in a writable secret provider (default
// "db"). A unique name is generated when a prefix is given; the returned
// SecretRef is the {{secret}} template reference to use in app params/config
func (s *Server) CreateSecret(ctx context.Context, req *types.CreateSecretRequest, update bool) (*types.SecretCreateResponse, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionSecretCreate, ""); err != nil {
		return nil, err
	}
	return s.secretsMgr().CreateSecret(ctx, req, system.GetContextUserId(ctx), update)
}

// DeleteSecret deletes a stored secret
func (s *Server) DeleteSecret(ctx context.Context, providerName, name string) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionSecretDelete, ""); err != nil {
		return err
	}
	return s.secretsMgr().DeleteSecret(ctx, providerName, name)
}

// ListSecrets returns info about stored secrets (never values), optionally
// filtered by a glob pattern on the name
func (s *Server) ListSecrets(ctx context.Context, providerName, nameGlob string) ([]types.SecretInfo, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionSecretRead, ""); err != nil {
		return nil, err
	}
	return s.secretsMgr().ListSecrets(ctx, providerName, nameGlob)
}

// GetSecret returns info about one stored secret. reveal additionally returns
// the secret value and requires the secret:reveal permission
func (s *Server) GetSecret(ctx context.Context, providerName, name string, reveal bool) (*types.SecretGetResponse, error) {
	perm := types.PermissionSecretRead
	if reveal {
		perm = types.PermissionSecretReveal
	}
	if err := s.enforceGlobalPerm(ctx, perm, ""); err != nil {
		return nil, err
	}
	return s.secretsMgr().GetSecretInfo(ctx, providerName, name, reveal)
}

// RekeySecrets re-encrypts stored secrets with the active master key
func (s *Server) RekeySecrets(ctx context.Context, providerName string) (*types.SecretRekeyResponse, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionSecretCreate, ""); err != nil {
		return nil, err
	}
	return s.secretsMgr().RekeySecrets(ctx, providerName)
}
