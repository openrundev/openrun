// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

// copyRBACConfig returns a deep copy, so draft edits never alias the live config
func copyRBACConfig(config *types.RBACConfig) (*types.RBACConfig, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("error copying rbac config: %w", err)
	}
	var copied types.RBACConfig
	if err := json.Unmarshal(data, &copied); err != nil {
		return nil, fmt.Errorf("error copying rbac config: %w", err)
	}
	return &copied, nil
}

// GetRBACDynamicConfig returns the live dynamic config and the staged draft
// (nil when there is none) for the configuration UI
func (s *Server) GetRBACDynamicConfig(ctx context.Context) (*types.DynamicConfig, *types.ConfigDraft, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, nil, err
	}
	config := s.GetDynamicConfig()

	draft, err := s.db.GetConfigDraft(ctx)
	if err != nil && err != metadata.ErrNoConfigDraft {
		return nil, nil, err
	}
	return &config, draft, nil
}

// UpdateRBACDraft applies one mutation to the draft config. The draft is
// created from the live config on first edit; draftVersion is the CAS token
// for edits on an existing draft (two operators editing concurrently conflict
// instead of overwriting each other). Draft edits do not touch the live
// config and are not recorded in the config history
func (s *Server) UpdateRBACDraft(ctx context.Context, draftVersion string,
	mutate func(*types.RBACConfig) error) (*types.ConfigDraft, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	user := system.GetContextUserId(ctx)
	now := time.Now().UTC()

	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		// First edit forks the draft from the live config
		live := s.GetDynamicConfig()
		rbacCopy, err := copyRBACConfig(&live.RBAC)
		if err != nil {
			return nil, err
		}
		draft = &types.ConfigDraft{
			RBAC:        *rbacCopy,
			BaseVersion: live.VersionId,
			CreatedBy:   user,
			CreateTime:  now,
		}
	} else if err != nil {
		return nil, err
	} else if draft.DraftVersion != draftVersion {
		return nil, fmt.Errorf("draft was updated by %s since you loaded it, reload and retry", draft.UpdatedBy)
	}

	if err := mutate(&draft.RBAC); err != nil {
		return nil, err
	}

	draft.DraftVersion = "draft_" + ksuid.New().String()
	draft.UpdatedBy = user
	draft.UpdateTime = now
	if err := s.db.SetConfigDraft(ctx, draft); err != nil {
		return nil, err
	}
	return draft, nil
}

// validateRBACCandidate runs the full config validation (the same checks the
// file upload path runs) plus the lockout check: publishing a config which
// removes the caller's own config:update permission requires force
func (s *Server) validateRBACCandidate(ctx context.Context, candidate *types.RBACConfig, force bool) error {
	scratch, err := rbac.NewRBACHandler(s.Logger, candidate, s.config)
	if err != nil {
		return fmt.Errorf("invalid rbac config: %w", err)
	}

	// The lockout check only applies when the caller would actually be subject
	// to enforcement after publish: enforcement is two-level, the enabled flag
	// AND the calling app's rbac: auth prefix. Admin access always works
	user := system.GetContextUserId(ctx)
	if candidate.Enabled && rbac.RequestHasRBACAuth(ctx) && user != "" && user != types.ADMIN_USER && !force {
		authorized, err := scratch.AuthorizeUserPerm(user, system.GetContextGroups(ctx), types.PermissionConfigUpdate)
		if err != nil {
			return err
		}
		if !authorized {
			return fmt.Errorf("this change would remove your own config:update permission, locking you out of configuration changes. Use force to publish anyway")
		}
	}
	return nil
}

// PublishRBACConfig validates the draft config and swaps it live atomically.
// draftVersion must match the current draft (the publisher has seen the
// latest edits); the live config must still be the draft's base version
// unless force is set (a CLI file upload mid-draft surfaces here)
func (s *Server) PublishRBACConfig(ctx context.Context, draftVersion string, force bool) (*types.DynamicConfig, error) {
	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		return nil, fmt.Errorf("no staged config changes to publish")
	} else if err != nil {
		return nil, err
	}
	if draft.DraftVersion != draftVersion {
		return nil, fmt.Errorf("draft was updated by %s since you loaded it, reload and retry", draft.UpdatedBy)
	}

	config := s.GetDynamicConfig()
	if config.VersionId != draft.BaseVersion && !force {
		return nil, fmt.Errorf("the live config changed since this draft was created (by upload or restore), review the draft against the current config. Use force to publish anyway")
	}

	candidate, err := copyRBACConfig(&draft.RBAC)
	if err != nil {
		return nil, err
	}
	if err := s.validateRBACCandidate(ctx, candidate, force); err != nil {
		return nil, err
	}

	config.RBAC = *candidate
	updated, err := s.UpdateDynamicConfig(ctx, &config, false)
	if err != nil {
		return nil, err
	}
	if err := s.db.DeleteConfigDraft(ctx); err != nil {
		return nil, err
	}
	return updated, nil
}

// DiscardRBACDraft drops the staged config changes. draftVersion is the CAS
// token: only a draft state the caller has actually seen can be discarded
func (s *Server) DiscardRBACDraft(ctx context.Context, draftVersion string) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return err
	}

	draft, err := s.db.GetConfigDraft(ctx)
	if err == metadata.ErrNoConfigDraft {
		return fmt.Errorf("no staged config changes to discard")
	} else if err != nil {
		return err
	}
	if draft.DraftVersion != draftVersion {
		return fmt.Errorf("draft was updated by %s since you loaded it, reload and review before discarding", draft.UpdatedBy)
	}
	return s.db.DeleteConfigDraft(ctx)
}

// ListConfigHistory returns the dynamic config snapshots, newest first
func (s *Server) ListConfigHistory(ctx context.Context) ([]types.ConfigHistoryEntry, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	return s.db.ListConfigHistory(ctx)
}

// GetConfigVersion returns one full config snapshot from the history
func (s *Server) GetConfigVersion(ctx context.Context, versionId string) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigRead, ""); err != nil {
		return nil, err
	}
	return s.db.GetConfigVersion(ctx, versionId)
}

// RestoreConfig restores the full dynamic config from a history snapshot. The
// restore is validated like a publish and written as a new version, keeping
// the history linear. An open draft is unaffected (it CAS's against its base
// version at publish time)
func (s *Server) RestoreConfig(ctx context.Context, historyVersionId string, force bool) (*types.DynamicConfig, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	snapshot, err := s.db.GetConfigVersion(ctx, historyVersionId)
	if err != nil {
		return nil, err
	}
	if err := s.validateRBACCandidate(ctx, &snapshot.RBAC, force); err != nil {
		return nil, err
	}

	current := s.GetDynamicConfig()
	candidate := *snapshot
	candidate.VersionId = current.VersionId
	return s.UpdateDynamicConfig(ctx, &candidate, false)
}
