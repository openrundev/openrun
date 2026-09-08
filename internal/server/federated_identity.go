// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

// The metadata-backed login store also retains verified IdP group observations
// for bearer credentials and scheduled jobs. Session-only stores need not
// implement this capability.
type federatedIdentityStore interface {
	ObserveFederatedIdentity(context.Context, *types.Identity) error
}

func observeFederatedIdentity(ctx context.Context, store KVStore, provider, subject, user string, groups []string) error {
	identities, ok := store.(federatedIdentityStore)
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	return identities.ObserveFederatedIdentity(ctx, &types.Identity{
		Id: "idn_" + ksuid.New().String(), Provider: provider, StableSubject: subject,
		PrincipalName: provider + ":" + user, Groups: groups, GroupsObservedAt: &now,
	})
}
