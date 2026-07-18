// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"fmt"
	"maps"
	"slices"
)

// ApplyGrantsIncremental is the ApplyGrants scaffolding for bindings that
// execute grant changes incrementally (SQL databases): parse the desired
// grants, diff them against the applied grants, execute only the new ones
// through apply, and assemble the GrantApplyResult bookkeeping the server's
// commit/rollback machinery depends on.
//
// apply executes the given grants on the service and returns the grants that
// were actually processed (a grant may be skipped, e.g. when its target table
// does not exist yet; it is then retried on a later reapplyAll). Grants no
// longer desired are never executed here: they are returned in PendingRevokes
// for the caller to run via RevokeGrants after its metadata transaction
// commits.
func ApplyGrantsIncremental(bindingMetadata BindingMetadata, supportedGrantTypes []GrantType, reapplyAll bool,
	apply func(grants []BindingGrant) ([]BindingGrant, error)) (GrantApplyResult, error) {
	if err := VerifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return GrantApplyResult{}, err
	}

	bindingGrants, err := ParseGrants(bindingMetadata.Grants, supportedGrantTypes)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error parsing grants: %w", err)
	}

	// Grants no longer desired are only computed here; the caller revokes them
	// after its metadata transaction commits.
	revokedGrants, applyGrants := DiffGrants(bindingMetadata.GrantsApplied, bindingGrants)
	if reapplyAll {
		applyGrants = bindingGrants // Apply all grants, can help when new tables are present which need to be granted
	}

	grantsProcessed, err := apply(applyGrants)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error applying new grants: %w", err)
	}

	grantsApplied := UnionGrants(bindingMetadata.GrantsApplied, grantsProcessed)
	if reapplyAll {
		// Drop applied entries whose grant could not be re-executed (e.g. the
		// table was dropped), so they are retried once the target exists again.
		// The pending revokes stay listed until the caller executes them.
		grantsApplied = UnionGrants(grantsProcessed, revokedGrants)
	}
	return GrantApplyResult{
		GrantsApplied:  grantsApplied,
		Granted:        SubtractGrants(grantsProcessed, bindingMetadata.GrantsApplied),
		PendingRevokes: revokedGrants,
	}, nil
}

// ApplyGrantsRebuild is the ApplyGrants scaffolding for bindings that replace
// the account's whole permission set atomically (redis ACL rules, mongodb role
// arrays): the desired state is the union of the applied and desired grants
// (revokes are deferred), and rebuild replaces the account's permissions with
// exactly that set.
func ApplyGrantsRebuild(bindingMetadata BindingMetadata, supportedGrantTypes []GrantType,
	rebuild func(grantsApplied []BindingGrant) error) (GrantApplyResult, error) {
	if err := VerifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return GrantApplyResult{}, err
	}

	bindingGrants, err := ParseGrants(bindingMetadata.Grants, supportedGrantTypes)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error parsing grants: %w", err)
	}

	pendingRevokes, newGrants := DiffGrants(bindingMetadata.GrantsApplied, bindingGrants)
	grantsApplied := UnionGrants(bindingMetadata.GrantsApplied, bindingGrants)

	if err := rebuild(grantsApplied); err != nil {
		return GrantApplyResult{}, err
	}

	return GrantApplyResult{
		GrantsApplied:  grantsApplied,
		Granted:        newGrants,
		PendingRevokes: pendingRevokes,
	}, nil
}

// RevokeThenRegrant is the RevokeGrants scaffolding for incremental bindings:
// execute the revokes, then re-apply the grants that must remain, because a
// revoke at the same scope removes privileges the remaining grants still need
// (e.g. revoking full:t1 while read:t1 remains drops the shared SELECT on t1).
// perms executes one grant or revoke batch; op is "grant" or "revoke".
func RevokeThenRegrant(revokes, regrants []BindingGrant,
	perms func(op string, grants []BindingGrant) error) error {
	if len(revokes) == 0 {
		return nil
	}
	if err := perms("revoke", revokes); err != nil {
		return fmt.Errorf("error revoking grants: %w", err)
	}
	if err := perms("grant", regrants); err != nil {
		return fmt.Errorf("error re-applying remaining grants: %w", err)
	}
	return nil
}
