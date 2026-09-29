// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
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

// ApplyGrantsIncrementalSafe is ApplyGrantsIncremental for bindings whose
// grant statements auto-commit individually (SQL databases): the server
// discards GrantApplyResult on error, so a batch that fails midway would
// leave the grants already executed untracked. Each grant is executed on its
// own and, on failure, the new grants executed so far (including the failing
// one, which may span several statements) are revoked and the previously
// applied grants re-granted, since a revoke can remove privileges shared
// with them. perms executes one grant or revoke batch; op is "grant" or
// "revoke". Cleanup runs under its own bounded context so that request
// cancellation does not leave permissions half applied.
func ApplyGrantsIncrementalSafe(ctx context.Context, bindingMetadata BindingMetadata, supportedGrantTypes []GrantType,
	reapplyAll bool, perms func(ctx context.Context, op string, grants []BindingGrant) ([]BindingGrant, error)) (GrantApplyResult, error) {
	return ApplyGrantsIncremental(bindingMetadata, supportedGrantTypes, reapplyAll,
		func(grants []BindingGrant) ([]BindingGrant, error) {
			return applyGrantsSafely(ctx, bindingMetadata.GrantsApplied, grants, perms)
		})
}

// applyGrantsSafely executes grants one at a time and compensates a partial
// failure by revoking the new grants executed so far and restoring previous.
func applyGrantsSafely(ctx context.Context, previous, grants []BindingGrant,
	perms func(context.Context, string, []BindingGrant) ([]BindingGrant, error)) ([]BindingGrant, error) {
	// Validate the whole batch before executing any SQL.
	for _, grant := range grants {
		if grant.GrantType == GrantTypeCreate && grant.GrantTarget != "" && grant.GrantTarget != GrantTargetAll {
			return nil, fmt.Errorf("create grant on specific table is not supported")
		}
	}
	var processed []BindingGrant
	for i, grant := range grants {
		done, err := perms(ctx, "grant", []BindingGrant{grant})
		if err == nil {
			processed = UnionGrants(processed, done)
			continue
		}
		// Include the failing grant: it may comprise several auto-committed SQL
		// statements. Do not revoke pre-existing grants during a reapply.
		rollback := SubtractGrants(grants[:i+1], previous)
		if len(rollback) == 0 {
			return nil, err
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		var cleanupErr error
		for j := len(rollback) - 1; j >= 0; j-- {
			_, revokeErr := perms(cleanupCtx, "revoke", rollback[j:j+1])
			cleanupErr = errors.Join(cleanupErr, revokeErr)
		}
		// A revoke can remove privileges shared with a previous grant. Restore
		// those even if a different revoke failed, and report every cleanup error.
		_, restoreErr := perms(cleanupCtx, "grant", previous)
		cleanupErr = errors.Join(cleanupErr, restoreErr)
		cancel()
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("error rolling back partial grants: %w", cleanupErr))
		}
		return nil, err
	}
	return processed, nil
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
