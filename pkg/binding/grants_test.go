// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPartialGrantFailureRestoresPreviousPrivileges(t *testing.T) {
	read := BindingGrant{GrantType: GrantTypeRead, GrantTarget: "*"}
	full := BindingGrant{GrantType: GrantTypeFull, GrantTarget: "*"}
	create := BindingGrant{GrantType: GrantTypeCreate, GrantTarget: "*"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Model overlapping grants: revoking full removes read, so the old read
	// grant must be restored. The failing create has already changed state.
	state := map[string]bool{"read": true}
	failure := errors.New("grant interrupted")
	var calls []string
	processed, err := applyGrantsSafely(ctx, []BindingGrant{read}, []BindingGrant{full, create},
		func(callCtx context.Context, op string, grants []BindingGrant) ([]BindingGrant, error) {
			if callCtx.Err() != nil {
				t.Fatal("cleanup used canceled context")
			}
			for _, g := range grants {
				calls = append(calls, op+" "+g.String())
				if op == "grant" {
					switch g.GrantType {
					case GrantTypeRead:
						state["read"] = true
					case GrantTypeFull:
						state["read"], state["write"] = true, true
					case GrantTypeCreate:
						state["create"] = true
						cancel()
						return nil, failure
					}
				} else {
					if _, ok := callCtx.Deadline(); !ok {
						t.Fatal("cleanup has no deadline")
					}
					switch g.GrantType {
					case GrantTypeFull:
						delete(state, "read")
						delete(state, "write")
					case GrantTypeCreate:
						delete(state, "create")
					}
				}
			}
			return grants, nil
		})
	if !errors.Is(err, failure) || len(processed) != 0 {
		t.Fatalf("result = %v, %v", processed, err)
	}
	if !reflect.DeepEqual(state, map[string]bool{"read": true}) {
		t.Fatalf("permissions after failed update: %v", state)
	}
	want := []string{"grant FULL:*", "grant CREATE:*", "revoke CREATE:*", "revoke FULL:*", "grant READ:*"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestInvalidGrantBatchHasNoSideEffects(t *testing.T) {
	grants := []BindingGrant{{GrantType: GrantTypeFull, GrantTarget: "*"}, {GrantType: GrantTypeCreate, GrantTarget: "table"}}
	_, err := applyGrantsSafely(context.Background(), nil, grants, func(context.Context, string, []BindingGrant) ([]BindingGrant, error) {
		t.Fatal("invalid batch executed SQL")
		return nil, nil
	})
	if err == nil {
		t.Fatal("invalid create grant accepted")
	}
}

func TestGrantCleanupContinuesAfterRevokeFailure(t *testing.T) {
	read := BindingGrant{GrantType: GrantTypeRead, GrantTarget: "*"}
	full := BindingGrant{GrantType: GrantTypeFull, GrantTarget: "*"}
	create := BindingGrant{GrantType: GrantTypeCreate, GrantTarget: "*"}
	failure, cleanupFailure := errors.New("apply failed"), errors.New("revoke failed")
	var revokedFull, restoredRead bool
	_, err := applyGrantsSafely(context.Background(), []BindingGrant{read}, []BindingGrant{full, create},
		func(_ context.Context, op string, grants []BindingGrant) ([]BindingGrant, error) {
			for _, g := range grants {
				if g == create {
					if op == "grant" {
						return nil, failure
					}
					return nil, cleanupFailure
				}
				if op == "revoke" && g == full {
					revokedFull = true
				}
				if op == "grant" && g == read {
					restoredRead = true
				}
			}
			return grants, nil
		})
	if !errors.Is(err, failure) || !errors.Is(err, cleanupFailure) || !revokedFull || !restoredRead {
		t.Fatalf("cleanup result: %v, revoked=%v restored=%v", err, revokedFull, restoredRead)
	}
}

func TestReapplyFailureDoesNotRevokeExistingGrants(t *testing.T) {
	read := BindingGrant{GrantType: GrantTypeRead, GrantTarget: "*"}
	failure := errors.New("apply failed")
	_, err := applyGrantsSafely(context.Background(), []BindingGrant{read}, []BindingGrant{read},
		func(_ context.Context, op string, _ []BindingGrant) ([]BindingGrant, error) {
			if op != "grant" {
				t.Fatal("revoked pre-existing grant")
			}
			return nil, failure
		})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyGrantsIncrementalSafeRollsBackNewGrantsOnly(t *testing.T) {
	read := BindingGrant{GrantType: GrantTypeRead, GrantTarget: "*"}
	full := BindingGrant{GrantType: GrantTypeFull, GrantTarget: "*"}
	failure := errors.New("grant failed")
	var calls []string
	metadata := BindingMetadata{Grants: []string{"read:*", "full:*"}, GrantsApplied: []BindingGrant{read}}
	_, err := ApplyGrantsIncrementalSafe(context.Background(), metadata, []GrantType{GrantTypeRead, GrantTypeFull}, false,
		func(_ context.Context, op string, grants []BindingGrant) ([]BindingGrant, error) {
			for _, g := range grants {
				calls = append(calls, op+" "+g.String())
			}
			if op == "grant" && grants[0] == full {
				return nil, failure
			}
			return grants, nil
		})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
	// Only the new full grant is executed and rolled back; read is restored, never revoked.
	want := []string{"grant FULL:*", "revoke FULL:*", "grant READ:*"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}
