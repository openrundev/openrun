// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"errors"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestDeployTxnRollbackAllReverseOrder(t *testing.T) {
	ctx := context.Background()
	d := NewDeployTxn()

	var order []string
	d.Register(types.AppId("app1"), func(context.Context) error { order = append(order, "app1"); return nil }, nil)
	d.Register(types.AppId("app2"), func(context.Context) error { order = append(order, "app2"); return nil }, nil)
	d.Register(types.AppId("app3"), func(context.Context) error { order = append(order, "app3"); return nil }, nil)

	if err := d.RollbackAll(ctx); err != nil {
		t.Fatalf("RollbackAll error: %v", err)
	}
	want := []string{"app3", "app2", "app1"}
	if len(order) != len(want) {
		t.Fatalf("order=%v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order=%v, want %v", order, want)
		}
	}

	order = nil
	if err := d.RollbackAll(ctx); err != nil {
		t.Fatalf("second RollbackAll error: %v", err)
	}
	if len(order) != 0 {
		t.Fatalf("second RollbackAll ran %v, want none", order)
	}
}

func TestDeployTxnRollbackAllJoinsErrors(t *testing.T) {
	ctx := context.Background()
	d := NewDeployTxn()
	errA := errors.New("boom-a")
	errB := errors.New("boom-b")
	d.Register(types.AppId("app1"), func(context.Context) error { return errA }, nil)
	d.Register(types.AppId("app2"), func(context.Context) error { return errB }, nil)

	err := d.RollbackAll(ctx)
	if err == nil {
		t.Fatal("expected joined error")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("joined error missing parts: %v", err)
	}
}

func TestDeployTxnCommitRunsCommitActions(t *testing.T) {
	ctx := context.Background()
	d := NewDeployTxn()

	var committed []string
	rolledBack := false
	d.Register(types.AppId("app1"),
		func(context.Context) error { rolledBack = true; return nil },
		func(context.Context) error { committed = append(committed, "app1"); return nil })
	d.Register(types.AppId("app2"), nil,
		func(context.Context) error { committed = append(committed, "app2"); return nil })

	if err := d.CommitAll(ctx); err != nil {
		t.Fatalf("CommitAll error: %v", err)
	}
	if len(committed) != 2 {
		t.Fatalf("committed=%v, want both apps", committed)
	}
	if rolledBack {
		t.Fatal("commit must not run rollback actions")
	}
	if err := d.RollbackAll(ctx); err != nil {
		t.Fatalf("RollbackAll after commit: %v", err)
	}
	if rolledBack {
		t.Fatal("rollback ran after the stack was drained by commit")
	}
}

func TestClusterRollbackClean(t *testing.T) {
	base := errors.New("verify failed")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"plain error is clean (db rollback reverts)", base, true},
		{"clean cluster rollback", &DeployRollbackError{Err: base, Available: true}, true},
		{"snapshot unavailable", &DeployRollbackError{Err: base, Available: false}, false},
		{"rollback failed", &DeployRollbackError{Err: base, Available: true, RollbackErr: errors.New("restore failed")}, false},
		{"wrapped clean", &DeployRollbackError{Err: base, Available: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClusterRollbackClean(tc.err); got != tc.want {
				t.Fatalf("ClusterRollbackClean=%v, want %v", got, tc.want)
			}
		})
	}

	de := &DeployRollbackError{Err: base, Available: false}
	if !errors.Is(de, base) {
		t.Fatal("DeployRollbackError should unwrap to the base error")
	}
}
