// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func testJobRun(id string, trigger string, scheduledAt time.Time) *types.JobRun {
	lease := time.Now().Add(time.Minute)
	return &types.JobRun{
		Id: id, AppId: "app_prd_1", AppPath: "/orders", JobName: "report", Trigger: trigger, Actor: "admin",
		Version: 3, Definition: `{"name":"report"}`, Args: map[string]string{"region": "eu"},
		ScheduledAt: scheduledAt, StartedAt: time.Now().UTC(), Status: types.JobRunRunning, NodeId: "node1", LeaseUntil: &lease,
	}
}

func TestJobRunsLifecycle(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()
	noTx := types.Transaction{}

	tick := time.Date(2026, 9, 3, 3, 0, 0, 0, time.UTC)
	run := testJobRun("run_1", types.JobTriggerCron, tick)
	if err := m.CreateJobRun(ctx, noTx, run); err != nil {
		t.Fatal(err)
	}
	// The same tick cannot be claimed twice, nor can a second run start
	// while the first is active
	if err := m.CreateJobRun(ctx, noTx, testJobRun("run_2", types.JobTriggerCron, tick)); !errors.Is(err, ErrJobRunConflict) {
		t.Fatalf("duplicate claim error %v", err)
	}
	manual := testJobRun("run_3", types.JobTriggerManual, time.Now())
	if err := m.CreateJobRun(ctx, noTx, manual); !errors.Is(err, ErrJobRunConflict) {
		t.Fatalf("second active run error %v", err)
	}
	// A forced run bypasses the active slot
	manual.Forced = true
	if err := m.CreateJobRun(ctx, noTx, manual); err != nil {
		t.Fatalf("forced run: %v", err)
	}

	got, err := m.GetJobRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.JobName != "report" || got.Args["region"] != "eu" || !got.ScheduledAt.Equal(tick) || got.Status != types.JobRunRunning || got.LeaseUntil == nil {
		t.Errorf("run %+v", got)
	}

	if err := m.UpdateJobRunContainer(ctx, noTx, "run_1", "clj-app-1", "cli-app_prd_1:abc"); err != nil {
		t.Fatal(err)
	}
	code := 0
	if err := m.FinishJobRun(ctx, noTx, "run_1", types.JobRunSucceeded, &code, "done"); err != nil {
		t.Fatal(err)
	}
	got, _ = m.GetJobRun(ctx, "run_1")
	if got.Status != types.JobRunSucceeded || got.ExitCode == nil || *got.ExitCode != 0 || got.EndedAt == nil || got.LeaseUntil != nil ||
		got.ContainerName != "clj-app-1" || got.Image != "cli-app_prd_1:abc" {
		t.Errorf("finished run %+v", got)
	}
	// Finishing again is a no-op (the row is no longer running)
	if err := m.FinishJobRun(ctx, noTx, "run_1", types.JobRunLost, nil, "late"); err != nil {
		t.Fatal(err)
	}
	if got, _ = m.GetJobRun(ctx, "run_1"); got.Status != types.JobRunSucceeded {
		t.Errorf("finish overwrote a terminal run: %s", got.Status)
	}

	// The slot is free again after the finish
	if err := m.CreateJobRun(ctx, noTx, testJobRun("run_4", types.JobTriggerManual, time.Now())); err != nil {
		t.Fatalf("run after finish: %v", err)
	}

	active, err := m.ActiveJobRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Errorf("active runs %d", len(active))
	}
	runs, err := m.ListJobRuns(ctx, []types.AppId{"app_prd_1"}, "report", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Errorf("listed runs %d", len(runs))
	}
	runs, _ = m.ListJobRuns(ctx, []types.AppId{"app_prd_1"}, "", types.JobRunSucceeded, 10)
	if len(runs) != 1 || runs[0].Id != "run_1" {
		t.Errorf("status filter %+v", runs)
	}
	if _, err := m.GetJobRun(ctx, "missing"); !errors.Is(err, ErrJobRunNotFound) {
		t.Errorf("missing run error %v", err)
	}
}

func TestJobRunsLeaseAndPrune(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()
	noTx := types.Transaction{}

	run := testJobRun("run_1", types.JobTriggerManual, time.Now())
	run.Forced = true
	if err := m.CreateJobRun(ctx, noTx, run); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateJobRunLease(ctx, "run_1", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	expired, err := m.ExpiredJobRuns(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Id != "run_1" {
		t.Errorf("expired %+v", expired)
	}
	if err := m.FinishJobRun(ctx, noTx, "run_1", types.JobRunLost, nil, "executing node stopped"); err != nil {
		t.Fatal(err)
	}

	for i := 2; i <= 5; i++ {
		r := testJobRun("run_"+string(rune('0'+i)), types.JobTriggerManual, time.Now().Add(time.Duration(i)*time.Second))
		r.Forced = true
		r.StartedAt = time.Now().Add(time.Duration(i) * time.Second).UTC()
		r.ContainerName = "clj-" + r.Id
		if err := m.CreateJobRun(ctx, noTx, r); err != nil {
			t.Fatal(err)
		}
		if err := m.FinishJobRun(ctx, noTx, r.Id, types.JobRunFailed, nil, "x"); err != nil {
			t.Fatal(err)
		}
	}
	old, err := m.PruneJobRuns(ctx, "app_prd_1", "report", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 3 {
		t.Fatalf("pruned %d runs, want 3", len(old))
	}
	remaining, _ := m.ListJobRuns(ctx, []types.AppId{"app_prd_1"}, "report", "", 0)
	if len(remaining) != 2 || remaining[0].Id != "run_5" || remaining[1].Id != "run_4" {
		t.Errorf("remaining %+v", remaining)
	}

	deleted, err := m.DeleteJobRunsForApps(ctx, []types.AppId{"app_prd_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted %d", len(deleted))
	}
	if remaining, _ = m.ListJobRuns(ctx, []types.AppId{"app_prd_1"}, "", "", 0); len(remaining) != 0 {
		t.Errorf("runs left after app delete: %d", len(remaining))
	}
}

func TestJobRunsInTransaction(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	run := testJobRun("run_tx", types.JobTriggerBeforeDeploy, time.Now())
	if err := m.CreateJobRun(ctx, tx, run); err != nil {
		t.Fatal(err)
	}
	if err := m.FinishJobRun(ctx, tx, "run_tx", types.JobRunFailed, nil, "migration failed"); err != nil {
		t.Fatal(err)
	}
	// Rolled back with the create transaction: the run never existed
	tx.Rollback() //nolint:errcheck
	if _, err := m.GetJobRun(ctx, "run_tx"); !errors.Is(err, ErrJobRunNotFound) {
		t.Errorf("run survived the rollback: %v", err)
	}
}

func TestGetJobApps(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	withJobs := &types.AppEntry{Id: "app_prd_j", Path: "/j", Metadata: types.AppMetadata{
		DefinitionJobs: []string{types.JobSpec{Name: "n", Command: []string{"x"}}.String()}}}
	withoutJobs := &types.AppEntry{Id: "app_prd_n", Path: "/n"}
	for _, entry := range []*types.AppEntry{withJobs, withoutJobs} {
		if err := m.CreateApp(ctx, tx, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	apps, err := m.GetJobApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Id != "app_prd_j" || len(apps[0].Metadata.DefinitionJobs) != 1 {
		t.Errorf("job apps %+v", apps)
	}
}
