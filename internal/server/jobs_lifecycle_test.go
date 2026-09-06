package server

import (
	"context"
	"testing"
	"time"
)

func TestJobShutdownCancelsAndWaitsForCleanup(t *testing.T) {
	var registry jobRunRegistry
	ctx, finish, err := registry.begin()
	if err != nil {
		t.Fatal(err)
	}
	registry.stop()
	if ctx.Err() != context.Canceled {
		t.Fatal("shutdown did not cancel registered work")
	}
	if _, _, err := registry.begin(); err == nil {
		t.Fatal("shutdown accepted new work")
	}
	waited := make(chan struct{})
	go func() { registry.wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("shutdown returned before cleanup finished")
	default:
	}
	finish()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join completed work")
	}
	registry.stop()
	registry.wait()
}

func TestStoppedJobRunnerClosesTemporaryApp(t *testing.T) {
	s := &Server{}
	s.jobRuns.stop()
	for _, run := range []func(context.Context, *jobExecution) error{
		func(ctx context.Context, exec *jobExecution) error { _, err := s.startJobRun(ctx, exec); return err },
		func(ctx context.Context, exec *jobExecution) error { _, err := s.executeJobRun(ctx, exec); return err },
	} {
		closed := 0
		err := run(context.Background(), &jobExecution{closeApp: func() { closed++ }})
		if err == nil || closed != 1 {
			t.Fatalf("rejected run: error %v, app closed %d times", err, closed)
		}
	}
}
