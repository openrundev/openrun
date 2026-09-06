package system

import (
	"context"
	"testing"
	"time"
)

func TestPeriodicTaskStopCancelsAndJoinsPass(t *testing.T) {
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	task := StartPeriodicTask(context.Background(), time.Millisecond, true, func(ctx context.Context) {
		close(started) // A second overlapping pass would panic.
		<-ctx.Done()
		close(canceled)
		<-release
	})
	<-started
	stopped := make(chan struct{})
	go func() { task.Stop(); close(stopped) }()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not cancel the pass")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before pass cleanup")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not join the pass")
	}
	task.Stop()
}

func TestPeriodicTaskDoesNotStartAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	task := StartPeriodicTask(ctx, time.Millisecond, true, func(context.Context) {
		t.Error("started a pass after cancellation")
	})
	task.Stop()
}
