// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestDeriveReplicationState(t *testing.T) {
	t.Parallel()

	now := time.Now()
	running := true
	stopped := false

	// Undefined config wins over everything
	if state := deriveReplicationState(false, &running, now, time.Second, now); state != types.ReplicationStateMisconfigured {
		t.Fatalf("state = %s, want misconfigured", state)
	}

	// A dead sidecar is flagged regardless of replica recency: the bucket
	// shows what arrived, not what is pending
	if state := deriveReplicationState(true, &stopped, now, time.Second, now); state != types.ReplicationStateSidecarDown {
		t.Fatalf("state = %s, want sidecar_down", state)
	}

	// Nothing replicated yet
	if state := deriveReplicationState(true, &running, time.Time{}, time.Second, now); state != types.ReplicationStatePending {
		t.Fatalf("state = %s, want pending", state)
	}

	// Never-deployed environment: no data and no sidecar is pending, not a
	// failure
	if state := deriveReplicationState(true, &stopped, time.Time{}, time.Second, now); state != types.ReplicationStatePending {
		t.Fatalf("state = %s, want pending", state)
	}

	// Recent upload with live sidecar
	if state := deriveReplicationState(true, &running, now.Add(-30*time.Second), time.Second, now); state != types.ReplicationStateHealthy {
		t.Fatalf("state = %s, want healthy", state)
	}

	// Old uploads with a live sidecar read as idle, not failure: an idle app
	// and a healthy sidecar produce the same bucket state
	if state := deriveReplicationState(true, &running, now.Add(-time.Hour), time.Second, now); state != types.ReplicationStateIdle {
		t.Fatalf("state = %s, want idle", state)
	}

	// Unknown sidecar state (kubernetes): recency alone decides
	if state := deriveReplicationState(true, nil, now.Add(-30*time.Second), time.Second, now); state != types.ReplicationStateHealthy {
		t.Fatalf("state with nil sidecar = %s, want healthy", state)
	}

	// The staleness threshold scales with the configured sync interval
	if state := deriveReplicationState(true, &running, now.Add(-15*time.Minute), 5*time.Minute, now); state != types.ReplicationStateHealthy {
		t.Fatalf("state with slow sync interval = %s, want healthy", state)
	}
}
