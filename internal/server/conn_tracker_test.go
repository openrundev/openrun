// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func newTrackedPipe(t *connTracker) (*trackedConn, net.Conn) {
	client, server := net.Pipe()
	return &trackedConn{Conn: server, tracker: t}, client
}

func TestConnTrackerHijackAndClose(t *testing.T) {
	tracker := &connTracker{}
	tc, client := newTrackedPipe(tracker)
	defer client.Close() //nolint:errcheck

	// Connections are only tracked once hijacked
	if tracker.count() != 0 {
		t.Fatalf("expected 0 tracked conns, got %d", tracker.count())
	}
	tracker.connState(tc, http.StateHijacked)
	if tracker.count() != 1 {
		t.Fatalf("expected 1 tracked conn, got %d", tracker.count())
	}

	// Closing the hijacked conn removes it, so drain returns immediately
	tc.Close() //nolint:errcheck
	if tracker.count() != 0 {
		t.Fatalf("expected 0 tracked conns after close, got %d", tracker.count())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracker.drain(ctx)
}

func TestConnTrackerDrainForceCloses(t *testing.T) {
	tracker := &connTracker{}
	tc, client := newTrackedPipe(tracker)
	tracker.connState(tc, http.StateHijacked)

	// Expired drain deadline force-closes the connection
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tracker.drain(ctx)
	if tracker.count() != 0 {
		t.Fatalf("expected 0 tracked conns after drain, got %d", tracker.count())
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF from force-closed conn, got %v", err)
	}
}

func TestConnTrackerUnwrapsTLS(t *testing.T) {
	tracker := &connTracker{}
	tc, client := newTrackedPipe(tracker)
	defer client.Close() //nolint:errcheck
	defer tc.Close() //nolint:errcheck

	// The HTTPS server reports the *tls.Conn; connState must unwrap it to
	// find the tracked conn
	tlsConn := tls.Client(tc, &tls.Config{InsecureSkipVerify: true})
	tracker.connState(tlsConn, http.StateHijacked)
	if tracker.count() != 1 {
		t.Fatalf("expected 1 tracked conn through tls unwrap, got %d", tracker.count())
	}
}

func TestConnTrackerIgnoresUntrackedStates(t *testing.T) {
	tracker := &connTracker{}
	tc, client := newTrackedPipe(tracker)
	defer client.Close() //nolint:errcheck
	defer tc.Close() //nolint:errcheck

	tracker.connState(tc, http.StateNew)
	tracker.connState(tc, http.StateActive)
	tracker.connState(tc, http.StateClosed)
	if tracker.count() != 0 {
		t.Fatalf("expected 0 tracked conns, got %d", tracker.count())
	}
}
