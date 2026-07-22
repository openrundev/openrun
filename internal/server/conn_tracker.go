// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// connTracker tracks connections that have been hijacked from the HTTP
// server (websocket upgrades through the app reverse proxy).
// http.Server.Shutdown neither waits for nor closes hijacked connections, so
// on shutdown the server would either exit with live websockets or leak
// them past the drain. The tracker wraps each accepted connection, marks it
// on the http.ConnState StateHijacked transition and forgets it on close,
// which lets Stop wait for hijacked connections to finish and force-close
// the stragglers when the drain deadline expires
type connTracker struct {
	conns sync.Map // *trackedConn -> struct{}
}

type trackedConn struct {
	net.Conn
	tracker  *connTracker
	hijacked atomic.Bool
	closed   atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	if c.hijacked.Load() {
		c.tracker.conns.Delete(c)
	}
	return c.Conn.Close()
}

type trackedListener struct {
	net.Listener
	tracker *connTracker
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: conn, tracker: l.tracker}, nil
}

// wrap returns a listener whose connections are tracked. For TLS servers the
// raw TCP listener must be wrapped (before tls.NewListener) so the tracked
// conn is reachable through tls.Conn.NetConn in connState
func (t *connTracker) wrap(ln net.Listener) net.Listener {
	return &trackedListener{Listener: ln, tracker: t}
}

// connState is the http.Server ConnState hook. It registers connections as
// they are hijacked
func (t *connTracker) connState(conn net.Conn, state http.ConnState) {
	if state != http.StateHijacked {
		return
	}
	for conn != nil {
		switch c := conn.(type) {
		case *trackedConn:
			c.hijacked.Store(true)
			t.conns.Store(c, struct{}{})
			// The hijacking handler can close the conn between the Store
			// calls above; re-check so the entry does not leak
			if c.closed.Load() {
				t.conns.Delete(c)
			}
			return
		case interface{ NetConn() net.Conn }: // tls.Conn
			conn = c.NetConn()
		default:
			return
		}
	}
}

func (t *connTracker) count() int {
	count := 0
	t.conns.Range(func(any, any) bool {
		count++
		return true
	})
	return count
}

// drain waits for all hijacked connections to close, or until the context
// expires, at which point the remaining connections are force-closed
func (t *connTracker) drain(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for t.count() > 0 {
		select {
		case <-ctx.Done():
			t.conns.Range(func(key, _ any) bool {
				key.(*trackedConn).Close() //nolint:errcheck
				return true
			})
			return
		case <-ticker.C:
		}
	}
}
