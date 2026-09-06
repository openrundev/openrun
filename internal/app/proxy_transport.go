// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/http"
	"sync/atomic"
)

// proxyTransport retires a router's connection pool without interrupting
// requests still using that router, including upgraded connections.
type proxyTransport struct {
	transport *http.Transport
	retired   atomic.Bool
}

func (p *proxyTransport) wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p.retired.Load() {
				// A request may have captured the old router before retirement
				// and used its transport afterward. Close its newly idle sockets.
				p.transport.CloseIdleConnections()
			}
		}()
		handler.ServeHTTP(w, r)
	})
}

func retireProxyTransports(transports []*proxyTransport) {
	for _, p := range transports {
		p.retired.Store(true)
		p.transport.CloseIdleConnections()
	}
}
