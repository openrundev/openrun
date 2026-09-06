// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

func TestProxyTransportRetirement(t *testing.T) {
	for _, when := range []string{"idle", "in flight", "before request"} {
		t.Run(when, func(t *testing.T) {
			closed := make(chan struct{}, 1)
			started := make(chan struct{})
			release := make(chan struct{})
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
				_, _ = w.Write([]byte("ok"))
			}))
			upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closed <- struct{}{}
				}
			}
			upstream.Start()
			defer upstream.Close()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.IdleConnTimeout = 0 // leaked idle sockets would live indefinitely
			defer transport.CloseIdleConnections()
			owned := &proxyTransport{transport: transport}
			target, _ := url.Parse(upstream.URL)
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.Transport = transport
			handler := owned.wrap(proxy)
			retire := func() { retireProxyTransports([]*proxyTransport{owned}) }
			if when == "before request" {
				retire()
			}
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handler.ServeHTTP(response, httptest.NewRequest("GET", "http://app/", nil))
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach upstream")
			}
			if when == "in flight" {
				retire()
			}
			close(release)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not finish")
			}
			if response.Code != http.StatusOK || response.Body.String() != "ok" {
				t.Fatalf("retirement interrupted request: %d %q", response.Code, response.Body.String())
			}
			if when == "idle" {
				retire()
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("retired transport retained its connection")
			}
		})
	}
}
