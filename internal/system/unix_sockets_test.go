// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestUnixClientClosesIdleConnections(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets")
	}
	socket := filepath.Join(t.TempDir(), "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "{}") }),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				closed <- struct{}{}
			}
		},
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	t.Setenv("OPENRUN_HOME", "")
	client := NewHttpClient(socket, "", false)
	defer client.CloseIdleConnections()
	var response map[string]any
	if err := client.Get("/", nil, &response); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle Unix socket was not closed")
	}
}
