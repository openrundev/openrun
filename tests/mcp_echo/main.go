// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// mcp_echo is the upstream for commander/test_mcp_apps.yaml: a stand-in MCP
// server that answers every request with a JSON-RPC-shaped document
// describing what it received (method, path, headers), so the tests can
// check what OpenRun forwarded to an MCP app. It listens on an ephemeral
// loopback port and writes the port to -port-file
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	portFile := flag.String("port-file", "mcp_echo_port.txt", "file to write the listening port to")
	flag.Parse()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(*portFile, []byte(strconv.Itoa(port)), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		headers := map[string]string{}
		for name, values := range r.Header {
			headers[name] = values[0]
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			// A CORS-aware upstream: preflight and simple responses
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}
		w.Header().Set("Content-Type", "application/json")
		result := map[string]any{
			"method": r.Method, "path": r.URL.Path, "headers": headers, "body_len": len(body),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	})
	if err := http.Serve(ln, handler); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
