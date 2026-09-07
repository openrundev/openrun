// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginCallbackDuplicatesDoNotBlock(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		status      int
	}{
		{"success", "state=expected&code=code", http.StatusOK},
		{"state mismatch", "state=wrong&code=code", http.StatusBadRequest},
		{"missing code", "state=expected", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codes, errs := make(chan string, 1), make(chan error, 1)
			handler := loginCallbackHandler("expected", codes, errs)
			// No consumer: a completed login no longer reads these channels.
			for range 3 {
				response := httptest.NewRecorder()
				done := make(chan struct{})
				go func() {
					handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/callback?"+tc.query, nil))
					close(done)
				}()
				select {
				case <-done:
				case <-time.After(time.Second):
					// Release a blocked handler even if this regression fails.
					select {
					case <-codes:
					default:
					}
					select {
					case <-errs:
					default:
					}
					t.Fatal("duplicate callback blocked without a login waiter")
				}
				if response.Code != tc.status {
					t.Fatalf("status = %d, want %d", response.Code, tc.status)
				}
			}
			if tc.status == http.StatusOK {
				if code := <-codes; code != "code" {
					t.Fatalf("code = %q", code)
				}
			} else if len(errs) != 1 {
				t.Fatal("callback error was not delivered")
			}
		})
	}
}
