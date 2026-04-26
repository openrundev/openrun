// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMetricRecordingNoopsWhenDisabled(t *testing.T) {
	metricsEnabled.Store(false)
	t.Cleanup(func() { metricsEnabled.Store(false) })

	if MetricsEnabled() {
		t.Fatal("metrics should start disabled")
	}

	RecordDBCall(context.Background(), DBSystemSQLite, "test", "select", time.Now(), nil)
	RecordContainerCall(context.Background(), "command", "run_container", time.Now(), nil)
	RecordAppRequest(context.Background(), "GET")
	RecordAppResponse(context.Background(), 200)
	RecordAppProxyBytes(context.Background(), 10, 20)
}

func TestMetricRecordingCreatesInstrumentsWhenEnabled(t *testing.T) {
	metricsEnabled.Store(true)
	resetMetricInstruments()
	t.Cleanup(func() {
		metricsEnabled.Store(false)
		resetMetricInstruments()
	})

	if !MetricsEnabled() {
		t.Fatal("metrics should be enabled")
	}

	RecordDBCall(context.Background(), DBSystemSQLite, "test", "select", time.Now().Add(-time.Millisecond), nil)
	if dbCallDuration == nil {
		t.Fatal("expected DB histogram to be initialized")
	}

	RecordContainerCall(context.Background(), "command", "run_container", time.Now().Add(-time.Millisecond), errors.New("boom"))
	if containerCallDuration == nil {
		t.Fatal("expected container histogram to be initialized")
	}

	RecordAppRequest(context.Background(), "GET")
	RecordAppRequest(context.Background(), "POST")
	RecordAppResponse(context.Background(), 200)
	RecordAppResponse(context.Background(), 401)
	RecordAppResponse(context.Background(), 403)
	RecordAppResponse(context.Background(), 404)
	RecordAppResponse(context.Background(), 500)
	RecordAppProxyBytes(context.Background(), 10, 20)
	if appRequest == nil {
		t.Fatal("expected app request counter to be initialized")
	}
	if appResponse == nil {
		t.Fatal("expected app response counter to be initialized")
	}
	if appProxyBytes == nil {
		t.Fatal("expected app proxy byte counter to be initialized")
	}
}

func TestStatusBucket(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{100, "1xx"},
		{200, "2xx"},
		{302, "3xx"},
		{401, "401"},
		{403, "403"},
		{404, "4xx"},
		{500, "5xx"},
		{0, "unknown"},
	}
	for _, tt := range tests {
		if got := statusBucket(tt.status); got != tt.want {
			t.Fatalf("statusBucket(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
