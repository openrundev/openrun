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
	RecordAppProxyBytes(context.Background(), 10, 20)
	if appRequest == nil {
		t.Fatal("expected app request counter to be initialized")
	}
	if appProxyBytes == nil {
		t.Fatal("expected app proxy byte counter to be initialized")
	}
}
