// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// metricsEnabled is set true by Setup when metrics are configured. It is a
// finer-grained switch than Enabled(): callers that only care about counters
// (e.g. the SQL driver wrapper, the container manager wrapper) can avoid the
// per-call work entirely when metrics are off.
var metricsEnabled atomic.Bool

// MetricsEnabled reports whether metric instrumentation is currently active.
func MetricsEnabled() bool {
	return metricsEnabled.Load()
}

var (
	dbInstrumentsOnce        sync.Once
	dbCallDuration           metric.Float64Histogram
	containerInstrumentsOnce sync.Once
	containerCallDuration    metric.Float64Histogram
)

// resetMetricInstruments is called from Shutdown so that a subsequent Setup
// re-creates instruments against a fresh MeterProvider.
func resetMetricInstruments() {
	dbInstrumentsOnce = sync.Once{}
	dbCallDuration = nil
	containerInstrumentsOnce = sync.Once{}
	containerCallDuration = nil
}

func ensureDBInstruments() metric.Float64Histogram {
	dbInstrumentsOnce.Do(func() {
		hist, err := Meter().Float64Histogram(
			"openrun.db.call.duration",
			metric.WithUnit("ms"),
			metric.WithDescription("Duration of database driver calls in milliseconds"),
		)
		if err != nil {
			return
		}
		dbCallDuration = hist
	})
	return dbCallDuration
}

func ensureContainerInstruments() metric.Float64Histogram {
	containerInstrumentsOnce.Do(func() {
		hist, err := Meter().Float64Histogram(
			"openrun.container.call.duration",
			metric.WithUnit("ms"),
			metric.WithDescription("Duration of container manager calls in milliseconds"),
		)
		if err != nil {
			return
		}
		containerCallDuration = hist
	})
	return containerCallDuration
}

// RecordDBCall records the duration and outcome of a SQL driver call. It is a
// no-op when metrics are disabled.
func RecordDBCall(ctx context.Context, dbSystem, invoker, operation string, start time.Time, err error) {
	if !MetricsEnabled() {
		return
	}
	hist := ensureDBInstruments()
	if hist == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("db.system", dbSystem),
		attribute.String("openrun.db.invoker", invoker),
		attribute.String("db.operation", operation),
		attribute.Bool("openrun.error", err != nil),
	}
	hist.Record(ctx, float64(time.Since(start).Microseconds())/1000.0, metric.WithAttributes(attrs...))
}

// RecordContainerCall records the duration and outcome of a container manager
// call. It is a no-op when metrics are disabled.
func RecordContainerCall(ctx context.Context, kind, operation string, start time.Time, err error) {
	if !MetricsEnabled() {
		return
	}
	hist := ensureContainerInstruments()
	if hist == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("openrun.container.kind", kind),
		attribute.String("openrun.container.op", operation),
		attribute.Bool("openrun.error", err != nil),
	}
	hist.Record(ctx, float64(time.Since(start).Microseconds())/1000.0, metric.WithAttributes(attrs...))
}
