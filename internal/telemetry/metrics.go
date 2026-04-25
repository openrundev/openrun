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
	appInstrumentsOnce       sync.Once
	appRequest               metric.Int64Counter
	appProxyBytes            metric.Int64Counter
)

// resetMetricInstruments is called from Shutdown so that a subsequent Setup
// re-creates instruments against a fresh MeterProvider.
func resetMetricInstruments() {
	dbInstrumentsOnce = sync.Once{}
	dbCallDuration = nil
	containerInstrumentsOnce = sync.Once{}
	containerCallDuration = nil
	appInstrumentsOnce = sync.Once{}
	appRequest = nil
	appProxyBytes = nil
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

func ensureAppInstruments() bool {
	appInstrumentsOnce.Do(func() {
		meter := Meter()
		var err error
		appRequest, err = meter.Int64Counter(
			"openrun.app.request",
			metric.WithDescription("Total app requests"),
		)
		if err != nil {
			return
		}
		appProxyBytes, err = meter.Int64Counter(
			"openrun.app.proxy.bytes",
			metric.WithUnit("By"),
			metric.WithDescription("Bytes transferred by app reverse proxies"),
		)
		if err != nil {
			appRequest = nil
			return
		}
	})
	return appRequest != nil && appProxyBytes != nil
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
func RecordContainerCall(ctx context.Context, kind, operation string, start time.Time, err error, extraAttrs ...attribute.KeyValue) {
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
	attrs = append(attrs, extraAttrs...)
	hist.Record(ctx, float64(time.Since(start).Microseconds())/1000.0, metric.WithAttributes(attrs...))
}

// RecordAppRequest records app-level request counters. It is a no-op when
// metrics are disabled.
func RecordAppRequest(ctx context.Context, method string, attrs ...attribute.KeyValue) {
	if !MetricsEnabled() || !ensureAppInstruments() {
		return
	}
	totalAttrs := metricAttrs(attrs, attribute.String("openrun.request.kind", "total"))
	appRequest.Add(ctx, 1, metric.WithAttributes(totalAttrs...))
	switch method {
	case "GET":
		getAttrs := metricAttrs(attrs, attribute.String("openrun.request.kind", "get"))
		appRequest.Add(ctx, 1, metric.WithAttributes(getAttrs...))
	case "HEAD", "OPTIONS":
		return
	default:
		updateAttrs := metricAttrs(attrs, attribute.String("openrun.request.kind", "update"))
		appRequest.Add(ctx, 1, metric.WithAttributes(updateAttrs...))
	}
}

// RecordAppProxyBytes records app reverse-proxy byte counters. bytesIn is
// traffic received from the client, and bytesOut is traffic sent to the client.
func RecordAppProxyBytes(ctx context.Context, bytesIn, bytesOut uint64, attrs ...attribute.KeyValue) {
	if !MetricsEnabled() || !ensureAppInstruments() {
		return
	}
	if bytesIn > 0 {
		inAttrs := metricAttrs(attrs, attribute.String("openrun.proxy.direction", "in"))
		appProxyBytes.Add(ctx, saturatingInt64(bytesIn), metric.WithAttributes(inAttrs...))
	}
	if bytesOut > 0 {
		outAttrs := metricAttrs(attrs, attribute.String("openrun.proxy.direction", "out"))
		appProxyBytes.Add(ctx, saturatingInt64(bytesOut), metric.WithAttributes(outAttrs...))
	}
}

func metricAttrs(attrs []attribute.KeyValue, extra attribute.KeyValue) []attribute.KeyValue {
	ret := make([]attribute.KeyValue, 0, len(attrs)+1)
	ret = append(ret, attrs...)
	ret = append(ret, extra)
	return ret
}

func saturatingInt64(v uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if v > maxInt64 {
		return int64(maxInt64)
	}
	return int64(v)
}
