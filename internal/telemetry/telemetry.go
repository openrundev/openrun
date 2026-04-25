// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/openrundev/openrun/internal/types"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const instrumentationName = "github.com/openrundev/openrun"

var (
	enabled         atomic.Bool
	pluginSpansOn   atomic.Bool
	emptyPropagator = propagation.NewCompositeTextMapPropagator()
)

// Providers owns the lifecycle of the SDK providers. It is always returned
// non-nil from Setup so callers do not need to nil-check before Shutdown.
type Providers struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
}

// Enabled reports whether telemetry is currently active.
func Enabled() bool {
	return enabled.Load()
}

// PluginSpansEnabled reports whether per-plugin-call spans should be created.
// Plugin spans can be expensive in apps with high plugin call counts, so they
// are gated independently of the master telemetry switch.
func PluginSpansEnabled() bool {
	return pluginSpansOn.Load()
}

// Setup initializes OpenTelemetry providers based on the server config. It
// always returns a non-nil Providers value: when telemetry is disabled or when
// initialization fails, Shutdown becomes a no-op and the helper functions
// short-circuit through Enabled().
func Setup(ctx context.Context, config *types.ServerConfig, logger *types.Logger) (*Providers, error) {
	providers := &Providers{}
	enabled.Store(false)
	pluginSpansOn.Store(false)
	metricsEnabled.Store(false)

	if config == nil || !config.Telemetry.Enabled {
		return providers, nil
	}

	res, err := newResource(ctx, config)
	if err != nil {
		return providers, err
	}

	if logger != nil {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			logger.Error().Err(err).Msg("OpenTelemetry error")
		}))
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if config.Telemetry.Traces {
		traceExporter, err := otlptracehttp.New(ctx, traceExporterOptions(config)...)
		if err != nil {
			return providers, fmt.Errorf("initialize OpenTelemetry trace exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(traceExporter),
			sdktrace.WithResource(res),
		)
		providers.tracerProvider = tp
		otel.SetTracerProvider(tp)
	}

	if config.Telemetry.Metrics {
		metricExporter, err := otlpmetrichttp.New(ctx, metricExporterOptions(config)...)
		if err != nil {
			return providers, fmt.Errorf("initialize OpenTelemetry metric exporter: %w", err)
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
			sdkmetric.WithResource(res),
		)
		providers.meterProvider = mp
		otel.SetMeterProvider(mp)
		metricsEnabled.Store(true)
	}

	enabled.Store(true)
	pluginSpansOn.Store(config.Telemetry.PluginSpans)
	if logger != nil {
		logger.Info().
			Bool("traces", config.Telemetry.Traces).
			Bool("metrics", config.Telemetry.Metrics).
			Bool("plugin_spans", config.Telemetry.PluginSpans).
			Str("endpoint", config.Telemetry.Endpoint).
			Msg("OpenTelemetry enabled")
	}
	return providers, nil
}

// Shutdown flushes and closes the SDK providers. It is safe to call on a
// disabled or partially-initialized Providers value.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	enabled.Store(false)
	pluginSpansOn.Store(false)
	metricsEnabled.Store(false)

	var err error
	if p.meterProvider != nil {
		err = errors.Join(err, p.meterProvider.Shutdown(ctx))
		p.meterProvider = nil
	}
	if p.tracerProvider != nil {
		err = errors.Join(err, p.tracerProvider.Shutdown(ctx))
		p.tracerProvider = nil
	}

	// Reset cached metric instruments so a subsequent Setup re-creates them
	// against the new MeterProvider rather than reusing handles bound to the
	// shut-down one.
	resetMetricInstruments()

	// Reset globals so callers that cached a tracer don't keep emitting into a
	// shut-down exporter (mostly relevant for tests that re-Setup in-process).
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	otel.SetTextMapPropagator(emptyPropagator)
	return err
}

// Tracer returns the OpenRun tracer (a no-op when telemetry is disabled).
func Tracer() trace.Tracer {
	return otel.Tracer(instrumentationName)
}

// Meter returns the OpenRun meter (a no-op when telemetry is disabled).
func Meter() metric.Meter {
	return otel.Meter(instrumentationName)
}

// StartSpan starts a span with the given name and attributes. When telemetry
// is disabled it returns the input context and a no-op span.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// RecordError annotates a span with an error if err is non-nil. Safe with a
// nil span.
func RecordError(span trace.Span, err error) {
	if err == nil || span == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// ServerHandlerOption configures WrapServerHandler.
type ServerHandlerOption struct {
	// Operation is the otelhttp base operation name.
	Operation string
	// Public marks the listener as untrusted. When true, incoming
	// trace-context headers are NOT extracted, so external clients cannot
	// inject parent spans into our trace.
	Public bool
	// ExtraSkipPaths lists URL path prefixes that should never be traced. The
	// internal health endpoint is always skipped.
	ExtraSkipPaths []string
	// TraceOnlyPrefixes, when set, limits server-level instrumentation to URL
	// path prefixes owned by OpenRun itself. Public app traffic should rely on
	// app-level spans where per-app redaction/skip policy is available.
	TraceOnlyPrefixes []string
}

// WrapServerHandler wraps an http.Handler with otelhttp instrumentation. When
// telemetry is disabled the handler is returned unchanged.
func WrapServerHandler(handler http.Handler, opt ServerHandlerOption) http.Handler {
	if !Enabled() {
		return handler
	}

	skipPrefixes := append([]string(nil), opt.ExtraSkipPaths...)
	traceOnlyPrefixes := append([]string(nil), opt.TraceOnlyPrefixes...)
	healthPath := types.INTERNAL_URL_PREFIX + "/health"

	otelOpts := []otelhttp.Option{
		otelhttp.WithSpanNameFormatter(serverSpanName),
		otelhttp.WithFilter(func(r *http.Request) bool {
			if r == nil || r.URL == nil {
				return true
			}
			if r.URL.Path == healthPath {
				return false
			}
			if len(traceOnlyPrefixes) > 0 {
				allowed := false
				for _, p := range traceOnlyPrefixes {
					if strings.HasPrefix(r.URL.Path, p) {
						allowed = true
						break
					}
				}
				if !allowed {
					return false
				}
			}
			for _, p := range skipPrefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					return false
				}
			}
			return true
		}),
		otelhttp.WithMetricAttributesFn(func(r *http.Request) []attribute.KeyValue {
			return []attribute.KeyValue{attribute.String("openrun.route_class", routeClass(r))}
		}),
	}
	if opt.Public {
		// Do not let untrusted clients become the parent of our spans.
		otelOpts = append(otelOpts, otelhttp.WithPropagators(emptyPropagator))
	}
	return otelhttp.NewHandler(handler, opt.Operation, otelOpts...)
}

// WrapTransport wraps an outbound RoundTripper with otelhttp instrumentation,
// which propagates the active trace context to the upstream and records a
// client span.
func WrapTransport(base http.RoundTripper) http.RoundTripper {
	if !Enabled() {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// AppAttributes returns the immutable per-app attribute set. Cache the result
// on the App and reuse across requests; do not call this on the hot path.
func AppAttributes(app *types.AppEntry) []attribute.KeyValue {
	if app == nil {
		return nil
	}
	return []attribute.KeyValue{
		attribute.String("openrun.app.id", string(app.Id)),
		attribute.String("openrun.app.path", app.Path),
		attribute.String("openrun.app.domain", app.Domain),
		attribute.Bool("openrun.app.is_dev", app.IsDev),
		attribute.String("openrun.app.auth_type", string(app.Metadata.AuthnType)),
		attribute.Int("openrun.app.version", app.Metadata.VersionMetadata.Version),
	}
}

// RequestAttributes returns per-request attributes that are safe to record.
// Notably, no client-supplied values (Host, URL path, query) are included
// here; those must be added by callers that have applied per-app redaction.
func RequestAttributes(r *http.Request) []attribute.KeyValue {
	if r == nil {
		return nil
	}
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", r.Method),
		attribute.String("url.scheme", requestScheme(r)),
	}
	if rid := r.Context().Value(types.REQUEST_ID); rid != nil {
		if ridStr, ok := rid.(string); ok && ridStr != "" {
			attrs = append(attrs, attribute.String("openrun.request_id", ridStr))
		}
	}
	return attrs
}

func traceExporterOptions(config *types.ServerConfig) []otlptracehttp.Option {
	opts := make([]otlptracehttp.Option, 0, 2)
	if endpoint := parseOTLPEndpoint(config.Telemetry.Endpoint); endpoint.configured() {
		if endpoint.fullURL != "" {
			opts = append(opts, otlptracehttp.WithEndpointURL(endpoint.fullURL))
		} else {
			opts = append(opts, otlptracehttp.WithEndpoint(endpoint.host))
			if endpoint.insecure {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
		}
	}
	if len(config.Telemetry.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(config.Telemetry.Headers))
	}
	return opts
}

func metricExporterOptions(config *types.ServerConfig) []otlpmetrichttp.Option {
	opts := make([]otlpmetrichttp.Option, 0, 2)
	if endpoint := parseOTLPEndpoint(config.Telemetry.Endpoint); endpoint.configured() {
		if endpoint.fullURL != "" {
			opts = append(opts, otlpmetrichttp.WithEndpointURL(endpoint.fullURL))
		} else {
			opts = append(opts, otlpmetrichttp.WithEndpoint(endpoint.host))
			if endpoint.insecure {
				opts = append(opts, otlpmetrichttp.WithInsecure())
			}
		}
	}
	if len(config.Telemetry.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(config.Telemetry.Headers))
	}
	return opts
}

type otlpEndpoint struct {
	host     string
	fullURL  string
	insecure bool
}

func (e otlpEndpoint) configured() bool {
	return e.host != "" || e.fullURL != ""
}

func parseOTLPEndpoint(raw string) otlpEndpoint {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return otlpEndpoint{}
	}

	u, err := url.Parse(raw)
	if err == nil && u.Scheme != "" && u.Host != "" {
		if u.Path == "" || u.Path == "/" {
			return otlpEndpoint{
				host:     u.Host,
				insecure: u.Scheme == "http",
			}
		}
		return otlpEndpoint{fullURL: raw}
	}

	return otlpEndpoint{host: raw}
}

func newResource(ctx context.Context, config *types.ServerConfig) (*resource.Resource, error) {
	serviceName := strings.TrimSpace(config.Telemetry.ServiceName)
	if serviceName == "" {
		serviceName = strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	}
	if serviceName == "" {
		serviceName = "openrun"
	}

	instanceID := string(types.CurrentServerId)
	attrs := []attribute.KeyValue{
		attribute.String("service.name", serviceName),
		attribute.String("service.version", types.GetVersion()),
		attribute.String("service.instance.id", instanceID),
		attribute.String("openrun.commit", types.GetCommit()),
		attribute.String("openrun.server_id", instanceID),
	}
	if config.Telemetry.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment.name", config.Telemetry.Environment))
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithProcess(),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize OpenTelemetry resource: %w", err)
	}
	return res, nil
}

func serverSpanName(_ string, r *http.Request) string {
	if r == nil {
		return "openrun.http"
	}
	return r.Method + " " + routeClass(r)
}

func routeClass(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "openrun.http"
	}
	switch {
	case r.URL.Path == types.INTERNAL_URL_PREFIX+"/health":
		return types.INTERNAL_URL_PREFIX + "/health"
	case strings.HasPrefix(r.URL.Path, types.INTERNAL_URL_PREFIX+"/"):
		return types.INTERNAL_URL_PREFIX + "/*"
	case strings.HasPrefix(r.URL.Path, types.WEBHOOK_URL_PREFIX+"/"):
		return types.WEBHOOK_URL_PREFIX + "/*"
	default:
		return "app.request"
	}
}

func requestScheme(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	if r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
