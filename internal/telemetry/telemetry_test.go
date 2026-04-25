// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

type testHandler struct{ called bool }

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
}

func TestDisabledTelemetryDoesNotWrap(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{}, nil)
	if err != nil {
		t.Fatalf("setup disabled telemetry: %v", err)
	}
	if providers == nil {
		t.Fatalf("Setup must always return a non-nil Providers value")
	}
	if Enabled() {
		t.Fatalf("telemetry should be disabled")
	}
	if PluginSpansEnabled() {
		t.Fatalf("plugin spans should be disabled")
	}

	transport := http.DefaultTransport
	if got := WrapTransport(transport); got != transport {
		t.Fatalf("disabled telemetry should not wrap transports")
	}

	handler := &testHandler{}
	if got := WrapServerHandler(handler, ServerHandlerOption{Operation: "test"}); got != http.Handler(handler) {
		t.Fatalf("disabled telemetry should not wrap handlers")
	}

	// Shutdown on a disabled-but-non-nil Providers must not panic.
	if err := providers.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown disabled telemetry: %v", err)
	}
}

func TestEnabledTelemetryCanPropagateWithoutExporters(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{
		Telemetry: types.TelemetryConfig{
			Enabled:     true,
			Traces:      false,
			Metrics:     false,
			PluginSpans: true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("setup enabled telemetry: %v", err)
	}
	defer func() {
		if err := providers.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown telemetry: %v", err)
		}
	}()

	if !Enabled() {
		t.Fatalf("telemetry should be enabled")
	}
	if !PluginSpansEnabled() {
		t.Fatalf("plugin spans should be enabled")
	}

	transport := http.DefaultTransport
	if got := WrapTransport(transport); got == transport {
		t.Fatalf("enabled telemetry should wrap transports")
	}
}

func TestRecordErrorAnnotatesSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	_, span := tp.Tracer("test").Start(context.Background(), "operation")

	RecordError(span, errors.New("boom"))
	span.End()

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected one ended span, got %d", len(ended))
	}
	if ended[0].Status().Code != codes.Error {
		t.Fatalf("expected error status, got %v", ended[0].Status().Code)
	}

	// Nil and nil-error calls are intentionally no-ops.
	RecordError(nil, errors.New("ignored"))
	RecordError(span, nil)
}

// TestPublicHandlerDoesNotExtractIncomingTraceparent verifies S1: a public
// listener must not let an external client become the parent of our spans.
func TestPublicHandlerDoesNotExtractIncomingTraceparent(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{
		Telemetry: types.TelemetryConfig{
			Enabled: true,
			Traces:  false, // we only need the propagator path
			Metrics: false,
		},
	}, nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer providers.Shutdown(context.Background()) //nolint:errcheck

	// A well-formed traceparent that an external client could send.
	const externalTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

	for _, tc := range []struct {
		name        string
		opt         ServerHandlerOption
		wantTraceID string
	}{
		{
			name:        "trusted listener accepts incoming traceparent",
			opt:         ServerHandlerOption{Operation: "trusted", Public: false},
			wantTraceID: "0af7651916cd43dd8448eb211c80319c",
		},
		{
			name:        "public listener ignores incoming traceparent",
			opt:         ServerHandlerOption{Operation: "public", Public: true},
			wantTraceID: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observedTraceID string
			handler := WrapServerHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				sc := trace.SpanContextFromContext(r.Context())
				if sc.IsValid() {
					observedTraceID = sc.TraceID().String()
				}
			}), tc.opt)

			req := httptest.NewRequest("GET", "/something", nil)
			req.Header.Set("traceparent", externalTraceparent)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if observedTraceID != tc.wantTraceID {
				t.Fatalf("trace id mismatch: got %q, want %q", observedTraceID, tc.wantTraceID)
			}
		})
	}
}

// TestExtraSkipPathsAreNotTraced verifies S4: webhook prefixes can be excluded
// from the wrapped handler so no span (and no URL attributes) are emitted.
func TestExtraSkipPathsAreNotTraced(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{
		Telemetry: types.TelemetryConfig{Enabled: true, Traces: false, Metrics: false},
	}, nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer providers.Shutdown(context.Background()) //nolint:errcheck

	called := false
	handler := WrapServerHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if span := trace.SpanFromContext(r.Context()); span.SpanContext().IsValid() {
			t.Fatalf("skipped path should not have an active span: %s", r.URL.Path)
		}
	}), ServerHandlerOption{
		Operation:      "test",
		ExtraSkipPaths: []string{types.WEBHOOK_URL_PREFIX + "/"},
	})

	req := httptest.NewRequest("POST", types.WEBHOOK_URL_PREFIX+"/abc/secret-token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatalf("inner handler should still run for skipped paths")
	}
}

func TestTraceOnlyPrefixesSkipAppTraffic(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{
		Telemetry: types.TelemetryConfig{Enabled: true, Traces: false, Metrics: false},
	}, nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer providers.Shutdown(context.Background()) //nolint:errcheck

	const externalTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

	for _, tc := range []struct {
		name        string
		path        string
		wantTraceID string
	}{
		{
			name:        "server owned route is traced",
			path:        types.INTERNAL_URL_PREFIX + "/apps",
			wantTraceID: "0af7651916cd43dd8448eb211c80319c",
		},
		{
			name:        "app route is not traced by outer server wrapper",
			path:        "/customer/acme/token/secret",
			wantTraceID: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observedTraceID string
			handler := WrapServerHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				sc := trace.SpanContextFromContext(r.Context())
				if sc.IsValid() {
					observedTraceID = sc.TraceID().String()
				}
			}), ServerHandlerOption{
				Operation:         "test",
				TraceOnlyPrefixes: []string{types.INTERNAL_URL_PREFIX + "/"},
			})

			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("traceparent", externalTraceparent)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if observedTraceID != tc.wantTraceID {
				t.Fatalf("trace id mismatch: got %q, want %q", observedTraceID, tc.wantTraceID)
			}
		})
	}
}

// TestShutdownResetsGlobals verifies F5: after Shutdown, callers that re-grab
// otel.Tracer should see a no-op tracer rather than a stale, shut-down one.
func TestShutdownResetsGlobals(t *testing.T) {
	providers, err := Setup(context.Background(), &types.ServerConfig{
		Telemetry: types.TelemetryConfig{Enabled: true, Traces: false, Metrics: false},
	}, nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// While enabled, the global propagator must include traceparent.
	if !propagatorHasField(otel.GetTextMapPropagator(), "traceparent") {
		t.Fatalf("expected traceparent propagator while telemetry is enabled")
	}

	if err := providers.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if Enabled() {
		t.Fatalf("Enabled should report false after Shutdown")
	}
	if propagatorHasField(otel.GetTextMapPropagator(), "traceparent") {
		t.Fatalf("propagator should be reset to no-op after Shutdown")
	}
}

func TestAppAttributes(t *testing.T) {
	if attrs := AppAttributes(nil); attrs != nil {
		t.Fatalf("nil app should return nil attrs, got %v", attrs)
	}

	attrs := attrSet(AppAttributes(&types.AppEntry{
		Id:     "app_123",
		Path:   "/reports",
		Domain: "example.com",
		IsDev:  true,
		Metadata: types.AppMetadata{
			AuthnType: types.AppAuthnSystem,
			VersionMetadata: types.VersionMetadata{
				Version: 42,
			},
		},
	}))

	assertAttrString(t, attrs, "openrun.app.id", "app_123")
	assertAttrString(t, attrs, "openrun.app.path", "/reports")
	assertAttrString(t, attrs, "openrun.app.domain", "example.com")
	assertAttrBool(t, attrs, "openrun.app.is_dev", true)
	assertAttrString(t, attrs, "openrun.app.auth_type", string(types.AppAuthnSystem))
	assertAttrInt(t, attrs, "openrun.app.version", 42)
}

func TestRequestAttributes(t *testing.T) {
	if attrs := RequestAttributes(nil); attrs != nil {
		t.Fatalf("nil request should return nil attrs, got %v", attrs)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.com/private/path?token=secret", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.REQUEST_ID, "req-123"))
	attrs := attrSet(RequestAttributes(req))

	assertAttrString(t, attrs, "http.request.method", http.MethodPost)
	assertAttrString(t, attrs, "url.scheme", "https")
	assertAttrString(t, attrs, "openrun.request_id", "req-123")
	if _, ok := attrs["url.path"]; ok {
		t.Fatal("request attributes must not include raw URL path")
	}
	if _, ok := attrs["url.query"]; ok {
		t.Fatal("request attributes must not include raw URL query")
	}
}

func TestRouteClassAndSpanName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		path      string
		wantClass string
		wantSpan  string
	}{
		{
			name:      "health",
			path:      types.INTERNAL_URL_PREFIX + "/health",
			wantClass: types.INTERNAL_URL_PREFIX + "/health",
			wantSpan:  "GET " + types.INTERNAL_URL_PREFIX + "/health",
		},
		{
			name:      "internal",
			path:      types.INTERNAL_URL_PREFIX + "/apps",
			wantClass: types.INTERNAL_URL_PREFIX + "/*",
			wantSpan:  "GET " + types.INTERNAL_URL_PREFIX + "/*",
		},
		{
			name:      "webhook",
			path:      types.WEBHOOK_URL_PREFIX + "/reload",
			wantClass: types.WEBHOOK_URL_PREFIX + "/*",
			wantSpan:  "GET " + types.WEBHOOK_URL_PREFIX + "/*",
		},
		{
			name:      "app",
			path:      "/some/app/path",
			wantClass: "app.request",
			wantSpan:  "GET app.request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if got := routeClass(req); got != tc.wantClass {
				t.Fatalf("routeClass mismatch: got %q, want %q", got, tc.wantClass)
			}
			if got := serverSpanName("ignored", req); got != tc.wantSpan {
				t.Fatalf("serverSpanName mismatch: got %q, want %q", got, tc.wantSpan)
			}
		})
	}

	if got := routeClass(nil); got != "openrun.http" {
		t.Fatalf("nil route class mismatch: got %q", got)
	}
	if got := serverSpanName("ignored", nil); got != "openrun.http" {
		t.Fatalf("nil span name mismatch: got %q", got)
	}
}

func TestRequestScheme(t *testing.T) {
	if got := requestScheme(nil); got != "" {
		t.Fatalf("nil scheme mismatch: got %q", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/relative", nil)
	if got := requestScheme(req); got != "http" {
		t.Fatalf("default scheme mismatch: got %q", got)
	}
	req.URL.Scheme = "custom"
	if got := requestScheme(req); got != "custom" {
		t.Fatalf("explicit scheme mismatch: got %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	req.URL.Scheme = ""
	if got := requestScheme(req); got != "https" {
		t.Fatalf("TLS scheme mismatch: got %q", got)
	}
}

func TestParseOTLPEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          string
		wantHost     string
		wantFullURL  string
		wantInsecure bool
	}{
		{
			name: "empty",
		},
		{
			name:         "http base endpoint uses default exporter paths",
			raw:          "http://localhost:4318",
			wantHost:     "localhost:4318",
			wantInsecure: true,
		},
		{
			name:         "http base endpoint with slash uses default exporter paths",
			raw:          "http://localhost:4318/",
			wantHost:     "localhost:4318",
			wantInsecure: true,
		},
		{
			name:     "https base endpoint",
			raw:      "https://otel.example.com:4318",
			wantHost: "otel.example.com:4318",
		},
		{
			name:        "full endpoint url is preserved",
			raw:         "http://localhost:4318/v1/traces",
			wantFullURL: "http://localhost:4318/v1/traces",
		},
		{
			name:     "host without scheme",
			raw:      "localhost:4318",
			wantHost: "localhost:4318",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOTLPEndpoint(tc.raw)
			if got.host != tc.wantHost || got.fullURL != tc.wantFullURL || got.insecure != tc.wantInsecure {
				t.Fatalf("parseOTLPEndpoint(%q) = %+v, want host=%q fullURL=%q insecure=%t",
					tc.raw, got, tc.wantHost, tc.wantFullURL, tc.wantInsecure)
			}
		})
	}
}

func propagatorHasField(p propagation.TextMapPropagator, want string) bool {
	for _, f := range p.Fields() {
		if f == want {
			return true
		}
	}
	return false
}

func attrSet(attrs []attribute.KeyValue) map[string]attribute.Value {
	ret := make(map[string]attribute.Value, len(attrs))
	for _, attr := range attrs {
		ret[string(attr.Key)] = attr.Value
	}
	return ret
}

func assertAttrString(t *testing.T, attrs map[string]attribute.Value, key, want string) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attr %q", key)
	}
	if got.AsString() != want {
		t.Fatalf("attr %q mismatch: got %q, want %q", key, got.AsString(), want)
	}
}

func assertAttrBool(t *testing.T, attrs map[string]attribute.Value, key string, want bool) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attr %q", key)
	}
	if got.AsBool() != want {
		t.Fatalf("attr %q mismatch: got %t, want %t", key, got.AsBool(), want)
	}
}

func assertAttrInt(t *testing.T, attrs map[string]attribute.Value, key string, want int64) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attr %q", key)
	}
	if got.AsInt64() != want {
		t.Fatalf("attr %q mismatch: got %d, want %d", key, got.AsInt64(), want)
	}
}
