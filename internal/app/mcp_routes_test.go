// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The implicit actions MCP endpoint must not shadow a route of the app: a
// route at or under the path, or one which matches it through a param. The
// root catch-all of a proxy or static app does not count
func TestRoutesTakePath(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, tc := range []struct {
		name  string
		setup func(r *chi.Mux)
		taken bool
	}{
		{"no routes", func(r *chi.Mux) {}, false},
		{"unrelated routes", func(r *chi.Mux) { r.Get("/other", handler); r.Get("/a/{b}", handler); r.Get("/mcpx", handler) }, false},
		{"literal route", func(r *chi.Mux) { r.Get("/mcp", handler) }, true},
		{"literal post route", func(r *chi.Mux) { r.Post("/mcp", handler) }, true},
		{"route under the path", func(r *chi.Mux) { r.Get("/mcp/status", handler) }, true},
		{"mount at the path", func(r *chi.Mux) { r.Mount("/mcp", handler) }, true},
		{"param route", func(r *chi.Mux) { r.Get("/{page}", handler) }, true},
		{"param route under the path", func(r *chi.Mux) { r.Get("/mcp/{id}", handler) }, true},
		{"param route, post only", func(r *chi.Mux) { r.Post("/{page}", handler) }, true},
		{"param route with more segments", func(r *chi.Mux) { r.Get("/{page}/status", handler) }, true},
		{"param route, delete only", func(r *chi.Mux) { r.Delete("/{page}", handler) }, true},
		{"param route, any method", func(r *chi.Mux) { r.Handle("/{page}/{item}", handler) }, true},
		{"mounted router under a param", func(r *chi.Mux) { r.Route("/{team}", func(sub chi.Router) { sub.Put("/x", handler) }) }, true},
		{"regexp param which matches", func(r *chi.Mux) { r.Get("/{name:[a-z]+}", handler) }, true},
		{"regexp param which cannot match", func(r *chi.Mux) { r.Get("/{id:[0-9]+}", handler); r.Get("/{id:[0-9]+}/edit", handler) }, false},
		{"literal and param segment", func(r *chi.Mux) { r.Get("/m{rest}", handler) }, true},
		{"literal and param segment, no match", func(r *chi.Mux) { r.Get("/user-{id}", handler) }, false},
		{"param below a literal", func(r *chi.Mux) { r.Get("/items/{page}", handler); r.Get("/", handler) }, false},
		{"root catch-all mount", func(r *chi.Mux) { r.Mount("/", handler) }, false},
		{"root catch-all handle", func(r *chi.Mux) { r.Handle("/*", handler) }, false},
		{"catch-all with a param route", func(r *chi.Mux) { r.Mount("/", handler); r.Get("/{page}", handler) }, true},
		{"static dir only", func(r *chi.Mux) { r.Handle("/static/*", handler) }, false},
	} {
		router := chi.NewRouter()
		tc.setup(router)
		if got := routesTakePath(router, "/mcp"); got != tc.taken {
			t.Errorf("%s: routesTakePath = %v, want %v", tc.name, got, tc.taken)
		}
	}
}
