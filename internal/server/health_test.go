// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
)

// healthTestServiceBinding is a fake service binding whose health checks are
// driven by the service config: "service_fail" fails CheckHealth with that
// message, "binding_fail_role" fails CheckBindingHealth for accounts whose
// role contains the value (the apply test fake generates roles suffixed
// _prod/_stage, so "_stage" fails only the staging account).
type healthTestServiceBinding struct {
	applyTestServiceBinding
	config    map[string]string
	dialCount *atomic.Int64
}

func (b *healthTestServiceBinding) InitializeService(_ context.Context, _ *types.Logger,
	config map[string]string, _ bindings.ServiceBindingRuntime) error {
	b.config = config
	return nil
}

func (b *healthTestServiceBinding) CheckHealth(context.Context) error {
	b.dialCount.Add(1)
	if msg := b.config["service_fail"]; msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (b *healthTestServiceBinding) CheckBindingHealth(_ context.Context, metadata types.BindingMetadata) error {
	b.dialCount.Add(1)
	if match := b.config["binding_fail_role"]; match != "" && strings.Contains(metadata.Account["role"], match) {
		return fmt.Errorf("account %s unhealthy", metadata.Account["role"])
	}
	return nil
}

func registerHealthTestBinding(t *testing.T, dialCount *atomic.Int64) {
	t.Helper()
	previousBuilder, hadPreviousBuilder := bindings.GetServiceBinding("healthtest")
	bindings.SetServiceBinding("healthtest", func() bindings.ServiceBinding {
		return &healthTestServiceBinding{dialCount: dialCount}
	})
	t.Cleanup(func() {
		if hadPreviousBuilder {
			bindings.SetServiceBinding("healthtest", previousBuilder)
		} else {
			bindings.SetServiceBinding("healthtest", nil)
		}
	})
}

func createHealthTestService(t *testing.T, server *Server, ctx context.Context, name string,
	staging string, config map[string]string) {
	t.Helper()
	tx, err := server.db.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	service := &types.Service{
		Id:          types.ID_PREFIX_SERVICE + "healthtest_" + name,
		Name:        name,
		ServiceType: "healthtest",
		Staging:     staging,
		Config:      config,
	}
	if err := server.db.CreateService(ctx, tx, service); err != nil {
		t.Fatalf("create service %s: %v", name, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit service %s: %v", name, err)
	}
}

func TestServicesHealth(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	var dialCount atomic.Int64
	registerHealthTestBinding(t, &dialCount)

	createHealthTestService(t, server, ctx, "good", "", map[string]string{})
	createHealthTestService(t, server, ctx, "bad", "", map[string]string{"service_fail": "endpoint down"})

	results, err := server.ServicesHealth(ctx)
	if err != nil {
		t.Fatalf("ServicesHealth: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	// Results are sorted by id
	if results[0].Id != "healthtest/bad" || results[0].Healthy || !strings.Contains(results[0].Error, "endpoint down") {
		t.Fatalf("bad service result = %+v", results[0])
	}
	if results[1].Id != "healthtest/good" || !results[1].Healthy || results[1].Error != "" {
		t.Fatalf("good service result = %+v", results[1])
	}

	// A repeat call within the TTL is served from the cache: no new dials
	dials := dialCount.Load()
	if _, err := server.ServicesHealth(ctx); err != nil {
		t.Fatalf("ServicesHealth cached: %v", err)
	}
	if dialCount.Load() != dials {
		t.Fatalf("cached call dialed the backend: %d -> %d", dials, dialCount.Load())
	}

	// An expired entry is re-checked (checkedAt pushed past the TTL)
	server.healthCache.Range(func(key, value any) bool {
		entry := value.(healthCacheEntry)
		entry.checkedAt = entry.checkedAt.Add(-2 * healthCacheTTL)
		server.healthCache.Store(key, entry)
		return true
	})
	if _, err := server.ServicesHealth(ctx); err != nil {
		t.Fatalf("ServicesHealth expired: %v", err)
	}
	if dialCount.Load() != dials+2 {
		t.Fatalf("expired entries not re-checked: %d dials, want %d", dialCount.Load(), dials+2)
	}

	// A config change invalidates immediately (the cache entry's update-time
	// key no longer matches), even within the TTL
	server.healthCache.Range(func(key, value any) bool {
		entry := value.(healthCacheEntry)
		entry.updateKey = "stale"
		server.healthCache.Store(key, entry)
		return true
	})
	dials = dialCount.Load()
	if _, err := server.ServicesHealth(ctx); err != nil {
		t.Fatalf("ServicesHealth after update: %v", err)
	}
	if dialCount.Load() != dials+2 {
		t.Fatalf("updated entries not re-checked: %d dials, want %d", dialCount.Load(), dials+2)
	}
}

func TestBindingsHealth(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	var dialCount atomic.Int64
	registerHealthTestBinding(t, &dialCount)

	// good: both accounts healthy. stagebad: the staging account fails (the
	// fake generates roles suffixed _prod/_stage).
	createHealthTestService(t, server, ctx, "good", "", map[string]string{})
	createHealthTestService(t, server, ctx, "stagebad", "", map[string]string{"binding_fail_role": "_stage"})

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/health/base", Source: "healthtest/good"}, false); err != nil {
		t.Fatalf("create base binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/health/base2", Source: "healthtest/stagebad"}, false); err != nil {
		t.Fatalf("create base2 binding: %v", err)
	}
	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/health/derived", Source: "/health/base", Grants: []string{"read:*"}}, false); err != nil {
		t.Fatalf("create derived binding: %v", err)
	}

	baseResults, err := server.BindingsHealth(ctx, "base")
	if err != nil {
		t.Fatalf("BindingsHealth base: %v", err)
	}
	if len(baseResults) != 2 {
		t.Fatalf("base results = %+v, want 2", baseResults)
	}
	// Results are sorted by path
	if baseResults[0].Path != "/health/base" || !baseResults[0].Healthy || !baseResults[0].StagingHealthy {
		t.Fatalf("base result = %+v", baseResults[0])
	}
	if baseResults[1].Path != "/health/base2" || !baseResults[1].Healthy || baseResults[1].StagingHealthy ||
		!strings.Contains(baseResults[1].StagingError, "unhealthy") {
		t.Fatalf("base2 result = %+v", baseResults[1])
	}
	if baseResults[1].Error != "" {
		t.Fatalf("base2 prod error = %q, want empty", baseResults[1].Error)
	}

	derivedResults, err := server.BindingsHealth(ctx, "derived")
	if err != nil {
		t.Fatalf("BindingsHealth derived: %v", err)
	}
	if len(derivedResults) != 1 || derivedResults[0].Path != "/health/derived" || !derivedResults[0].Healthy {
		t.Fatalf("derived results = %+v", derivedResults)
	}

	allResults, err := server.BindingsHealth(ctx, "")
	if err != nil {
		t.Fatalf("BindingsHealth all: %v", err)
	}
	if len(allResults) != 3 {
		t.Fatalf("all results = %d, want 3", len(allResults))
	}

	if _, err := server.BindingsHealth(ctx, "bogus"); err == nil ||
		!strings.Contains(err.Error(), "invalid binding health kind") {
		t.Fatalf("bogus kind error = %v", err)
	}

	// Repeat within the TTL: served from cache, no new dials
	dials := dialCount.Load()
	if _, err := server.BindingsHealth(ctx, "base"); err != nil {
		t.Fatalf("BindingsHealth cached: %v", err)
	}
	if dialCount.Load() != dials {
		t.Fatalf("cached call dialed the backend: %d -> %d", dials, dialCount.Load())
	}
}

// TestBindingsHealthStagingService verifies the staging account is checked
// against the linked staging service when the binding's service sets one
func TestBindingsHealthStagingService(t *testing.T) {
	server, db, ctx := newApplyTestServer(t)
	defer db.Close()

	var dialCount atomic.Int64
	registerHealthTestBinding(t, &dialCount)

	// The staging service fails every binding account check; the prod service
	// is healthy. The binding's staging account must be checked against the
	// staging service, so only the staging side reports unhealthy.
	createHealthTestService(t, server, ctx, "stg", "", map[string]string{"binding_fail_role": "_"})
	createHealthTestService(t, server, ctx, "prd", "stg", map[string]string{})

	if _, err := server.CreateBinding(ctx, &types.CreateBindingRequest{
		Path: "/health/linked", Source: "healthtest/prd"}, false); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	results, err := server.BindingsHealth(ctx, "base")
	if err != nil {
		t.Fatalf("BindingsHealth: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %+v, want 1", results)
	}
	if !results[0].Healthy || results[0].Error != "" {
		t.Fatalf("prod side = %+v, want healthy", results[0])
	}
	if results[0].StagingHealthy || !strings.Contains(results[0].StagingError, "unhealthy") {
		t.Fatalf("staging side = %+v, want unhealthy via the staging service", results[0])
	}
}

// Guard against the aggregate call blowing past the per-check timeout: a
// hung backend reports a timeout error instead of hanging the caller
func TestBindingsHealthTimeoutMessage(t *testing.T) {
	if healthCheckTimeout < time.Second {
		t.Fatalf("healthCheckTimeout too low: %v", healthCheckTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if msg := healthErrString(ctx, ctx.Err()); !strings.Contains(msg, "timed out") {
		t.Fatalf("timeout message = %q", msg)
	}
}
