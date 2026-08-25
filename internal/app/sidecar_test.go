// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/types"
)

func sidecarTestHandler(t *testing.T, kubernetes bool, specs ...types.SidecarSpec) *ContainerHandler {
	t.Helper()
	h := &ContainerHandler{
		Logger:       types.NewLogger(&types.LogConfig{}),
		app:          &App{AppEntry: &types.AppEntry{Id: "app_prd_test1", Path: "/t"}},
		isKubernetes: kubernetes,
		port:         5000,
		GenImageName: "cli-app_prd_test1:abcd",
	}
	var err error
	if h.sidecars, err = h.parseSidecarConfigs(specs); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestBuildSidecarsEnv(t *testing.T) {
	h := sidecarTestHandler(t, false,
		types.SidecarSpec{Name: "cache", Image: "image:memcached:1.6-alpine", Port: 11211},
		types.SidecarSpec{Name: "worker", Command: []string{"python", "w.py"}, Env: map[string]string{"ROLE": "w"}},
	)
	h.sidecarDigests = map[string]string{"cache": "sha256:abc"}
	base := map[string]string{"PORT": "5000", "CL_APP_PATH": "/t", "CL_APP_URL": "http://x/t", "POSTGRES_URL": "secret", "app_name": "n"}
	sidecars := h.buildSidecars(base)
	if len(sidecars) != 2 {
		t.Fatalf("got %d sidecars", len(sidecars))
	}
	cache, worker := sidecars[0], sidecars[1]
	if cache.Image != "memcached:1.6-alpine@sha256:abc" || cache.IsAppImage {
		t.Errorf("cache image %s", cache.Image)
	}
	if _, ok := cache.Env["POSTGRES_URL"]; ok {
		t.Error("foreign image sidecar inherited app secrets")
	}
	if cache.Env["CL_APP_PATH"] != "/t" || cache.Env["PORT"] != "11211" {
		t.Errorf("cache env %v", cache.Env)
	}
	if worker.Image != "cli-app_prd_test1:abcd" || !worker.IsAppImage {
		t.Errorf("worker image %s", worker.Image)
	}
	if worker.Env["POSTGRES_URL"] != "secret" || worker.Env["ROLE"] != "w" || worker.Env["app_name"] != "n" {
		t.Errorf("worker env %v", worker.Env)
	}
	if _, ok := worker.Env["PORT"]; ok {
		t.Error("worker inherited the app PORT")
	}
	if !worker.AlwaysOn || cache.AlwaysOn {
		t.Errorf("always_on defaults: worker=%v cache=%v", worker.AlwaysOn, cache.AlwaysOn)
	}

	addr := h.sidecarAddrEnv("0123456789abcdef0123")
	if addr["CL_SIDECAR_CACHE_ADDR"] != "clc-app_prd_test1-0123456789abcdef-cache:11211" {
		t.Errorf("docker addr env %v", addr)
	}
	if _, ok := addr["CL_SIDECAR_WORKER_ADDR"]; ok {
		t.Error("port-less sidecar got an address")
	}
	h.isKubernetes = true
	if got := h.sidecarAddrEnv("x")["CL_SIDECAR_CACHE_ADDR"]; got != "localhost:11211" {
		t.Errorf("kubernetes addr %s", got)
	}
}

func TestSidecarHashes(t *testing.T) {
	h := sidecarTestHandler(t, false,
		types.SidecarSpec{Name: "worker", Command: []string{"python", "w.py"}},
		types.SidecarSpec{Name: "cache", Image: "image:memcached:1.6-alpine", Port: 11211},
	)
	base := map[string]string{"A": "1"}
	hash1, err := h.sidecarsHash(base)
	if err != nil {
		t.Fatal(err)
	}
	// The app image name is not part of the version hash contribution of an
	// app image sidecar (it derives from the version hash)
	h.GenImageName = "cli-app_prd_test1:other"
	hash2, _ := h.sidecarsHash(base)
	if hash1 != hash2 {
		t.Error("app image name changed the sidecars hash")
	}
	// But the container run hash does follow the image
	run1, _ := sidecarRunHash(h.buildSidecars(base)[0])
	h.GenImageName = "cli-app_prd_test1:third"
	run2, _ := sidecarRunHash(h.buildSidecars(base)[0])
	if run1 == run2 {
		t.Error("run hash ignored the image")
	}
	// Env and foreign image digest changes roll the version
	hash3, _ := h.sidecarsHash(map[string]string{"A": "2"})
	if hash3 == hash1 {
		t.Error("inherited env change did not change the hash")
	}
	h.sidecarDigests = map[string]string{"cache": "sha256:new"}
	hash4, _ := h.sidecarsHash(base)
	if hash4 == hash2 {
		t.Error("foreign image digest change did not change the hash")
	}

	empty := sidecarTestHandler(t, false)
	if got, _ := empty.sidecarsHash(base); got != "" {
		t.Errorf("apps without sidecars must contribute an empty hash, got %s", got)
	}
	if names := empty.SidecarContainerNames(); len(names) != 0 {
		t.Errorf("unexpected names %v", names)
	}
	h.activeVersionHash = "0123456789abcdef0123"
	names := h.SidecarContainerNames()
	if len(names) != 2 || names[0] != container.SidecarContainerName("app_prd_test1", h.activeVersionHash, "worker") {
		t.Errorf("names %v", names)
	}
}

func TestParseSidecarConfigsPortConflict(t *testing.T) {
	h := &ContainerHandler{
		Logger: types.NewLogger(&types.LogConfig{}),
		app:    &App{AppEntry: &types.AppEntry{Id: "app_prd_test1"}},
		port:   5000,
	}
	if _, err := h.parseSidecarConfigs([]types.SidecarSpec{{Name: "c", Image: "image:m", Port: 5000}}); err == nil {
		t.Error("app port conflict not detected")
	}
}
