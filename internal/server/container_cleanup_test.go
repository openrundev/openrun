// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/testutil"
)

type fakeStaleContainerManager struct {
	containers []container.Container
	stopped    []container.ContainerName
	stopErr    error
}

func (f *fakeStaleContainerManager) ListOpenRunContainers(context.Context) ([]container.Container, error) {
	return f.containers, nil
}

func (f *fakeStaleContainerManager) StopContainer(_ context.Context, name container.ContainerName) error {
	f.stopped = append(f.stopped, name)
	return f.stopErr
}

func TestCleanupStaleContainersStopsOnlyUnreferencedContainers(t *testing.T) {
	manager := &fakeStaleContainerManager{
		containers: []container.Container{
			{ID: "1", Names: "clc-active", State: "running"},
			{ID: "2", Names: "clc-stale", State: "running"},
			{ID: "3", State: "running"},
		},
	}

	err := cleanupStaleContainers(context.Background(), testutil.TestLogger(), manager, map[container.ContainerName]bool{
		"clc-active": true,
	}, nil)
	if err != nil {
		t.Fatalf("cleanupStaleContainers returned error: %v", err)
	}

	want := []container.ContainerName{"clc-stale"}
	if !slices.Equal(manager.stopped, want) {
		t.Fatalf("stopped containers = %#v, want %#v", manager.stopped, want)
	}
}

func TestCleanupStaleContainersKeepsAlwaysOnSidecars(t *testing.T) {
	// An idle-stopped app is closed (not in the active set); its always_on
	// worker sidecar stays up while the app exists, a deleted app's does not
	manager := &fakeStaleContainerManager{
		containers: []container.Container{
			{ID: "1", Names: "clc-app1-abcd-worker", State: "running",
				LabelString: container.SidecarAlwaysOnLabelKey + "=true," + container.LABEL_PREFIX + "app.id=app1"},
			{ID: "2", Names: "clc-app1-abcd-cache", State: "running",
				LabelString: container.LABEL_PREFIX + "app.id=app1"},
			{ID: "3", Names: "clc-gone-abcd-worker", State: "running",
				LabelString: container.SidecarAlwaysOnLabelKey + "=true," + container.LABEL_PREFIX + "app.id=gone"},
		},
	}
	existing := map[string]bool{"app1": true}
	keep := func(cont container.Container) bool {
		return cont.HasLabel(container.SidecarAlwaysOnLabelKey, "true") &&
			existing[cont.LabelValue(container.LABEL_PREFIX+"app.id")]
	}
	if err := cleanupStaleContainers(context.Background(), testutil.TestLogger(), manager, nil, keep); err != nil {
		t.Fatalf("cleanupStaleContainers returned error: %v", err)
	}
	want := []container.ContainerName{"clc-app1-abcd-cache", "clc-gone-abcd-worker"}
	if !slices.Equal(manager.stopped, want) {
		t.Fatalf("stopped containers = %#v, want %#v", manager.stopped, want)
	}
}

func TestCleanupStaleContainersReturnsStopErrors(t *testing.T) {
	stopErr := errors.New("stop failed")
	manager := &fakeStaleContainerManager{
		containers: []container.Container{{ID: "1", Names: "clc-stale", State: "running"}},
		stopErr:    stopErr,
	}

	err := cleanupStaleContainers(context.Background(), testutil.TestLogger(), manager, nil, nil)
	if !errors.Is(err, stopErr) {
		t.Fatalf("cleanupStaleContainers error = %v, want %v", err, stopErr)
	}
}
