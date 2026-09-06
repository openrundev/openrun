// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/openrundev/openrun/internal/types"
)

func TestCompressionCancellation(t *testing.T) {
	store := &FileStore{metadata: &Metadata{config: &types.ServerConfig{}}}
	for _, empty := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		paths := []string{"file"}
		if empty {
			paths = nil
		}
		err := store.compressSourceFiles(ctx, fstest.MapFS{"file": {Data: []byte("content")}}, paths, nil, func(fileEntry) error {
			t.Error("consumer called after cancellation")
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	}
}

func TestCompressionCancellationDuringConsumption(t *testing.T) {
	store := &FileStore{metadata: &Metadata{config: &types.ServerConfig{}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := store.compressSourceFiles(ctx, fstest.MapFS{"file": {Data: []byte("content")}}, []string{"file", "file"}, nil, func(fileEntry) error {
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("got error %v and %d calls, want cancellation after one call", err, calls)
	}
}
