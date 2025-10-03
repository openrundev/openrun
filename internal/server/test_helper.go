// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type InmemoryKVStore struct {
	store map[string][]byte
}

func NewInmemoryKVStore() *InmemoryKVStore {
	return &InmemoryKVStore{
		store: make(map[string][]byte),
	}
}

var _ KVStore = (*InmemoryKVStore)(nil)

func (s *InmemoryKVStore) FetchKV(ctx context.Context, key string) (map[string]any, error) {
	value := make(map[string]any)
	err := json.Unmarshal(s.store[key], &value)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling value: %w", err)
	}
	return value, nil
}

func (s *InmemoryKVStore) StoreKV(ctx context.Context, key string, value map[string]any, expireAt *time.Time) error {
	valueJson, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("error marshalling value: %w", err)
	}
	s.store[key] = valueJson
	return nil
}

func (s *InmemoryKVStore) StoreKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error {
	s.store[key] = value
	return nil
}

func (s *InmemoryKVStore) UpdateKV(ctx context.Context, key string, value map[string]any) error {
	valueJson, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("error marshalling value: %w", err)
	}
	s.store[key] = valueJson
	return nil
}

func (s *InmemoryKVStore) UpdateKVBlob(ctx context.Context, key string, value []byte) error {
	s.store[key] = value
	return nil
}

func (s *InmemoryKVStore) DeleteKV(ctx context.Context, key string) error {
	delete(s.store, key)
	return nil
}
