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
	store    map[string][]byte
	deleteAt map[string]*time.Time
}

func NewInmemoryKVStore() *InmemoryKVStore {
	return &InmemoryKVStore{
		store:    make(map[string][]byte),
		deleteAt: make(map[string]*time.Time),
	}
}

var _ KVStore = (*InmemoryKVStore)(nil)

func (s *InmemoryKVStore) FetchKV(ctx context.Context, key string) (map[string]any, error) {
	value := make(map[string]any)
	raw, err := s.FetchKVBlob(ctx, key)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(raw, &value)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling value: %w", err)
	}
	return value, nil
}

func (s *InmemoryKVStore) FetchKVBlob(ctx context.Context, key string) ([]byte, error) {
	value, ok := s.store[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	if expiresAt := s.deleteAt[key]; expiresAt != nil && !expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("key not found")
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
	s.ensureMaps()
	s.store[key] = value
	s.deleteAt[key] = copyTime(expireAt)
	return nil
}

func (s *InmemoryKVStore) UpsertKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error {
	s.ensureMaps()
	s.store[key] = value
	s.deleteAt[key] = copyTime(expireAt)
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
	if _, ok := s.store[key]; !ok {
		return fmt.Errorf("key not found")
	}
	s.store[key] = value
	return nil
}

func (s *InmemoryKVStore) DeleteKV(ctx context.Context, key string) error {
	delete(s.store, key)
	delete(s.deleteAt, key)
	return nil
}

func (s *InmemoryKVStore) ensureMaps() {
	if s.store == nil {
		s.store = make(map[string][]byte)
	}
	if s.deleteAt == nil {
		s.deleteAt = make(map[string]*time.Time)
	}
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	copied := *t
	return &copied
}
