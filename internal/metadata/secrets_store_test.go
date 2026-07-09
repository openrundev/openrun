// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestSecretsStoreCRUD(t *testing.T) {
	m, cleanup := setupTestMetadata(t)
	defer cleanup()
	ctx := context.Background()

	_, err := m.GetSecretEntry(ctx, "missing")
	testutil.AssertEqualsError(t, "get missing", err, types.ErrSecretNotFound)

	entry := &types.SecretEntry{
		Name:      "mysecret",
		Value:     []byte{1, 2, 3},
		Nonce:     []byte{4, 5, 6},
		KeyId:     "k1",
		CreatedBy: "testuser",
		Metadata:  types.SecretMetadata{Description: "desc", SourceFile: "file.pem"},
	}
	testutil.AssertNoError(t, m.InsertSecretEntry(ctx, entry))

	// Duplicate insert reports ErrSecretExists
	err = m.InsertSecretEntry(ctx, entry)
	testutil.AssertEqualsError(t, "duplicate insert", err, types.ErrSecretExists)

	got, err := m.GetSecretEntry(ctx, "mysecret")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "name", "mysecret", got.Name)
	testutil.AssertEqualsString(t, "key id", "k1", got.KeyId)
	testutil.AssertEqualsString(t, "created by", "testuser", got.CreatedBy)
	testutil.AssertEqualsString(t, "description", "desc", got.Metadata.Description)
	testutil.AssertEqualsString(t, "source file", "file.pem", got.Metadata.SourceFile)
	if string(got.Value) != string([]byte{1, 2, 3}) || string(got.Nonce) != string([]byte{4, 5, 6}) {
		t.Fatalf("unexpected value/nonce: %v %v", got.Value, got.Nonce)
	}
	if got.CreateTime.IsZero() || got.UpdateTime.IsZero() {
		t.Fatal("expected create/update times to be set")
	}

	// Update changes value, nonce, key id and metadata
	updated := &types.SecretEntry{
		Name:     "mysecret",
		Value:    []byte{7, 8},
		Nonce:    []byte{9},
		KeyId:    "k2",
		Metadata: types.SecretMetadata{Description: "desc2"},
	}
	testutil.AssertNoError(t, m.UpdateSecretEntry(ctx, updated))

	got, err = m.GetSecretEntry(ctx, "mysecret")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "key id", "k2", got.KeyId)
	testutil.AssertEqualsString(t, "description", "desc2", got.Metadata.Description)
	testutil.AssertEqualsString(t, "created by", "testuser", got.CreatedBy)

	err = m.UpdateSecretEntry(ctx, &types.SecretEntry{Name: "missing", Value: []byte{1}})
	testutil.AssertEqualsError(t, "update missing", err, types.ErrSecretNotFound)

	// Conditional update only applies when key id and nonce are unchanged
	updated2, err := m.UpdateSecretEntryIfUnchanged(ctx,
		&types.SecretEntry{Name: "mysecret", Value: []byte{10}, Nonce: []byte{11}, KeyId: "k3"}, "k1", []byte{4, 5, 6})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "stale conditional update", false, updated2)
	updated2, err = m.UpdateSecretEntryIfUnchanged(ctx,
		&types.SecretEntry{Name: "mysecret", Value: []byte{10}, Nonce: []byte{11}, KeyId: "k3"}, "k2", []byte{9})
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "matching conditional update", true, updated2)
	got, err = m.GetSecretEntry(ctx, "mysecret")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "key id after conditional update", "k3", got.KeyId)

	// List is sorted by name; values are omitted unless requested
	testutil.AssertNoError(t, m.InsertSecretEntry(ctx, &types.SecretEntry{Name: "asecret", Value: []byte{1}, Nonce: []byte{2}, KeyId: "k1"}))
	entries, err := m.ListSecretEntries(ctx, false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "list", 2, len(entries))
	testutil.AssertEqualsString(t, "first", "asecret", entries[0].Name)
	testutil.AssertEqualsString(t, "second", "mysecret", entries[1].Name)
	if len(entries[0].Value) != 0 || len(entries[0].Nonce) != 0 {
		t.Fatalf("expected no value/nonce in listing, got %v %v", entries[0].Value, entries[0].Nonce)
	}
	entries, err = m.ListSecretEntries(ctx, true)
	testutil.AssertNoError(t, err)
	if len(entries[0].Value) == 0 || len(entries[0].Nonce) == 0 {
		t.Fatal("expected value/nonce when includeValues is set")
	}

	testutil.AssertNoError(t, m.DeleteSecretEntry(ctx, "mysecret"))
	err = m.DeleteSecretEntry(ctx, "mysecret")
	testutil.AssertEqualsError(t, "delete missing", err, types.ErrSecretNotFound)

	entries, err = m.ListSecretEntries(ctx, false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "list after delete", 1, len(entries))
}
