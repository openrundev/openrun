// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The secrets table CRUD. Metadata implements the system.SecretStore
// interface used by the db secret provider; values are stored as AES-256-GCM
// ciphertext, encryption is done by the provider before these are called

// GetSecretEntry returns the secret row for the given name,
// types.ErrSecretNotFound if it does not exist
func (m *Metadata) GetSecretEntry(ctx context.Context, name string) (*types.SecretEntry, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select name, value, nonce, key_id, created_by, create_time, update_time, metadata from secrets where name = ?`), name)
	entry, err := scanSecretEntry(row)
	if err == sql.ErrNoRows {
		return nil, types.ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("error querying secret: %w", err)
	}
	return entry, nil
}

// InsertSecretEntry inserts a new secret row, types.ErrSecretExists if a row
// with the same name is already present
func (m *Metadata) InsertSecretEntry(ctx context.Context, entry *types.SecretEntry) error {
	metadataJson, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling secret metadata: %w", err)
	}

	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		system.InsertIgnorePrefix(m.dbType)+` into secrets (name, value, nonce, key_id, created_by, create_time, update_time, metadata) values `+
			`(?, ?, ?, ?, ?, `+system.FuncNow(m.dbType)+`, `+system.FuncNow(m.dbType)+`, ?)`+system.InsertIgnoreSuffix(m.dbType)),
		entry.Name, entry.Value, entry.Nonce, entry.KeyId, entry.CreatedBy, string(metadataJson))
	if err != nil {
		return fmt.Errorf("error inserting secret: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return types.ErrSecretExists
	}
	return nil
}

// UpdateSecretEntry updates the value (and metadata) of an existing secret,
// types.ErrSecretNotFound if the name is not present
func (m *Metadata) UpdateSecretEntry(ctx context.Context, entry *types.SecretEntry) error {
	metadataJson, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling secret metadata: %w", err)
	}

	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update secrets set value = ?, nonce = ?, key_id = ?, update_time = `+system.FuncNow(m.dbType)+`, metadata = ? where name = ?`),
		entry.Value, entry.Nonce, entry.KeyId, string(metadataJson), entry.Name)
	if err != nil {
		return fmt.Errorf("error updating secret: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return types.ErrSecretNotFound
	}
	return nil
}

// UpdateSecretEntryIfUnchanged updates the row only if its current key_id and
// nonce still match prevKeyId/prevNonce, returning whether a row was updated
func (m *Metadata) UpdateSecretEntryIfUnchanged(ctx context.Context, entry *types.SecretEntry, prevKeyId string, prevNonce []byte) (bool, error) {
	metadataJson, err := json.Marshal(entry.Metadata)
	if err != nil {
		return false, fmt.Errorf("error marshalling secret metadata: %w", err)
	}

	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update secrets set value = ?, nonce = ?, key_id = ?, update_time = `+system.FuncNow(m.dbType)+
			`, metadata = ? where name = ? and key_id = ? and nonce = ?`),
		entry.Value, entry.Nonce, entry.KeyId, string(metadataJson), entry.Name, prevKeyId, prevNonce)
	if err != nil {
		return false, fmt.Errorf("error updating secret: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("error getting rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

// DeleteSecretEntry deletes the secret with the given name,
// types.ErrSecretNotFound if it does not exist
func (m *Metadata) DeleteSecretEntry(ctx context.Context, name string) error {
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from secrets where name = ?`), name)
	if err != nil {
		return fmt.Errorf("error deleting secret: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return types.ErrSecretNotFound
	}
	return nil
}

// ListSecretEntries returns all secret rows, sorted by name. With
// includeValues false the ciphertext and nonce columns are not fetched;
// listing does not need to pull up to 1MiB blobs per row
func (m *Metadata) ListSecretEntries(ctx context.Context, includeValues bool) ([]*types.SecretEntry, error) {
	valueCols := "value, nonce"
	if !includeValues {
		valueCols = "null, null"
	}
	rows, err := m.db.QueryContext(ctx,
		`select name, `+valueCols+`, key_id, created_by, create_time, update_time, metadata from secrets order by name`)
	if err != nil {
		return nil, fmt.Errorf("error querying secrets: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	entries := make([]*types.SecretEntry, 0)
	for rows.Next() {
		entry, err := scanSecretEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("error scanning secret: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}
	return entries, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSecretEntry(row rowScanner) (*types.SecretEntry, error) {
	entry := types.SecretEntry{}
	var createdBy, keyId, metadataStr sql.NullString
	var createTime, updateTime sql.NullTime
	if err := row.Scan(&entry.Name, &entry.Value, &entry.Nonce, &keyId, &createdBy, &createTime, &updateTime, &metadataStr); err != nil {
		return nil, err
	}
	entry.KeyId = keyId.String
	entry.CreatedBy = createdBy.String
	entry.CreateTime = createTime.Time
	entry.UpdateTime = updateTime.Time
	if metadataStr.Valid && metadataStr.String != "" {
		if err := json.Unmarshal([]byte(metadataStr.String), &entry.Metadata); err != nil {
			return nil, fmt.Errorf("error unmarshalling secret metadata: %w", err)
		}
	}
	return &entry, nil
}
