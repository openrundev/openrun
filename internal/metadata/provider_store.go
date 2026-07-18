// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// UpsertBindingProvider creates or replaces a binding provider entry.
func (m *Metadata) UpsertBindingProvider(ctx context.Context, tx types.Transaction, provider *types.BindingProvider) error {
	checksumsJson, err := json.Marshal(provider.Checksums)
	if err != nil {
		return fmt.Errorf("error marshalling provider checksums: %w", err)
	}
	serviceTypesJson, err := json.Marshal(provider.ServiceTypes)
	if err != nil {
		return fmt.Errorf("error marshalling provider service types: %w", err)
	}

	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`UPDATE binding_providers set version = ?, source_url = ?, checksums = ?, service_types = ?, update_time = `+
			system.FuncNow(m.dbType)+` where name = ?`),
		provider.Version, provider.SourceURL, string(checksumsJson), string(serviceTypesJson), provider.Name)
	if err != nil {
		return fmt.Errorf("error updating binding provider: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected > 0 {
		return nil
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`INSERT into binding_providers(name, version, source_url, checksums, service_types, created_by, create_time, update_time) `+
			`values(?, ?, ?, ?, ?, ?, `+system.FuncNow(m.dbType)+`, `+system.FuncNow(m.dbType)+`)`),
		provider.Name, provider.Version, provider.SourceURL, string(checksumsJson), string(serviceTypesJson), provider.CreatedBy)
	if err != nil {
		return fmt.Errorf("error inserting binding provider: %w", err)
	}
	return nil
}

func (m *Metadata) DeleteBindingProvider(ctx context.Context, tx types.Transaction, name string) error {
	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from binding_providers where name = ?`), name)
	if err != nil {
		return fmt.Errorf("error deleting binding provider: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("binding provider %s not found", name)
	}
	return nil
}

func (m *Metadata) GetBindingProvider(ctx context.Context, tx types.Transaction, name string) (*types.BindingProvider, error) {
	row := tx.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select name, version, source_url, checksums, service_types, created_by, create_time, update_time `+
			`from binding_providers where name = ?`), name)
	provider, err := scanBindingProvider(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("binding provider %s not found", name)
		}
		return nil, fmt.Errorf("error querying binding provider: %w", err)
	}
	return provider, nil
}

func (m *Metadata) ListBindingProviders(ctx context.Context, tx types.Transaction) ([]*types.BindingProvider, error) {
	rows, err := tx.QueryContext(ctx,
		`select name, version, source_url, checksums, service_types, created_by, create_time, update_time `+
			`from binding_providers order by name`)
	if err != nil {
		return nil, fmt.Errorf("error querying binding providers: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	providers := []*types.BindingProvider{}
	for rows.Next() {
		provider, err := scanBindingProvider(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("error scanning binding provider: %w", err)
		}
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

func scanBindingProvider(scan func(dest ...any) error) (*types.BindingProvider, error) {
	provider := types.BindingProvider{}
	var checksumsJson, serviceTypesJson sql.NullString
	if err := scan(&provider.Name, &provider.Version, &provider.SourceURL, &checksumsJson, &serviceTypesJson,
		&provider.CreatedBy, &provider.CreateTime, &provider.UpdateTime); err != nil {
		return nil, err
	}
	if checksumsJson.Valid && checksumsJson.String != "" {
		if err := json.Unmarshal([]byte(checksumsJson.String), &provider.Checksums); err != nil {
			return nil, fmt.Errorf("error unmarshalling provider checksums: %w", err)
		}
	}
	if serviceTypesJson.Valid && serviceTypesJson.String != "" {
		if err := json.Unmarshal([]byte(serviceTypesJson.String), &provider.ServiceTypes); err != nil {
			return nil, fmt.Errorf("error unmarshalling provider service types: %w", err)
		}
	}
	return &provider, nil
}

// NotifyProviderUpdate broadcasts that a binding provider was installed,
// updated or uninstalled, so other replicas reconcile it from the database.
func (m *Metadata) NotifyProviderUpdate(name string, deleted bool) error {
	if m.dbType != system.DB_TYPE_POSTGRES {
		return nil
	}

	msg := types.ProviderUpdateMessage{
		MessageType: types.MessageTypeProviderUpdate,
		Payload: types.ProviderUpdatePayload{
			Name:     name,
			Deleted:  deleted,
			ServerId: types.CurrentServerId,
		},
	}

	payloadBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = m.db.Exec("select pg_notify($1,$2)", pg_listen_channel, string(payloadBytes))
	return err
}
