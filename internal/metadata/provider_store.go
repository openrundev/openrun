// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The binding_providers table (the name predates provider kinds) is the
// registry for all out-of-process providers: binding providers and Starlark
// plugin providers, distinguished by the provider_type column. Rows created
// before provider kinds existed have provider_type 'binding' (the column
// default); providerTypeOrDefault applies the same default on scan.

func providerTypeOrDefault(providerType string) string {
	if providerType == "" {
		return "binding"
	}
	return providerType
}

// UpsertBindingProvider creates or replaces a provider entry. The provider's
// Type and Name together identify the row.
func (m *Metadata) UpsertBindingProvider(ctx context.Context, tx types.Transaction, provider *types.BindingProvider) error {
	checksumsJson, err := json.Marshal(provider.Checksums)
	if err != nil {
		return fmt.Errorf("error marshalling provider checksums: %w", err)
	}
	serviceTypesJson, err := json.Marshal(provider.ServiceTypes)
	if err != nil {
		return fmt.Errorf("error marshalling provider service types: %w", err)
	}
	providerType := providerTypeOrDefault(provider.Type)

	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`UPDATE binding_providers set version = ?, source_url = ?, checksums = ?, service_types = ?, manifest = ?, update_time = `+
			system.FuncNow(m.dbType)+` where provider_type = ? and name = ?`),
		provider.Version, provider.SourceURL, string(checksumsJson), string(serviceTypesJson), provider.Manifest,
		providerType, provider.Name)
	if err != nil {
		return fmt.Errorf("error updating provider: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected > 0 {
		return nil
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`INSERT into binding_providers(name, provider_type, version, source_url, checksums, service_types, manifest, created_by, create_time, update_time) `+
			`values(?, ?, ?, ?, ?, ?, ?, ?, `+system.FuncNow(m.dbType)+`, `+system.FuncNow(m.dbType)+`)`),
		provider.Name, providerType, provider.Version, provider.SourceURL, string(checksumsJson), string(serviceTypesJson),
		provider.Manifest, provider.CreatedBy)
	if err != nil {
		return fmt.Errorf("error inserting provider: %w", err)
	}
	return nil
}

func (m *Metadata) DeleteBindingProvider(ctx context.Context, tx types.Transaction, providerType, name string) error {
	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from binding_providers where provider_type = ? and name = ?`), providerTypeOrDefault(providerType), name)
	if err != nil {
		return fmt.Errorf("error deleting provider: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s provider %s not found", providerTypeOrDefault(providerType), name)
	}
	return nil
}

func (m *Metadata) GetBindingProvider(ctx context.Context, tx types.Transaction, providerType, name string) (*types.BindingProvider, error) {
	row := tx.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select name, provider_type, version, source_url, checksums, service_types, manifest, created_by, create_time, update_time `+
			`from binding_providers where provider_type = ? and name = ?`), providerTypeOrDefault(providerType), name)
	provider, err := scanBindingProvider(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s provider %s not found", providerTypeOrDefault(providerType), name)
		}
		return nil, fmt.Errorf("error querying provider: %w", err)
	}
	return provider, nil
}

// ListBindingProviders returns all installed providers, of every type.
func (m *Metadata) ListBindingProviders(ctx context.Context, tx types.Transaction) ([]*types.BindingProvider, error) {
	rows, err := tx.QueryContext(ctx,
		`select name, provider_type, version, source_url, checksums, service_types, manifest, created_by, create_time, update_time `+
			`from binding_providers order by provider_type, name`)
	if err != nil {
		return nil, fmt.Errorf("error querying providers: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	providers := []*types.BindingProvider{}
	for rows.Next() {
		provider, err := scanBindingProvider(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("error scanning provider: %w", err)
		}
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

func scanBindingProvider(scan func(dest ...any) error) (*types.BindingProvider, error) {
	provider := types.BindingProvider{}
	var checksumsJson, serviceTypesJson, manifest sql.NullString
	if err := scan(&provider.Name, &provider.Type, &provider.Version, &provider.SourceURL, &checksumsJson, &serviceTypesJson,
		&manifest, &provider.CreatedBy, &provider.CreateTime, &provider.UpdateTime); err != nil {
		return nil, err
	}
	provider.Type = providerTypeOrDefault(provider.Type)
	if manifest.Valid {
		provider.Manifest = manifest.String
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

// NotifyProviderUpdate broadcasts that a provider was installed, updated or
// uninstalled, so other replicas reconcile it from the database.
func (m *Metadata) NotifyProviderUpdate(providerType, name string, deleted bool) error {
	if m.dbType != system.DB_TYPE_POSTGRES {
		return nil
	}

	msg := types.ProviderUpdateMessage{
		MessageType: types.MessageTypeProviderUpdate,
		Payload: types.ProviderUpdatePayload{
			Name:     name,
			Type:     providerTypeOrDefault(providerType),
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
