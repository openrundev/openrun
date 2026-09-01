// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// The identities, credentials and oauth_clients table CRUD, backing the
// remote API auth layer (openrun apikey and the OAuth access/refresh
// tokens). Secrets are stored only as SHA-256 hashes; verification happens
// in the server layer.

// GetIdentityByPrincipal returns the identity row for a provider:username
// principal, sql.ErrNoRows wrapped when absent
func (m *Metadata) GetIdentityByPrincipal(ctx context.Context, principal string) (*types.Identity, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select id, provider, stable_subject, principal_name, groups, groups_observed_at, disabled_at, create_time`+
			` from identities where principal_name = ?`), principal)
	return scanIdentity(row)
}

// CreateIdentity inserts a new identity row. The caller generates the id and
// ensures the principal does not exist (unique index enforces it)
func (m *Metadata) CreateIdentity(ctx context.Context, identity *types.Identity) error {
	groupsJson, err := json.Marshal(identity.Groups)
	if err != nil {
		return fmt.Errorf("error marshalling identity groups: %w", err)
	}
	_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`insert into identities (id, provider, stable_subject, principal_name, groups, groups_observed_at, disabled_at, create_time)`+
			` values (?, ?, ?, ?, ?, ?, NULL, `+system.FuncNow(m.dbType)+`)`),
		identity.Id, identity.Provider, identity.StableSubject, identity.PrincipalName,
		string(groupsJson), nullTime(identity.GroupsObservedAt))
	if err != nil {
		return fmt.Errorf("error inserting identity: %w", err)
	}
	return nil
}

// credentialExecer is the shared surface of *sql.DB and types.Transaction
// used by the credential insert
type credentialExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// insertCredential writes one credential row through the given executor
// (the pool, or a transaction during refresh rotation)
func (m *Metadata) insertCredential(ctx context.Context, ex credentialExecer, cred *types.Credential) error {
	scopesJson := sql.NullString{}
	if cred.Scopes != nil {
		data, err := json.Marshal(cred.Scopes)
		if err != nil {
			return fmt.Errorf("error marshalling credential scopes: %w", err)
		}
		scopesJson = sql.NullString{String: string(data), Valid: true}
	}
	resourcesJson, err := json.Marshal(cred.Resources)
	if err != nil {
		return fmt.Errorf("error marshalling credential resources: %w", err)
	}
	_, err = ex.ExecContext(ctx, system.RebindQuery(m.dbType,
		`insert into credentials (id, secret_hash, type, identity_id, scopes, resources, description,`+
			` oauth_client_id, grant_id, family_id, replaced_by_id, consumed_at, revoked_at, revocation_reason,`+
			` expires_at, created_by, create_time, last_used_at)`+
			` values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', NULL, NULL, '', ?, ?, `+system.FuncNow(m.dbType)+`, NULL)`),
		cred.Id, cred.SecretHash, cred.Type, cred.IdentityId, scopesJson, string(resourcesJson),
		cred.Description, cred.OAuthClientId, cred.GrantId, cred.FamilyId,
		nullTime(cred.ExpiresAt), cred.CreatedBy)
	if err != nil {
		return fmt.Errorf("error inserting credential: %w", err)
	}
	return nil
}

// CreateCredential inserts a credential row (the secret hash, never the secret)
func (m *Metadata) CreateCredential(ctx context.Context, cred *types.Credential) error {
	return m.insertCredential(ctx, m.db, cred)
}

// GetCredentialWithIdentity returns the credential and its identity row,
// types.ErrApiKeyNotFound when absent
func (m *Metadata) GetCredentialWithIdentity(ctx context.Context, id string) (*types.Credential, *types.Identity, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select c.id, c.secret_hash, c.type, c.identity_id, c.scopes, c.resources, c.description,`+
			` c.oauth_client_id, c.grant_id, c.family_id, c.replaced_by_id, c.consumed_at, c.revoked_at,`+
			` c.revocation_reason, c.expires_at, c.created_by, c.create_time, c.last_used_at,`+
			` i.id, i.provider, i.stable_subject, i.principal_name, i.groups, i.groups_observed_at, i.disabled_at, i.create_time`+
			` from credentials c join identities i on c.identity_id = i.id where c.id = ?`), id)
	cred, identity, err := scanCredentialWithIdentity(row)
	if err == sql.ErrNoRows {
		return nil, nil, types.ErrApiKeyNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error querying credential: %w", err)
	}
	return cred, identity, nil
}

// ListCredentials returns credentials joined with their principal names.
// principal "" lists all credentials; otherwise only that principal's.
// Revoked credentials and consumed rotation history are retained in the
// table as evidence but are dead for use, so the listing excludes them
func (m *Metadata) ListCredentials(ctx context.Context, principal string) ([]types.ApiKeyInfo, error) {
	query := `select c.id, c.type, c.scopes, c.resources, c.description, c.expires_at, c.created_by,` +
		` c.create_time, c.last_used_at, i.principal_name` +
		` from credentials c join identities i on c.identity_id = i.id` +
		` where c.revoked_at is null and c.consumed_at is null`
	args := []any{}
	if principal != "" {
		query += ` and i.principal_name = ?`
		args = append(args, principal)
	}
	query += ` order by c.create_time desc`
	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, query), args...)
	if err != nil {
		return nil, fmt.Errorf("error listing credentials: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	keys := []types.ApiKeyInfo{}
	for rows.Next() {
		var info types.ApiKeyInfo
		var scopes, resources sql.NullString
		var expiresAt, lastUsedAt sql.NullTime
		if err := rows.Scan(&info.Id, &info.Type, &scopes, &resources, &info.Description,
			&expiresAt, &info.CreatedBy, &info.CreateTime, &lastUsedAt, &info.User); err != nil {
			return nil, fmt.Errorf("error scanning credential: %w", err)
		}
		if scopes.Valid && scopes.String != "" {
			if err := json.Unmarshal([]byte(scopes.String), &info.Scopes); err != nil {
				return nil, fmt.Errorf("error parsing credential scopes: %w", err)
			}
		}
		if resources.Valid && resources.String != "" {
			if err := json.Unmarshal([]byte(resources.String), &info.Resources); err != nil {
				return nil, fmt.Errorf("error parsing credential resources: %w", err)
			}
		}
		info.ExpiresAt = timePtr(expiresAt)
		info.LastUsedAt = timePtr(lastUsedAt)
		keys = append(keys, info)
	}
	return keys, rows.Err()
}

// DeleteCredential removes a credential row, types.ErrApiKeyNotFound when absent
func (m *Metadata) DeleteCredential(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from credentials where id = ?`), id)
	if err != nil {
		return fmt.Errorf("error deleting credential: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return types.ErrApiKeyNotFound
	}
	return nil
}

// UpdateCredentialLastUsed stamps the credential's last use time. Callers
// throttle this (once per verification is acceptable at management API rates)
func (m *Metadata) UpdateCredentialLastUsed(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update credentials set last_used_at = `+system.FuncNow(m.dbType)+` where id = ?`), id)
	return err
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	value := t.Time
	return &value
}

func scanIdentity(row *sql.Row) (*types.Identity, error) {
	var identity types.Identity
	var groups sql.NullString
	var groupsObservedAt, disabledAt sql.NullTime
	if err := row.Scan(&identity.Id, &identity.Provider, &identity.StableSubject, &identity.PrincipalName,
		&groups, &groupsObservedAt, &disabledAt, &identity.CreateTime); err != nil {
		return nil, err
	}
	if groups.Valid && groups.String != "" {
		if err := json.Unmarshal([]byte(groups.String), &identity.Groups); err != nil {
			return nil, fmt.Errorf("error parsing identity groups: %w", err)
		}
	}
	identity.GroupsObservedAt = timePtr(groupsObservedAt)
	identity.DisabledAt = timePtr(disabledAt)
	return &identity, nil
}

func scanCredentialWithIdentity(row *sql.Row) (*types.Credential, *types.Identity, error) {
	var cred types.Credential
	var identity types.Identity
	var scopes, resources, groups sql.NullString
	var consumedAt, revokedAt, expiresAt, lastUsedAt, groupsObservedAt, disabledAt sql.NullTime
	if err := row.Scan(&cred.Id, &cred.SecretHash, &cred.Type, &cred.IdentityId, &scopes, &resources,
		&cred.Description, &cred.OAuthClientId, &cred.GrantId, &cred.FamilyId, &cred.ReplacedById,
		&consumedAt, &revokedAt, &cred.RevocationReason, &expiresAt, &cred.CreatedBy, &cred.CreateTime, &lastUsedAt,
		&identity.Id, &identity.Provider, &identity.StableSubject, &identity.PrincipalName,
		&groups, &groupsObservedAt, &disabledAt, &identity.CreateTime); err != nil {
		return nil, nil, err
	}
	if scopes.Valid && scopes.String != "" {
		if err := json.Unmarshal([]byte(scopes.String), &cred.Scopes); err != nil {
			return nil, nil, fmt.Errorf("error parsing credential scopes: %w", err)
		}
	}
	if resources.Valid && resources.String != "" {
		if err := json.Unmarshal([]byte(resources.String), &cred.Resources); err != nil {
			return nil, nil, fmt.Errorf("error parsing credential resources: %w", err)
		}
	}
	if groups.Valid && groups.String != "" {
		if err := json.Unmarshal([]byte(groups.String), &identity.Groups); err != nil {
			return nil, nil, fmt.Errorf("error parsing identity groups: %w", err)
		}
	}
	cred.ConsumedAt = timePtr(consumedAt)
	cred.RevokedAt = timePtr(revokedAt)
	cred.ExpiresAt = timePtr(expiresAt)
	cred.LastUsedAt = timePtr(lastUsedAt)
	identity.GroupsObservedAt = timePtr(groupsObservedAt)
	identity.DisabledAt = timePtr(disabledAt)
	return &cred, &identity, nil
}

// ErrRefreshConsumed is returned by RotateRefreshToken when the presented
// refresh token was concurrently consumed by another rotation. Callers treat
// this exactly like reuse of a rotated token: the grant is compromised
var ErrRefreshConsumed = errors.New("refresh token was already consumed")

// OAuthClient is one dynamically registered OAuth client (public, PKCE only)
type OAuthClient struct {
	Id           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	RedirectUris []string `json:"redirect_uris"`
}

// CreateOAuthClient inserts a registered client row
func (m *Metadata) CreateOAuthClient(ctx context.Context, client *OAuthClient) error {
	urisJson, err := json.Marshal(client.RedirectUris)
	if err != nil {
		return fmt.Errorf("error marshalling redirect uris: %w", err)
	}
	_, err = m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`insert into oauth_clients (id, name, redirect_uris, create_time) values (?, ?, ?, `+system.FuncNow(m.dbType)+`)`),
		client.Id, client.Name, string(urisJson))
	if err != nil {
		return fmt.Errorf("error inserting oauth client: %w", err)
	}
	return nil
}

// GetOAuthClient returns the registered client, sql.ErrNoRows when absent
func (m *Metadata) GetOAuthClient(ctx context.Context, id string) (*OAuthClient, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select id, name, redirect_uris from oauth_clients where id = ?`), id)
	var client OAuthClient
	var uris sql.NullString
	if err := row.Scan(&client.Id, &client.Name, &uris); err != nil {
		return nil, err
	}
	if uris.Valid && uris.String != "" {
		if err := json.Unmarshal([]byte(uris.String), &client.RedirectUris); err != nil {
			return nil, fmt.Errorf("error parsing redirect uris: %w", err)
		}
	}
	return &client, nil
}

// CountOAuthClients returns the number of registered clients (DCR quota)
func (m *Metadata) CountOAuthClients(ctx context.Context) (int, error) {
	var count int
	err := m.db.QueryRowContext(ctx, `select count(*) from oauth_clients`).Scan(&count)
	return count, err
}

// RotateRefreshToken atomically consumes the presented refresh token and
// inserts its successor plus the new access token in one transaction. Returns
// types.ErrApiKeyNotFound-style failure via error when the old token was
// already consumed by a concurrent rotation (the caller treats that as reuse)
func (m *Metadata) RotateRefreshToken(ctx context.Context, oldId string, newRefresh, newAccess *types.Credential) error {
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update credentials set consumed_at = `+system.FuncNow(m.dbType)+`, replaced_by_id = ?`+
			` where id = ? and consumed_at is null and revoked_at is null`), newRefresh.Id, oldId)
	if err != nil {
		return fmt.Errorf("error consuming refresh token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrRefreshConsumed
	}
	for _, cred := range []*types.Credential{newRefresh, newAccess} {
		if err := m.insertCredential(ctx, tx, cred); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeGrantCredentials revokes every credential minted under one grant
// (logout, or refresh-token reuse detection). Consumed rotation history is
// retained as replay evidence until family expiry
func (m *Metadata) RevokeGrantCredentials(ctx context.Context, grantId string, reason string) error {
	if grantId == "" {
		return fmt.Errorf("grant id is required")
	}
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update credentials set revoked_at = `+system.FuncNow(m.dbType)+`, revocation_reason = ?`+
			` where grant_id = ? and revoked_at is null`), reason, grantId)
	return err
}

// RevokeCredential revokes one credential (access token or PAT)
func (m *Metadata) RevokeCredential(ctx context.Context, id string, reason string) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update credentials set revoked_at = `+system.FuncNow(m.dbType)+`, revocation_reason = ?`+
			` where id = ? and revoked_at is null`), reason, id)
	return err
}

// GetGrantStartTime returns the creation time of the oldest credential minted
// under the grant: the consent time, which anchors the absolute grant
// lifetime (api.grant_max_ttl) that refresh rotation cannot slide past
func (m *Metadata) GetGrantStartTime(ctx context.Context, grantId string) (time.Time, error) {
	if grantId == "" {
		return time.Time{}, fmt.Errorf("grant id is required")
	}
	// order by + limit instead of min(): an aggregate loses the column's
	// declared type, which breaks the sqlite driver's time.Time scan
	var start time.Time
	err := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select create_time from credentials where grant_id = ? order by create_time asc limit 1`),
		grantId).Scan(&start)
	if err == sql.ErrNoRows {
		return time.Time{}, fmt.Errorf("grant %s has no credentials", grantId)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("error querying grant start time: %w", err)
	}
	return start, nil
}

// PruneCredentials deletes credential rows past use and past their
// evidence-retention window: rows revoked before the cutoff, and expired rows
// of any type (consumed rotation history included) whose expiry is before the
// cutoff. Rotation replay evidence therefore survives until the whole family
// is past its expiry window plus the retention grace. Non-expiring, unrevoked
// PATs are never pruned
func (m *Metadata) PruneCredentials(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from credentials where (revoked_at is not null and revoked_at < ?)`+
			` or (expires_at is not null and expires_at < ?)`), cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("error pruning credentials: %w", err)
	}
	return result.RowsAffected()
}

// PruneUnusedOAuthClients deletes registered clients older than the cutoff
// that no live (unrevoked) credential references, freeing DCR quota slots
func (m *Metadata) PruneUnusedOAuthClients(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from oauth_clients where create_time < ? and id not in`+
			` (select distinct oauth_client_id from credentials where revoked_at is null and oauth_client_id != '')`),
		olderThan)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
