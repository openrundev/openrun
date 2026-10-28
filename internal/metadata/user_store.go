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
	"github.com/segmentio/ksuid"
)

// The builtin_users table CRUD: the accounts of the builtin app auth type.
// Password hashes are stored as PHC strings (internal/passwd); verification
// and the lockout policy live in the server layer, this file only persists
// their outcome (RecordBuiltinLoginSuccess/Failure)

const builtinUserColumns = `id, username, password_hash, credential_version, groups, display_name, email, ` +
	`email_verified_at, disabled_at, must_change_password, failed_attempts, locked_until, ` +
	`password_updated_at, last_login_at, created_by, create_time, update_time, row_version`

// createBuiltinUsersTable creates the builtin_users table (DB version 33)
func (m *Metadata) createBuiltinUsersTable(ctx context.Context, tx types.Transaction) error {
	datetime := system.MapDataType(m.dbType, "datetime")
	if _, err := tx.ExecContext(ctx, `create table builtin_users (id text not null, username text not null, `+
		`password_hash text not null, credential_version int not null default 1, `+
		`groups `+system.MapDataType(m.dbType, "json")+`, display_name text not null default '', `+
		`email text, email_verified_at `+datetime+`, disabled_at `+datetime+`, `+
		`must_change_password bool not null default false, failed_attempts int not null default 0, `+
		`locked_until `+datetime+`, password_updated_at `+datetime+` not null, last_login_at `+datetime+`, `+
		`created_by text not null default '', create_time `+datetime+` not null, update_time `+datetime+` not null, `+
		`row_version int not null default 1, PRIMARY KEY(id))`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `create unique index idx_builtin_users_username on builtin_users (username)`); err != nil {
		return err
	}
	return nil
}

type userRowScanner interface {
	Scan(dest ...any) error
}

func scanBuiltinUser(row userRowScanner) (*types.BuiltinUser, error) {
	var u types.BuiltinUser
	var groups, email sql.NullString
	var emailVerifiedAt, disabledAt, lockedUntil, lastLoginAt sql.NullTime
	if err := row.Scan(&u.Id, &u.Username, &u.PasswordHash, &u.CredentialVersion, &groups, &u.DisplayName, &email,
		&emailVerifiedAt, &disabledAt, &u.MustChangePassword, &u.FailedAttempts, &lockedUntil,
		&u.PasswordUpdatedAt, &lastLoginAt, &u.CreatedBy, &u.CreateTime, &u.UpdateTime, &u.RowVersion); err != nil {
		return nil, err
	}
	u.Groups = []string{}
	if groups.Valid && groups.String != "" {
		if err := json.Unmarshal([]byte(groups.String), &u.Groups); err != nil {
			return nil, fmt.Errorf("error parsing user groups: %w", err)
		}
		if u.Groups == nil {
			u.Groups = []string{}
		}
	}
	u.Email = email.String
	u.EmailVerifiedAt = timePtr(emailVerifiedAt)
	u.DisabledAt = timePtr(disabledAt)
	u.LockedUntil = timePtr(lockedUntil)
	u.LastLoginAt = timePtr(lastLoginAt)
	return &u, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// GetBuiltinUser returns the user row, types.ErrUserNotFound when absent
func (m *Metadata) GetBuiltinUser(ctx context.Context, username string) (*types.BuiltinUser, error) {
	row := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select `+builtinUserColumns+` from builtin_users where username = ?`), username)
	user, err := scanBuiltinUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, types.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("error querying user %s: %w", username, err)
	}
	return user, nil
}

// ListBuiltinUsers returns all users sorted by username
func (m *Metadata) ListBuiltinUsers(ctx context.Context) ([]types.BuiltinUser, error) {
	rows, err := m.db.QueryContext(ctx, `select `+builtinUserColumns+` from builtin_users order by username`)
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	users := []types.BuiltinUser{}
	for rows.Next() {
		user, err := scanBuiltinUser(rows)
		if err != nil {
			return nil, fmt.Errorf("error scanning user: %w", err)
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

var ErrUserExists = errors.New("user already exists")

// CreateBuiltinUser inserts a user row. The caller sets the id and the hash;
// create/update/password times are set here. ErrUserExists when a user with
// the same name (or the same name in another letter case) exists
func (m *Metadata) CreateBuiltinUser(ctx context.Context, user *types.BuiltinUser) error {
	var count int
	if err := m.db.QueryRowContext(ctx, system.RebindQuery(m.dbType,
		`select count(*) from builtin_users where lower(username) = lower(?)`), user.Username).Scan(&count); err != nil {
		return fmt.Errorf("error checking user %s: %w", user.Username, err)
	}
	if count > 0 {
		return ErrUserExists
	}
	now := time.Now().UTC()
	user.CreateTime, user.UpdateTime, user.PasswordUpdatedAt = now, now, now
	if user.CredentialVersion == 0 {
		user.CredentialVersion = 1
	}
	user.RowVersion = 1
	inserted, err := m.insertBuiltinUser(ctx, user, false)
	if err != nil {
		return err
	}
	if !inserted {
		return ErrUserExists
	}
	return nil
}

// ImportBuiltinUser inserts a user row unless a user of that name exists,
// returning whether the row was inserted. Used for the startup import of the
// deprecated static [builtin_auth.*] entries
func (m *Metadata) ImportBuiltinUser(ctx context.Context, user *types.BuiltinUser) (bool, error) {
	now := time.Now().UTC()
	user.CreateTime, user.UpdateTime, user.PasswordUpdatedAt = now, now, now
	if user.CredentialVersion == 0 {
		user.CredentialVersion = 1
	}
	user.RowVersion = 1
	return m.insertBuiltinUser(ctx, user, true)
}

func (m *Metadata) insertBuiltinUser(ctx context.Context, user *types.BuiltinUser, ignoreConflict bool) (bool, error) {
	groupsJson, err := json.Marshal(user.GroupList())
	if err != nil {
		return false, fmt.Errorf("error marshalling user groups: %w", err)
	}
	prefix, suffix := "insert", ""
	if ignoreConflict {
		prefix, suffix = system.InsertIgnorePrefix(m.dbType), system.InsertIgnoreSuffix(m.dbType)
	}
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		prefix+` into builtin_users (`+builtinUserColumns+`) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`+suffix),
		user.Id, user.Username, user.PasswordHash, user.CredentialVersion, string(groupsJson), user.DisplayName,
		nullString(user.Email), nullTime(user.EmailVerifiedAt), nullTime(user.DisabledAt), user.MustChangePassword,
		user.FailedAttempts, nullTime(user.LockedUntil), user.PasswordUpdatedAt, nullTime(user.LastLoginAt),
		user.CreatedBy, user.CreateTime, user.UpdateTime, user.RowVersion)
	if err != nil {
		return false, fmt.Errorf("error inserting user %s: %w", user.Username, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("error inserting user %s: %w", user.Username, err)
	}
	return rows > 0, nil
}

var ErrUserConflict = errors.New("user was modified concurrently")

// UpdateBuiltinUser writes the account fields of the row (by id): password
// hash and its timestamp, credential version, groups, display name, email,
// disabled state and must-change flag. The login counters are not written
// here (see UnlockBuiltinUser and the login bookkeeping). The write is
// conditional on the row version the caller read, so two concurrent updates
// cannot silently undo each other (a groups change must not re-enable a
// user disabled in between): ErrUserConflict tells the caller to re-read and
// retry. On success the user's RowVersion is advanced
func (m *Metadata) UpdateBuiltinUser(ctx context.Context, user *types.BuiltinUser) error {
	groupsJson, err := json.Marshal(user.GroupList())
	if err != nil {
		return fmt.Errorf("error marshalling user groups: %w", err)
	}
	now := time.Now().UTC()
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set password_hash = ?, credential_version = ?, groups = ?, display_name = ?, email = ?, `+
			`email_verified_at = ?, disabled_at = ?, must_change_password = ?, password_updated_at = ?, `+
			`update_time = ?, row_version = row_version + 1 where id = ? and row_version = ?`),
		user.PasswordHash, user.CredentialVersion, string(groupsJson), user.DisplayName, nullString(user.Email),
		nullTime(user.EmailVerifiedAt), nullTime(user.DisabledAt), user.MustChangePassword, user.PasswordUpdatedAt,
		now, user.Id, user.RowVersion)
	if err != nil {
		return fmt.Errorf("error updating user %s: %w", user.Username, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error updating user %s: %w", user.Username, err)
	}
	if rows == 0 {
		if _, err := m.GetBuiltinUser(ctx, user.Username); errors.Is(err, types.ErrUserNotFound) {
			return types.ErrUserNotFound
		}
		return ErrUserConflict
	}
	user.UpdateTime = now
	user.RowVersion++
	return nil
}

// UnlockBuiltinUser clears the login lockout and failure counter of the row
func (m *Metadata) UnlockBuiltinUser(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set failed_attempts = 0, locked_until = NULL, update_time = ? where id = ?`),
		time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("error unlocking user %s: %w", id, err)
	}
	return nil
}

// DeleteBuiltinUser removes the user row and, in the same transaction,
// revokes every live credential (API keys, OAuth tokens) of the
// builtin:<username> principal, so a deleted user cannot leave reusable
// credentials behind: either the account and its credentials go together or
// nothing changes. The identity row is kept as it is: a user of the same
// name created later is the same principal for RBAC and gets fresh
// credentials against it. types.ErrUserNotFound when absent
func (m *Metadata) DeleteBuiltinUser(ctx context.Context, username string) error {
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("error deleting user %s: %w", username, err)
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`delete from builtin_users where username = ?`), username)
	if err != nil {
		return fmt.Errorf("error deleting user %s: %w", username, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error deleting user %s: %w", username, err)
	}
	if rows == 0 {
		return types.ErrUserNotFound
	}
	principal := string(types.AppAuthnBuiltin) + ":" + username
	if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update credentials set revoked_at = `+system.FuncNow(m.dbType)+`, revocation_reason = ?`+
			` where revoked_at is null and identity_id in (select id from identities where principal_name = ?)`),
		"user deleted", principal); err != nil {
		return fmt.Errorf("error revoking credentials of deleted user %s: %w", username, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error deleting user %s: %w", username, err)
	}
	return nil
}

// RecordBuiltinLoginSuccess persists a successful password verification:
// the failure counter and lockout are reset and last_login_at stamped. With
// rehash set, the stored hash is replaced by it (an in-place upgrade of the
// same password; the credential version is not bumped) only while the row
// still holds verifiedHash, so a password set by an administrator while the
// login was being verified is never undone
func (m *Metadata) RecordBuiltinLoginSuccess(ctx context.Context, id string, verifiedHash, rehash string) error {
	now := time.Now().UTC()
	if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set failed_attempts = 0, locked_until = NULL, last_login_at = ?, update_time = ? where id = ?`),
		now, now, id); err != nil {
		return fmt.Errorf("error recording login for %s: %w", id, err)
	}
	if rehash == "" {
		return nil
	}
	if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set password_hash = ?, update_time = ? where id = ? and password_hash = ?`),
		rehash, now, id, verifiedHash); err != nil {
		return fmt.Errorf("error rehashing the password of %s: %w", id, err)
	}
	return nil
}

// RecordBuiltinLoginFailure counts a failed password verification atomically
// in the database and locks the account until lockUntil once the counter
// reaches threshold (the counter restarts), returning whether it locked.
// Concurrent failures cannot slip past the threshold: every one of them
// increments the stored counter before it is compared
func (m *Metadata) RecordBuiltinLoginFailure(ctx context.Context, id string, threshold int, lockUntil time.Time) (bool, error) {
	now := time.Now().UTC()
	if _, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set failed_attempts = failed_attempts + 1, update_time = ? where id = ?`), now, id); err != nil {
		return false, fmt.Errorf("error recording login failure for %s: %w", id, err)
	}
	result, err := m.db.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builtin_users set failed_attempts = 0, locked_until = ?, update_time = ? `+
			`where id = ? and failed_attempts >= ?`), lockUntil.UTC(), now, id, threshold)
	if err != nil {
		return false, fmt.Errorf("error locking user %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("error locking user %s: %w", id, err)
	}
	return rows > 0, nil
}

// NotifyUserUpdate tells the other servers of a cluster that the named users
// changed, so they drop their cached rows
func (m *Metadata) NotifyUserUpdate(usernames []string) error {
	if m.dbType != system.DB_TYPE_POSTGRES {
		return nil
	}
	msg := types.UserUpdateMessage{
		MessageType: types.MessageTypeUserUpdate,
		Payload:     types.UserUpdatePayload{Usernames: usernames, ServerId: types.CurrentServerId},
	}
	payloadBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = m.db.Exec("select pg_notify($1,$2)", pg_listen_channel, string(payloadBytes))
	return err
}

// legacyDefaultUserHashes are the password hashes of the test1/test1 and
// test2/test2 users that DB versions 31 and 32 seeded into every install as
// dynamic [builtin_auth.*] entries. The version 33 migration drops an entry
// with one of these hashes instead of migrating it: a well-known password
// must not survive into the users table. A test1 whose password was changed
// is an ordinary user and is migrated
var legacyDefaultUserHashes = map[string]string{
	"test1": "$2a$10$u3QRqV7t9Y6coh4j3CS9dukY5AJ4NU7.tdosH.7qd.81nD8FncEKa",
	"test2": "$2a$10$oY2VLrKH/JhFFvVn411jLuvvLH9.S136u0hm6EcJtvlConmsMSGQC",
}

// stripBuiltinAuthEntries removes entries.builtin_auth from a dynamic config
// JSON document, returning the users it held (minus the unmodified legacy
// defaults, counted in dropped) and whether the document changed. Operates on
// the raw JSON so every other field survives untouched
func stripBuiltinAuthEntries(configJson []byte) (out []byte, users map[string]types.BuiltinAuthEntry, dropped []string, changed bool, err error) {
	var doc map[string]any
	if err := json.Unmarshal(configJson, &doc); err != nil {
		return nil, nil, nil, false, err
	}
	entries, _ := doc["entries"].(map[string]any)
	raw, _ := entries["builtin_auth"].(map[string]any)
	if raw == nil {
		return configJson, nil, nil, false, nil
	}
	users = map[string]types.BuiltinAuthEntry{}
	for name, value := range raw {
		values, _ := value.(map[string]any)
		password, _ := values["password"].(string)
		if legacyDefaultUserHashes[name] != "" && legacyDefaultUserHashes[name] == password {
			dropped = append(dropped, name)
			continue
		}
		entry := types.BuiltinAuthEntry{Password: password, Groups: []string{}}
		if groups, ok := values["groups"].([]any); ok {
			for _, g := range groups {
				if s, ok := g.(string); ok {
					entry.Groups = append(entry.Groups, s)
				}
			}
		}
		users[name] = entry
	}
	delete(entries, "builtin_auth")
	if len(entries) == 0 {
		delete(doc, "entries")
	} else {
		doc["entries"] = entries
	}
	out, err = json.Marshal(doc)
	if err != nil {
		return nil, nil, nil, false, err
	}
	return out, users, dropped, true, nil
}

// migrateBuiltinUsersToTable is the DB version 33 migration: the dynamic
// config's builtin_auth entries become builtin_users rows (the stored hash
// is kept, bcrypt hashes are upgraded on the user's next login), the section
// is removed from the live config and scrubbed from every history snapshot
// (so hashes do not linger there and a restore cannot bring the section
// back). The unmodified test1/test2 defaults are dropped, not migrated
func (m *Metadata) migrateBuiltinUsersToTable(ctx context.Context, tx types.Transaction) error {
	exists, err := m.tableExists(ctx, tx, "builtin_users")
	if err != nil {
		return err
	}
	if !exists {
		if err := m.createBuiltinUsersTable(ctx, tx); err != nil {
			return err
		}
	}

	var configStr sql.NullString
	err = tx.QueryRowContext(ctx, `select config from config`).Scan(&configStr)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && configStr.Valid && configStr.String != "" {
		migrated, users, dropped, changed, err := stripBuiltinAuthEntries([]byte(configStr.String))
		if err != nil {
			return fmt.Errorf("error reading dynamic config for the builtin users migration: %w", err)
		}
		if changed {
			now := time.Now().UTC()
			for name, entry := range users {
				groupsJson, err := json.Marshal(entry.Groups)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
					system.InsertIgnorePrefix(m.dbType)+` into builtin_users (`+builtinUserColumns+`) values `+
						`(?, ?, ?, 1, ?, '', NULL, NULL, NULL, false, 0, NULL, ?, NULL, 'migration', ?, ?, 1)`+system.InsertIgnoreSuffix(m.dbType)),
					types.ID_PREFIX_USER+ksuid.New().String(), name, entry.Password, string(groupsJson), now, now, now); err != nil {
					return fmt.Errorf("error migrating builtin user %s: %w", name, err)
				}
			}
			if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `update config set config = ?`), string(migrated)); err != nil {
				return err
			}
			m.Info().Msgf("Builtin users migrated to the builtin_users table: %d migrated, dropped default users %v", len(users), dropped)
		}
	}

	// History snapshots: strip the section wherever present
	rows, err := tx.QueryContext(ctx, `select version_id, config from config_history`)
	if err != nil {
		return err
	}
	updates := map[string]string{}
	for rows.Next() {
		var versionId string
		var snapshot sql.NullString
		if err := rows.Scan(&versionId, &snapshot); err != nil {
			rows.Close() //nolint:errcheck
			return err
		}
		if !snapshot.Valid || snapshot.String == "" {
			continue
		}
		out, _, _, changed, err := stripBuiltinAuthEntries([]byte(snapshot.String))
		if err != nil {
			m.Warn().Err(err).Msgf("could not scrub builtin users from config history version %s", versionId)
			continue
		}
		if changed {
			updates[versionId] = string(out)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close() //nolint:errcheck
		return err
	}
	rows.Close() //nolint:errcheck
	for versionId, out := range updates {
		if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
			`update config_history set config = ? where version_id = ?`), out, versionId); err != nil {
			return err
		}
	}
	return nil
}
