// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func NewCertStorage(ctx context.Context, logger *types.Logger, metadata *Metadata) (*CertStorage, error) {
	s := &CertStorage{
		Logger:       logger,
		metadata:     metadata,
		lockTimeout:  1 * time.Minute,
		queryTimeout: 5 * time.Second,
	}
	return s, nil
}

// CertStorage is the database backed storage for the cert info. Implements the certmagic.Storage interface.
type CertStorage struct {
	*types.Logger
	metadata     *Metadata
	queryTimeout time.Duration
	lockTimeout  time.Duration
}

var _ certmagic.Storage = (*CertStorage)(nil)

// createTables creates the tables for the certificates.
func (s *CertStorage) createTables(ctx context.Context, tx types.Transaction) error {
	var err error
	_, err = tx.ExecContext(ctx, "create table if not exists cert_data (id text, value blob, update_time "+system.MapDataType(s.metadata.dbType, "datetime")+", PRIMARY KEY(id))")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "create table if not exists cert_locks (id text, expires bigint, PRIMARY KEY(id))")
	if err != nil {
		return err
	}
	return nil
}

// Lock locks the certificate with the given id.
func (c *CertStorage) Lock(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()

	tx, err := c.metadata.BeginTransaction(ctx)
	if err != nil {
		return err
	}

	isLocked, err := c.isLocked(ctx, tx, id)
	if err != nil {
		return err
	}
	if isLocked {
		return fmt.Errorf("id is locked: %s", id)
	}

	expires := time.Now().Add(c.lockTimeout).UnixNano()
	if _, err := tx.ExecContext(ctx, system.RebindQuery(c.metadata.dbType, `insert into cert_locks (id, expires) values (?, ?) on conflict (id) do update set expires = ?`), id, expires, expires); err != nil {
		return fmt.Errorf("failed to set lock on id: %s: %w", id, err)
	}

	return tx.Commit()
}

// Unlock unlocks the certificate with the given id.
func (c *CertStorage) Unlock(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	_, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType, `delete from cert_locks where id = ?`), id)
	return err
}

// isLocked checks if the certificate with the given id is locked.
func (c *CertStorage) isLocked(ctx context.Context, tx types.Transaction, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	now := time.Now().UnixNano()
	row := tx.QueryRowContext(ctx, system.RebindQuery(c.metadata.dbType, `select exists(select 1 from cert_locks where id = ? and expires > ?)`), key, now)
	var isLocked bool
	if err := row.Scan(&isLocked); err != nil {
		return false, err
	}
	return isLocked, nil
}

// Store stores the certificate with the given id and value.
func (c *CertStorage) Store(ctx context.Context, id string, value []byte) error {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	_, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType, `insert into cert_data (id, value, update_time) values (?, ?, `+system.FuncNow(c.metadata.dbType)+`) on conflict (id) do update set value = ?, update_time = `+system.FuncNow(c.metadata.dbType)), id, value, value)
	return err
}

// Load loads the certificate with the given id.
func (c *CertStorage) Load(ctx context.Context, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	var value []byte
	err := c.metadata.db.QueryRowContext(ctx, system.RebindQuery(c.metadata.dbType, `select value from cert_data where id = ?`), id).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("id %q not found: %w", id, err)
	}
	return value, err
}

// Delete deletes the certificate with the given id.
func (c *CertStorage) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	_, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType, `delete from cert_data where id = ?`), id)
	return err
}

// Exists checks if the certificate with the given id exists.
func (c *CertStorage) Exists(ctx context.Context, id string) bool {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	row := c.metadata.db.QueryRowContext(ctx, system.RebindQuery(c.metadata.dbType, `select exists(select 1 from cert_data where id = ?)`), id)
	var exists bool
	err := row.Scan(&exists)
	return err == nil && exists
}

// List lists the certificates with the given prefix.
func (c *CertStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	if recursive {
		return nil, fmt.Errorf("recursive not supported")
	}
	rows, err := c.metadata.db.QueryContext(ctx, system.RebindQuery(c.metadata.dbType, `select id from cert_data where id like ?`), prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Stat returns the information about the certificate with the given id.
func (c *CertStorage) Stat(ctx context.Context, id string) (certmagic.KeyInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	var modified time.Time
	var size int64
	row := c.metadata.db.QueryRowContext(ctx, system.RebindQuery(c.metadata.dbType, `select length(value), update_time from cert_data where id = ?`), id)
	err := row.Scan(&size, &modified)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{
		Key:        id,
		Modified:   modified,
		Size:       size,
		IsTerminal: true,
	}, nil
}
