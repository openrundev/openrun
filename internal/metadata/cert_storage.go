// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func NewCertStorage(ctx context.Context, logger *types.Logger, metadata *Metadata) (*CertStorage, error) {
	s := &CertStorage{
		Logger:       logger,
		metadata:     metadata,
		lockLease:    1 * time.Minute,
		lockRefresh:  15 * time.Second,
		lockPoll:     1 * time.Second,
		queryTimeout: 5 * time.Second,
		locks:        map[string]*certLock{},
	}
	return s, nil
}

// CertStorage is the database backed storage for the cert info. Implements the certmagic.Storage interface.
//
// Locks are rows in cert_locks: each row carries an owner token and an
// expiry. A lock is held from a successful Lock until Unlock, with a
// background goroutine extending the expiry every lockRefresh so that a
// slow certificate operation (ACME retries can span hours) never loses the
// lock while the holder is alive. A row whose expiry has passed belongs to
// a holder that died, and the next Lock takes it over. Unlock and lease
// renewal check the owner token, so a holder whose lock was taken over
// cannot delete or extend its successor's lock.
type CertStorage struct {
	*types.Logger
	metadata     *Metadata
	queryTimeout time.Duration
	lockLease    time.Duration // how long a lock row stays valid without a refresh
	lockRefresh  time.Duration // how often a held lock's expiry is extended
	lockPoll     time.Duration // how often Lock retries while the lock is held elsewhere

	locksMu sync.Mutex
	locks   map[string]*certLock // locks held by this process, by id
	closed  bool                 // set by Close: no more refresh workers are started
}

// certLock is a lock held by this process.
type certLock struct {
	owner  string
	cancel context.CancelFunc // stops the refresh goroutine
	done   chan struct{}      // closed when the refresh goroutine exits
}

var _ certmagic.Storage = (*CertStorage)(nil)
var _ certmagic.LockLeaseRenewer = (*CertStorage)(nil)
var _ certmagic.TryLocker = (*CertStorage)(nil)

// createTables creates the tables for the certificates.
func (s *CertStorage) createTables(ctx context.Context, tx types.Transaction) error {
	var err error
	_, err = tx.ExecContext(ctx, "create table if not exists cert_data (id text, value "+system.MapDataType(s.metadata.dbType, "blob")+
		", update_time "+system.MapDataType(s.metadata.dbType, "datetime")+", PRIMARY KEY(id))")
	if err != nil {
		return err
	}
	// The owner column is added by the version 35 upgrade, which runs after
	// this on a new database
	_, err = tx.ExecContext(ctx, "create table if not exists cert_locks (id text, expires bigint, PRIMARY KEY(id))")
	if err != nil {
		return err
	}
	return nil
}

// addLockOwnerColumn adds the owner column to cert_locks for databases
// created before the column existed.
func (s *CertStorage) addLockOwnerColumn(ctx context.Context, tx types.Transaction) error {
	_, err := tx.ExecContext(ctx, "alter table cert_locks add column owner text not null default ''")
	return err
}

// newLockOwner returns a random token identifying one Lock acquisition.
func newLockOwner() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate lock owner: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Lock acquires the lock with the given id, blocking until it is acquired
// or ctx is done. A lock whose expiry has passed is taken over.
func (c *CertStorage) Lock(ctx context.Context, id string) error {
	owner, err := newLockOwner()
	if err != nil {
		return err
	}

	for {
		acquired, err := c.tryLock(ctx, id, owner)
		if err != nil {
			return err
		}
		if acquired {
			break
		}
		select {
		case <-time.After(c.lockPoll):
		case <-ctx.Done():
			return fmt.Errorf("waiting for lock on id: %s: %w", id, ctx.Err())
		}
	}

	c.holdLock(id, owner)
	return nil
}

// TryLock implements certmagic.TryLocker: a single attempt to acquire the
// lock, reporting false without waiting if it is held elsewhere. Certmagic
// uses it for work that another holder may just as well do, such as the ARI
// renewal window refresh.
func (c *CertStorage) TryLock(ctx context.Context, id string) (bool, error) {
	owner, err := newLockOwner()
	if err != nil {
		return false, err
	}
	acquired, err := c.tryLock(ctx, id, owner)
	if err != nil || !acquired {
		return false, err
	}
	c.holdLock(id, owner)
	return true, nil
}

// holdLock records a lock this process just acquired and starts refreshing
// its lease until Unlock or Close.
func (c *CertStorage) holdLock(id, owner string) {
	refreshCtx, cancel := context.WithCancel(context.Background())
	lock := &certLock{owner: owner, cancel: cancel, done: make(chan struct{})}
	c.locksMu.Lock()
	if previous, ok := c.locks[id]; ok {
		// Should not happen: a lock this process holds is refreshed, so the
		// upsert above cannot take it over. Keep the newest holder.
		c.Warn().Str("id", id).Msg("Lock acquired while already held by this process")
		previous.cancel()
	}
	c.locks[id] = lock
	closed := c.closed
	c.locksMu.Unlock()

	if closed {
		// The database is going away: the lock row is left to expire
		cancel()
		close(lock.done)
		return
	}
	go c.refreshLock(refreshCtx, id, lock)
}

// Close stops the lease refresh workers of all held locks. It is called
// before the database is closed, so that a certificate operation still
// running in the background (certmagic's renewals are not stopped by the
// HTTP server drain) does not keep querying a closed database. The lock
// rows are left in place and expire at the end of their lease; a later
// Unlock from the operation finds the lock still recorded and releases it
// if the database is still reachable.
func (c *CertStorage) Close() {
	c.locksMu.Lock()
	c.closed = true
	locks := make([]*certLock, 0, len(c.locks))
	for _, lock := range c.locks {
		locks = append(locks, lock)
	}
	c.locksMu.Unlock()
	for _, lock := range locks {
		lock.cancel()
		<-lock.done
	}
}

// tryLock makes one attempt to take the lock. The insert takes a free lock;
// on conflict an existing lock is taken over only if it has expired. A single
// conditional upsert keeps two servers racing for the lock from both getting
// it (a separate check followed by an upsert is not atomic under read
// committed isolation).
func (c *CertStorage) tryLock(ctx context.Context, id, owner string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()

	now := time.Now()
	result, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType,
		`insert into cert_locks (id, expires, owner) values (?, ?, ?) on conflict (id) do update set expires = excluded.expires, owner = excluded.owner where cert_locks.expires <= ?`),
		id, now.Add(c.lockLease).UnixNano(), owner, now.UnixNano())
	if err != nil {
		return false, fmt.Errorf("failed to set lock on id: %s: %w", id, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected for lock on id: %s: %w", id, err)
	}
	return rowsAffected > 0, nil
}

// refreshLock extends the lock's expiry every lockRefresh until ctx is
// cancelled by Unlock. If the row is no longer owned by this holder (taken
// over after the refreshes fell behind for longer than the lease), the lock
// is lost and refreshing stops.
func (c *CertStorage) refreshLock(ctx context.Context, id string, lock *certLock) {
	defer close(lock.done)
	ticker := time.NewTicker(c.lockRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		extended, err := c.extendLock(ctx, id, lock.owner, c.lockLease)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.Warn().Err(err).Str("id", id).Msg("Error refreshing cert lock, will retry")
			continue
		}
		if !extended {
			c.Error().Str("id", id).Msg("Cert lock was taken over by another holder, stopped refreshing")
			return
		}
	}
}

// extendLock sets the lock's expiry to now+lease if it is still owned by owner.
func (c *CertStorage) extendLock(ctx context.Context, id, owner string, lease time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	result, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType,
		`update cert_locks set expires = ? where id = ? and owner = ?`),
		time.Now().Add(lease).UnixNano(), id, owner)
	if err != nil {
		return false, fmt.Errorf("failed to extend lock on id: %s: %w", id, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected for lock extend on id: %s: %w", id, err)
	}
	return rowsAffected > 0, nil
}

// RenewLockLease implements certmagic.LockLeaseRenewer. The lock must be
// held by this process. The expiry is extended by the lease duration the
// storage uses rather than the requested one: the refresh goroutine keeps a
// held lock alive for as long as the holder runs, and a shorter lease means
// a lock left by a crashed holder is taken over sooner.
func (c *CertStorage) RenewLockLease(ctx context.Context, id string, leaseDuration time.Duration) error {
	c.locksMu.Lock()
	lock, ok := c.locks[id]
	c.locksMu.Unlock()
	if !ok {
		return fmt.Errorf("lock on id %s is not held by this process", id)
	}
	extended, err := c.extendLock(ctx, id, lock.owner, c.lockLease)
	if err != nil {
		return err
	}
	if !extended {
		return fmt.Errorf("lock on id %s was taken over by another holder", id)
	}
	return nil
}

// Unlock releases the lock with the given id. Only a lock acquired by this
// process is deleted: a lock that was taken over by another holder after it
// expired is left in place.
func (c *CertStorage) Unlock(ctx context.Context, id string) error {
	c.locksMu.Lock()
	lock, ok := c.locks[id]
	if ok {
		delete(c.locks, id)
	}
	c.locksMu.Unlock()
	if !ok {
		return fmt.Errorf("lock on id %s is not held by this process", id)
	}

	lock.cancel()
	<-lock.done

	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	result, err := c.metadata.db.ExecContext(ctx, system.RebindQuery(c.metadata.dbType,
		`delete from cert_locks where id = ? and owner = ?`), id, lock.owner)
	if err != nil {
		return fmt.Errorf("failed to release lock on id: %s: %w", id, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected for unlock on id: %s: %w", id, err)
	}
	if rowsAffected == 0 {
		c.Warn().Str("id", id).Msg("Cert lock was taken over by another holder before release")
	}
	return nil
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
		return nil, fs.ErrNotExist // certmagic expects fs.ErrNotExist for missing keys
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
	defer rows.Close() //nolint:errcheck
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
