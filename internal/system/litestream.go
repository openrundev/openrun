// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/benbjohnson/litestream"
	lsfile "github.com/benbjohnson/litestream/file"
	lss3 "github.com/benbjohnson/litestream/s3"
	"github.com/openrundev/openrun/internal/types"
)

// LitestreamReplicaTypeFile is the litestream config type for a local
// directory replica (tests, simple local-disk backups); the default is s3.
const LitestreamReplicaTypeFile = "file"

// LitestreamMetadataPrefix is the replica sub-path for the server's own
// databases, below the config's path_prefix. App binding replicas use
// "bindings/<binding-id>/<env>" instead.
const LitestreamMetadataPrefix = "metadata"

// litestreamManagedFiles tracks database files replicated by the embedded
// litestream, so the sqlite self-maintenance loop leaves checkpointing to
// litestream (which holds a long-lived read transaction and runs its own
// passive/truncate checkpoint strategy).
var (
	litestreamManagedMu    sync.Mutex
	litestreamManagedFiles = map[string]bool{}
)

func markLitestreamManaged(dbFilePath string) {
	key := dbFilePath
	if abs, err := filepath.Abs(dbFilePath); err == nil {
		key = abs
	}
	litestreamManagedMu.Lock()
	litestreamManagedFiles[key] = true
	litestreamManagedMu.Unlock()
}

func isLitestreamManaged(dbFilePath string) bool {
	key := dbFilePath
	if abs, err := filepath.Abs(dbFilePath); err == nil {
		key = abs
	}
	litestreamManagedMu.Lock()
	defer litestreamManagedMu.Unlock()
	return litestreamManagedFiles[key]
}

// ValidateLitestreamConfig checks one named [litestream.<name>] entry. The
// credential values are expected to be already secret-resolved.
func ValidateLitestreamConfig(name string, config types.LitestreamConfig) error {
	switch config.Type {
	case "", "s3":
		if config.Bucket == "" {
			return fmt.Errorf("litestream config %s: bucket is required for the s3 replica type", name)
		}
		if config.Path != "" {
			return fmt.Errorf("litestream config %s: path applies to the file replica type only, use path_prefix for s3", name)
		}
	case LitestreamReplicaTypeFile:
		if config.Path == "" {
			return fmt.Errorf("litestream config %s: path is required for the file replica type", name)
		}
		if config.Bucket != "" || config.Endpoint != "" {
			return fmt.Errorf("litestream config %s: bucket/endpoint do not apply to the file replica type", name)
		}
	default:
		return fmt.Errorf("litestream config %s: unknown replica type %q, expected s3 or file", name, config.Type)
	}

	for _, d := range []struct{ key, value string }{
		{"sync_interval", config.SyncInterval},
		{"retention", config.Retention},
		{"snapshot_interval", config.SnapshotInterval},
		{"checkpoint_interval", config.CheckpointInterval},
	} {
		if d.value == "" {
			continue
		}
		if _, err := time.ParseDuration(d.value); err != nil {
			return fmt.Errorf("litestream config %s: invalid %s %q: %w", name, d.key, d.value, err)
		}
	}
	return nil
}

// litestreamDuration parses an optional duration config value, returning def
// when unset. Values are pre-validated by ValidateLitestreamConfig.
func litestreamDuration(value string, def time.Duration) time.Duration {
	if value == "" {
		return def
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return def
	}
	return d
}

// newLitestreamReplicaClient builds the replica client for one database at
// subPath below the config's prefix (e.g. "metadata/clace_metadata.db").
func newLitestreamReplicaClient(config types.LitestreamConfig, subPath string) (litestream.ReplicaClient, error) {
	switch config.Type {
	case "", "s3":
		client := lss3.NewReplicaClient()
		client.Bucket = config.Bucket
		client.Path = path.Join(config.PathPrefix, subPath)
		client.Region = config.Region
		client.Endpoint = config.Endpoint
		client.ForcePathStyle = config.ForcePathStyle
		client.AccessKeyID = config.AccessKeyId
		client.SecretAccessKey = config.SecretAccessKey
		client.StorageClass = config.StorageClass
		client.SSEKMSKeyID = config.SseKmsKeyId
		return client, nil
	case LitestreamReplicaTypeFile:
		return lsfile.NewReplicaClient(filepath.Join(config.Path, filepath.FromSlash(subPath))), nil
	default:
		return nil, fmt.Errorf("unknown litestream replica type %q", config.Type)
	}
}

// LitestreamDBStatus is the replication state of one embedded-litestream
// database, reported by the replication status API.
type LitestreamDBStatus struct {
	Name       string    `json:"name"` // metadata, audit
	Path       string    `json:"path"`
	LocalTXID  uint64    `json:"local_txid"`
	RemoteTXID uint64    `json:"remote_txid"`
	InSync     bool      `json:"in_sync"`
	LastSyncAt time.Time `json:"last_sync_at"`
	Error      string    `json:"error,omitempty"`
}

// LitestreamManager replicates the server's own sqlite databases (metadata
// and audit; the file cache is a rebuildable cache and is excluded) using
// litestream embedded as a library. Usage: NewLitestreamManager, PrepareDB for
// each database before its pool is opened (restores a missing file from the
// replica), Start once all databases are open, Close on server shutdown.
type LitestreamManager struct {
	logger     *types.Logger
	configName string
	config     types.LitestreamConfig

	mu    sync.Mutex
	dbs   []*litestream.DB
	names map[*litestream.DB]string
	store *litestream.Store
}

func NewLitestreamManager(logger *types.Logger, configName string, config types.LitestreamConfig) (*LitestreamManager, error) {
	if err := ValidateLitestreamConfig(configName, config); err != nil {
		return nil, err
	}
	return &LitestreamManager{
		logger:     logger,
		configName: configName,
		config:     config,
		names:      map[*litestream.DB]string{},
	}, nil
}

// ConfigName returns the [litestream.<name>] config name this manager uses.
func (m *LitestreamManager) ConfigName() string {
	return m.configName
}

// PrepareDB registers one database for replication and restores it from the
// replica if the local file is missing (disaster recovery: a wiped metadata
// directory is repopulated from the replica on startup). Must be called
// before the database pool is opened and before Start.
func (m *LitestreamManager) PrepareDB(ctx context.Context, name, dbFilePath string) error {
	client, err := newLitestreamReplicaClient(m.config, path.Join(LitestreamMetadataPrefix, filepath.Base(dbFilePath)))
	if err != nil {
		return err
	}

	db := litestream.NewDB(dbFilePath)
	db.Logger = slog.Default().With("litestream_db", name)
	db.Replica = litestream.NewReplicaWithClient(db, client)
	db.Replica.SyncInterval = litestreamDuration(m.config.SyncInterval, litestream.DefaultSyncInterval)
	db.CheckpointInterval = litestreamDuration(m.config.CheckpointInterval, litestream.DefaultCheckpointInterval)
	if m.config.MinCheckpointPageCount > 0 {
		db.MinCheckpointPageN = m.config.MinCheckpointPageCount
	}
	if m.config.TruncatePageN != nil {
		db.TruncatePageN = *m.config.TruncatePageN
	}

	existed := true
	if _, statErr := os.Stat(dbFilePath); os.IsNotExist(statErr) {
		existed = false
	}
	if err := db.EnsureExists(ctx); err != nil {
		return fmt.Errorf("litestream restore check for %s db failed: %w", name, err)
	}
	if !existed {
		if _, statErr := os.Stat(dbFilePath); statErr == nil {
			m.logger.Info().Str("db", name).Str("path", dbFilePath).
				Msgf("Restored %s database from litestream replica %s", name, m.configName)
		} else {
			m.logger.Info().Str("db", name).Str("path", dbFilePath).
				Msg("No litestream replica found, starting with a fresh database")
		}
	}

	m.mu.Lock()
	m.dbs = append(m.dbs, db)
	m.names[db] = name
	m.mu.Unlock()
	markLitestreamManaged(dbFilePath)
	return nil
}

// Start begins replication for all prepared databases. Called after the
// database pools are open (litestream opens its own read connection).
func (m *LitestreamManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store != nil {
		return fmt.Errorf("litestream manager already started")
	}
	if len(m.dbs) == 0 {
		return fmt.Errorf("litestream manager has no databases prepared")
	}

	store := litestream.NewStore(m.dbs, litestream.DefaultCompactionLevels)
	store.SnapshotInterval = litestreamDuration(m.config.SnapshotInterval, litestream.DefaultSnapshotInterval)
	store.SnapshotRetention = litestreamDuration(m.config.Retention, litestream.DefaultSnapshotRetention)
	if err := store.Open(ctx); err != nil {
		return fmt.Errorf("error starting litestream replication: %w", err)
	}
	m.store = store
	names := make([]string, 0, len(m.dbs))
	for _, db := range m.dbs {
		names = append(names, m.names[db])
	}
	m.logger.Info().Strs("dbs", names).Str("config", m.configName).Msg("Litestream metadata replication started")
	return nil
}

// Close performs a final sync and stops replication.
func (m *LitestreamManager) Close(ctx context.Context) error {
	m.mu.Lock()
	store := m.store
	m.store = nil
	m.mu.Unlock()
	if store == nil {
		return nil
	}
	if err := store.Close(ctx); err != nil {
		return fmt.Errorf("error closing litestream replication: %w", err)
	}
	return nil
}

// Status reports the replication state of each managed database.
func (m *LitestreamManager) Status(ctx context.Context) []LitestreamDBStatus {
	m.mu.Lock()
	dbs := append([]*litestream.DB{}, m.dbs...)
	started := m.store != nil
	m.mu.Unlock()

	statuses := make([]LitestreamDBStatus, 0, len(dbs))
	for _, db := range dbs {
		status := LitestreamDBStatus{
			Name: m.names[db],
			Path: db.Path(),
		}
		if !started {
			status.Error = "replication not started"
			statuses = append(statuses, status)
			continue
		}
		syncStatus, err := db.SyncStatus(ctx)
		if err != nil {
			status.Error = err.Error()
		} else {
			status.LocalTXID = uint64(syncStatus.LocalTXID)
			status.RemoteTXID = uint64(syncStatus.RemoteTXID)
			status.InSync = syncStatus.InSync
		}
		status.LastSyncAt = db.LastSuccessfulSyncAt()
		statuses = append(statuses, status)
	}
	return statuses
}
