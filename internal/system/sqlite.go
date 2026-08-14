// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

const (
	DB_CONNECTION_CONFIG = "db_connection"

	// Defaults for the sqlite self-maintenance settings, used when no
	// [metadata] config is available (app data stores, tests). The server
	// databases read the values from MetadataConfig, with these as fallback
	// for unset fields.

	// sqliteJournalSizeLimit caps the WAL file size: whenever a checkpoint
	// completes and the WAL is reset, any file larger than this is truncated
	// back to the limit instead of being reused at its grown size
	sqliteJournalSizeLimit = 32 * 1024 * 1024

	// sqliteMaintenanceIntervalSecs is how often the background maintenance
	// pass runs a passive checkpoint and an incremental vacuum step
	sqliteMaintenanceIntervalSecs = 60

	// sqliteTruncateEvery is the number of maintenance passes between forced
	// truncate checkpoints. A truncate checkpoint waits (up to busy_timeout)
	// for readers, blocking writers while it waits, so it runs less often than
	// the non-blocking passive pass
	sqliteTruncateEvery = 10

	// sqliteVacuumPages is the max free-list pages returned to the OS per
	// maintenance pass. Vacuum only runs after the WAL is fully checkpointed.
	sqliteVacuumPages = 2000

	// Maintenance uses its own connection with a short busy timeout. A
	// checkpoint is best-effort housekeeping and must not stall application
	// writers for the normal 10 second sqlite busy timeout.
	sqliteMaintenanceBusyTimeoutMillis = 100
	sqliteCheckpointCatchUpAttempts    = 3
	sqliteCheckpointCatchUpDelay       = 25 * time.Millisecond
	// Do not defer incremental vacuum forever behind a continuously moving WAL
	// tail. Nine dirty passes are deferred; the tenth still runs the configured,
	// bounded vacuum batch.
	sqliteVacuumMaxDeferredPasses = 9

	sqliteConnMaxIdleTime   = 30 * time.Minute
	postgresConnMaxIdleTime = 30 * time.Minute
)

// sqliteMaintenanceSettings are the resolved self-maintenance values for one
// sqlite database, defaults applied
type sqliteMaintenanceSettings struct {
	journalSizeLimit int64
	interval         time.Duration
	truncateEvery    int
	vacuumPages      int
}

// resolveSQLiteMaintenance merges the [metadata] config over the built-in
// defaults. A nil config means every default applies; explicit non-positive
// values in the config disable the corresponding behavior (the defaults are
// set in openrun.default.toml, so a zero here is an explicit user choice).
func resolveSQLiteMaintenance(sqliteCfg *types.MetadataConfig) sqliteMaintenanceSettings {
	if sqliteCfg == nil {
		return sqliteMaintenanceSettings{
			journalSizeLimit: sqliteJournalSizeLimit,
			interval:         sqliteMaintenanceIntervalSecs * time.Second,
			truncateEvery:    sqliteTruncateEvery,
			vacuumPages:      sqliteVacuumPages,
		}
	}
	return sqliteMaintenanceSettings{
		journalSizeLimit: sqliteCfg.SQLiteJournalSizeLimit,
		interval:         time.Duration(sqliteCfg.SQLiteMaintenanceIntervalSecs) * time.Second,
		truncateEvery:    sqliteCfg.SQLiteTruncateCheckpointEvery,
		vacuumPages:      sqliteCfg.SQLiteVacuumPages,
	}
}

// sqlitePragmas returns the pragmas applied to every sqlite connection.
// busy_timeout, synchronous and journal_size_limit are per-connection
// settings, so they are passed as _pragma DSN query parameters which the
// sqlite driver applies to each new pooled connection (a plain "PRAGMA ..."
// exec would apply to one connection only). journal_mode=WAL is not included
// here: it is persisted in the database file and is set once at init, since a
// journal mode change does not use the busy handler and racing conversions on
// new connections fail with SQLITE_BUSY.
func sqlitePragmas(journalSizeLimit int64) [][2]string {
	pragmas := [][2]string{
		{"busy_timeout", "10000"},
		{"synchronous", "NORMAL"},
	}
	if journalSizeLimit > 0 {
		pragmas = append(pragmas, [2]string{"journal_size_limit", strconv.FormatInt(journalSizeLimit, 10)})
	}
	return pragmas
}

// AddSQLitePragmas appends the default _pragma query parameters to a sqlite
// connect string (the file path part, after the sqlite: prefix is stripped).
// Pragmas already present in the connect string are not overridden.
func AddSQLitePragmas(connectString string, journalSizeLimit int64) string {
	var b strings.Builder
	b.WriteString(connectString)
	sep := "?"
	if strings.Contains(connectString, "?") {
		sep = "&"
	}
	for _, pragma := range sqlitePragmas(journalSizeLimit) {
		if strings.Contains(connectString, "_pragma="+pragma[0]) {
			continue // user-specified pragma wins
		}
		b.WriteString(sep)
		b.WriteString("_pragma=")
		b.WriteString(pragma[0])
		b.WriteString("(")
		b.WriteString(pragma[1])
		b.WriteString(")")
		sep = "&"
	}
	return b.String()
}

func CheckConnectString(connStr string, invoker string, supportedDBs []DBType) (DBType, string, error) {
	parts := strings.SplitN(connStr, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid connection string: %s", connStr)
	}

	if !slices.Contains(supportedDBs, DBType(parts[0])) {
		return "", "", fmt.Errorf("invalid database type: %s for %s", parts[0], invoker)
	}

	if DBType(parts[0]) == DB_TYPE_SQLITE {
		return DBType(parts[0]), os.ExpandEnv(parts[1]), nil
	}

	return DBType(parts[0]), os.ExpandEnv(connStr), nil
}

type DBType string

const (
	DB_TYPE_SQLITE   DBType = "sqlite"
	DB_TYPE_POSTGRES DBType = "postgres"
)

var (
	DB_SQLITE_POSTGRES = []DBType{DB_TYPE_SQLITE, DB_TYPE_POSTGRES}
	DB_SQLITE          = []DBType{DB_TYPE_SQLITE}
	DRIVER_MAP         = map[DBType]string{
		DB_TYPE_SQLITE:   "sqlite",
		DB_TYPE_POSTGRES: "pgx",
	}
)

// InitDBConnection opens a database connection pool. sqliteCfg carries the
// sqlite self-maintenance settings from the [metadata] config section; nil
// uses the built-in defaults (app data stores, tests). It is ignored for
// postgres.
func InitDBConnection(logger *types.Logger, connectString string, invoker string, supportedDBs []DBType,
	sqliteCfg *types.MetadataConfig) (*sql.DB, DBType, error) {
	if logger == nil {
		nop := zerolog.Nop()
		logger = &types.Logger{Logger: &nop}
	}
	var err error
	dbType, connectString, err := CheckConnectString(connectString, invoker, supportedDBs)
	if err != nil {
		return nil, "", err
	}

	dbFilePath := ""
	maint := resolveSQLiteMaintenance(sqliteCfg)
	driver := DRIVER_MAP[dbType]
	if driver == "" {
		return nil, "", fmt.Errorf("unknown database type: %s", dbType)
	}
	if dbType == DB_TYPE_SQLITE {
		dbFilePath = strings.SplitN(connectString, "?", 2)[0]
		connectString = AddSQLitePragmas(connectString, maint.journalSizeLimit)
	}
	if telemetry.MetricsEnabled() {
		wrapped, err := telemetry.SQLDriverName(driver, telemetryDBSystem(dbType), invoker)
		if err != nil {
			return nil, "", fmt.Errorf("error wrapping %s driver for telemetry: %w", driver, err)
		}
		driver = wrapped
	}

	db, err := sql.Open(driver, connectString)
	if err != nil {
		return nil, "", fmt.Errorf("error opening %s db %s: %w", invoker, connectString, err)
	}

	if dbType == DB_TYPE_SQLITE { //nolint:staticcheck
		// journal_mode is persistent in the database file, set it once here.
		// The per-connection pragmas are applied through the DSN (see AddSQLitePragmas)
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			db.Close() //nolint:errcheck
			return nil, "", fmt.Errorf("error setting journal mode: %w", err)
		}
		// Keep more idle connections around than the database/sql default of two;
		// sqlite connections are file opens plus pragma execs, and connection churn
		// under concurrent reads costs more than the idle handles
		db.SetMaxIdleConns(10)
		db.SetConnMaxIdleTime(sqliteConnMaxIdleTime)
		initSQLiteSelfMaintenance(logger, db, invoker, dbFilePath, maint, driver, connectString)
	} else if dbType == DB_TYPE_POSTGRES {
		// Configure connection pool settings for Postgres. The server opens
		// multiple pools (metadata, audit, file store, per-app stores), so the
		// per-pool cap is kept well below the postgres default max_connections
		// of 100 to avoid exhausting the server connection limit
		db.SetMaxOpenConns(50) // Maximum number of open connections
		db.SetMaxIdleConns(10) // Maximum number of idle connections
		// Keep the explicitly configured 30-minute idle window separate from the
		// SQLite setting so future tuning of one pool type cannot silently affect
		// the other.
		db.SetConnMaxIdleTime(postgresConnMaxIdleTime) // Maximum time a connection can be idle
		db.SetConnMaxLifetime(15 * time.Minute)        // Maximum lifetime of a connection

		// Test the connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			db.Close() //nolint:errcheck
			return nil, "", fmt.Errorf("error connecting to postgres database: %w", err)
		}
	}
	return db, dbType, nil
}

// sqliteMaintFiles tracks the database files already maintained by this
// process. Multiple application pools can open the same file, especially as
// apps reload, so the maintenance loop never retains one of those pools. The
// first open creates one dedicated, process-lifetime maintenance pool per file;
// later opens do not add owners or standby references.
var (
	sqliteMaintMu    sync.Mutex
	sqliteMaintFiles = map[string]*sqliteMaintenanceState{}
)

type sqliteMaintenanceState struct {
	mu                   sync.RWMutex
	status               types.SQLiteMetadataMetrics
	vacuumDeferredPasses int
	maintenanceDB        *sql.DB            // guarded by sqliteMaintMu
	maintenanceCancel    context.CancelFunc // guarded by sqliteMaintMu
}

func sqliteMaintenanceKey(dbFilePath string) string {
	if dbFilePath == ":memory:" || strings.HasPrefix(dbFilePath, "file:") {
		return dbFilePath
	}
	if abs, err := filepath.Abs(dbFilePath); err == nil {
		return abs
	}
	return dbFilePath
}

func sqliteDSNWithCanonicalPath(connectString, canonicalPath string) string {
	pathPart, queryPart, found := strings.Cut(connectString, "?")
	if pathPart == ":memory:" || strings.HasPrefix(pathPart, "file:") {
		return connectString
	}
	if !found {
		return canonicalPath
	}
	return canonicalPath + "?" + queryPart
}

// SQLiteFilePath resolves the canonical file identity used by SQLite
// maintenance. Callers should resolve it while opening the database; relative
// paths must not be interpreted again after a later process-wide chdir.
func SQLiteFilePath(connectString, invoker string) (string, error) {
	dbType, dbPath, err := CheckConnectString(connectString, invoker, DB_SQLITE_POSTGRES)
	if err != nil {
		return "", err
	}
	if dbType != DB_TYPE_SQLITE {
		return "", nil
	}
	dbPath = strings.SplitN(dbPath, "?", 2)[0]
	return sqliteMaintenanceKey(dbPath), nil
}

// GetSQLiteMaintenanceStatus returns the latest maintenance counters plus
// current sqlite file sizes. false means this process has not opened the file.
func GetSQLiteMaintenanceStatus(dbFilePath string) (types.SQLiteMetadataMetrics, bool) {
	key := sqliteMaintenanceKey(dbFilePath)
	sqliteMaintMu.Lock()
	state, ok := sqliteMaintFiles[key]
	sqliteMaintMu.Unlock()
	if !ok {
		return types.SQLiteMetadataMetrics{}, false
	}
	state.mu.RLock()
	status := state.status
	state.mu.RUnlock()
	status.DatabaseBytes = fileSize(status.DatabasePath)
	status.WALBytes = fileSize(status.DatabasePath + "-wal")
	status.SHMBytes = fileSize(status.DatabasePath + "-shm")
	status.LastCheckpointBacklog = max(0, status.LastWALFrames-status.LastCheckpointedFrames)
	return status, true
}

func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

func (s *sqliteMaintenanceState) recordCheckpoint(mode string, busy, walFrames, checkpointed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.status.CheckpointErrors++
		s.status.LastCheckpointError = err.Error()
		// Scan does not populate the three PRAGMA result columns on failure.
		// Preserve the last successful measurements instead of reporting a
		// misleading zero backlog while checkpointing is broken.
		return
	}

	s.status.CheckpointRuns++
	s.status.LastCheckpointAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.status.LastCheckpointMode = mode
	s.status.LastCheckpointBusy = busy
	s.status.LastWALFrames = walFrames
	s.status.LastCheckpointedFrames = checkpointed
	s.status.LastCheckpointError = ""
	if mode == "TRUNCATE" {
		s.status.TruncateRuns++
		if busy != 0 {
			s.status.TruncateBlocked++
		}
	}
}

func (s *sqliteMaintenanceState) recordVacuum(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vacuumDeferredPasses = 0
	s.status.VacuumRuns++
	s.status.LastVacuumAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.status.LastVacuumError = ""
	if err != nil {
		s.status.LastVacuumError = err.Error()
	}
}

// deferVacuum records a dirty checkpoint pass. It returns false while vacuum
// should remain deferred and true once the bounded deferral limit is reached.
func (s *sqliteMaintenanceState) deferVacuum() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vacuumDeferredPasses >= sqliteVacuumMaxDeferredPasses {
		s.vacuumDeferredPasses = 0
		return true
	}
	s.vacuumDeferredPasses++
	s.status.VacuumSkippedRuns++
	return false
}

func (s *sqliteMaintenanceState) recordVacuumSkipped() {
	s.mu.Lock()
	s.status.VacuumSkippedRuns++
	s.mu.Unlock()
}

// initSQLiteSelfMaintenance makes a sqlite database self-maintaining: it
// recovers any WAL left over from the previous run, migrates the file to
// incremental auto-vacuum (one time), and starts a background loop that keeps
// the WAL checkpointed and returns freed pages to the OS. Everything here is
// best-effort: a failure is logged and normal operation continues.
func initSQLiteSelfMaintenance(logger *types.Logger, db *sql.DB, invoker, dbFilePath string, maint sqliteMaintenanceSettings,
	driverName, connectString string) {
	maintKey := sqliteMaintenanceKey(dbFilePath)
	state := &sqliteMaintenanceState{status: types.SQLiteMetadataMetrics{
		DatabasePath:       maintKey,
		MaintenanceEnabled: maint.interval > 0,
		LitestreamManaged:  isLitestreamManaged(dbFilePath),
	}}
	sqliteMaintMu.Lock()
	if _, exists := sqliteMaintFiles[maintKey]; exists {
		sqliteMaintMu.Unlock()
		return // one dedicated pool already maintains this database file
	}
	sqliteMaintFiles[maintKey] = state
	sqliteMaintMu.Unlock()

	ctx := context.Background()

	// At init no other transaction is running on this pool, so a truncate
	// checkpoint succeeds and resets a WAL that grew in a previous run while
	// readers pinned it. busy=1 means another process/pool has the file open.
	// Skipped for litestream-replicated databases: litestream owns
	// checkpointing for them (it holds a long-lived read transaction and runs
	// its own passive/truncate checkpoint strategy)
	if !isLitestreamManaged(dbFilePath) {
		var busy, walFrames, checkpointed int
		err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &walFrames, &checkpointed)
		state.recordCheckpoint("TRUNCATE", busy, walFrames, checkpointed, err)
		if err != nil {
			logger.Warn().Err(err).Str("db", invoker).Msg("sqlite startup checkpoint failed")
		} else if busy != 0 {
			logger.Warn().Str("db", invoker).Msg("sqlite startup checkpoint could not complete, database in use elsewhere")
		}
	}

	// One-time migration to incremental auto-vacuum, so pages freed by row
	// deletes (session and audit cleanup) can be returned to the OS by the
	// periodic incremental_vacuum instead of accumulating as dead pages. The
	// pragma only takes effect through a VACUUM, which also compacts any bloat
	// accumulated before the migration; both statements must run on the same
	// connection. auto_vacuum is persisted in the file, so this runs once ever.
	conn, err := db.Conn(ctx)
	if err != nil {
		logger.Warn().Err(err).Str("db", invoker).Msg("sqlite maintenance connection failed")
	} else {
		var autoVacuum int
		if err := conn.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
			logger.Warn().Err(err).Str("db", invoker).Msg("sqlite auto_vacuum check failed")
		} else if autoVacuum != 2 { // 2 == incremental
			if _, err := conn.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
				logger.Warn().Err(err).Str("db", invoker).Msg("sqlite auto_vacuum pragma failed")
			} else if _, err := conn.ExecContext(ctx, "VACUUM"); err != nil {
				// VACUUM needs free disk space and an idle database; failing
				// here is not fatal, the migration is retried on next startup
				logger.Warn().Err(err).Str("db", invoker).Msg("sqlite auto_vacuum migration failed, will retry on next startup")
			} else {
				logger.Info().Str("db", invoker).Msg("sqlite database migrated to incremental auto_vacuum")
			}
		}
		conn.Close() //nolint:errcheck
	}

	if maint.interval <= 0 {
		return
	}

	// Never tie file-wide maintenance to an application pool. App reloads can
	// create many pools for the same SQLite file, and retaining them as fallback
	// owners prevents garbage collection and grows without bound. A single
	// dedicated pool is stable for the process lifetime and needs no handoff.
	maintenanceDB, err := sql.Open(driverName, sqliteDSNWithCanonicalPath(connectString, maintKey))
	if err != nil {
		logger.Warn().Err(err).Str("db", invoker).Msg("sqlite dedicated maintenance pool failed")
		return
	}
	maintenanceDB.SetMaxOpenConns(1)
	maintenanceDB.SetMaxIdleConns(1)
	maintenanceCtx, maintenanceCancel := context.WithCancel(context.Background())
	sqliteMaintMu.Lock()
	state.maintenanceDB = maintenanceDB
	state.maintenanceCancel = maintenanceCancel
	sqliteMaintMu.Unlock()
	go sqliteMaintenanceLoop(maintenanceCtx, logger, maintenanceDB, invoker, maintKey, maint, state)
}

// sqliteMaintenanceLoop periodically reclaims freed pages and checkpoints the
// WAL so neither the database file nor the WAL grows without bound. The loop
// owns a dedicated pool, so closing or reloading any application pool
// cannot interrupt file-wide maintenance.
func sqliteMaintenanceLoop(ctx context.Context, logger *types.Logger, db *sql.DB, invoker, dbFilePath string,
	maint sqliteMaintenanceSettings, state *sqliteMaintenanceState) {
	ticker := time.NewTicker(maint.interval)
	defer ticker.Stop()
	if err := db.PingContext(ctx); err != nil {
		logger.Warn().Err(err).Str("db", invoker).Msg("sqlite dedicated maintenance connection failed")
	}

	// walWarnBytes is the WAL size above which a warning is logged; based on
	// the configured size limit, with the default limit as floor so a disabled
	// limit does not disable the warning
	walWarnBytes := max(8*maint.journalSizeLimit, 8*sqliteJournalSizeLimit)

	runCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		runCount++
		truncatePass := maint.truncateEvery > 0 && runCount%maint.truncateEvery == 0
		checkpointClean := false
		if truncatePass && !isLitestreamManaged(dbFilePath) {
			// TRUNCATE is the infrequent recovery pass that is allowed to wait for
			// readers under the connection's normal busy_timeout (10 seconds by
			// default). Attempt it even when a passive pass would report backlog;
			// waiting for that reader is precisely what TRUNCATE is for.
			busy, walFrames, checkpointed, err := runSQLiteCheckpoint(ctx, db, "TRUNCATE", state)
			warnLargeSQLiteWAL(logger, invoker, dbFilePath, walWarnBytes, walFrames, checkpointed)
			if err != nil {
				logger.Debug().Err(err).Str("db", invoker).Msg("sqlite truncate checkpoint failed")
			} else if busy != 0 {
				logger.Debug().Str("db", invoker).Msg("sqlite truncate checkpoint blocked by a long-lived transaction")
			} else {
				checkpointClean = true
			}
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			if isDBClosedErr(err) {
				return
			}
			logger.Debug().Err(err).Str("db", invoker).Msg("sqlite maintenance connection failed")
			continue
		}
		priorBusyTimeout, err := setSQLiteMaintenanceBusyTimeout(ctx, conn)
		if err != nil {
			closeSQLiteMaintenanceConn(ctx, logger, conn, invoker, priorBusyTimeout)
			if isDBClosedErr(err) {
				return
			}
			logger.Debug().Err(err).Str("db", invoker).Msg("sqlite maintenance busy timeout failed")
			continue
		}
		runSQLiteMaintenancePass(ctx, logger, conn, invoker, dbFilePath, maint, state, checkpointClean)
		closeSQLiteMaintenanceConn(ctx, logger, conn, invoker, priorBusyTimeout)
	}
}

func setSQLiteMaintenanceBusyTimeout(ctx context.Context, conn *sql.Conn) (int, error) {
	var prior int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&prior); err != nil {
		return -1, err
	}
	_, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", sqliteMaintenanceBusyTimeoutMillis))
	return prior, err
}

func closeSQLiteMaintenanceConn(ctx context.Context, logger *types.Logger, conn *sql.Conn, invoker string, timeout int) {
	var restoreErr error
	if timeout >= 0 {
		_, restoreErr = conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", timeout))
	}
	if timeout < 0 || restoreErr != nil {
		if restoreErr != nil {
			logger.Warn().Err(restoreErr).Str("db", invoker).Msg("sqlite maintenance busy timeout restore failed; discarding connection")
		}
		// Returning driver.ErrBadConn from Raw tells database/sql not to put
		// this connection—with an unknown or 100ms timeout—back in the pool.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	conn.Close() //nolint:errcheck
}

// runSQLiteMaintenancePass uses short-timeout passive checkpoints around a
// bounded incremental vacuum. A dirty WAL normally defers vacuum to avoid
// amplifying a pinned WAL, but a bounded catch-up pass prevents vacuum from
// being starved indefinitely by continuous traffic.
func runSQLiteMaintenancePass(ctx context.Context, logger *types.Logger, conn *sql.Conn, invoker, dbFilePath string,
	maint sqliteMaintenanceSettings, state *sqliteMaintenanceState, checkpointClean bool) {
	if isLitestreamManaged(dbFilePath) {
		// Litestream owns checkpointing. Preserve incremental vacuum behavior;
		// its checkpoint loop will consume the bounded batch of resulting frames.
		runSQLiteIncrementalVacuum(ctx, logger, conn, invoker, maint, state)
		return
	}

	if !checkpointClean {
		busy, walFrames, checkpointed, err := runSQLiteCheckpoint(ctx, conn, "PASSIVE", state)
		if err != nil {
			logger.Debug().Err(err).Str("db", invoker).Msg("sqlite passive checkpoint failed")
			if maint.vacuumPages > 0 {
				state.recordVacuumSkipped()
			}
			return
		}
		// Reader turnover can leave a momentary tail after the first passive
		// checkpoint. Retry briefly before treating it as a pinned or constantly
		// moving WAL.
		for attempt := 1; (busy != 0 || walFrames != checkpointed) && attempt < sqliteCheckpointCatchUpAttempts; attempt++ {
			timer := time.NewTimer(sqliteCheckpointCatchUpDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			busy, walFrames, checkpointed, err = runSQLiteCheckpoint(ctx, conn, "PASSIVE", state)
			if err != nil {
				logger.Debug().Err(err).Str("db", invoker).Msg("sqlite passive checkpoint catch-up failed")
				if maint.vacuumPages > 0 {
					state.recordVacuumSkipped()
				}
				return
			}
		}
		if busy != 0 || walFrames != checkpointed {
			if maint.vacuumPages <= 0 || !state.deferVacuum() {
				return
			}
			logger.Debug().Str("db", invoker).Msg("sqlite forcing bounded incremental vacuum after repeated checkpoint backlog")
		}
	}

	if !runSQLiteIncrementalVacuum(ctx, logger, conn, invoker, maint, state) {
		return
	}
	// Vacuum itself writes WAL frames. Checkpoint them immediately while the
	// batch is small instead of leaving them for the next periodic pass.
	if _, _, _, err := runSQLiteCheckpoint(ctx, conn, "PASSIVE", state); err != nil {
		logger.Debug().Err(err).Str("db", invoker).Msg("sqlite post-vacuum checkpoint failed")
	}
}

func warnLargeSQLiteWAL(logger *types.Logger, invoker, dbFilePath string, walWarnBytes int64,
	walFrames, checkpointed int) {
	walBytes := fileSize(dbFilePath + "-wal")
	if walBytes > walWarnBytes {
		logger.Warn().Int64("wal_bytes", walBytes).Int("wal_frames", walFrames).
			Int("checkpointed_frames", checkpointed).Str("db", invoker).
			Msg("sqlite WAL is not checkpointing, a long-lived transaction may be pinning it")
	}
}

type sqliteCheckpointQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func runSQLiteCheckpoint(ctx context.Context, conn sqliteCheckpointQuerier, mode string, state *sqliteMaintenanceState) (int, int, int, error) {
	var busy, walFrames, checkpointed int
	err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &walFrames, &checkpointed)
	state.recordCheckpoint(mode, busy, walFrames, checkpointed, err)
	return busy, walFrames, checkpointed, err
}

// runSQLiteIncrementalVacuum returns true when a vacuum statement ran, even
// if it failed, so the caller can checkpoint any frames written before error.
func runSQLiteIncrementalVacuum(ctx context.Context, logger *types.Logger, conn *sql.Conn, invoker string,
	maint sqliteMaintenanceSettings, state *sqliteMaintenanceState) bool {
	if maint.vacuumPages <= 0 {
		return false
	}
	_, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", maint.vacuumPages))
	state.recordVacuum(err)
	if err != nil {
		logger.Debug().Err(err).Str("db", invoker).Msg("sqlite incremental_vacuum failed")
	}
	return true
}

func isDBClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, sql.ErrConnDone) || strings.Contains(err.Error(), "database is closed")
}

func telemetryDBSystem(dbType DBType) string {
	switch dbType {
	case DB_TYPE_SQLITE:
		return telemetry.DBSystemSQLite
	case DB_TYPE_POSTGRES:
		return telemetry.DBSystemPostgres
	default:
		return string(dbType)
	}
}

func GetConnectString(pluginContext *types.PluginContext) (string, error) {
	connectStringConfig, ok := pluginContext.Config[DB_CONNECTION_CONFIG]
	if !ok {
		return "", fmt.Errorf("db connection string not found in config")
	}
	connectString, ok := connectStringConfig.(string)
	if !ok {
		return "", fmt.Errorf("db connection string is not a string")
	}
	return connectString, nil
}

func PostgresRebind(q string) string {
	var b strings.Builder
	n := 1
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

func RebindQuery(dbType DBType, q string) string {
	if dbType == DB_TYPE_POSTGRES {
		return PostgresRebind(q)
	}
	return q
}

func MapDataType(dbType DBType, dataType string) string {
	if dbType == DB_TYPE_POSTGRES {
		dataType = strings.ToLower(dataType)
		switch dataType {
		case "datetime":
			return "timestamptz"
		case "blob":
			return "bytea"
		}
	}
	return dataType
}

func FuncNow(dbType DBType) string {
	if dbType == DB_TYPE_POSTGRES {
		return "now()"
	}
	return "datetime('now')"
}

func InsertIgnorePrefix(dbType DBType) string {
	if dbType == DB_TYPE_POSTGRES {
		return "insert "
	}
	return "insert or ignore"
}

func InsertIgnoreSuffix(dbType DBType) string {
	if dbType == DB_TYPE_POSTGRES {
		return " on conflict do nothing"
	}
	return ""
}
