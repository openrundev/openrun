// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"database/sql"
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
	// maintenance pass, bounding the write work done in one step
	sqliteVacuumPages = 2000
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
		initSQLiteSelfMaintenance(logger, db, invoker, dbFilePath, maint)
	} else if dbType == DB_TYPE_POSTGRES {
		// Configure connection pool settings for Postgres. The server opens
		// multiple pools (metadata, audit, file store, per-app stores), so the
		// per-pool cap is kept well below the postgres default max_connections
		// of 100 to avoid exhausting the server connection limit
		db.SetMaxOpenConns(50)                  // Maximum number of open connections
		db.SetMaxIdleConns(10)                  // Maximum number of idle connections
		db.SetConnMaxIdleTime(5 * time.Minute)  // Maximum time a connection can be idle
		db.SetConnMaxLifetime(15 * time.Minute) // Maximum lifetime of a connection

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

// sqliteMaintFiles tracks the database files that already have a maintenance
// owner in this process. Multiple pools can open the same file (every app's
// store.in plugin shares one app store database, and those pools are never
// closed on app reload), so maintenance is deduplicated per file: the first
// open runs the startup recovery/migration and owns the background loop,
// later opens skip both.
var (
	sqliteMaintMu    sync.Mutex
	sqliteMaintFiles = map[string]bool{}
)

// initSQLiteSelfMaintenance makes a sqlite database self-maintaining: it
// recovers any WAL left over from the previous run, migrates the file to
// incremental auto-vacuum (one time), and starts a background loop that keeps
// the WAL checkpointed and returns freed pages to the OS. Everything here is
// best-effort: a failure is logged and normal operation continues.
func initSQLiteSelfMaintenance(logger *types.Logger, db *sql.DB, invoker, dbFilePath string, maint sqliteMaintenanceSettings) {
	maintKey := dbFilePath
	if abs, err := filepath.Abs(dbFilePath); err == nil {
		maintKey = abs
	}
	sqliteMaintMu.Lock()
	if sqliteMaintFiles[maintKey] {
		sqliteMaintMu.Unlock()
		return // another open pool already maintains this database file
	}
	sqliteMaintFiles[maintKey] = true
	sqliteMaintMu.Unlock()

	ctx := context.Background()

	// At init no other transaction is running on this pool, so a truncate
	// checkpoint succeeds and resets a WAL that grew in a previous run while
	// readers pinned it. busy=1 means another process/pool has the file open.
	var busy, walFrames, checkpointed int
	if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &walFrames, &checkpointed); err != nil {
		logger.Warn().Err(err).Str("db", invoker).Msg("sqlite startup checkpoint failed")
	} else if busy != 0 {
		logger.Warn().Str("db", invoker).Msg("sqlite startup checkpoint could not complete, database in use elsewhere")
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

	if maint.interval > 0 {
		go sqliteMaintenanceLoop(logger, db, invoker, dbFilePath, maintKey, maint)
	}
}

// sqliteMaintenanceLoop periodically reclaims freed pages and checkpoints the
// WAL so neither the database file nor the WAL grows without bound. The loop
// exits when the database pool is closed, releasing the file's maintenance
// ownership so a later reopen can take over.
func sqliteMaintenanceLoop(logger *types.Logger, db *sql.DB, invoker, dbFilePath, maintKey string, maint sqliteMaintenanceSettings) {
	ctx := context.Background()
	ticker := time.NewTicker(maint.interval)
	defer ticker.Stop()
	defer func() {
		sqliteMaintMu.Lock()
		delete(sqliteMaintFiles, maintKey)
		sqliteMaintMu.Unlock()
	}()

	// walWarnBytes is the WAL size above which a warning is logged; based on
	// the configured size limit, with the default limit as floor so a disabled
	// limit does not disable the warning
	walWarnBytes := max(8*maint.journalSizeLimit, 8*sqliteJournalSizeLimit)

	runCount := 0
	for range ticker.C {
		runCount++
		if maint.vacuumPages > 0 {
			if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", maint.vacuumPages)); err != nil {
				if isDBClosedErr(err) {
					return
				}
				logger.Debug().Err(err).Str("db", invoker).Msg("sqlite incremental_vacuum failed")
			}
		}

		// A passive checkpoint copies whatever frames it can without blocking
		// anyone; it keeps the WAL checkpointed even when the commit-time
		// autocheckpoint keeps losing the race with new readers. The periodic
		// truncate checkpoint additionally resets the WAL file so
		// journal_size_limit can bound its size
		mode := "PASSIVE"
		truncatePass := maint.truncateEvery > 0 && runCount%maint.truncateEvery == 0
		if truncatePass {
			mode = "TRUNCATE"
		}
		var busy, walFrames, checkpointed int
		if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &walFrames, &checkpointed); err != nil {
			if isDBClosedErr(err) {
				return
			}
			logger.Debug().Err(err).Str("db", invoker).Msg("sqlite checkpoint failed")
			continue
		}

		if truncatePass {
			if busy != 0 {
				logger.Debug().Str("db", invoker).Msg("sqlite truncate checkpoint blocked by a long-lived transaction")
			}
			// Surface runaway WAL growth so operators can alert on the logs
			// well before the disk fills
			if dbFilePath != "" {
				if fi, err := os.Stat(dbFilePath + "-wal"); err == nil && fi.Size() > walWarnBytes {
					logger.Warn().Int64("wal_bytes", fi.Size()).Str("db", invoker).
						Msg("sqlite WAL is not checkpointing, a long-lived transaction may be pinning it")
				}
			}
		}
	}
}

func isDBClosedErr(err error) bool {
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
