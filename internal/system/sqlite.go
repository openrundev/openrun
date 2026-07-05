// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
)

const (
	DB_CONNECTION_CONFIG = "db_connection"
)

// defaultSQLitePragmas are the pragmas applied to every sqlite connection.
// busy_timeout and synchronous are per-connection settings, so they are passed
// as _pragma DSN query parameters which the sqlite driver applies to each new
// pooled connection (a plain "PRAGMA ..." exec would apply to one connection
// only). journal_mode=WAL is not included here: it is persisted in the database
// file and is set once at init, since a journal mode change does not use the
// busy handler and racing conversions on new connections fail with SQLITE_BUSY.
var defaultSQLitePragmas = [][2]string{
	{"busy_timeout", "10000"},
	{"synchronous", "NORMAL"},
}

// AddSQLitePragmas appends the default _pragma query parameters to a sqlite
// connect string (the file path part, after the sqlite: prefix is stripped).
// Pragmas already present in the connect string are not overridden.
func AddSQLitePragmas(connectString string) string {
	var b strings.Builder
	b.WriteString(connectString)
	sep := "?"
	if strings.Contains(connectString, "?") {
		sep = "&"
	}
	for _, pragma := range defaultSQLitePragmas {
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

func InitDBConnection(connectString string, invoker string, supportedDBs []DBType) (*sql.DB, DBType, error) {
	var err error
	dbType, connectString, err := CheckConnectString(connectString, invoker, supportedDBs)
	if err != nil {
		return nil, "", err
	}

	driver := DRIVER_MAP[dbType]
	if driver == "" {
		return nil, "", fmt.Errorf("unknown database type: %s", dbType)
	}
	if dbType == DB_TYPE_SQLITE {
		connectString = AddSQLitePragmas(connectString)
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
