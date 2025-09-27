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

	"github.com/openrundev/openrun/internal/types"
)

const (
	DB_CONNECTION_CONFIG = "db_connection"
)

func SQLItePragmas(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=10000"); err != nil {
		return err
	}

	return nil
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

	db, err := sql.Open(driver, connectString)
	if err != nil {
		return nil, "", fmt.Errorf("error opening %s db %s: %w", invoker, connectString, err)
	}

	if dbType == DB_TYPE_SQLITE { //nolint:staticcheck
		if err := SQLItePragmas(db); err != nil {
			return nil, "", err
		}
	} else if dbType == DB_TYPE_POSTGRES {
		// Configure connection pool settings for Postgres
		db.SetMaxOpenConns(200)                 // Maximum number of open connections
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
