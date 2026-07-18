// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package sqlbinding provides helpers for bindings backed by database/sql
// drivers: service initialization, the RunCommand implementation, and
// identifier quoting primitives.
package sqlbinding

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/openrundev/openrun/pkg/binding"
)

// RunCommand result keys. These are a wire contract: CLI and app callers
// address the result with them.
const (
	ResultColumns      = "columns"
	ResultRows         = "rows"
	ResultRowsAffected = "rows_affected"
	ResultCommandTag   = "command_tag"
)

// RunCommandOptions controls RunCommand behavior per dialect.
type RunCommandOptions struct {
	// RowReturningKeywords lists leading keywords (upper case) treated as
	// row-returning in addition to SELECT and WITH (e.g. EXEC/EXECUTE for
	// SQL Server).
	RowReturningKeywords []string
}

// RunCommand implements ServiceBinding.RunCommand for database/sql drivers:
// it connects with the binding account's DSN, runs the command as a query when
// it starts with a row-returning keyword and as a statement otherwise, and
// returns the standard result shape (ResultColumns/ResultRows/
// ResultRowsAffected/ResultCommandTag).
func RunCommand(ctx context.Context, driverName, dsn, command string, opts RunCommandOptions) (map[string]any, error) {
	conn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("error opening connection: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	if err := conn.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("error verifying connection: %w", err)
	}

	// Heuristic: a statement that returns rows is treated as a query; otherwise
	// we use Exec so callers can issue DDL/DML and still see rows_affected.
	first := ""
	if fields := strings.Fields(command); len(fields) > 0 {
		first = strings.ToUpper(fields[0])
	}
	rowReturning := first == "SELECT" || first == "WITH" || slices.Contains(opts.RowReturningKeywords, first)

	if !rowReturning {
		result, err := conn.ExecContext(ctx, command)
		if err != nil {
			return nil, fmt.Errorf("error executing command: %w", err)
		}
		rowsAffected, _ := result.RowsAffected()
		return map[string]any{
			ResultColumns:      []string{},
			ResultRows:         []map[string]any{},
			ResultRowsAffected: rowsAffected,
			ResultCommandTag:   first,
		}, nil
	}

	rows, err := conn.QueryContext(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("error executing command: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("error reading command result columns: %w", err)
	}

	resultRows := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("error reading command result row: %w", err)
		}

		resultRow := make(map[string]any, len(columns))
		for i, column := range columns {
			// Convert []byte values (binary and some text results) to string
			// so JSON marshalling produces something useful for callers.
			if b, ok := values[i].([]byte); ok {
				resultRow[column] = string(b)
			} else {
				resultRow[column] = values[i]
			}
		}
		resultRows = append(resultRows, resultRow)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading command result: %w", err)
	}

	return map[string]any{
		ResultColumns:      columns,
		ResultRows:         resultRows,
		ResultRowsAffected: int64(len(resultRows)),
		ResultCommandTag:   first,
	}, nil
}

// InitService implements the common InitializeService steps for database/sql
// bindings: validate the service config keys (url required, binding_hostname
// optional), open and ping the admin connection with the given DSN (usually
// the url itself; mysql converts to its DSN format first), and return the
// effective service config with the localhost binding hostname applied.
func InitService(ctx context.Context, driverName, dsn string, serviceConfig map[string]string,
	runtime binding.ServiceBindingRuntime) (*sql.DB, map[string]string, error) {
	if err := binding.VerifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{"binding_hostname"}); err != nil {
		return nil, nil, err
	}

	adminConn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening admin connection: %w", err)
	}
	if err := adminConn.PingContext(ctx); err != nil {
		adminConn.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("error verifying %s connection: %w", driverName, err)
	}

	effectiveConfig := binding.ServiceConfigWithLocalhostBindingHostname(serviceConfig, serviceConfig["url"], runtime)
	return adminConn, effectiveConfig, nil
}

// QuoteIdentBracket quotes an identifier with brackets (SQL Server). Embedded
// closing brackets are doubled.
func QuoteIdentBracket(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

// QuoteIdentDouble quotes an identifier with double quotes (Oracle, Postgres).
// Embedded double quotes are doubled.
func QuoteIdentDouble(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// QuoteStringSingle quotes a value as a single-quoted SQL string literal.
// Embedded single quotes are doubled.
func QuoteStringSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
