// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"modernc.org/sqlite"
)

const (
	DBSystemSQLite   = "sqlite"
	DBSystemPostgres = "postgresql"
)

// registeredSQLDrivers maps the wrapped driver name to a sync.Once guarding
// the corresponding sql.Register call. Storing the once (rather than the
// driver) ensures that "name is in the map" is equivalent to "registration
// has run to completion": a concurrent caller cannot observe the name as
// present and race ahead to sql.Open before sql.Register has actually
// completed.
var registeredSQLDrivers sync.Map

func SQLDriverName(driverName, dbSystem, invoker string) (string, error) {
	if !MetricsEnabled() {
		return driverName, nil
	}
	base := baseDriver(driverName)
	if base == nil {
		return "", fmt.Errorf("telemetry: unknown sql driver %q", driverName)
	}

	name := "openrun_otel_" + driverName + "_" + safeDriverName(invoker)
	onceAny, _ := registeredSQLDrivers.LoadOrStore(name, &sync.Once{})
	once := onceAny.(*sync.Once)
	once.Do(func() {
		sql.Register(name, &sqlDriver{
			driver:   base,
			dbSystem: dbSystem,
			invoker:  invoker,
		})
	})
	return name, nil
}

func baseDriver(driverName string) driver.Driver {
	switch driverName {
	case "sqlite":
		return &sqlite.Driver{}
	case "pgx":
		return stdlib.GetDefaultDriver()
	default:
		return nil
	}
}

type sqlDriver struct {
	driver   driver.Driver
	dbSystem string
	invoker  string
}

func (d *sqlDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &sqlConn{Conn: conn, dbSystem: d.dbSystem, invoker: d.invoker}, nil
}

type sqlConn struct {
	driver.Conn
	dbSystem string
	invoker  string
}

func (c *sqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	preparer, ok := c.Conn.(driver.ConnPrepareContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	stmt, err := preparer.PrepareContext(ctx, query)
	RecordDBCall(ctx, c.dbSystem, c.invoker, "prepare", start, err)
	if err != nil {
		return nil, err
	}
	return &sqlStmt{Stmt: stmt, query: query, dbSystem: c.dbSystem, invoker: c.invoker}, nil
}

func (c *sqlConn) Prepare(query string) (driver.Stmt, error) {
	start := time.Now()
	stmt, err := c.Conn.Prepare(query)
	RecordDBCall(context.Background(), c.dbSystem, c.invoker, "prepare", start, err)
	if err != nil {
		return nil, err
	}
	return &sqlStmt{Stmt: stmt, query: query, dbSystem: c.dbSystem, invoker: c.invoker}, nil
}

func (c *sqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	result, err := execer.ExecContext(ctx, query, args)
	RecordDBCall(ctx, c.dbSystem, c.invoker, queryOperation(query), start, err)
	return result, err
}

func (c *sqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := queryer.QueryContext(ctx, query, args)
	RecordDBCall(ctx, c.dbSystem, c.invoker, queryOperation(query), start, err)
	return rows, err
}

func (c *sqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	tx, err := beginner.BeginTx(ctx, opts)
	RecordDBCall(ctx, c.dbSystem, c.invoker, "begin", start, err)
	if err != nil {
		return nil, err
	}
	return &sqlTx{Tx: tx, dbSystem: c.dbSystem, invoker: c.invoker}, nil
}

func (c *sqlConn) Ping(ctx context.Context) error {
	pinger, ok := c.Conn.(driver.Pinger)
	if !ok {
		return driver.ErrSkip
	}
	start := time.Now()
	err := pinger.Ping(ctx)
	RecordDBCall(ctx, c.dbSystem, c.invoker, "ping", start, err)
	return err
}

func (c *sqlConn) CheckNamedValue(value *driver.NamedValue) error {
	checker, ok := c.Conn.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return checker.CheckNamedValue(value)
}

func (c *sqlConn) ResetSession(ctx context.Context) error {
	resetter, ok := c.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return resetter.ResetSession(ctx)
}

func (c *sqlConn) IsValid() bool {
	validator, ok := c.Conn.(driver.Validator)
	if !ok {
		return true
	}
	return validator.IsValid()
}

type sqlStmt struct {
	driver.Stmt
	query    string
	dbSystem string
	invoker  string
}

func (s *sqlStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := s.Stmt.(driver.StmtExecContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	result, err := execer.ExecContext(ctx, args)
	RecordDBCall(ctx, s.dbSystem, s.invoker, queryOperation(s.query), start, err)
	return result, err
}

func (s *sqlStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := queryer.QueryContext(ctx, args)
	RecordDBCall(ctx, s.dbSystem, s.invoker, queryOperation(s.query), start, err)
	return rows, err
}

func (s *sqlStmt) CheckNamedValue(value *driver.NamedValue) error {
	checker, ok := s.Stmt.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return checker.CheckNamedValue(value)
}

type sqlTx struct {
	driver.Tx
	dbSystem string
	invoker  string
}

func (t *sqlTx) Commit() error {
	start := time.Now()
	err := t.Tx.Commit()
	RecordDBCall(context.Background(), t.dbSystem, t.invoker, "commit", start, err)
	return err
}

func (t *sqlTx) Rollback() error {
	start := time.Now()
	err := t.Tx.Rollback()
	RecordDBCall(context.Background(), t.dbSystem, t.invoker, "rollback", start, err)
	return err
}

func queryOperation(query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return "unknown"
	}
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return "unknown"
	}
	return strings.ToLower(fields[0])
}

func safeDriverName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
