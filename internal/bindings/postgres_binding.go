// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type PostgresServiceBinding struct {
	serviceConfig map[string]string
	bindingConfig map[string]string

	adminConn *sql.DB // The admin connection to the main database, available after InitService
}

func init() {
	RegisterServiceBinding("postgres", NewPostgresServiceBinding)
}

var _ ServiceBinding = (*PostgresServiceBinding)(nil)

func NewPostgresServiceBinding() ServiceBinding {
	return &PostgresServiceBinding{}
}

func (b *PostgresServiceBinding) InitService(ctx context.Context, serviceConfig map[string]string) error {
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{}); err != nil {
		return err
	}

	connURL := serviceConfig["url"]
	adminConn, err := sql.Open("pgx", connURL)
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}

	if err := adminConn.PingContext(ctx); err != nil {
		return fmt.Errorf("error verifying postgres connection: %w", err)
	}

	b.serviceConfig = serviceConfig
	b.adminConn = adminConn
	return nil
}

func (b *PostgresServiceBinding) InitBaseBinding(ctx context.Context, bindingConfig map[string]string) error {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingConfig)), []string{}, []string{"inherit_default"}); err != nil {
		return err
	}
	b.bindingConfig = bindingConfig
	return nil
}

func (b *PostgresServiceBinding) InitDerivedBinding(ctx context.Context, grants []string, bindingConfig map[string]string) error {
	// TODO: Implement derived binding initialization
	return nil
}

func (b *PostgresServiceBinding) GenerateAccount(ctx context.Context, bindingId string, isStaging bool) (map[string]string, error) {
	inheritDefault := true
	var err error

	inheritDefaultStr, ok := b.bindingConfig["inherit_default"]
	if ok {
		inheritDefault, err = strconv.ParseBool(inheritDefaultStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing inherit_default: %w", err)
		}
	}

	// Create a new schema, create a login role and grant full access on the schema for that role.
	password, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("error generating random password: %w", err)
	}
	modePrefix := "prd_"
	if isStaging {
		modePrefix = "stg_"
	}

	schemaName := "cl_sch_" + modePrefix + bindingId
	roleName := "cl_rol_" + modePrefix + bindingId

	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	quotedRole := pgx.Identifier{roleName}.Sanitize()
	quotedPassword := quoteLiteral(password)

	roleOptions := "LOGIN"
	if !inheritDefault {
		// NOINHERIT prevents the role from automatically using privileges granted to roles it is a member of (e.g. PUBLIC).
		roleOptions += " NOINHERIT"
	}

	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	createRoleSQL := fmt.Sprintf("CREATE ROLE %s WITH %s PASSWORD %s", quotedRole, roleOptions, quotedPassword)
	if _, err := tx.ExecContext(ctx, createRoleSQL); err != nil {
		return nil, fmt.Errorf("error creating role %s: %w", roleName, err)
	}

	createSchemaSQL := fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", quotedSchema, quotedRole)
	if _, err := tx.ExecContext(ctx, createSchemaSQL); err != nil {
		return nil, fmt.Errorf("error creating schema %s: %w", schemaName, err)
	}

	grantSQL := fmt.Sprintf("GRANT ALL ON SCHEMA %s TO %s", quotedSchema, quotedRole)
	if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
		return nil, fmt.Errorf("error granting privileges on schema %s: %w", schemaName, err)
	}

	setSearchPathSQL := fmt.Sprintf("ALTER ROLE %s SET search_path = %s", quotedRole, quotedSchema)
	if _, err := tx.ExecContext(ctx, setSearchPathSQL); err != nil {
		return nil, fmt.Errorf("error setting search_path on role %s: %w", roleName, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("error committing account creation: %w", err)
	}

	accountURL, err := buildAccountURL(b.serviceConfig["url"], roleName, password, schemaName)
	if err != nil {
		return nil, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":    accountURL,
		"schema": schemaName,
		"role":   roleName,
	}, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// quoteLiteral quotes a string for safe use as a SQL string literal.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// buildAccountURL constructs a new postgres URL using the admin URL's host/port/database
// but with the supplied user, password and a search_path set to the new schema.
func buildAccountURL(adminURL, user, password, schema string) (string, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)

	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
