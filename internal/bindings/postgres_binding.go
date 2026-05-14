// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/openrundev/openrun/internal/types"
)

// pgUndefinedTable is the SQLSTATE code returned by Postgres when a relation
// referenced in a statement does not exist (42P01 "relation does not exist").
const pgUndefinedTable = "42P01"

// isUndefinedTable reports whether err is a Postgres "relation does not exist"
// error. This is used to detect grants targeting a table that has not yet been
// created by the base binding's role, so the grant can be deferred.
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable
}

type PostgresServiceBinding struct {
	*types.Logger
	serviceConfig map[string]string
	adminConn     *sql.DB // The admin connection to the main database, available after InitService
}

func init() {
	RegisterServiceBinding("postgres", NewPostgresServiceBinding)
}

var _ ServiceBinding = (*PostgresServiceBinding)(nil)

func NewPostgresServiceBinding() ServiceBinding {
	return &PostgresServiceBinding{}
}

func (b *PostgresServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string) error {
	b.Logger = logger
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

func (b *PostgresServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata, derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, error) {
	inheritDefault := true
	var err error

	inheritDefaultStr, ok := bindingMetadata.Config["inherit_default"]
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
	if derivedFromMetadata != nil {
		// Derived binding, use the base binding's schema
		schemaName = derivedFromMetadata.Account["schema"]
	}

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

	if derivedFromMetadata == nil {
		// Base binding, create a new schema
		createSchemaSQL := fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, createSchemaSQL); err != nil {
			return nil, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}

		grantSQL := fmt.Sprintf("GRANT ALL ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
			return nil, fmt.Errorf("error granting privileges on schema %s: %w", schemaName, err)
		}
	} else {
		// Derived binding, grant usage on the base binding's schema
		grantUsageSQL := fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantUsageSQL); err != nil {
			return nil, fmt.Errorf("error granting usage privileges on schema %s: %w", schemaName, err)
		}
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

func (b *PostgresServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata types.BindingMetadata, derivedFromMetadata types.BindingMetadata) ([]types.BindingGrant, error) {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{"inherit_default"}); err != nil {
		return nil, err
	}

	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	grantsProcessed, err := b.processGrants(ctx, tx, account["role"], account["schema"], derivedFromMetadata.Account["role"], bindingMetadata.Grants)
	if err != nil {
		return nil, fmt.Errorf("error processing grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("error committing grants: %w", err)
	}

	return grantsProcessed, nil
}

func (b *PostgresServiceBinding) processGrants(ctx context.Context, tx *sql.Tx, role, schema string, baseRoleName string, grants []string) ([]types.BindingGrant, error) {
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	quotedRole := pgx.Identifier{role}.Sanitize()
	quotedBaseRole := pgx.Identifier{baseRoleName}.Sanitize()

	grantsProcessed := []types.BindingGrant{}
	for i, g := range grants {
		grant, err := types.ParseGrant(g, []types.GrantType{types.GrantTypeRead, types.GrantTypeCreate, types.GrantTypeFull})
		if err != nil {
			return nil, fmt.Errorf("error parsing grant: %w", err)
		}

		switch grant.GrantType {
		case types.GrantTypeRead:
			if grant.GrantTarget == types.GrantTargetAll {
				// Read grant on all tables in the schema
				grantSQL := fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s", quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
					return nil, fmt.Errorf("error granting select privileges on all tables in schema %s: %w", schema, err)
				}

				// grant select on any tables created later by the base role using DEFAULT PRIVILEGES
				grantDefaultSQL := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT SELECT ON TABLES TO %s", quotedBaseRole, quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantDefaultSQL); err != nil {
					return nil, fmt.Errorf("error granting default select privileges on all tables in schema %s: %w", schema, err)
				}
				grantsProcessed = append(grantsProcessed, grant)
			} else {
				// Read grant on specific table. Wrapped in a SAVEPOINT so that a
				// missing-table error does not abort the outer transaction.
				quotedTableName := pgx.Identifier{schema, grant.GrantTarget}.Sanitize()
				grantSQL := fmt.Sprintf("GRANT SELECT ON TABLE %s TO %s", quotedTableName, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(i), grantSQL)
				if err != nil {
					return nil, fmt.Errorf("error granting select privileges on table %s.%s: %w", schema, grant.GrantTarget, err)
				}
				if applied {
					grantsProcessed = append(grantsProcessed, grant)
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				}
			}

		case types.GrantTypeCreate:
			if grant.GrantTarget != "" && grant.GrantTarget != types.GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			// Create grant on all tables in the schema
			grantSQL := fmt.Sprintf("GRANT CREATE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
			if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
				return nil, fmt.Errorf("error granting create privileges on all tables in schema %s: %w", schema, err)
			}

			grantsProcessed = append(grantsProcessed, grant)
		case types.GrantTypeFull:
			if grant.GrantTarget == types.GrantTargetAll {
				// Full grant on all tables in the schema
				grantSQL := fmt.Sprintf("GRANT ALL ON ALL TABLES IN SCHEMA %s TO %s", quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
					return nil, fmt.Errorf("error granting full privileges on all tables in schema %s: %w", schema, err)
				}

				// grant access to all sequences in the schema
				grantSequenceSQL := fmt.Sprintf("GRANT ALL ON ALL SEQUENCES IN SCHEMA %s TO %s", quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantSequenceSQL); err != nil {
					return nil, fmt.Errorf("error granting full privileges on all sequences in schema %s: %w", schema, err)
				}

				// Grant create on schema
				grantCreateSQL := fmt.Sprintf("GRANT CREATE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantCreateSQL); err != nil {
					return nil, fmt.Errorf("error granting create privileges on table and sequence in schema %s: %w", schema, err)
				}

				// grant full privileges on any tables created later by the base role using DEFAULT PRIVILEGES
				grantDefaultSQL := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT ALL ON TABLES TO %s", quotedBaseRole, quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantDefaultSQL); err != nil {
					return nil, fmt.Errorf("error granting default full privileges on all tables in schema %s: %w", schema, err)
				}

				// grant full privileges on any sequences created later by the base role using DEFAULT PRIVILEGES
				grantDefaultSeqSQL := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT ALL ON SEQUENCES TO %s", quotedBaseRole, quotedSchema, quotedRole)
				if _, err := tx.ExecContext(ctx, grantDefaultSeqSQL); err != nil {
					return nil, fmt.Errorf("error granting default full privileges on all sequences in schema %s: %w", schema, err)
				}
				grantsProcessed = append(grantsProcessed, grant)
			} else {
				// Full grant on a specific table. Wrapped in a SAVEPOINT so that a
				// missing-table error does not abort the outer transaction.
				quotedTableName := pgx.Identifier{schema, grant.GrantTarget}.Sanitize()
				grantSQL := fmt.Sprintf("GRANT ALL ON TABLE %s TO %s", quotedTableName, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(i), grantSQL)
				if err != nil {
					return nil, fmt.Errorf("error granting full privileges on table %s.%s: %w", schema, grant.GrantTarget, err)
				}
				if applied {
					grantsProcessed = append(grantsProcessed, grant)
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				}
			}
		}
	}
	b.Debug().Msgf("processed grants %v", grantsProcessed)
	return grantsProcessed, nil
}

func savepointName(i int) string {
	return fmt.Sprintf("grant_sp_%d", i)
}

// trySoftGrant runs a single GRANT-like statement inside a SAVEPOINT so that a
// "relation does not exist" error (42P01) does not poison the surrounding
// transaction.
func (b *PostgresServiceBinding) trySoftGrant(ctx context.Context, tx *sql.Tx, name, stmt string) (bool, error) {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return false, fmt.Errorf("error creating savepoint %s: %w", name, err)
	}

	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		if !isUndefinedTable(err) {
			// Real error: the outer transaction is now aborted by Postgres.
			// Surface the original error so callers can bail out cleanly.
			return false, err
		}

		// Target relation does not exist yet. Undo the failed statement so the
		// outer transaction can continue, then release the savepoint to keep
		// the savepoint stack bounded for callers running many grants.
		if _, rerr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rerr != nil {
			return false, fmt.Errorf("error rolling back to savepoint %s after %w: %w", name, err, rerr)
		}
		if _, rerr := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name); rerr != nil {
			return false, fmt.Errorf("error releasing savepoint %s after rollback: %w", name, rerr)
		}
		return false, nil
	}

	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name); err != nil {
		return false, fmt.Errorf("error releasing savepoint %s: %w", name, err)
	}
	return true, nil
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
