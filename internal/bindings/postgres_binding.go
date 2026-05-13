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
	binding       *types.Binding
	baseBinding   *types.Binding
	grants        []string

	adminConn *sql.DB // The admin connection to the main database, available after InitService
}

func init() {
	RegisterServiceBinding("postgres", NewPostgresServiceBinding)
}

var _ ServiceBinding = (*PostgresServiceBinding)(nil)

func NewPostgresServiceBinding() ServiceBinding {
	return &PostgresServiceBinding{}
}

func (b *PostgresServiceBinding) InitService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string) error {
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

func (b *PostgresServiceBinding) InitBinding(ctx context.Context, binding *types.Binding, baseBinding *types.Binding, grants []string) error {
	if err := verifyKeys(slices.Collect(maps.Keys(binding.StagedMetadata.Config)), []string{}, []string{"inherit_default"}); err != nil {
		return err
	}

	b.grants = grants
	b.binding = binding
	b.baseBinding = baseBinding
	return nil
}

func (b *PostgresServiceBinding) GenerateAccount(ctx context.Context, bindingConfig map[string]string, isStaging bool) (map[string]string, []string, error) {
	inheritDefault := true
	var err error

	inheritDefaultStr, ok := bindingConfig["inherit_default"]
	if ok {
		inheritDefault, err = strconv.ParseBool(inheritDefaultStr)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing inherit_default: %w", err)
		}
	}

	// Create a new schema, create a login role and grant full access on the schema for that role.
	password, err := randomHex(32)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}
	modePrefix := "prd_"
	if isStaging {
		modePrefix = "stg_"
	}

	schemaName := "cl_sch_" + modePrefix + b.binding.Id
	roleName := "cl_rol_" + modePrefix + b.binding.Id
	baseRoleName := ""
	if b.baseBinding != nil {
		// Derived binding, use the base binding's schema
		if isStaging {
			schemaName = b.baseBinding.StagedMetadata.Account["schema"]
			baseRoleName = b.baseBinding.StagedMetadata.Account["role"]

		} else {
			schemaName = b.baseBinding.Metadata.Account["schema"]
			baseRoleName = b.baseBinding.Metadata.Account["role"]
		}
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
		return nil, nil, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	createRoleSQL := fmt.Sprintf("CREATE ROLE %s WITH %s PASSWORD %s", quotedRole, roleOptions, quotedPassword)
	if _, err := tx.ExecContext(ctx, createRoleSQL); err != nil {
		return nil, nil, fmt.Errorf("error creating role %s: %w", roleName, err)
	}

	grantsProcessed := []string{}
	if b.baseBinding == nil {
		// Base binding, create a new schema
		createSchemaSQL := fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, createSchemaSQL); err != nil {
			return nil, nil, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}

		grantSQL := fmt.Sprintf("GRANT ALL ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
			return nil, nil, fmt.Errorf("error granting privileges on schema %s: %w", schemaName, err)
		}
	} else {
		grantUsageSQL := fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantUsageSQL); err != nil {
			return nil, nil, fmt.Errorf("error granting usage privileges on schema %s: %w", schemaName, err)
		}

		// Setup the grants
		grantsProcessed, err = b.processGrants(ctx, tx, roleName, schemaName, b.grants, baseRoleName)
		if err != nil {
			return nil, nil, fmt.Errorf("error processing grants: %w", err)
		}
	}

	setSearchPathSQL := fmt.Sprintf("ALTER ROLE %s SET search_path = %s", quotedRole, quotedSchema)
	if _, err := tx.ExecContext(ctx, setSearchPathSQL); err != nil {
		return nil, nil, fmt.Errorf("error setting search_path on role %s: %w", roleName, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("error committing account creation: %w", err)
	}

	accountURL, err := buildAccountURL(b.serviceConfig["url"], roleName, password, schemaName)
	if err != nil {
		return nil, nil, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":    accountURL,
		"schema": schemaName,
		"role":   roleName,
	}, grantsProcessed, nil
}

func (b *PostgresServiceBinding) processGrants(ctx context.Context, tx *sql.Tx, role, schema string, grants []string, baseRoleName string) ([]string, error) {
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	quotedRole := pgx.Identifier{role}.Sanitize()
	quotedBaseRole := pgx.Identifier{baseRoleName}.Sanitize()

	grantsProcessed := []string{}
	for i, grant := range grants {
		grantType, grantTarget, err := parseGrant(grant, []GrantType{GrantTypeRead, GrantTypeCreate, GrantTypeFull})
		if err != nil {
			return nil, fmt.Errorf("error parsing grant: %w", err)
		}

		switch grantType {
		case GrantTypeRead:
			if grantTarget == GrantTargetAll {
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
				quotedTableName := pgx.Identifier{schema, grantTarget}.Sanitize()
				grantSQL := fmt.Sprintf("GRANT SELECT ON TABLE %s TO %s", quotedTableName, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(i), grantSQL)
				if err != nil {
					return nil, fmt.Errorf("error granting select privileges on table %s.%s: %w", schema, grantTarget, err)
				}
				if applied {
					grantsProcessed = append(grantsProcessed, grant)
				} else {
					b.Warn().Str("grant", grant).Str("schema", schema).Str("table", grantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				}
			}

		case GrantTypeCreate:
			if grantTarget != "" && grantTarget != GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			// Create grant on all tables in the schema
			grantSQL := fmt.Sprintf("GRANT CREATE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
			if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
				return nil, fmt.Errorf("error granting create privileges on all tables in schema %s: %w", schema, err)
			}

			grantsProcessed = append(grantsProcessed, grant)
		case GrantTypeFull:
			if grantTarget == GrantTargetAll {
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
				quotedTableName := pgx.Identifier{schema, grantTarget}.Sanitize()
				grantSQL := fmt.Sprintf("GRANT ALL ON TABLE %s TO %s", quotedTableName, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(i), grantSQL)
				if err != nil {
					return nil, fmt.Errorf("error granting full privileges on table %s.%s: %w", schema, grantTarget, err)
				}
				if applied {
					grantsProcessed = append(grantsProcessed, grant)
				} else {
					b.Warn().Str("grant", grant).Str("schema", schema).Str("table", grantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				}
			}
		}
	}
	b.Debug().Strs("grants_processed", grantsProcessed).Msg("processed grants")
	return grantsProcessed, nil
}

// savepointName returns a unique savepoint identifier for the i-th grant in a
// processGrants loop. Postgres savepoint names are simple identifiers; we keep
// them short and ASCII-only.
func savepointName(i int) string {
	return fmt.Sprintf("grant_sp_%d", i)
}

// trySoftGrant runs a single GRANT-like statement inside a SAVEPOINT so that a
// "relation does not exist" error (42P01) does not poison the surrounding
// transaction. It returns (applied, err):
//   - applied=true, err=nil:  the statement succeeded and is committed within
//     the outer transaction.
//   - applied=false, err=nil: the target table does not exist yet; the grant
//     should be retried later (e.g. via reconcile) after the base binding
//     creates the table. The outer transaction is left in a clean state.
//   - applied=false, err!=nil: a real error occurred. The caller should treat
//     this as fatal for the binding operation; the outer transaction is
//     already aborted by Postgres at this point and must be rolled back.
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
