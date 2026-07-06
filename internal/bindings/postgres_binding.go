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

func (b *PostgresServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	b.Logger = logger
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{"binding_hostname"}); err != nil {
		return err
	}

	connURL := serviceConfig["url"]
	adminConn, err := sql.Open("pgx", connURL)
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}

	if err := adminConn.PingContext(ctx); err != nil {
		adminConn.Close() //nolint:errcheck
		return fmt.Errorf("error verifying postgres connection: %w", err)
	}

	b.serviceConfig = serviceConfigWithLocalhostBindingHostname(serviceConfig, connURL, runtime)
	b.adminConn = adminConn
	return nil
}

func (b *PostgresServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

func (b *PostgresServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata, derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	inheritDefault := true
	var err error

	inheritDefaultStr, ok := bindingMetadata.Config["inherit_default"]
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

	// All the statements run in a single transaction so a partial failure leaves no
	// artifacts behind; no artifacts are reported as created on error.
	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	createRoleSQL := fmt.Sprintf("CREATE ROLE %s WITH %s PASSWORD %s", quotedRole, roleOptions, quotedPassword)
	if _, err := tx.ExecContext(ctx, createRoleSQL); err != nil {
		return nil, nil, fmt.Errorf("error creating role %s: %w", roleName, err)
	}
	artifacts := []Artifact{{Type: ArtifactRole, Name: roleName}}

	if derivedFromMetadata == nil {
		// Base binding, create a new schema
		createSchemaSQL := fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, createSchemaSQL); err != nil {
			return nil, nil, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}
		artifacts = append(artifacts, Artifact{Type: ArtifactSchema, Name: schemaName})

		grantSQL := fmt.Sprintf("GRANT ALL ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantSQL); err != nil {
			return nil, nil, fmt.Errorf("error granting privileges on schema %s: %w", schemaName, err)
		}
	} else {
		// Derived binding, grant usage on the base binding's schema. The schema belongs
		// to the base binding and is not reported as a created artifact.
		grantUsageSQL := fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", quotedSchema, quotedRole)
		if _, err := tx.ExecContext(ctx, grantUsageSQL); err != nil {
			return nil, nil, fmt.Errorf("error granting usage privileges on schema %s: %w", schemaName, err)
		}
	}

	setSearchPathSQL := fmt.Sprintf("ALTER ROLE %s SET search_path = %s", quotedRole, quotedSchema)
	if _, err := tx.ExecContext(ctx, setSearchPathSQL); err != nil {
		return nil, nil, fmt.Errorf("error setting search_path on role %s: %w", roleName, err)
	}

	accountDirectURL, err := buildAccountURL(b.serviceConfig["url"], roleName, password, "")
	if err != nil {
		return nil, nil, fmt.Errorf("error building account url: %w", err)
	}
	accountURL, err := buildAccountURL(b.serviceConfig["url"], roleName, password, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, nil, fmt.Errorf("error building binding account url: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("error committing transaction: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"schema":     schemaName,
		"role":       roleName,
	}, artifacts, nil
}

// DeleteArtifact drops one role or schema previously reported as created by
// GenerateAccount. The caller only passes back artifacts created during the current
// operation, so a newly created role cannot own pre-existing objects and a schema
// drop only removes objects created since the schema itself was created.
func (b *PostgresServiceBinding) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	switch artifact.Type {
	case ArtifactSchema:
		quotedSchema := pgx.Identifier{artifact.Name}.Sanitize()
		if _, err := tx.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
			return fmt.Errorf("error dropping schema %s: %w", artifact.Name, err)
		}
	case ArtifactRole:
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", artifact.Name).Scan(&exists); err != nil {
			return fmt.Errorf("error checking role %s: %w", artifact.Name, err)
		}
		if !exists {
			return nil
		}
		quotedRole := pgx.Identifier{artifact.Name}.Sanitize()
		// DROP OWNED clears all the dependencies on the role so it can be dropped: it
		// drops any objects the role created and revokes the privileges (including
		// default privileges) granted to it.
		if _, err := tx.ExecContext(ctx, "DROP OWNED BY "+quotedRole+" CASCADE"); err != nil {
			return fmt.Errorf("error dropping objects owned by role %s: %w", artifact.Name, err)
		}
		if _, err := tx.ExecContext(ctx, "DROP ROLE "+quotedRole); err != nil {
			return fmt.Errorf("error dropping role %s: %w", artifact.Name, err)
		}
	default:
		return fmt.Errorf("unsupported postgres artifact type %s", artifact.Type)
	}
	return tx.Commit()
}

func (b *PostgresServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata types.BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{"inherit_default"}); err != nil {
		return GrantApplyResult{}, err
	}

	// The grant statements run in a single transaction (also needed for the savepoint
	// handling of missing tables) and are committed before returning.
	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := b.processGrants(ctx, tx, account["role"], account["schema"], derivedFromMetadata.Account["role"], bindingMetadata, reapplyAll)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error processing grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return GrantApplyResult{}, fmt.Errorf("error committing transaction: %w", err)
	}
	return result, nil
}

func (b *PostgresServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata types.BindingMetadata, revokes, regrants []types.BindingGrant) error {
	if len(revokes) == 0 {
		return nil
	}

	tx, err := b.adminConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	schema := account["schema"]
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	quotedRole := pgx.Identifier{account["role"]}.Sanitize()
	quotedBaseRole := pgx.Identifier{derivedFromMetadata.Account["role"]}.Sanitize()

	if _, err := b.applyPerms(ctx, tx, "revoke", revokes, quotedSchema, quotedRole, schema, quotedBaseRole); err != nil {
		return fmt.Errorf("error revoking grants: %w", err)
	}

	// Re-apply the grants that must remain: an overlapping revoke removes privileges
	// the remaining grants still need (e.g. revoking read:t1 while read:* remains).
	// Running the revokes and regrants in one transaction means concurrent sessions
	// never observe the intermediate revoked state.
	if _, err := b.applyPerms(ctx, tx, "grant", regrants, quotedSchema, quotedRole, schema, quotedBaseRole); err != nil {
		return fmt.Errorf("error re-applying remaining grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}
	return nil
}

func (b *PostgresServiceBinding) processGrants(ctx context.Context, tx *sql.Tx, role, schema string,
	baseRoleName string, bindingMetadata types.BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	quotedRole := pgx.Identifier{role}.Sanitize()
	quotedBaseRole := pgx.Identifier{baseRoleName}.Sanitize()

	bindingGrants, err := parseGrants(bindingMetadata.Grants, []types.GrantType{types.GrantTypeRead, types.GrantTypeCreate, types.GrantTypeFull})
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error parsing grants: %w", err)
	}

	// Grants no longer desired are only computed here; the caller revokes them
	// after its metadata transaction commits.
	revokedGrants, applyGrants := diffGrants(bindingMetadata.GrantsApplied, bindingGrants)
	if reapplyAll {
		applyGrants = bindingGrants // Apply all grants, can help when new tables are present which need to be granted to the role
	}

	grantsProcessed, err := b.applyPerms(ctx, tx, "grant", applyGrants, quotedSchema, quotedRole, schema, quotedBaseRole)
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error applying new grants: %w", err)
	}
	b.Debug().Msgf("processed grants %v", grantsProcessed)

	grantsApplied := unionGrants(bindingMetadata.GrantsApplied, grantsProcessed)
	if reapplyAll {
		// Drop applied entries whose grant could not be re-executed (e.g. the
		// table was dropped), so they are retried once the target exists again.
		// The pending revokes stay listed until the caller executes them.
		grantsApplied = unionGrants(grantsProcessed, revokedGrants)
	}
	return GrantApplyResult{
		GrantsApplied:  grantsApplied,
		Granted:        subtractGrants(grantsProcessed, bindingMetadata.GrantsApplied),
		PendingRevokes: revokedGrants,
	}, nil
}

// applyPerms runs GRANT or REVOKE statements for binding grants.
// operation must be "grant" or "revoke".
func (b *PostgresServiceBinding) applyPerms(ctx context.Context, tx *sql.Tx, operation string,
	grants []types.BindingGrant, quotedSchema string, quotedRole string, schema string, quotedBaseRole string) ([]types.BindingGrant, error) {
	var isGrant bool
	switch operation {
	case "grant":
		isGrant = true
	case "revoke":
		isGrant = false
	default:
		return nil, fmt.Errorf("invalid grant operation %q: want %q or %q", operation, "grant", "revoke")
	}
	grantOrRevoke := "REVOKE"
	toOrFrom := "FROM"
	verb := "revoking"
	if isGrant {
		grantOrRevoke = "GRANT"
		toOrFrom = "TO"
		verb = "granting"
	}

	grantsDone := []types.BindingGrant{}
	for i, grant := range grants {
		switch grant.GrantType {
		case types.GrantTypeRead:
			if grant.GrantTarget == types.GrantTargetAll {
				stmt := fmt.Sprintf("%s SELECT ON ALL TABLES IN SCHEMA %s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s select privileges on all tables in schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s %s SELECT ON TABLES %s %s", quotedBaseRole, quotedSchema, grantOrRevoke, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s default select privileges on all tables in schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				quotedTableName := pgx.Identifier{schema, grant.GrantTarget}.Sanitize()
				stmt := fmt.Sprintf("%s SELECT ON TABLE %s %s %s", grantOrRevoke, quotedTableName, toOrFrom, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(operation, i), stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s select privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}

		case types.GrantTypeCreate:
			if isGrant && grant.GrantTarget != "" && grant.GrantTarget != types.GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			stmt := fmt.Sprintf("%s CREATE ON SCHEMA %s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedRole)
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("error %s create privileges on schema %s: %w", verb, schema, err)
			}
			grantsDone = append(grantsDone, grant)

		case types.GrantTypeFull:
			if grant.GrantTarget == types.GrantTargetAll {
				stmt := fmt.Sprintf("%s ALL ON ALL TABLES IN SCHEMA %s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s full privileges on all tables in schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("%s ALL ON ALL SEQUENCES IN SCHEMA %s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s full privileges on all sequences in schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("%s CREATE ON SCHEMA %s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s create privileges on schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s %s ALL ON TABLES %s %s", quotedBaseRole, quotedSchema, grantOrRevoke, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s default full privileges on all tables in schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s %s ALL ON SEQUENCES %s %s", quotedBaseRole, quotedSchema, grantOrRevoke, toOrFrom, quotedRole)
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s default full privileges on all sequences in schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				quotedTableName := pgx.Identifier{schema, grant.GrantTarget}.Sanitize()
				stmt := fmt.Sprintf("%s ALL ON TABLE %s %s %s", grantOrRevoke, quotedTableName, toOrFrom, quotedRole)
				applied, err := b.trySoftGrant(ctx, tx, savepointName(operation, i), stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s full privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}
		}
	}
	return grantsDone, nil
}

func savepointName(prefix string, i int) string {
	return fmt.Sprintf("%s_sp_%d", prefix, i)
}

// trySoftGrant runs a single GRANT or REVOKE statement inside a SAVEPOINT so that a
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
// but with the supplied user and password.
func buildAccountURL(adminURL, user, password, bindingHostname string) (string, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)
	setURLHostname(u, bindingHostname)
	return u.String(), nil
}

func (b *PostgresServiceBinding) RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error) {
	conn, err := pgx.Connect(ctx, bindingMetadata.Account["url_direct"])
	if err != nil {
		return nil, fmt.Errorf("error opening connection: %w", err)
	}
	defer conn.Close(ctx) //nolint:errcheck

	rows, err := conn.Query(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("error executing command: %w", err)
	}
	defer rows.Close()

	fieldDescriptions := rows.FieldDescriptions()
	columns := make([]string, len(fieldDescriptions))
	for i, fieldDescription := range fieldDescriptions {
		columns[i] = string(fieldDescription.Name)
	}

	resultRows := make([]map[string]any, 0)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, fmt.Errorf("error reading command result row: %w", err)
		}

		resultRow := make(map[string]any, len(columns))
		for i, column := range columns {
			resultRow[column] = values[i]
		}
		resultRows = append(resultRows, resultRow)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading command result: %w", err)
	}
	rows.Close()

	commandTag := rows.CommandTag()
	return map[string]any{
		"columns":       columns,
		"rows":          resultRows,
		"rows_affected": commandTag.RowsAffected(),
		"command_tag":   commandTag.String(),
	}, nil
}
