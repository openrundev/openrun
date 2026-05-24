// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/openrundev/openrun/internal/types"
)

// mysqlErrNoSuchTable is the MySQL error number for ER_NO_SUCH_TABLE
// (returned when a table referenced in a statement does not exist).
const mysqlErrNoSuchTable = 1146

// mysqlErrNonExistingGrant is the MySQL error number for
// ER_NONEXISTING_TABLE_GRANT (returned by REVOKE when no matching grant
// exists for the user on the table).
const mysqlErrNonExistingGrant = 1147

// MySQL identifier length limits (8.0):
//   - user name: 32 characters
//   - database name: 64 characters
//
// A bindingId is `bnd_` + 27-char ksuid = 31 chars, which already exceeds
// the user limit when any prefix is added. We strip the `bnd_` prefix from
// the binding id when forming the user name to stay within the 32-char
// budget: `cl_p_` (5) + ksuid (27) = 32.
const (
	mysqlUserPrefixProd = "cl_p_"
	mysqlUserPrefixStg  = "cl_s_"
	mysqlDBPrefixProd   = "cl_db_prd_"
	mysqlDBPrefixStg    = "cl_db_stg_"
	mysqlBindingIDTrim  = "bnd_"
	mysqlDefaultHost    = "%"

	// Privileges granted/revoked for `full:*` and `full:tbl`. Chosen to mirror
	// Postgres' `full` semantics (ALL ON TABLES = SELECT/INSERT/UPDATE/DELETE/
	// TRUNCATE/REFERENCES/TRIGGER, plus the schema-level CREATE family) while
	// deliberately *not* using `ALL PRIVILEGES`: that would also revoke the
	// SHOW VIEW baseline granted in GenerateAccount, breaking the account's
	// ability to connect to its default database after a `full:*` revoke.
	//
	// Intentionally excluded:
	//   - GRANT OPTION (matches Postgres binding policy)
	//   - SHOW VIEW (reserved as the connect-time baseline; see GenerateAccount)
	//   - CREATE/ALTER ROUTINE, EXECUTE, EVENT (stored procs and scheduled
	//     events are out of scope for v1; users can grant them via custom SQL)
	//
	// Table-scoped GRANTs cannot include the database-only privileges
	// (CREATE TEMPORARY TABLES, LOCK TABLES) — MySQL rejects them at the
	// table level. mysqlFullPrivilegesTable is the safe subset for `full:tbl`.
	mysqlFullPrivilegesDB    = "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, TRIGGER, CREATE VIEW, CREATE TEMPORARY TABLES, LOCK TABLES"
	mysqlFullPrivilegesTable = "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, TRIGGER, CREATE VIEW"
)

// isMysqlErrNo reports whether err is a MySQL error with the given numeric code.
func isMysqlErrNo(err error, code uint16) bool {
	var mErr *mysql.MySQLError
	return errors.As(err, &mErr) && mErr.Number == code
}

type MysqlServiceBinding struct {
	*types.Logger
	serviceConfig map[string]string
	hostPattern   string  // The @host part used when creating users (default '%')
	adminConn     *sql.DB // Admin connection to the MySQL server, available after InitService
}

func init() {
	RegisterServiceBinding("mysql", NewMysqlServiceBinding)
}

var _ ServiceBinding = (*MysqlServiceBinding)(nil)

func NewMysqlServiceBinding() ServiceBinding {
	return &MysqlServiceBinding{}
}

func (b *MysqlServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string) error {
	b.Logger = logger
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{"host_pattern"}); err != nil {
		return err
	}

	hostPattern := serviceConfig["host_pattern"]
	if hostPattern == "" {
		hostPattern = mysqlDefaultHost
	}

	dsn, err := mysqlURLToDSN(serviceConfig["url"], "")
	if err != nil {
		return fmt.Errorf("error parsing mysql url: %w", err)
	}

	adminConn, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}

	if err := adminConn.PingContext(ctx); err != nil {
		adminConn.Close() //nolint:errcheck
		return fmt.Errorf("error verifying mysql connection: %w", err)
	}

	b.serviceConfig = serviceConfig
	b.hostPattern = hostPattern
	b.adminConn = adminConn
	return nil
}

func (b *MysqlServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

type MysqlContextKey string

const MYSQL_TX_STATE_KEY MysqlContextKey = "mysql_sb_tx_state"

// mysqlTxState tracks objects created during a logical "transaction" so they
// can be cleaned up on rollback. MySQL DDL auto-commits, so the binding
// interface's transaction methods cannot give us true atomicity; instead we
// record compensating actions and run them if RollbackTransaction is called
// without a matching CommitTransaction.
type mysqlTxState struct {
	createdUsers     []string // user identities in form `'name'@'host'` (already SQL-quoted)
	createdDatabases []string // database identifiers (already backtick-quoted)
	committed        bool
}

func (b *MysqlServiceBinding) BeginTransaction(ctx context.Context) (context.Context, error) {
	// MySQL DDL (CREATE USER, GRANT, CREATE DATABASE, ...) implicitly commits
	// any open transaction, so we cannot use sql.Tx for atomicity. Stash a
	// tracker in the context so RollbackTransaction can issue compensating
	// DROP statements for anything we created in this logical transaction.
	return context.WithValue(ctx, MYSQL_TX_STATE_KEY, &mysqlTxState{}), nil
}

func (b *MysqlServiceBinding) CommitTransaction(ctx context.Context) error {
	state, ok := ctx.Value(MYSQL_TX_STATE_KEY).(*mysqlTxState)
	if !ok {
		return fmt.Errorf("transaction state not found in context")
	}
	state.committed = true
	return nil
}

func (b *MysqlServiceBinding) RollbackTransaction(ctx context.Context) error {
	state, ok := ctx.Value(MYSQL_TX_STATE_KEY).(*mysqlTxState)
	if !ok {
		return fmt.Errorf("transaction state not found in context")
	}
	if state.committed {
		// Commit already ran — nothing to undo.
		return nil
	}

	// Best-effort cleanup. We use a fresh context.Background() so that
	// cancellation of the outer context does not abort the cleanup. Failures
	// are logged but not propagated; an operator may need to clean up
	// manually if a DROP also fails.
	cleanupCtx := context.Background()
	for i := len(state.createdUsers) - 1; i >= 0; i-- {
		stmt := "DROP USER IF EXISTS " + state.createdUsers[i]
		if _, err := b.adminConn.ExecContext(cleanupCtx, stmt); err != nil {
			b.Warn().Err(err).Str("user", state.createdUsers[i]).Msg("error dropping user during mysql binding rollback")
		}
	}
	for i := len(state.createdDatabases) - 1; i >= 0; i-- {
		stmt := "DROP DATABASE IF EXISTS " + state.createdDatabases[i]
		if _, err := b.adminConn.ExecContext(cleanupCtx, stmt); err != nil {
			b.Warn().Err(err).Str("database", state.createdDatabases[i]).Msg("error dropping database during mysql binding rollback")
		}
	}
	return nil
}

func (b *MysqlServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata, derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, error) {
	state, ok := ctx.Value(MYSQL_TX_STATE_KEY).(*mysqlTxState)
	if !ok {
		return nil, fmt.Errorf("transaction state not found in context")
	}

	password, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("error generating random password: %w", err)
	}

	userPrefix := mysqlUserPrefixProd
	dbPrefix := mysqlDBPrefixProd
	if isStaging {
		userPrefix = mysqlUserPrefixStg
		dbPrefix = mysqlDBPrefixStg
	}

	idCore := strings.TrimPrefix(bindingId, mysqlBindingIDTrim)
	userName := userPrefix + idCore
	databaseName := dbPrefix + bindingId
	if derivedFromMetadata != nil {
		// Derived binding, reuse the base binding's database
		databaseName = derivedFromMetadata.Account["database"]
		if databaseName == "" {
			return nil, fmt.Errorf("derived binding base account is missing the database field")
		}
	}

	if len(userName) > 32 {
		return nil, fmt.Errorf("computed mysql user name %q exceeds the 32-char identifier limit", userName)
	}
	if len(databaseName) > 64 {
		return nil, fmt.Errorf("computed mysql database name %q exceeds the 64-char identifier limit", databaseName)
	}

	host := b.hostPattern
	userRef := mysqlUserRef(userName, host)
	quotedDB := quoteMysqlIdent(databaseName)
	quotedPassword := quoteMysqlString(password)

	if derivedFromMetadata == nil {
		// Base binding: create database, then user, then grant ALL on the database.
		createDBSQL := fmt.Sprintf("CREATE DATABASE %s", quotedDB)
		if _, err := b.adminConn.ExecContext(ctx, createDBSQL); err != nil {
			return nil, fmt.Errorf("error creating database %s: %w", databaseName, err)
		}
		state.createdDatabases = append(state.createdDatabases, quotedDB)

		createUserSQL := fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s", userRef, quotedPassword)
		if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
			return nil, fmt.Errorf("error creating user %s: %w", userName, err)
		}
		state.createdUsers = append(state.createdUsers, userRef)

		// ALL on the new database. A database-level grant in MySQL covers
		// every current and future table in that database, so this is also
		// how the base user owns objects later created by derived bindings.
		grantSQL := fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s", quotedDB, userRef)
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, fmt.Errorf("error granting privileges on database %s: %w", databaseName, err)
		}
	} else {
		// Derived binding: create the user in the base binding's database.
		// Application privileges are still assigned only by ApplyGrants.
		createUserSQL := fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s", userRef, quotedPassword)
		if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
			return nil, fmt.Errorf("error creating user %s: %w", userName, err)
		}
		state.createdUsers = append(state.createdUsers, userRef)

		// Let the derived account select the database so negative permission
		// checks fail on the intended table/DDL privilege instead of during
		// connection setup. MySQL USAGE is not enough to pass the default
		// database access check, so use SHOW VIEW as a minimal database-level
		// privilege and keep full:* grants from revoking it.
		grantUsageSQL := fmt.Sprintf("GRANT SHOW VIEW ON %s.* TO %s", quotedDB, userRef)
		if _, err := b.adminConn.ExecContext(ctx, grantUsageSQL); err != nil {
			return nil, fmt.Errorf("error granting baseline privileges on database %s: %w", databaseName, err)
		}
	}

	accountURL, err := buildMysqlAccountURL(b.serviceConfig["url"], userName, password, databaseName)
	if err != nil {
		return nil, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":      accountURL,
		"database": databaseName,
		"user":     userName,
		"host":     host,
	}, nil
}

func (b *MysqlServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata types.BindingMetadata, reapplyAll bool) ([]types.BindingGrant, error) {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return nil, err
	}

	if _, ok := ctx.Value(MYSQL_TX_STATE_KEY).(*mysqlTxState); !ok {
		return nil, fmt.Errorf("transaction state not found in context")
	}

	grantsProcessed, err := b.processGrants(ctx, account["user"], account["host"], account["database"], bindingMetadata, reapplyAll)
	if err != nil {
		return nil, fmt.Errorf("error processing grants: %w", err)
	}
	return grantsProcessed, nil
}

func (b *MysqlServiceBinding) processGrants(ctx context.Context, user, host, database string,
	bindingMetadata types.BindingMetadata, reapplyAll bool) ([]types.BindingGrant, error) {
	userRef := mysqlUserRef(user, host)
	quotedDB := quoteMysqlIdent(database)

	bindingGrants, err := parseGrants(bindingMetadata.Grants, []types.GrantType{types.GrantTypeRead, types.GrantTypeCreate, types.GrantTypeFull})
	if err != nil {
		return nil, fmt.Errorf("error parsing grants: %w", err)
	}

	revokedGrants, applyGrants := diffGrants(bindingMetadata.GrantsApplied, bindingGrants)
	_, err = b.applyPerms(ctx, "revoke", revokedGrants, quotedDB, database, userRef)
	if err != nil {
		return nil, fmt.Errorf("error revoking grants: %w", err)
	}

	if reapplyAll {
		applyGrants = bindingGrants // Apply all grants, can help when new tables are present which need to be granted to the role
	}

	grantsProcessed, err := b.applyPerms(ctx, "grant", applyGrants, quotedDB, database, userRef)
	if err != nil {
		return nil, fmt.Errorf("error applying new grants: %w", err)
	}
	b.Debug().Msgf("processed grants %v", grantsProcessed)

	if reapplyAll {
		return grantsProcessed, nil
	}

	grantsApplied := []types.BindingGrant{}
	grantsApplied = append(grantsApplied, bindingMetadata.GrantsApplied...)
	for _, grant := range grantsProcessed {
		if !slices.Contains(grantsApplied, grant) {
			grantsApplied = append(grantsApplied, grant)
		}
	}
	for _, grant := range revokedGrants {
		index := slices.Index(grantsApplied, grant)
		if index != -1 {
			grantsApplied = slices.Delete(grantsApplied, index, index+1)
		}
	}
	return grantsApplied, nil
}

// applyPerms runs GRANT or REVOKE statements for binding grants on the MySQL
// admin connection. operation must be "grant" or "revoke".
//
// Future-table behavior: in MySQL, a database-level grant (`ON db.*`) covers
// every current and future table in that database, so `*`-target grants do
// not need a "default privileges" follow-up like Postgres requires. Only
// table-specific grants need to be deferred when the target table does not
// yet exist.
func (b *MysqlServiceBinding) applyPerms(ctx context.Context, operation string,
	grants []types.BindingGrant, quotedDB, database, userRef string) ([]types.BindingGrant, error) {
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
	for _, grant := range grants {
		switch grant.GrantType {
		case types.GrantTypeRead:
			if grant.GrantTarget == types.GrantTargetAll {
				stmt := fmt.Sprintf("%s SELECT ON %s.* %s %s", grantOrRevoke, quotedDB, toOrFrom, userRef)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s select privileges on database %s: %w", verb, database, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				quotedTable := quoteMysqlIdent(grant.GrantTarget)
				stmt := fmt.Sprintf("%s SELECT ON %s.%s %s %s", grantOrRevoke, quotedDB, quotedTable, toOrFrom, userRef)
				applied, err := b.trySoftGrant(ctx, isGrant, database, grant.GrantTarget, stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s select privileges on table %s.%s: %w", verb, database, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}

		case types.GrantTypeCreate:
			if isGrant && grant.GrantTarget != "" && grant.GrantTarget != types.GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			// In Postgres the role-on-schema CREATE privilege also lets the
			// role drop/alter objects it owns. MySQL splits these into
			// distinct privileges, so to match that semantic we bundle the
			// table-lifecycle privileges together for `create:*`.
			stmt := fmt.Sprintf("%s CREATE, ALTER, INDEX, DROP, REFERENCES ON %s.* %s %s", grantOrRevoke, quotedDB, toOrFrom, userRef)
			if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("error %s create privileges on database %s: %w", verb, database, err)
			}
			grantsDone = append(grantsDone, grant)

		case types.GrantTypeFull:
			if grant.GrantTarget == types.GrantTargetAll {
				// Use explicit privileges rather than ALL PRIVILEGES so
				// revoking full:* does not remove the baseline SHOW VIEW
				// privilege needed for the account to connect to its default
				// database. There is no separate "sequence" privilege space in
				// MySQL (AUTO_INCREMENT columns are part of the table).
				stmt := fmt.Sprintf("%s %s ON %s.* %s %s", grantOrRevoke, mysqlFullPrivilegesDB, quotedDB, toOrFrom, userRef)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s full privileges on database %s: %w", verb, database, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				// Use the same explicit list as full:* (minus the DB-only
				// privileges MySQL rejects at the table level), so the meaning
				// of "full" is consistent regardless of target and avoids the
				// SHOW VIEW-revoking pitfall of ALL PRIVILEGES.
				quotedTable := quoteMysqlIdent(grant.GrantTarget)
				stmt := fmt.Sprintf("%s %s ON %s.%s %s %s", grantOrRevoke, mysqlFullPrivilegesTable, quotedDB, quotedTable, toOrFrom, userRef)
				applied, err := b.trySoftGrant(ctx, isGrant, database, grant.GrantTarget, stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s full privileges on table %s.%s: %w", verb, database, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}
		}
	}
	return grantsDone, nil
}

// trySoftGrant runs a single GRANT or REVOKE on a specific table. Because
// MySQL DDL auto-commits we cannot use SAVEPOINT to recover from a missing
// table the way the Postgres binding does. Instead we precheck the table's
// existence: if it is missing we report the grant as deferred (returns
// false, nil). For revokes we additionally swallow ER_NONEXISTING_TABLE_GRANT
// so removing a grant from a metadata list does not fail if it was never
// applied (e.g. it was deferred).
func (b *MysqlServiceBinding) trySoftGrant(ctx context.Context, isGrant bool, database, table, stmt string) (bool, error) {
	exists, err := b.tableExists(ctx, database, table)
	if err != nil {
		return false, fmt.Errorf("error checking if table %s.%s exists: %w", database, table, err)
	}
	if !exists {
		return false, nil
	}

	if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
		if !isGrant && isMysqlErrNo(err, mysqlErrNonExistingGrant) {
			// Revoking something that was never granted is harmless.
			return false, nil
		}
		if isMysqlErrNo(err, mysqlErrNoSuchTable) {
			// Lost a race with a DROP TABLE between precheck and grant; treat
			// as deferred so the caller logs and moves on instead of aborting.
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// tableExists reports whether the given database/table is present in
// information_schema. Used to precheck table-level GRANT/REVOKE.
func (b *MysqlServiceBinding) tableExists(ctx context.Context, database, table string) (bool, error) {
	const q = "SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ? LIMIT 1"
	row := b.adminConn.QueryRowContext(ctx, q, database, table)
	var present int
	if err := row.Scan(&present); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// quoteMysqlIdent quotes an identifier (database, table, column) using
// backticks. Embedded backticks are doubled, per MySQL's identifier rules.
func quoteMysqlIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// quoteMysqlString quotes a value as a SQL string literal. Embedded single
// quotes are doubled and backslashes escaped, to defend against both standard
// quoting and the (default) NO_BACKSLASH_ESCAPES-off mode where backslash is
// also an escape character.
func quoteMysqlString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "''")
	return "'" + s + "'"
}

// mysqlUserRef returns a `'user'@'host'` reference suitable for use in
// CREATE USER, GRANT, REVOKE, DROP USER statements.
func mysqlUserRef(user, host string) string {
	return quoteMysqlString(user) + "@" + quoteMysqlString(host)
}

// mysqlURLToDSN converts a mysql:// URL to a go-sql-driver DSN. If
// overrideDB is non-empty it replaces the URL's path-derived database.
func mysqlURLToDSN(rawURL, overrideDB string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "mysql" && u.Scheme != "" {
		// Allow callers to pass a bare host:port or a mysql:// URL; reject
		// other schemes outright so misconfiguration fails loudly.
		return "", fmt.Errorf("unsupported mysql url scheme %q (expected mysql://)", u.Scheme)
	}

	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	// go-sql-driver expects host:port; URLs like mysql://host/db (no port)
	// or mysql://[::1]/db (bracketed IPv6, no port) would otherwise emit
	// `tcp(host)` which the driver's parser handles inconsistently across
	// versions. Default to :3306 when no port is present. net.SplitHostPort
	// is used so IPv6 literals are not misclassified as host:port by a naive
	// strings.Contains(":") check.
	host := u.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "3306")
		}
	}
	cfg.Addr = host
	if u.User != nil {
		cfg.User = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			cfg.Passwd = pw
		}
	}
	db := strings.TrimPrefix(u.Path, "/")
	if overrideDB != "" {
		db = overrideDB
	}
	cfg.DBName = db

	for k, vs := range u.Query() {
		if len(vs) == 0 {
			continue
		}
		// Map common URL-style flags to go-sql-driver Config fields where
		// possible; otherwise fall through to the generic Params bag so the
		// driver still sees them.
		switch k {
		case "tls":
			cfg.TLSConfig = vs[0]
		case "parseTime":
			cfg.ParseTime = vs[0] == "true" || vs[0] == "1"
		case "loc":
			// loc is a tz name; deferred to the driver via Params to avoid
			// pulling time.LoadLocation here.
			if cfg.Params == nil {
				cfg.Params = map[string]string{}
			}
			cfg.Params[k] = vs[0]
		default:
			if cfg.Params == nil {
				cfg.Params = map[string]string{}
			}
			cfg.Params[k] = vs[0]
		}
	}

	return cfg.FormatDSN(), nil
}

// buildMysqlAccountURL constructs a new mysql:// URL using the admin URL's
// host/port and the supplied user, password and default database. The result
// is what we store in BindingMetadata.Account["url"] and hand back to apps.
func buildMysqlAccountURL(adminURL, user, password, database string) (string, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/" + database
	return u.String(), nil
}

func (b *MysqlServiceBinding) RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error) {
	dsn, err := mysqlURLToDSN(bindingMetadata.Account["url"], "")
	if err != nil {
		return nil, fmt.Errorf("error parsing account url: %w", err)
	}

	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error opening connection: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	if err := conn.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("error verifying connection: %w", err)
	}

	// Heuristic: a statement that returns rows is treated as a query; otherwise
	// we use Exec so callers can issue DDL/DML and still see rows_affected.
	trimmed := strings.TrimLeft(command, " \t\n\r")
	first := strings.ToUpper(strings.SplitN(trimmed, " ", 2)[0])
	rowReturning := first == "SELECT" || first == "SHOW" || first == "DESCRIBE" || first == "DESC" || first == "EXPLAIN" || first == "WITH"

	if !rowReturning {
		result, err := conn.ExecContext(ctx, command)
		if err != nil {
			return nil, fmt.Errorf("error executing command: %w", err)
		}
		rowsAffected, _ := result.RowsAffected()
		lastInsertID, _ := result.LastInsertId()
		return map[string]any{
			"columns":        []string{},
			"rows":           []map[string]any{},
			"rows_affected":  rowsAffected,
			"last_insert_id": lastInsertID,
			"command_tag":    first,
		}, nil
	}

	rows, err := conn.QueryContext(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("error executing command: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("error reading column metadata: %w", err)
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
			v := values[i]
			// The mysql driver returns text-protocol values as []byte; convert
			// to string so JSON marshalling produces something useful for
			// callers.
			if b, ok := v.([]byte); ok {
				resultRow[column] = string(b)
			} else {
				resultRow[column] = v
			}
		}
		resultRows = append(resultRows, resultRow)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading command result: %w", err)
	}

	return map[string]any{
		"columns":       columns,
		"rows":          resultRows,
		"rows_affected": int64(len(resultRows)),
		"command_tag":   first,
	}, nil
}
