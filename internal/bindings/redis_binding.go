// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/openrundev/openrun/internal/types"
	"github.com/redis/go-redis/v9"
)

// Redis/Valkey service binding. Isolation between bindings is implemented with
// server-enforced ACLs (Redis 6+/Valkey): each base binding gets a dedicated ACL
// user restricted to a unique key prefix (`~<prefix>*`) and pub/sub channel
// prefix (`&<prefix>*`). Derived bindings share the base binding's key prefix
// with a separate ACL user whose key patterns are controlled by grants.
//
// Unlike SQL databases, the server does not rewrite key names: apps must
// prepend the generated `key_prefix` (exposed in the binding account) to every
// key they use. Access outside the prefix fails with NOPERM, so a
// misconfigured app fails loudly instead of silently clobbering a neighbor.
const (
	redisUserPrefixProd = "cl_usr_prd_"
	redisUserPrefixStg  = "cl_usr_stg_"
	redisKeyPrefixProd  = "cl:prd:"
	redisKeyPrefixStg   = "cl:stg:"

	// Redis 7 is required: read-only key patterns (%R~), per-subcommand ACL
	// rules and ACL enforcement inside scripts are all 7.0 features. Valkey
	// forked from Redis 7.2 and always satisfies this floor.
	redisMinMajorVersion = 7
)

// redisCommandRules is the command policy applied to every binding user, base
// and derived. Key and channel patterns provide the actual isolation; the
// command rules remove administrative commands and the commands that bypass
// key patterns entirely:
//   - @admin/@dangerous cover CONFIG, ACL, FLUSHALL/FLUSHDB, KEYS, SORT (its
//     BY/GET clauses read arbitrary keys), RESTORE, MIGRATE, SWAPDB, MONITOR,
//     DEBUG, CLIENT KILL/LIST and INFO among others.
//   - RANDOMKEY takes no key argument, so key patterns cannot constrain it and
//     it leaks key names from other bindings.
//   - PUBSUB (CHANNELS/NUMSUB/SHARDCHANNELS) similarly leaks the active
//     channel names of other bindings.
//   - FUNCTION libraries are named, instance-global state; one binding could
//     overwrite another's libraries. The content-addressed script cache
//     (SCRIPT LOAD/EVALSHA) has no such conflict and stays allowed, but
//     SCRIPT FLUSH/KILL affect other connections and are denied.
//
// SCAN is intentionally allowed: it is the only way for an app to enumerate
// and clear its own keys (there is no FLUSHDB scoped to a prefix). Like
// RANDOMKEY it can observe other bindings' key names (never values); this is
// a documented trade-off.
var redisCommandRules = []string{
	"+@all", "-@admin", "-@dangerous",
	"-randomkey", "-pubsub", "-function", "-script|flush", "-script|kill",
}

// redisGrantTargetRegex limits grant targets to characters that are safe
// inside an ACL glob pattern, so a target cannot widen the pattern beyond the
// binding's key prefix or inject additional ACL rules.
var redisGrantTargetRegex = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

type redisAclPersistMode int

const (
	redisAclPersistUnknown redisAclPersistMode = iota // CONFIG GET denied, try ACL SAVE and ignore failures
	redisAclPersistOff                                // no aclfile configured, skip ACL SAVE
	redisAclPersistOn                                 // aclfile configured, ACL SAVE after every mutation
)

type RedisServiceBinding struct {
	*types.Logger
	serviceConfig map[string]string
	adminClient   *redis.Client // The admin connection, available after InitializeService
	aclPersist    redisAclPersistMode
}

func init() {
	// One ACL-compatible implementation serves both service types
	RegisterServiceBinding("redis", NewRedisServiceBinding)
	RegisterServiceBinding("valkey", NewRedisServiceBinding)
}

var _ ServiceBinding = (*RedisServiceBinding)(nil)

func (b *RedisServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "username", "password", "key_prefix"}, []string{}, nil
}

func NewRedisServiceBinding() ServiceBinding {
	return &RedisServiceBinding{}
}

func (b *RedisServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	b.Logger = logger
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{"binding_hostname"}); err != nil {
		return err
	}

	connURL := serviceConfig["url"]
	opts, err := redisParseURL(connURL)
	if err != nil {
		return fmt.Errorf("error parsing redis url: %w", err)
	}

	adminClient := redis.NewClient(opts)
	if err := adminClient.Ping(ctx).Err(); err != nil {
		adminClient.Close() //nolint:errcheck
		return fmt.Errorf("error verifying redis connection: %w", err)
	}

	if err := b.checkServerCompatibility(ctx, adminClient); err != nil {
		adminClient.Close() //nolint:errcheck
		return err
	}

	b.aclPersist = b.detectAclPersistMode(ctx, adminClient)
	b.serviceConfig = serviceConfigWithLocalhostBindingHostname(serviceConfig, connURL, runtime)
	b.adminClient = adminClient
	return nil
}

// checkServerCompatibility enforces the Redis >= 7 (or Valkey) version floor
// and rejects cluster mode. Cluster is unsupported because ACL users must be
// created on every node and prefix-based keys spread across hash slots.
func (b *RedisServiceBinding) checkServerCompatibility(ctx context.Context, client *redis.Client) error {
	serverInfo, err := client.Info(ctx, "server").Result()
	if err != nil {
		return fmt.Errorf("error reading server info: %w", err)
	}

	versionStr, major, err := redisServerVersion(serverInfo)
	if err != nil {
		return err
	}
	if major < redisMinMajorVersion {
		return fmt.Errorf("redis/valkey server version %s is not supported, version %d or newer is required for ACL based isolation", versionStr, redisMinMajorVersion)
	}

	clusterInfo, err := client.Info(ctx, "cluster").Result()
	if err != nil {
		return fmt.Errorf("error reading cluster info: %w", err)
	}
	if redisInfoField(clusterInfo, "cluster_enabled") == "1" {
		return fmt.Errorf("redis/valkey cluster mode is not supported for service bindings, use a standalone server")
	}
	return nil
}

// detectAclPersistMode checks whether the server persists ACL users across
// restarts. ACL SETUSER only changes in-memory state; without an aclfile the
// binding users vanish on server restart (derived users can be restored with
// `binding update --reapply-all`, base users need the aclfile).
func (b *RedisServiceBinding) detectAclPersistMode(ctx context.Context, client *redis.Client) redisAclPersistMode {
	configValues, err := client.ConfigGet(ctx, "aclfile").Result()
	if err != nil {
		// CONFIG may be renamed or denied on managed servers; ACL SAVE is
		// attempted after mutations and failures are ignored.
		b.Debug().Err(err).Msg("could not determine redis aclfile config")
		return redisAclPersistUnknown
	}
	if configValues["aclfile"] == "" {
		b.Warn().Msg("redis server has no aclfile configured; binding ACL users will not survive a server restart")
		return redisAclPersistOff
	}
	return redisAclPersistOn
}

func (b *RedisServiceBinding) CloseService(ctx context.Context) error {
	if b.adminClient == nil {
		return nil
	}
	return b.adminClient.Close()
}

func (b *RedisServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return nil, nil, err
	}

	password, err := randomHex(32)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}

	userPrefix := redisUserPrefixProd
	keyModePrefix := redisKeyPrefixProd
	if isStaging {
		userPrefix = redisUserPrefixStg
		keyModePrefix = redisKeyPrefixStg
	}

	userName := userPrefix + bindingId
	keyPrefix := keyModePrefix + bindingId + ":"
	if derivedFromMetadata != nil {
		// Derived binding, share the base binding's key prefix
		keyPrefix = derivedFromMetadata.Account["key_prefix"]
		if keyPrefix == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the key_prefix field")
		}
	}

	exists, err := b.aclUserExists(ctx, userName)
	if err != nil {
		return nil, nil, fmt.Errorf("error checking user %s: %w", userName, err)
	}
	if exists {
		// ACL SETUSER silently updates existing users, so check first to avoid
		// clobbering a leftover user from a previous partial operation.
		return nil, nil, fmt.Errorf("redis user %s already exists", userName)
	}

	// The base binding user gets full access to the key prefix and its pub/sub
	// channels. A derived binding user starts with no key or channel patterns:
	// it can authenticate but every data command fails with NOPERM until
	// ApplyGrants (called right after account creation) adds patterns.
	var grants []types.BindingGrant
	if derivedFromMetadata == nil {
		grants = []types.BindingGrant{{GrantType: types.GrantTypeFull, GrantTarget: types.GrantTargetAll}}
	}
	rules, err := buildRedisACLRules(password, keyPrefix, grants)
	if err != nil {
		return nil, nil, err
	}
	if err := b.aclSetUser(ctx, userName, rules); err != nil {
		return nil, nil, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts := []Artifact{{Type: ArtifactUser, Name: userName}}
	b.persistAcls(ctx)

	accountDirectURL, err := buildRedisAccountURL(b.serviceConfig["url"], userName, password, "")
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}
	accountURL, err := buildRedisAccountURL(b.serviceConfig["url"], userName, password, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building binding account url: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"username":   userName,
		"password":   password,
		"key_prefix": keyPrefix,
	}, artifacts, nil
}

// DeleteArtifact deletes one ACL user previously reported as created by
// GenerateAccount. Keys under the binding's prefix are not touched; like the
// other bindings, data outlives the account.
func (b *RedisServiceBinding) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}
	if artifact.Type != ArtifactUser {
		return fmt.Errorf("unsupported redis artifact type %s", artifact.Type)
	}

	if err := b.adminClient.Do(ctx, "acl", "deluser", artifact.Name).Err(); err != nil {
		return fmt.Errorf("error deleting user %s: %w", artifact.Name, err)
	}
	b.persistAcls(ctx)
	return nil
}

// ApplyGrants rebuilds the derived user's complete ACL rule set in one atomic
// ACL SETUSER, from the union of the currently applied and the desired grants.
// The union keeps this additive, per the interface contract: grants that are no
// longer desired are reported in PendingRevokes but stay in effect until the
// caller runs RevokeGrants after its metadata transaction commits. Since ACL
// SETUSER creates missing users, this also restores a derived user lost to a
// server restart without an aclfile (via `binding update --reapply-all`).
// The full rule set is applied every time, so reapplyAll needs no special
// handling and nothing is ever deferred (a grant target is just a key pattern,
// it does not need to exist).
func (b *RedisServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata types.BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	if err := verifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return GrantApplyResult{}, err
	}

	bindingGrants, err := parseGrants(bindingMetadata.Grants, []types.GrantType{types.GrantTypeRead, types.GrantTypeFull})
	if err != nil {
		return GrantApplyResult{}, fmt.Errorf("error parsing grants: %w", err)
	}

	pendingRevokes, newGrants := diffGrants(bindingMetadata.GrantsApplied, bindingGrants)
	grantsApplied := unionGrants(bindingMetadata.GrantsApplied, bindingGrants)

	if err := b.setUserGrants(ctx, account, grantsApplied); err != nil {
		return GrantApplyResult{}, err
	}

	return GrantApplyResult{
		GrantsApplied:  grantsApplied,
		Granted:        newGrants,
		PendingRevokes: pendingRevokes,
	}, nil
}

// RevokeGrants removes grants that are no longer desired. Every caller path
// maintains the invariant that the account's remaining grants after the revoke
// equal exactly the regrants list (the revokes are a subset of what is applied,
// and everything else applied is in regrants), so the rule set is rebuilt from
// regrants in one atomic ACL SETUSER. Kept grants are never transiently
// revoked, and revoking a grant that was never applied is naturally harmless.
func (b *RedisServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata types.BindingMetadata, revokes, regrants []types.BindingGrant) error {
	if len(revokes) == 0 {
		return nil
	}
	return b.setUserGrants(ctx, account, regrants)
}

// setUserGrants applies the complete ACL rule set for the account's user,
// built from the given grants, in one atomic ACL SETUSER.
func (b *RedisServiceBinding) setUserGrants(ctx context.Context, account map[string]string, grants []types.BindingGrant) error {
	userName := account["username"]
	password := account["password"]
	keyPrefix := account["key_prefix"]
	if userName == "" || password == "" || keyPrefix == "" {
		return fmt.Errorf("binding account is missing the username, password or key_prefix field")
	}

	rules, err := buildRedisACLRules(password, keyPrefix, grants)
	if err != nil {
		return err
	}
	if err := b.aclSetUser(ctx, userName, rules); err != nil {
		return fmt.Errorf("error applying grants to user %s: %w", userName, err)
	}
	b.persistAcls(ctx)
	return nil
}

// buildRedisACLRules builds the complete ACL SETUSER rule list for a binding
// user. The list starts with `reset` so applying it is idempotent: the user is
// wiped and rebuilt in one atomic command. `resetchannels` is included even
// though `reset` implies it, to guard against servers running with
// `acl-pubsub-default allchannels` where the post-reset default would grant
// all channels.
func buildRedisACLRules(password, keyPrefix string, grants []types.BindingGrant) ([]string, error) {
	rules := []string{"reset", "on", ">" + password, "resetchannels"}
	rules = append(rules, redisCommandRules...)

	patterns := []string{}
	addPattern := func(pattern string) {
		if !slices.Contains(patterns, pattern) {
			patterns = append(patterns, pattern)
			rules = append(rules, pattern)
		}
	}

	for _, grant := range grants {
		target := grant.GrantTarget
		if target == types.GrantTargetAll {
			target = ""
		} else {
			if target == "" {
				return nil, fmt.Errorf("grant target is required, use %s:* for all keys", strings.ToLower(string(grant.GrantType)))
			}
			if !redisGrantTargetRegex.MatchString(target) {
				return nil, fmt.Errorf("invalid grant target %q: only letters, digits and _ . : - are allowed", target)
			}
		}
		pattern := keyPrefix + target + "*"

		switch grant.GrantType {
		case types.GrantTypeRead:
			// Server-enforced read-only access: writes to matching keys fail
			// with NOPERM. Read grants do not include pub/sub access.
			addPattern("%R~" + pattern)
		case types.GrantTypeFull:
			// Read-write keys plus pub/sub channels under the same pattern.
			// Channel access comes only from full grants since channel ACLs
			// cannot separate subscribe from publish.
			addPattern("~" + pattern)
			addPattern("&" + pattern)
		default:
			return nil, fmt.Errorf("unsupported grant type %s for redis", grant.GrantType)
		}
	}
	return rules, nil
}

// aclUserExists reports whether the ACL user is already defined on the server.
func (b *RedisServiceBinding) aclUserExists(ctx context.Context, userName string) (bool, error) {
	err := b.adminClient.Do(ctx, "acl", "getuser", userName).Err()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return false, err
}

func (b *RedisServiceBinding) aclSetUser(ctx context.Context, userName string, rules []string) error {
	args := make([]any, 0, len(rules)+3)
	args = append(args, "acl", "setuser", userName)
	for _, rule := range rules {
		args = append(args, rule)
	}
	return b.adminClient.Do(ctx, args...).Err()
}

// persistAcls saves the ACL state to the configured aclfile after a mutation,
// so binding users survive a server restart. Failures are logged, not
// returned: the in-memory ACL change already succeeded and the binding
// metadata must stay in sync with it.
func (b *RedisServiceBinding) persistAcls(ctx context.Context) {
	switch b.aclPersist {
	case redisAclPersistOff:
		return
	case redisAclPersistOn:
		if err := b.adminClient.Do(ctx, "acl", "save").Err(); err != nil {
			b.Warn().Err(err).Msg("error saving redis acls to aclfile")
		}
	case redisAclPersistUnknown:
		if err := b.adminClient.Do(ctx, "acl", "save").Err(); err != nil {
			b.Debug().Err(err).Msg("redis acl save not available")
		}
	}
}

// CheckHealth verifies the admin connection with a PING.
func (b *RedisServiceBinding) CheckHealth(ctx context.Context) error {
	if b.adminClient == nil {
		return fmt.Errorf("service is not initialized")
	}
	if err := b.adminClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("error pinging redis: %w", err)
	}
	return nil
}

// CheckBindingHealth connects as the binding's ACL user and runs a PING
// (allowed by the binding command rules), verifying the user still exists and
// its password works.
func (b *RedisServiceBinding) CheckBindingHealth(ctx context.Context, bindingMetadata types.BindingMetadata) error {
	opts, err := redisParseURL(bindingMetadata.Account["url_direct"])
	if err != nil {
		return fmt.Errorf("error parsing account url: %w", err)
	}
	client := redis.NewClient(opts)
	defer client.Close() //nolint:errcheck
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("error pinging redis as binding account: %w", err)
	}
	return nil
}

func (b *RedisServiceBinding) RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error) {
	args, err := tokenizeRedisCommand(command)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("command is required")
	}

	opts, err := redisParseURL(bindingMetadata.Account["url_direct"])
	if err != nil {
		return nil, fmt.Errorf("error parsing account url: %w", err)
	}

	client := redis.NewClient(opts)
	defer client.Close() //nolint:errcheck

	doArgs := make([]any, len(args))
	for i, arg := range args {
		doArgs[i] = arg
	}
	result, err := client.Do(ctx, doArgs...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Missing key (or empty reply); a null result, not an error
			return map[string]any{"result": nil}, nil
		}
		return nil, fmt.Errorf("error executing command: %w", err)
	}
	return map[string]any{"result": redisReplyToJSON(result)}, nil
}

// redisReplyToJSON converts a go-redis reply value into JSON-marshalable
// types. RESP3 map replies use any-typed keys which encoding/json/v2 rejects.
func redisReplyToJSON(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case string, int64, float64, bool:
		return v
	case []any:
		converted := make([]any, len(v))
		for i, item := range v {
			converted[i] = redisReplyToJSON(item)
		}
		return converted
	case map[any]any:
		converted := make(map[string]any, len(v))
		for key, item := range v {
			converted[fmt.Sprint(key)] = redisReplyToJSON(item)
		}
		return converted
	case map[string]any:
		converted := make(map[string]any, len(v))
		for key, item := range v {
			converted[key] = redisReplyToJSON(item)
		}
		return converted
	default:
		return fmt.Sprint(v)
	}
}

// tokenizeRedisCommand splits a command line into RESP arguments. Single and
// double quotes group words; inside double quotes backslash escapes the next
// character (with \n, \r and \t translated). Arguments are passed to the
// server as separate protocol values, so no server-side quoting is involved.
func tokenizeRedisCommand(command string) ([]string, error) {
	args := []string{}
	var current strings.Builder
	inSingle, inDouble, escaped, hasToken := false, false, false, false

	flush := func() {
		if hasToken {
			args = append(args, current.String())
			current.Reset()
			hasToken = false
		}
	}

	for _, r := range command {
		switch {
		case escaped:
			switch r {
			case 'n':
				current.WriteRune('\n')
			case 'r':
				current.WriteRune('\r')
			case 't':
				current.WriteRune('\t')
			default:
				current.WriteRune(r)
			}
			escaped = false
		case inDouble && r == '\\':
			escaped = true
		case inDouble && r == '"':
			inDouble = false
		case inSingle && r == '\'':
			inSingle = false
		case inSingle || inDouble:
			current.WriteRune(r)
		case r == '"':
			inDouble = true
			hasToken = true
		case r == '\'':
			inSingle = true
			hasToken = true
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
			hasToken = true
		}
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in command")
	}
	if escaped {
		return nil, fmt.Errorf("unterminated escape in command")
	}
	flush()
	return args, nil
}

// normalizeRedisScheme maps valkey:// and valkeys:// URLs to the redis://
// schemes understood by client libraries.
func normalizeRedisScheme(rawURL string) string {
	if rest, ok := strings.CutPrefix(rawURL, "valkeys://"); ok {
		return "rediss://" + rest
	}
	if rest, ok := strings.CutPrefix(rawURL, "valkey://"); ok {
		return "redis://" + rest
	}
	return rawURL
}

func redisParseURL(rawURL string) (*redis.Options, error) {
	return redis.ParseURL(normalizeRedisScheme(rawURL))
}

// buildRedisAccountURL constructs an account URL using the admin URL's
// host/port/database and query options with the supplied user and password.
// valkey:// schemes are normalized to redis:// so any client library can use
// the generated URL.
func buildRedisAccountURL(adminURL, user, password, bindingHostname string) (string, error) {
	u, err := url.Parse(normalizeRedisScheme(adminURL))
	if err != nil {
		return "", err
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" && u.Scheme != "unix" {
		return "", fmt.Errorf("unsupported redis url scheme %q (expected redis:// or rediss://)", u.Scheme)
	}
	u.User = url.UserPassword(user, password)
	setURLHostname(u, bindingHostname)
	return u.String(), nil
}

// redisServerVersion extracts the server version from INFO server output.
// Valkey reports both a redis_version compatibility field (7.2.x) and its own
// valkey_version; the redis_version field is used for the compatibility floor.
func redisServerVersion(serverInfo string) (string, int, error) {
	versionStr := redisInfoField(serverInfo, "redis_version")
	if versionStr == "" {
		versionStr = redisInfoField(serverInfo, "valkey_version")
	}
	if versionStr == "" {
		return "", 0, fmt.Errorf("could not determine redis/valkey server version from INFO output")
	}

	majorStr, _, _ := strings.Cut(versionStr, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return versionStr, 0, fmt.Errorf("could not parse redis/valkey server version %q", versionStr)
	}
	return versionStr, major, nil
}

// redisInfoField extracts one `field:value` line from INFO command output.
func redisInfoField(info, field string) string {
	for line := range strings.Lines(info) {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), field+":"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
