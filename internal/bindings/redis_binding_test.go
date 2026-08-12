// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestBuildRedisAccountURLWithBindingHostname(t *testing.T) {
	accountURL, err := buildRedisAccountURL("redis://admin:secret@localhost:6379/2", "cl_user", "p@ss", "")
	if err != nil {
		t.Fatalf("buildRedisAccountURL() error = %v", err)
	}
	assertURL(t, accountURL, "redis", "localhost:6379", "cl_user", "p@ss", "/2", map[string]string{})

	bindingURL, err := buildRedisAccountURL("redis://admin:secret@localhost:6379/2", "cl_user", "p@ss", "host.docker.internal")
	if err != nil {
		t.Fatalf("buildRedisAccountURL() with binding hostname error = %v", err)
	}
	assertURL(t, bindingURL, "redis", "host.docker.internal:6379", "cl_user", "p@ss", "/2", map[string]string{})

	disabledURL, err := buildRedisAccountURL("redis://admin:secret@localhost:6379/2", "cl_user", "p@ss", "disable")
	if err != nil {
		t.Fatalf("buildRedisAccountURL() with disabled binding hostname error = %v", err)
	}
	assertURL(t, disabledURL, "redis", "localhost:6379", "cl_user", "p@ss", "/2", map[string]string{})
}

func TestBuildRedisAccountURLSchemes(t *testing.T) {
	valkeyURL, err := buildRedisAccountURL("valkey://admin:secret@localhost:6379/0", "cl_user", "pass", "")
	if err != nil {
		t.Fatalf("buildRedisAccountURL() valkey scheme error = %v", err)
	}
	if !strings.HasPrefix(valkeyURL, "redis://") {
		t.Fatalf("valkey scheme was not normalized: %s", valkeyURL)
	}

	valkeysURL, err := buildRedisAccountURL("valkeys://admin:secret@redis.example.com:6379/0", "cl_user", "pass", "")
	if err != nil {
		t.Fatalf("buildRedisAccountURL() valkeys scheme error = %v", err)
	}
	if !strings.HasPrefix(valkeysURL, "rediss://") {
		t.Fatalf("valkeys scheme was not normalized: %s", valkeysURL)
	}

	if _, err := buildRedisAccountURL("http://localhost:6379", "cl_user", "pass", ""); err == nil {
		t.Fatal("buildRedisAccountURL() with http scheme should fail")
	}
}

func TestBuildRedisACLRules(t *testing.T) {
	baseGrants := []types.BindingGrant{{GrantType: types.GrantTypeFull, GrantTarget: types.GrantTargetAll}}
	rules, err := buildRedisACLRules("pwd123", "cl:prd:bnd_1:", baseGrants)
	if err != nil {
		t.Fatalf("buildRedisACLRules() error = %v", err)
	}

	// The rule list must start with reset so reapplying is idempotent, and
	// must set the password and enabled state after the reset.
	if rules[0] != "reset" {
		t.Fatalf("rules[0] = %q, want reset", rules[0])
	}
	for _, required := range []string{"on", ">pwd123", "resetchannels", "+@all", "-@admin", "-@dangerous",
		"-randomkey", "-pubsub", "-function", "~cl:prd:bnd_1:*", "&cl:prd:bnd_1:*"} {
		if !slices.Contains(rules, required) {
			t.Fatalf("rules missing %q: %v", required, rules)
		}
	}

	// A derived binding with no grants gets no key or channel patterns
	emptyRules, err := buildRedisACLRules("pwd123", "cl:prd:bnd_1:", nil)
	if err != nil {
		t.Fatalf("buildRedisACLRules() empty grants error = %v", err)
	}
	for _, rule := range emptyRules {
		if strings.Contains(rule, "~") || strings.HasPrefix(rule, "&") {
			t.Fatalf("empty grants produced pattern rule %q", rule)
		}
	}
}

func TestBuildRedisACLRulesGrants(t *testing.T) {
	prefix := "cl:prd:bnd_1:"

	readRules, err := buildRedisACLRules("pwd", prefix, []types.BindingGrant{
		{GrantType: types.GrantTypeRead, GrantTarget: types.GrantTargetAll}})
	if err != nil {
		t.Fatalf("buildRedisACLRules() read:* error = %v", err)
	}
	if !slices.Contains(readRules, "%R~"+prefix+"*") {
		t.Fatalf("read:* rules missing read-only pattern: %v", readRules)
	}
	for _, rule := range readRules {
		if strings.HasPrefix(rule, "&") {
			t.Fatalf("read grant produced channel rule %q; channels are full-grant only", rule)
		}
		if rule == "~"+prefix+"*" {
			t.Fatalf("read grant produced read-write pattern: %v", readRules)
		}
	}

	targetRules, err := buildRedisACLRules("pwd", prefix, []types.BindingGrant{
		{GrantType: types.GrantTypeRead, GrantTarget: "sess"},
		{GrantType: types.GrantTypeFull, GrantTarget: "jobs"},
		{GrantType: types.GrantTypeFull, GrantTarget: "jobs"}, // duplicate is deduped
	})
	if err != nil {
		t.Fatalf("buildRedisACLRules() targeted error = %v", err)
	}
	for _, required := range []string{"%R~" + prefix + "sess*", "~" + prefix + "jobs*", "&" + prefix + "jobs*"} {
		if !slices.Contains(targetRules, required) {
			t.Fatalf("targeted rules missing %q: %v", required, targetRules)
		}
	}
	jobsCount := 0
	for _, rule := range targetRules {
		if rule == "~"+prefix+"jobs*" {
			jobsCount++
		}
	}
	if jobsCount != 1 {
		t.Fatalf("duplicate grant was not deduped: %v", targetRules)
	}
}

func TestBuildRedisACLRulesInvalidTargets(t *testing.T) {
	prefix := "cl:prd:bnd_1:"
	invalidTargets := []string{"a b", "a*b", "a?b", "a[b]", "a\nb", "'quoted'"}
	for _, target := range invalidTargets {
		if _, err := buildRedisACLRules("pwd", prefix, []types.BindingGrant{
			{GrantType: types.GrantTypeRead, GrantTarget: target}}); err == nil {
			t.Fatalf("buildRedisACLRules() accepted invalid target %q", target)
		}
	}

	// Empty target (grant given as "read:") is rejected
	if _, err := buildRedisACLRules("pwd", prefix, []types.BindingGrant{
		{GrantType: types.GrantTypeRead, GrantTarget: ""}}); err == nil {
		t.Fatal("buildRedisACLRules() accepted empty target")
	}

	// Unsupported grant type is rejected
	if _, err := buildRedisACLRules("pwd", prefix, []types.BindingGrant{
		{GrantType: types.GrantTypeCreate, GrantTarget: types.GrantTargetAll}}); err == nil {
		t.Fatal("buildRedisACLRules() accepted create grant")
	}
}

func TestTokenizeRedisCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
		wantErr bool
	}{
		{name: "simple", command: "get key1", want: []string{"get", "key1"}},
		{name: "extra whitespace", command: "  set   key1\tval1  ", want: []string{"set", "key1", "val1"}},
		{name: "double quotes", command: `set key1 "hello world"`, want: []string{"set", "key1", "hello world"}},
		{name: "single quotes", command: `set key1 'hello world'`, want: []string{"set", "key1", "hello world"}},
		{name: "escapes in double quotes", command: `set key1 "a\"b\\c\nd"`, want: []string{"set", "key1", "a\"b\\c\nd"}},
		{name: "no escapes in single quotes", command: `set key1 'a\nb'`, want: []string{"set", "key1", `a\nb`}},
		{name: "empty quoted arg", command: `set key1 ""`, want: []string{"set", "key1", ""}},
		{name: "adjacent quotes", command: `set key1 "a b"'c d'`, want: []string{"set", "key1", "a bc d"}},
		{name: "empty", command: "   ", want: []string{}},
		{name: "unterminated double quote", command: `set key1 "abc`, wantErr: true},
		{name: "unterminated single quote", command: `set key1 'abc`, wantErr: true},
		{name: "unterminated escape", command: `set key1 "abc\`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenizeRedisCommand(tt.command)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("tokenizeRedisCommand(%q) expected error, got %v", tt.command, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("tokenizeRedisCommand(%q) error = %v", tt.command, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("tokenizeRedisCommand(%q) = %#v, want %#v", tt.command, got, tt.want)
			}
		})
	}
}

func TestRedisServerVersion(t *testing.T) {
	redisInfo := "# Server\r\nredis_version:8.0.1\r\nredis_mode:standalone\r\n"
	versionStr, major, err := redisServerVersion(redisInfo)
	if err != nil {
		t.Fatalf("redisServerVersion() error = %v", err)
	}
	if versionStr != "8.0.1" || major != 8 {
		t.Fatalf("redisServerVersion() = %q, %d; want 8.0.1, 8", versionStr, major)
	}

	// Valkey reports a redis_version compatibility field which takes priority
	valkeyInfo := "# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.1.0\r\n"
	versionStr, major, err = redisServerVersion(valkeyInfo)
	if err != nil {
		t.Fatalf("redisServerVersion() valkey error = %v", err)
	}
	if versionStr != "7.2.4" || major != 7 {
		t.Fatalf("redisServerVersion() valkey = %q, %d; want 7.2.4, 7", versionStr, major)
	}

	valkeyOnly := "# Server\r\nvalkey_version:9.0.0\r\n"
	versionStr, major, err = redisServerVersion(valkeyOnly)
	if err != nil {
		t.Fatalf("redisServerVersion() valkey-only error = %v", err)
	}
	if versionStr != "9.0.0" || major != 9 {
		t.Fatalf("redisServerVersion() valkey-only = %q, %d; want 9.0.0, 9", versionStr, major)
	}

	if _, _, err := redisServerVersion("# Server\r\nuptime_in_seconds:1\r\n"); err == nil {
		t.Fatal("redisServerVersion() with missing version should fail")
	}
}

func TestRedisReplyToJSON(t *testing.T) {
	// RESP3 map replies have any-typed keys which encoding/json rejects
	reply := map[any]any{
		"a": int64(1),
		int64(2): []any{
			"x", nil, map[any]any{"nested": "v"},
		},
	}
	converted, ok := redisReplyToJSON(reply).(map[string]any)
	if !ok {
		t.Fatalf("redisReplyToJSON() did not return map[string]any: %#v", converted)
	}
	if converted["a"] != int64(1) {
		t.Fatalf("converted[a] = %#v, want 1", converted["a"])
	}
	list, ok := converted["2"].([]any)
	if !ok || len(list) != 3 {
		t.Fatalf("converted[2] = %#v, want 3-element list", converted["2"])
	}
	nested, ok := list[2].(map[string]any)
	if !ok || nested["nested"] != "v" {
		t.Fatalf("nested map not converted: %#v", list[2])
	}
}
