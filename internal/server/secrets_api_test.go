// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func newSecretsTestServer(t *testing.T) (*Server, *metadata.Metadata, context.Context) {
	t.Helper()
	t.Setenv("OPENRUN_HOME", t.TempDir())
	ctx := context.Background()
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	config := &types.ServerConfig{
		Metadata: types.MetadataConfig{
			DBConnection: "sqlite:" + filepath.Join(t.TempDir(), "metadata.db"),
			AutoUpgrade:  true,
		},
	}
	db, err := metadata.NewMetadata(logger, config)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	t.Cleanup(db.Close)

	secretManager, err := system.NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "env", config)
	if err != nil {
		t.Fatalf("new secret manager: %v", err)
	}
	if err := secretManager.BindDBStores(ctx, db); err != nil {
		t.Fatalf("bind db stores: %v", err)
	}

	server := &Server{
		Logger:       logger,
		staticConfig: config,
		db:           db,
		rbacManager: &rbac.RBACManager{
			Logger:     logger,
			RbacConfig: &types.RBACConfig{},
		},
	}
	server.secretsManager.Store(secretManager)
	return server, db, ctx
}

func TestSecretAPIs(t *testing.T) {
	server, _, ctx := newSecretsTestServer(t)

	// Create with a generated name
	response, err := server.CreateSecret(ctx, &types.CreateSecretRequest{
		Prefix:      "myapp_dbpass",
		Value:       "s3cret",
		Description: "db password",
	}, false)
	testutil.AssertNoError(t, err)
	if !strings.HasPrefix(response.Name, "myapp_dbpass_") {
		t.Fatalf("unexpected generated name %s", response.Name)
	}
	testutil.AssertEqualsString(t, "ref", `{{secret_from "db" "`+response.Name+`"}}`, response.SecretRef)

	// The reference resolves through app template evaluation
	resolved, err := server.AppEvalTemplate([][]string{{"regex:.*"}}, "", response.SecretRef)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "resolved", "s3cret", resolved)

	// List and get
	infos, err := server.ListSecrets(ctx, "", "myapp_*")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "list", 1, len(infos))
	testutil.AssertEqualsString(t, "description", "db password", infos[0].Description)

	getResponse, err := server.GetSecret(ctx, "", response.Name, false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "no value without reveal", "", getResponse.Value)

	getResponse, err = server.GetSecret(ctx, "", response.Name, true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "revealed", "s3cret", getResponse.Value)

	// Rekey is a no-op when everything uses the active key
	rekeyResponse, err := server.RekeySecrets(ctx, "")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "rekeyed", 0, rekeyResponse.Rekeyed)
	testutil.AssertEqualsInt(t, "skipped", 0, rekeyResponse.Skipped)

	// Delete
	testutil.AssertNoError(t, server.DeleteSecret(ctx, "", response.Name))
	_, err = server.GetSecret(ctx, "", response.Name, false)
	testutil.AssertEqualsError(t, "deleted", err, types.ErrSecretNotFound)
}

func TestDynamicSecretBindFailureRejected(t *testing.T) {
	server, _, ctx := newSecretsTestServer(t)
	server.staticConfig.Secret = map[string]types.SecretConfig{"db": {}}

	_, err := server.CreateSecret(ctx, &types.CreateSecretRequest{Name: "before", Value: "v1"}, false)
	testutil.AssertNoError(t, err)

	// Overwrite the auto key file: the next manager rebuild fails its key
	// check against the stored secrets
	keyPath := filepath.Join(os.Getenv("OPENRUN_HOME"), "config", "secret.key")
	newKey := "k9:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	testutil.AssertNoError(t, os.WriteFile(keyPath, []byte(newKey), 0600))

	// A dynamic [secret] change rebuilds the manager. The bind failure must
	// reject the runtime update instead of swapping in a disabled manager
	dyn := &types.DynamicConfig{Entries: map[string]map[string]map[string]any{
		"secret": {"env": {}},
	}}
	err = server.applyDynamicConfig(ctx, dyn, true)
	if err == nil || !strings.Contains(err.Error(), "rejecting config update") {
		t.Fatalf("expected bind rejection, got %v", err)
	}

	// The previous manager keeps serving stored secrets
	get, err := server.GetSecret(ctx, "", "before", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "v1", get.Value)

	// A rejected update must not leave the rejected request's RBAC rules
	// live: updateDynamicConfigCache restores the previous RBAC config
	server.dynamicConfig = &types.DynamicConfig{}
	dyn.RBAC = types.RBACConfig{Enabled: true, Groups: map[string][]string{"g1": {"user1"}}}
	err = server.updateDynamicConfigCache(ctx, dyn)
	if err == nil || !strings.Contains(err.Error(), "rejecting config update") {
		t.Fatalf("expected bind rejection, got %v", err)
	}
	if server.rbacManager.RbacConfig.Enabled || len(server.rbacManager.RbacConfig.Groups) != 0 {
		t.Fatalf("rbac config not rolled back after rejected update: %+v", server.rbacManager.RbacConfig)
	}

	// At startup the same failure is nonfatal: the manager is swapped in
	// with the db provider disabled, matching NewServer's own bind behavior
	err = server.applyDynamicConfig(ctx, dyn, false)
	testutil.AssertNoError(t, err)
	_, err = server.GetSecret(ctx, "", "before", true)
	testutil.AssertErrorContains(t, err, "not in the configured key material")
}

func TestGitAuthSecretResolution(t *testing.T) {
	server, _, ctx := newSecretsTestServer(t)

	_, err := server.CreateSecret(ctx, &types.CreateSecretRequest{
		Name:  "gitauth_key",
		Value: "-----BEGIN OPENSSH PRIVATE KEY-----",
	}, false)
	testutil.AssertNoError(t, err)

	// {{secret}} references in git auth entries resolve at loadGitKey time
	// (the db provider is not bound when the static config is processed)
	server.staticConfig.GitAuth = map[string]types.GitAuthEntry{
		"mykey": {
			PrivateKey: `{{secret_from "db" "gitauth_key"}}`,
			Password:   "plainpass",
		},
	}

	entry, err := server.loadGitKey("mykey")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "resolved key", "-----BEGIN OPENSSH PRIVATE KEY-----", string(entry.key))
	testutil.AssertEqualsString(t, "password", "plainpass", entry.password)
	testutil.AssertEqualsBool(t, "ssh", true, entry.usingSSH)
	testutil.AssertEqualsString(t, "user", "git", entry.user)

	// The resolved key is not written back into the config
	testutil.AssertEqualsString(t, "config unchanged", `{{secret_from "db" "gitauth_key"}}`,
		server.staticConfig.GitAuth["mykey"].PrivateKey)
}
