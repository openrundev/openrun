// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// fakeSecretStore is an in-memory SecretStore for tests
type fakeSecretStore struct {
	mu      sync.Mutex
	entries map[string]*types.SecretEntry
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{entries: map[string]*types.SecretEntry{}}
}

func copyEntry(entry *types.SecretEntry) *types.SecretEntry {
	ret := *entry
	return &ret
}

func (f *fakeSecretStore) GetSecretEntry(ctx context.Context, name string) (*types.SecretEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.entries[name]
	if !ok {
		return nil, types.ErrSecretNotFound
	}
	return copyEntry(entry), nil
}

func (f *fakeSecretStore) InsertSecretEntry(ctx context.Context, entry *types.SecretEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.entries[entry.Name]; ok {
		return types.ErrSecretExists
	}
	stored := copyEntry(entry)
	stored.CreateTime = time.Now()
	stored.UpdateTime = stored.CreateTime
	f.entries[entry.Name] = stored
	return nil
}

func (f *fakeSecretStore) UpdateSecretEntry(ctx context.Context, entry *types.SecretEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.entries[entry.Name]
	if !ok {
		return types.ErrSecretNotFound
	}
	stored := copyEntry(entry)
	stored.CreateTime = existing.CreateTime
	stored.CreatedBy = existing.CreatedBy
	stored.UpdateTime = time.Now()
	f.entries[entry.Name] = stored
	return nil
}

func (f *fakeSecretStore) UpdateSecretEntryIfUnchanged(ctx context.Context, entry *types.SecretEntry, prevKeyId string, prevNonce []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.entries[entry.Name]
	if !ok || existing.KeyId != prevKeyId || string(existing.Nonce) != string(prevNonce) {
		return false, nil
	}
	stored := copyEntry(entry)
	stored.CreateTime = existing.CreateTime
	stored.CreatedBy = existing.CreatedBy
	stored.UpdateTime = time.Now()
	f.entries[entry.Name] = stored
	return true, nil
}

func (f *fakeSecretStore) DeleteSecretEntry(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.entries[name]; !ok {
		return types.ErrSecretNotFound
	}
	delete(f.entries, name)
	return nil
}

func (f *fakeSecretStore) ListSecretEntries(ctx context.Context, includeValues bool) ([]*types.SecretEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries := make([]*types.SecretEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		copied := copyEntry(entry)
		if !includeValues {
			copied.Value = nil
			copied.Nonce = nil
		}
		entries = append(entries, copied)
	}
	return entries, nil
}

var _ SecretStore = &fakeSecretStore{}

// setupDBSecretManager creates a SecretManager with the db provider bound to
// an in-memory store, with OPENRUN_HOME pointing at a temp dir for auto keys
func setupDBSecretManager(t *testing.T, secretConfig map[string]types.SecretConfig, defaultProvider string) (*SecretManager, *fakeSecretStore) {
	t.Helper()
	t.Setenv("OPENRUN_HOME", t.TempDir())

	if secretConfig == nil {
		secretConfig = map[string]types.SecretConfig{"db": {}}
	}
	s, err := NewSecretManager(context.Background(), secretConfig, defaultProvider, &types.ServerConfig{})
	testutil.AssertNoError(t, err)

	store := newFakeSecretStore()
	err = s.BindDBStores(context.Background(), store)
	testutil.AssertNoError(t, err)
	return s, store
}

func TestParseSecretKeyMaterial(t *testing.T) {
	key1 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	key2bytes := make([]byte, 32)
	key2bytes[0] = 1
	key2 := base64.StdEncoding.EncodeToString(key2bytes)

	// Bare key gets the id "default"
	keys, order, err := parseSecretKeyMaterial(key1 + "\n")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "keys", 1, len(keys))
	testutil.AssertEqualsString(t, "active", "default", order[0])

	// Multiple entries, newline and comma separated, first is active
	keys, order, err = parseSecretKeyMaterial("k2:" + key2 + ",k1:" + key1 + "\n")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "keys", 2, len(keys))
	testutil.AssertEqualsString(t, "active", "k2", order[0])

	_, _, err = parseSecretKeyMaterial("")
	testutil.AssertErrorContains(t, err, "no keys found")

	_, _, err = parseSecretKeyMaterial("k1:notbase64!!")
	testutil.AssertErrorContains(t, err, "not valid base64")

	_, _, err = parseSecretKeyMaterial("k1:" + base64.StdEncoding.EncodeToString(make([]byte, 16)))
	testutil.AssertErrorContains(t, err, "must be 32 bytes")

	_, _, err = parseSecretKeyMaterial("k1:" + key1 + "\nk1:" + key2)
	testutil.AssertErrorContains(t, err, "duplicate key id")
}

func TestDBSecretRoundtrip(t *testing.T) {
	s, store := setupDBSecretManager(t, nil, "db")
	ctx := context.Background()

	// Auto key file is created
	keyPath := os.ExpandEnv(secretKeyFile)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file %s: %v", keyPath, err)
	}

	response, err := s.CreateSecret(ctx, &types.CreateSecretRequest{
		Prefix:      "myapp_dbpass",
		Value:       "s3cret-value",
		Description: "test secret",
	}, "testuser", false)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(response.Name, "myapp_dbpass_") {
		t.Fatalf("unexpected generated name %s", response.Name)
	}
	testutil.AssertEqualsString(t, "provider", "db", response.Provider)
	testutil.AssertEqualsString(t, "ref", fmt.Sprintf("{{secret %q}}", response.Name), response.SecretRef)

	// Value resolves through the template functions
	resolved, err := s.EvalTemplate(response.SecretRef)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "s3cret-value", resolved)

	resolved, err = s.EvalTemplate(fmt.Sprintf(`{{secret_from "db" %q}}`, response.Name))
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "s3cret-value", resolved)

	// Reveal returns the value, list does not
	getResponse, err := s.GetSecretInfo(ctx, "db", response.Name, true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "reveal", "s3cret-value", getResponse.Value)
	testutil.AssertEqualsString(t, "created by", "testuser", getResponse.CreatedBy)

	infos, err := s.ListSecrets(ctx, "db", "")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "list", 1, len(infos))
	testutil.AssertEqualsString(t, "description", "test secret", infos[0].Description)

	infos, err = s.ListSecrets(ctx, "db", "other_*")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsInt(t, "list glob", 0, len(infos))

	// Restarting with the same key file (fresh manager, same store) decrypts
	// the existing values
	s2, err := NewSecretManager(context.Background(), map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	err = s2.BindDBStores(ctx, store)
	testutil.AssertNoError(t, err)
	restartGet, err := s2.GetSecretInfo(ctx, "db", response.Name, true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value after restart", "s3cret-value", restartGet.Value)

	err = s.DeleteSecret(ctx, "db", response.Name)
	testutil.AssertNoError(t, err)
	_, err = s.GetSecretInfo(ctx, "db", response.Name, false)
	testutil.AssertEqualsError(t, "deleted", err, types.ErrSecretNotFound)
}

func TestDBSecretExplicitNameAndUpdate(t *testing.T) {
	s, _ := setupDBSecretManager(t, map[string]types.SecretConfig{"db": {}, "env": {}}, "env")
	ctx := context.Background()

	response, err := s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name:  "mytoken",
		Value: "value1",
	}, "testuser", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "name", "mytoken", response.Name)
	// db is not the default provider, secret_from reference is returned
	testutil.AssertEqualsString(t, "ref", `{{secret_from "db" "mytoken"}}`, response.SecretRef)

	// Create again without update fails
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name:  "mytoken",
		Value: "value2",
	}, "testuser", false)
	testutil.AssertErrorContains(t, err, "already exists")

	// Update overwrites
	response, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name:  "mytoken",
		Value: "value2",
	}, "testuser", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "updated", true, response.Updated)

	getResponse, err := s.GetSecretInfo(ctx, "db", "mytoken", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "value2", getResponse.Value)

	// Update without a description keeps the existing description; a new
	// description overwrites it
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name: "mytoken", Value: "value3", Description: "desc1"}, "testuser", true)
	testutil.AssertNoError(t, err)
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name: "mytoken", Value: "value4"}, "testuser", true)
	testutil.AssertNoError(t, err)
	getResponse, err = s.GetSecretInfo(ctx, "db", "mytoken", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "kept description", "desc1", getResponse.Description)
	testutil.AssertEqualsString(t, "value", "value4", getResponse.Value)
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name: "mytoken", Value: "value5", Description: "desc2"}, "testuser", true)
	testutil.AssertNoError(t, err)
	getResponse, err = s.GetSecretInfo(ctx, "db", "mytoken", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "new description", "desc2", getResponse.Description)

	// Validation errors
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "bad name", Value: "v"}, "u", false)
	testutil.AssertErrorContains(t, err, "invalid secret name")
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Prefix: "1badprefix", Value: "v"}, "u", false)
	testutil.AssertErrorContains(t, err, "invalid secret prefix")
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "a", Prefix: "b", Value: "v"}, "u", false)
	testutil.AssertErrorContains(t, err, "cannot both be set")
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "a"}, "u", false)
	testutil.AssertErrorContains(t, err, "value is required")
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Value: "v"}, "u", false)
	testutil.AssertErrorContains(t, err, "name or prefix is required")
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "a", Value: "v", Provider: "env"}, "u", false)
	testutil.AssertErrorContains(t, err, "does not support storing secrets")
	// Update requires an explicit name: with a prefix it would silently create
	// another randomly named secret instead of updating anything
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Prefix: "myprefix", Value: "v"}, "u", true)
	testutil.AssertErrorContains(t, err, "update requires an explicit name")
}

func TestDBSecretSingleProvider(t *testing.T) {
	t.Setenv("OPENRUN_HOME", t.TempDir())
	_, err := NewSecretManager(context.Background(),
		map[string]types.SecretConfig{"db": {}, "db_second": {}}, "db", &types.ServerConfig{})
	testutil.AssertErrorContains(t, err, "only one db secret provider")
}

// racingStore triggers a callback before an insert, to simulate a concurrent
// writer winning a create race
type racingStore struct {
	*fakeSecretStore
	onInsert func()
}

func (r *racingStore) InsertSecretEntry(ctx context.Context, entry *types.SecretEntry) error {
	if r.onInsert != nil {
		race := r.onInsert
		r.onInsert = nil
		race()
	}
	return r.fakeSecretStore.InsertSecretEntry(ctx, entry)
}

func TestDBSecretUpdateCreateRace(t *testing.T) {
	t.Setenv("OPENRUN_HOME", t.TempDir())
	ctx := context.Background()
	s, err := NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	store := &racingStore{fakeSecretStore: newFakeSecretStore()}
	testutil.AssertNoError(t, s.BindDBStores(ctx, store))

	// An update of a missing name attempts a create; a concurrent create of
	// the same name wins just before the insert. The update must retry and
	// preserve the winner's description instead of clobbering it
	store.onInsert = func() {
		_, cerr := s.CreateSecret(ctx, &types.CreateSecretRequest{
			Name: "raced", Value: "winner-value", Description: "winner-desc"}, "winner-user", false)
		testutil.AssertNoError(t, cerr)
	}

	response, err := s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "raced", Value: "loser-value"}, "loser-user", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsBool(t, "updated", true, response.Updated)

	get, err := s.GetSecretInfo(ctx, "db", "raced", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "loser-value", get.Value)
	testutil.AssertEqualsString(t, "description kept", "winner-desc", get.Description)
	testutil.AssertEqualsString(t, "created by kept", "winner-user", get.CreatedBy)
}

func TestDBSecretInvalidGlobAndCorruptRows(t *testing.T) {
	s, store := setupDBSecretManager(t, nil, "db")
	ctx := context.Background()

	// Invalid glob errors even when no secrets are stored
	_, err := s.ListSecrets(ctx, "db", "bad[")
	testutil.AssertErrorContains(t, err, "invalid glob pattern")

	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s1", Value: "v1"}, "u", false)
	testutil.AssertNoError(t, err)

	// A corrupt nonce must produce a decryption error, not a panic
	store.mu.Lock()
	store.entries["s1"].Nonce = []byte{1, 2, 3}
	store.mu.Unlock()
	_, err = s.GetSecretInfo(ctx, "db", "s1", true)
	testutil.AssertErrorContains(t, err, "invalid nonce length")

	// Internal rows are not readable through the template functions
	_, err = s.EvalTemplate(`{{secret_from "db" "openrun:keycheck:db"}}`)
	testutil.AssertErrorContains(t, err, "secret not found")
}

func TestDBSecretBinaryValue(t *testing.T) {
	s, _ := setupDBSecretManager(t, nil, "db")
	ctx := context.Background()

	binary := []byte{0xff, 0xfe, 0x00, 0x01}
	response, err := s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name:       "mycert",
		Value:      base64.StdEncoding.EncodeToString(binary),
		Encoding:   "base64",
		SourceFile: "ca.der",
	}, "testuser", false)
	testutil.AssertNoError(t, err)

	// Reveal returns base64 for binary values
	getResponse, err := s.GetSecretInfo(ctx, "db", response.Name, true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "encoding", "base64", getResponse.Encoding)
	testutil.AssertEqualsString(t, "value", base64.StdEncoding.EncodeToString(binary), getResponse.Value)
	testutil.AssertEqualsString(t, "source file", "ca.der", getResponse.SourceFile)

	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{
		Name: "bad", Value: "not-base64!!", Encoding: "base64"}, "u", false)
	testutil.AssertErrorContains(t, err, "not valid base64")
}

func TestDBSecretAADTamper(t *testing.T) {
	s, store := setupDBSecretManager(t, nil, "db")
	ctx := context.Background()

	_, err := s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "secret1", Value: "value1"}, "u", false)
	testutil.AssertNoError(t, err)

	// Move the ciphertext to a different name in the store; decryption must
	// fail since the name is authenticated data
	store.mu.Lock()
	entry := store.entries["secret1"]
	moved := copyEntry(entry)
	moved.Name = "secret2"
	store.entries["secret2"] = moved
	store.mu.Unlock()

	provider := s.providers["db"]
	_, err = provider.GetSecret(ctx, "secret2")
	testutil.AssertErrorContains(t, err, "error decrypting secret")

	// The original row still decrypts
	value, err := provider.GetSecret(ctx, "secret1")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "value1", value)
}

func TestDBSecretKeyCheck(t *testing.T) {
	t.Setenv("OPENRUN_HOME", t.TempDir())
	ctx := context.Background()

	s, err := NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	store := newFakeSecretStore()
	testutil.AssertNoError(t, s.BindDBStores(ctx, store))

	// Change the key file and bind against the same store: key check must fail
	keyPath := os.ExpandEnv(secretKeyFile)
	newKey := "k9:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	testutil.AssertNoError(t, os.WriteFile(keyPath, []byte(newKey), 0600))

	s2, err := NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	err = s2.BindDBStores(ctx, store)
	testutil.AssertErrorContains(t, err, "not in the configured key material")

	// After a failed bind the provider is disabled: operations fail with the
	// bind error instead of decrypting garbage
	_, err = s2.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s1", Value: "v1"}, "u", false)
	testutil.AssertErrorContains(t, err, "not in the configured key material")

	// Deleting the key file generates a new key, which fails against the old rows
	testutil.AssertNoError(t, os.Remove(keyPath))
	s3, err := NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	err = s3.BindDBStores(ctx, store)
	testutil.AssertErrorContains(t, err, "not in the configured key material")
}

func TestDBSecretKeyTemplate(t *testing.T) {
	key1 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	t.Setenv("OPENRUN_TEST_SECRET_KEY", "mk1:"+key1)

	secretConfig := map[string]types.SecretConfig{
		"db":  {"key": `{{secret_from "env" "OPENRUN_TEST_SECRET_KEY"}}`},
		"env": {},
	}
	s, _ := setupDBSecretManager(t, secretConfig, "db")
	ctx := context.Background()

	// No auto key file is created when the key comes from a reference
	if _, err := os.Stat(os.ExpandEnv(secretKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("key file should not exist, stat err: %v", err)
	}

	response, err := s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s1", Value: "v1"}, "u", false)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "key id", "mk1", func() string {
		info, err := s.GetSecretInfo(ctx, "db", response.Name, false)
		testutil.AssertNoError(t, err)
		return info.KeyId
	}())

	// Referencing the db provider itself for the key fails with a clear error
	badConfig := map[string]types.SecretConfig{
		"db": {"key": `{{secret_from "db" "somekey"}}`},
	}
	t.Setenv("OPENRUN_HOME", t.TempDir())
	sBad, err := NewSecretManager(ctx, badConfig, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	err = sBad.BindDBStores(ctx, newFakeSecretStore())
	testutil.AssertErrorContains(t, err, "not initialized")

	// Invalid key specs are rejected at configure time
	_, err = NewSecretManager(ctx, map[string]types.SecretConfig{"db": {"key": "env:FOO"}}, "db", &types.ServerConfig{})
	testutil.AssertErrorContains(t, err, `must be "auto" or a {{secret_from ...}} template`)
}

func TestDBSecretRekey(t *testing.T) {
	key1 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	key2 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	t.Setenv("OPENRUN_TEST_SECRET_KEY", "mk1:"+key1)

	secretConfig := map[string]types.SecretConfig{
		"db":  {"key": `{{secret_from "env" "OPENRUN_TEST_SECRET_KEY"}}`},
		"env": {},
	}
	s, store := setupDBSecretManager(t, secretConfig, "db")
	ctx := context.Background()

	_, err := s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s1", Value: "v1"}, "u", false)
	testutil.AssertNoError(t, err)
	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s2", Value: "v2"}, "u", false)
	testutil.AssertNoError(t, err)

	// Add a row sealed with an unknown key id, it must be skipped by rekey
	store.mu.Lock()
	store.entries["foreign"] = &types.SecretEntry{Name: "foreign", Value: []byte("x"), Nonce: []byte("y"), KeyId: "other"}
	store.mu.Unlock()

	// Rotate: prepend mk2 as the active key, keep mk1 for decryption
	t.Setenv("OPENRUN_TEST_SECRET_KEY", "mk2:"+key2+",mk1:"+key1)
	s2, err := NewSecretManager(ctx, secretConfig, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, s2.BindDBStores(ctx, store))

	// Old values still readable before rekey
	value, err := s2.GetSecretInfo(ctx, "db", "s1", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "v1", value.Value)

	response, err := s2.RekeySecrets(ctx, "db")
	testutil.AssertNoError(t, err)
	// s1 and s2 move to mk2; the internal key check row is re-encrypted but
	// not counted, the foreign row is skipped
	testutil.AssertEqualsInt(t, "rekeyed", 2, response.Rekeyed)
	testutil.AssertEqualsInt(t, "skipped", 1, response.Skipped)
	keycheck, err := store.GetSecretEntry(ctx, "openrun:keycheck:db")
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "keycheck rekeyed", "mk2", keycheck.KeyId)

	info, err := s2.GetSecretInfo(ctx, "db", "s1", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "key id", "mk2", info.KeyId)
	testutil.AssertEqualsString(t, "value", "v1", info.Value)

	// Now the old key can be dropped
	t.Setenv("OPENRUN_TEST_SECRET_KEY", "mk2:"+key2)
	s3, err := NewSecretManager(ctx, secretConfig, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, s3.BindDBStores(ctx, store))
	info, err = s3.GetSecretInfo(ctx, "db", "s2", true)
	testutil.AssertNoError(t, err)
	testutil.AssertEqualsString(t, "value", "v2", info.Value)
}

func TestDBSecretUnboundProvider(t *testing.T) {
	t.Setenv("OPENRUN_HOME", t.TempDir())
	ctx := context.Background()

	s, err := NewSecretManager(ctx, map[string]types.SecretConfig{"db": {}}, "db", &types.ServerConfig{})
	testutil.AssertNoError(t, err)

	// Config values resolved before the metadata db is up cannot use the db provider
	_, err = s.EvalTemplate(`{{secret_from "db" "somekey"}}`)
	testutil.AssertErrorContains(t, err, "not initialized")

	_, err = s.CreateSecret(ctx, &types.CreateSecretRequest{Name: "s1", Value: "v1"}, "u", false)
	testutil.AssertErrorContains(t, err, "not initialized")
}

func TestDBSecretAutoKeyFilePermissions(t *testing.T) {
	setupDBSecretManager(t, nil, "db")

	keyPath := filepath.Join(os.Getenv("OPENRUN_HOME"), "config", "secret.key")
	info, err := os.Stat(keyPath)
	testutil.AssertNoError(t, err)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected key file mode 0600, got %v", info.Mode().Perm())
	}
}
