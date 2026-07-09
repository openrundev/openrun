// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/types"
)

// SecretStore is the persistence interface for the db secret provider,
// implemented by the metadata database layer. Values are encrypted by the
// provider before being stored
type SecretStore interface {
	GetSecretEntry(ctx context.Context, name string) (*types.SecretEntry, error)
	InsertSecretEntry(ctx context.Context, entry *types.SecretEntry) error
	UpdateSecretEntry(ctx context.Context, entry *types.SecretEntry) error
	// UpdateSecretEntryIfUnchanged updates the row only if its current key_id
	// and nonce still match prevKeyId/prevNonce, returning whether a row was
	// updated. Used by rekey so a concurrent value update is never overwritten
	// with re-encrypted stale plaintext
	UpdateSecretEntryIfUnchanged(ctx context.Context, entry *types.SecretEntry, prevKeyId string, prevNonce []byte) (bool, error)
	DeleteSecretEntry(ctx context.Context, name string) error
	// ListSecretEntries returns all rows sorted by name. With includeValues
	// false, the Value and Nonce fields are not fetched (listing does not need
	// the ciphertext)
	ListSecretEntries(ctx context.Context, includeValues bool) ([]*types.SecretEntry, error)
}

const (
	// secretAADPrefix is prepended to the secret name to form the GCM
	// additional authenticated data, so a ciphertext cannot be moved to a
	// different row in the database without decryption failing
	secretAADPrefix = "openrun:secret:"

	// secretReservedPrefix marks internal rows in the secrets table. User
	// secret names cannot contain ":" so there is no collision
	secretReservedPrefix = "openrun:"

	// secretKeyCheckValue is the known plaintext stored per provider to detect
	// a lost or changed master key at startup instead of per-secret failures
	secretKeyCheckValue = "openrun-key-check"

	// MaxSecretValueBytes is the max size of a secret value (after base64
	// decoding). This is a config secrets store, not a blob store
	MaxSecretValueBytes = 1 << 20

	secretKeyFile = "$OPENRUN_HOME/config/secret.key"

	// secretSuffixChars is the charset for generated secret name suffixes and
	// auto key ids
	secretSuffixChars = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// dbSecretProvider is a secret provider that stores AES-256-GCM encrypted
// values in the metadata database. The master key lives outside the database:
// either auto generated in $OPENRUN_HOME/config/secret.key or resolved from a
// {{secret}} reference to another (non db) provider. The provider is created
// unbound; the store and key are bound after the metadata database is
// initialized since the database connection setup itself can use secrets
type dbSecretProvider struct {
	name    string // provider name from the config (db or db_*)
	keySpec string // "auto" or a {{secret}}/{{secret_from}} template

	mu       sync.RWMutex
	store    SecretStore
	aeads    map[string]cipher.AEAD // key id -> AEAD built from the 32 byte master key
	activeId string                 // key id used for new writes
	bindErr  error                  // key load/verify error from bind; all operations fail with it
}

func (d *dbSecretProvider) Configure(ctx context.Context, conf map[string]any) error {
	keySpec := "auto"
	if key, ok := conf["key"]; ok {
		keyStr, ok := key.(string)
		if !ok {
			return fmt.Errorf("secret provider %s: key must be a string", d.name)
		}
		if keyStr != "" {
			keySpec = keyStr
		}
	}

	if keySpec != "auto" && !strings.Contains(keySpec, "{{") {
		return fmt.Errorf("secret provider %s: key must be \"auto\" or a {{secret_from ...}} template reference", d.name)
	}
	d.keySpec = keySpec
	return nil
}

// bind connects the provider to the secret store and loads the master key.
// Called once the metadata database is up. evalTemplate resolves a
// {{secret}} key reference through the other configured providers. On
// failure the provider is left disabled (all operations return the bind
// error) instead of blocking server startup: a node whose key does not match
// the stored secrets (for example a multi node setup still on auto keys)
// must not crash loop when the app workload does not use stored secrets
func (d *dbSecretProvider) bind(ctx context.Context, store SecretStore, evalTemplate func(string) (string, error)) error {
	err := d.bindInt(ctx, store, evalTemplate)
	if err != nil {
		err = fmt.Errorf("secret provider %s: %w", d.name, err)
		d.mu.Lock()
		d.bindErr = err
		d.mu.Unlock()
	}
	return err
}

func (d *dbSecretProvider) bindInt(ctx context.Context, store SecretStore, evalTemplate func(string) (string, error)) error {
	material, err := d.loadKeyMaterial(evalTemplate)
	if err != nil {
		return err
	}

	keys, order, err := parseSecretKeyMaterial(material)
	if err != nil {
		return err
	}

	// The AEADs are built once here: the key set is immutable after bind, so
	// seal/unseal on the request path do not pay the AES key schedule setup
	aeads := make(map[string]cipher.AEAD, len(keys))
	for keyId, key := range keys {
		if aeads[keyId], err = newSecretGCM(key); err != nil {
			return err
		}
	}

	d.mu.Lock()
	d.store = store
	d.aeads = aeads
	d.activeId = order[0]
	d.mu.Unlock()

	return d.verifyKeyCheck(ctx)
}

// loadKeyMaterial returns the raw key material for the provider. For "auto"
// the key is read from (or generated into) $OPENRUN_HOME/config/secret.key
func (d *dbSecretProvider) loadKeyMaterial(evalTemplate func(string) (string, error)) (string, error) {
	if d.keySpec != "auto" {
		material, err := evalTemplate(d.keySpec)
		if err != nil {
			return "", fmt.Errorf("error resolving key reference: %w", err)
		}
		if strings.TrimSpace(material) == "" {
			return "", fmt.Errorf("key reference %q resolved to an empty value", d.keySpec)
		}
		return material, nil
	}

	keyPath := os.ExpandEnv(secretKeyFile)
	material, err := os.ReadFile(keyPath)
	if err == nil {
		return string(material), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("error reading key file %s: %w", keyPath, err)
	}

	// Generate a new master key on first use
	newKey, err := passwd.GenerateRandomKey(32)
	if err != nil {
		return "", err
	}
	suffix, err := passwd.GenerateRandString(8, secretSuffixChars)
	if err != nil {
		return "", err
	}
	newMaterial := "k" + suffix + ":" + base64.StdEncoding.EncodeToString(newKey) + "\n"

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("error creating config directory for key file: %w", err)
	}

	// Write to a temp file, then hard link it to the final name. The link
	// fails if the file already exists, so concurrent first startups sharing
	// OPENRUN_HOME cannot clobber each other's key, and the loser always
	// reads a fully written file (never a created-but-not-yet-written one)
	tmp, err := os.CreateTemp(dir, ".secret.key.tmp*") // CreateTemp uses mode 0600
	if err != nil {
		return "", fmt.Errorf("error creating key file %s: %w", keyPath, err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	if _, err := tmp.Write([]byte(newMaterial)); err != nil {
		tmp.Close() //nolint:errcheck
		return "", fmt.Errorf("error writing key file %s: %w", keyPath, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("error writing key file %s: %w", keyPath, err)
	}
	if err := os.Link(tmp.Name(), keyPath); err != nil {
		if os.IsExist(err) {
			// Lost the race with a concurrent first startup; use the winner's key
			material, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				return "", fmt.Errorf("error reading key file %s: %w", keyPath, readErr)
			}
			return string(material), nil
		}
		return "", fmt.Errorf("error creating key file %s: %w", keyPath, err)
	}
	return newMaterial, nil
}

// parseSecretKeyMaterial parses master key material: one or more entries
// separated by newlines or commas, each "<key_id>:<base64 32 byte key>" or a
// bare base64 32 byte key (key id "default"). The first entry is the active
// key used for new writes; all entries can decrypt
func parseSecretKeyMaterial(material string) (map[string][]byte, []string, error) {
	keys := map[string][]byte{}
	order := []string{}
	for _, line := range strings.FieldsFunc(material, func(r rune) bool { return r == '\n' || r == ',' }) {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		keyId := "default"
		keyStr := entry
		if id, key, found := strings.Cut(entry, ":"); found {
			keyId = strings.TrimSpace(id)
			keyStr = strings.TrimSpace(key)
		}
		if keyId == "" {
			return nil, nil, fmt.Errorf("empty key id in key material")
		}

		key, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, nil, fmt.Errorf("key %s is not valid base64: %w", keyId, err)
		}
		if len(key) != 32 {
			return nil, nil, fmt.Errorf("key %s must be 32 bytes after base64 decoding, got %d", keyId, len(key))
		}
		if _, ok := keys[keyId]; ok {
			return nil, nil, fmt.Errorf("duplicate key id %s in key material", keyId)
		}
		keys[keyId] = key
		order = append(order, keyId)
	}

	if len(order) == 0 {
		return nil, nil, fmt.Errorf("no keys found in key material")
	}
	return keys, order, nil
}

// verifyKeyCheck verifies the master key against a known plaintext row,
// creating the row on first startup. This fails fast with a clear error when
// the key file is lost or the key value changed
func (d *dbSecretProvider) verifyKeyCheck(ctx context.Context) error {
	checkName := secretReservedPrefix + "keycheck:" + d.name

	verify := func(entry *types.SecretEntry) error {
		if _, ok := d.aeads[entry.KeyId]; !ok {
			return fmt.Errorf("stored secrets were encrypted with key id %q which is not in the configured key material; "+
				"restore the previous key or delete the stored secrets", entry.KeyId)
		}
		if _, err := d.unseal(entry); err != nil {
			return fmt.Errorf("master key does not match the key previously used for stored secrets; "+
				"restore the previous key or delete the stored secrets: %w", err)
		}
		return nil
	}

	entry, err := d.store.GetSecretEntry(ctx, checkName)
	if err == nil {
		return verify(entry)
	}
	if err != types.ErrSecretNotFound {
		return err
	}

	newEntry, err := d.seal(checkName, []byte(secretKeyCheckValue), types.SecretMetadata{}, "")
	if err != nil {
		return err
	}
	err = d.store.InsertSecretEntry(ctx, newEntry)
	if err == nil {
		return nil
	}
	if err != types.ErrSecretExists {
		return err
	}
	// Concurrent insert from another server, verify against the stored row
	entry, err = d.store.GetSecretEntry(ctx, checkName)
	if err != nil {
		return err
	}
	return verify(entry)
}

// seal encrypts value with the active key. The secret name is used as GCM
// additional authenticated data
func (d *dbSecretProvider) seal(name string, value []byte, meta types.SecretMetadata, createdBy string) (*types.SecretEntry, error) {
	aead, ok := d.aeads[d.activeId]
	if !ok {
		return nil, fmt.Errorf("active key %s not found", d.activeId)
	}
	return sealSecret(aead, d.activeId, name, value, meta, createdBy)
}

// sealSecret encrypts value with the given AEAD and key id. The secret name
// is used as GCM additional authenticated data
func sealSecret(aead cipher.AEAD, keyId, name string, value []byte, meta types.SecretMetadata, createdBy string) (*types.SecretEntry, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, value, []byte(secretAADPrefix+name))
	return &types.SecretEntry{
		Name:      name,
		Value:     ciphertext,
		Nonce:     nonce,
		KeyId:     keyId,
		CreatedBy: createdBy,
		Metadata:  meta,
	}, nil
}

// unseal decrypts a secret row using the key identified by its key id
func (d *dbSecretProvider) unseal(entry *types.SecretEntry) ([]byte, error) {
	aead, ok := d.aeads[entry.KeyId]
	if !ok {
		return nil, fmt.Errorf("secret %s uses key id %q which is not in the configured key material", entry.Name, entry.KeyId)
	}
	return unsealSecret(aead, entry)
}

// unsealSecret decrypts a secret row with the AEAD for its key id
func unsealSecret(aead cipher.AEAD, entry *types.SecretEntry) ([]byte, error) {
	// aead.Open panics (not errors) on a wrong length nonce, so a corrupt row
	// must be rejected here to surface as a decryption error
	if len(entry.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("error decrypting secret %s: invalid nonce length %d", entry.Name, len(entry.Nonce))
	}
	plaintext, err := aead.Open(nil, entry.Nonce, entry.Value, []byte(secretAADPrefix+entry.Name))
	if err != nil {
		return nil, fmt.Errorf("error decrypting secret %s: %w", entry.Name, err)
	}
	return plaintext, nil
}

func newSecretGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// checkBound returns an error if the provider has not been bound to the
// metadata database yet, or if binding failed (key load or key check error)
func (d *dbSecretProvider) checkBound() error {
	if d.bindErr != nil {
		return d.bindErr
	}
	if d.store == nil {
		return fmt.Errorf("secret provider %s is not initialized yet; the db provider cannot be used for "+
			"server config values (including its own encryption key)", d.name)
	}
	return nil
}

func (d *dbSecretProvider) GetSecret(ctx context.Context, secretName string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return "", err
	}
	if strings.HasPrefix(secretName, secretReservedPrefix) {
		// Internal rows (key check) are not readable through templates
		return "", types.ErrSecretNotFound
	}

	entry, err := d.store.GetSecretEntry(ctx, secretName)
	if err != nil {
		return "", err
	}
	plaintext, err := d.unseal(entry)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (d *dbSecretProvider) GetJoinDelimiter() string {
	return "/"
}

// CreateSecret stores a new encrypted secret, types.ErrSecretExists if the
// name is already in use
func (d *dbSecretProvider) CreateSecret(ctx context.Context, name string, value []byte, meta types.SecretMetadata, createdBy string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return err
	}

	entry, err := d.seal(name, value, meta, createdBy)
	if err != nil {
		return err
	}
	return d.store.InsertSecretEntry(ctx, entry)
}

// UpdateSecret updates an existing secret value, creating it if not present.
// An unset description keeps the existing description; SourceFile always
// reflects the new value's source. Returns true if an existing secret was
// updated
func (d *dbSecretProvider) UpdateSecret(ctx context.Context, name string, value []byte, meta types.SecretMetadata, createdBy string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return false, err
	}

	// Losing a create or delete race retries from the read, so the
	// description merge always runs against the row actually being replaced
	// (a lost create race must not clobber the winner's description)
	for range 4 {
		existing, err := d.store.GetSecretEntry(ctx, name)
		if err != nil && err != types.ErrSecretNotFound {
			return false, err
		}

		entryMeta := meta
		if existing != nil {
			entryMeta.Description = cmp.Or(entryMeta.Description, existing.Metadata.Description)
		}
		entry, err := d.seal(name, value, entryMeta, createdBy)
		if err != nil {
			return false, err
		}

		if existing == nil {
			err = d.store.InsertSecretEntry(ctx, entry)
			if err == types.ErrSecretExists {
				continue // lost a create race, re-read to merge the winner's metadata
			}
			return false, err
		}
		err = d.store.UpdateSecretEntry(ctx, entry)
		if err == types.ErrSecretNotFound {
			continue // deleted concurrently, retry as a create
		}
		return true, err
	}
	return false, fmt.Errorf("secret %s is being modified concurrently, try again", name)
}

func (d *dbSecretProvider) DeleteSecret(ctx context.Context, name string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return err
	}
	return d.store.DeleteSecretEntry(ctx, name)
}

// ListSecrets returns info about the stored secrets (never values). Internal
// rows like the key check entry are filtered out
func (d *dbSecretProvider) ListSecrets(ctx context.Context) ([]types.SecretInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return nil, err
	}

	entries, err := d.store.ListSecretEntries(ctx, false)
	if err != nil {
		return nil, err
	}
	infos := make([]types.SecretInfo, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, secretReservedPrefix) {
			continue
		}
		infos = append(infos, secretEntryInfo(entry))
	}
	return infos, nil
}

// GetSecretInfo returns info about one stored secret. With includeValue, the
// decrypted value is also returned; the row is fetched once so the info and
// the value always come from the same version
func (d *dbSecretProvider) GetSecretInfo(ctx context.Context, name string, includeValue bool) (*types.SecretInfo, []byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.checkBound(); err != nil {
		return nil, nil, err
	}

	entry, err := d.store.GetSecretEntry(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	info := secretEntryInfo(entry)
	if !includeValue {
		return &info, nil, nil
	}
	value, err := d.unseal(entry)
	if err != nil {
		return nil, nil, err
	}
	return &info, value, nil
}

func secretEntryInfo(entry *types.SecretEntry) types.SecretInfo {
	return types.SecretInfo{
		Name:        entry.Name,
		KeyId:       entry.KeyId,
		CreatedBy:   entry.CreatedBy,
		CreateTime:  entry.CreateTime,
		UpdateTime:  entry.UpdateTime,
		Description: entry.Metadata.Description,
		SourceFile:  entry.Metadata.SourceFile,
	}
}

// Rekey re-encrypts all rows not sealed with the active key. Rows sealed with
// a key id outside the configured key material are counted as skipped. Rows
// updated concurrently while the rekey runs are left to the concurrent writer
// (which seals with the active key anyway) so a value update is never
// overwritten with re-encrypted stale plaintext. Internal rows (key check)
// are re-encrypted but not counted. The provider lock is held only to
// snapshot the key state, and each row's ciphertext is fetched individually,
// so memory stays flat regardless of store size
func (d *dbSecretProvider) Rekey(ctx context.Context) (rekeyed int, skipped int, err error) {
	d.mu.RLock()
	err = d.checkBound()
	store, aeads, activeId := d.store, d.aeads, d.activeId
	d.mu.RUnlock()
	if err != nil {
		return 0, 0, err
	}
	activeAead, ok := aeads[activeId]
	if !ok {
		return 0, 0, fmt.Errorf("active key %s not found", activeId)
	}

	listed, err := store.ListSecretEntries(ctx, false)
	if err != nil {
		return 0, 0, err
	}

	for _, meta := range listed {
		internal := strings.HasPrefix(meta.Name, secretReservedPrefix)
		if meta.KeyId == activeId {
			continue
		}
		if _, ok := aeads[meta.KeyId]; !ok {
			if !internal {
				skipped++
			}
			continue
		}

		entry, err := store.GetSecretEntry(ctx, meta.Name)
		if err == types.ErrSecretNotFound {
			continue // deleted while the rekey was running
		}
		if err != nil {
			return rekeyed, skipped, err
		}
		aead, ok := aeads[entry.KeyId]
		if entry.KeyId == activeId || !ok {
			continue // rewritten while the rekey was running
		}

		plaintext, err := unsealSecret(aead, entry)
		if err != nil {
			return rekeyed, skipped, err
		}
		newEntry, err := sealSecret(activeAead, activeId, entry.Name, plaintext, entry.Metadata, entry.CreatedBy)
		if err != nil {
			return rekeyed, skipped, err
		}
		updated, err := store.UpdateSecretEntryIfUnchanged(ctx, newEntry, entry.KeyId, entry.Nonce)
		if err != nil {
			return rekeyed, skipped, err
		}
		if updated && !internal {
			rekeyed++
		}
	}
	return rekeyed, skipped, nil
}

var _ secretProvider = &dbSecretProvider{}
