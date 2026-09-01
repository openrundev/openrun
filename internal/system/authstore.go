// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// Client-side storage for openrun login credentials: the OS keychain (macOS
// Keychain, Windows Credential Manager, Linux Secret Service) via go-keyring,
// with a 0600 file fallback under $OPENRUN_HOME/config when no keyring service
// is available or OPENRUN_NO_KEYRING is set.

const keyringService = "openrun-login"

// StoredLogin is the persisted result of an openrun login flow for one server
type StoredLogin struct {
	ServerUrl     string    `json:"server_url"`
	Principal     string    `json:"principal"`
	AccessToken   string    `json:"access_token"`
	AccessExpiry  time.Time `json:"access_expiry"`
	RefreshToken  string    `json:"refresh_token"`
	TokenEndpoint string    `json:"token_endpoint"`
}

func normalizeServerUrl(serverUrl string) string {
	return strings.TrimSuffix(strings.TrimSpace(serverUrl), "/")
}

func useKeyring() bool {
	return os.Getenv("OPENRUN_NO_KEYRING") == ""
}

func loginFilePath(serverUrl string) (string, error) {
	home := os.Getenv("OPENRUN_HOME")
	if home == "" {
		return "", fmt.Errorf("OPENRUN_HOME is not set")
	}
	sum := sha256.Sum256([]byte(serverUrl))
	return filepath.Join(home, "config", "login_"+hex.EncodeToString(sum[:8])+".json"), nil
}

// SaveLogin persists the login for its server url
func SaveLogin(login *StoredLogin) error {
	login.ServerUrl = normalizeServerUrl(login.ServerUrl)
	data, err := json.Marshal(login)
	if err != nil {
		return err
	}
	if useKeyring() {
		if err := keyring.Set(keyringService, login.ServerUrl, string(data)); err == nil {
			return nil
		}
		// Fall through to the file store when no keyring service is available
	}
	path, err := loginFilePath(login.ServerUrl)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Atomic replace: a concurrent reader never sees a partial write
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadLogin returns the stored login for the server url, nil when absent
func LoadLogin(serverUrl string) *StoredLogin {
	serverUrl = normalizeServerUrl(serverUrl)
	var data string
	if useKeyring() {
		if value, err := keyring.Get(keyringService, serverUrl); err == nil {
			data = value
		}
	}
	if data == "" {
		path, err := loginFilePath(serverUrl)
		if err != nil {
			return nil
		}
		fileData, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		data = string(fileData)
	}
	var login StoredLogin
	if err := json.Unmarshal([]byte(data), &login); err != nil {
		return nil
	}
	return &login
}

// DeleteLogin removes the stored login for the server url
func DeleteLogin(serverUrl string) {
	serverUrl = normalizeServerUrl(serverUrl)
	if useKeyring() {
		_ = keyring.Delete(keyringService, serverUrl)
	}
	if path, err := loginFilePath(serverUrl); err == nil {
		_ = os.Remove(path)
	}
}

// ResolveLoginToken returns a valid access token for the server from the
// stored login, transparently refreshing (with rotation) when the access
// token is stale. Returns "" when no stored login exists or refresh fails.
// Refresh runs under a cross-process lock: refresh tokens are single-use
// (rotation), so two CLI processes refreshing concurrently would trip the
// server's reuse detection and revoke the whole login
func ResolveLoginToken(serverUrl string, skipCertCheck bool) string {
	login := LoadLogin(serverUrl)
	if login == nil {
		return ""
	}
	if login.AccessToken != "" && time.Now().Before(login.AccessExpiry) {
		return login.AccessToken
	}
	if login.RefreshToken == "" || login.TokenEndpoint == "" {
		return ""
	}

	unlock, err := acquireLoginLock(serverUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not lock login store (%s), skipping refresh\n", err)
		return ""
	}
	defer unlock()

	// Another process may have rotated while this one waited for the lock
	login = LoadLogin(serverUrl)
	if login == nil {
		return ""
	}
	if login.AccessToken != "" && time.Now().Before(login.AccessExpiry) {
		return login.AccessToken
	}
	refreshed, err := RefreshLogin(login, skipCertCheck)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token refresh failed (%s), run openrun login again\n", err)
		return ""
	}
	return refreshed.AccessToken
}

// loginLockDir returns a per-user directory for the login lock files. The
// shared system temp dir is only the last resort: there another local user
// could pre-create the predictable lock path and stall every CLI refresh
func loginLockDir() string {
	if home := os.Getenv("OPENRUN_HOME"); home != "" {
		dir := filepath.Join(home, "config")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	if cache, err := os.UserCacheDir(); err == nil {
		dir := filepath.Join(cache, "openrun")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	return os.TempDir()
}

// acquireLoginLock takes a cross-process lock for one server's login store,
// via an exclusively created lock file. A lock older than the stale window is
// stolen (a crashed process must not wedge every future CLI call)
func acquireLoginLock(serverUrl string) (func(), error) {
	sum := sha256.Sum256([]byte(normalizeServerUrl(serverUrl)))
	lockPath := filepath.Join(loginLockDir(), "openrun_login_"+hex.EncodeToString(sum[:8])+".lock")
	const staleAfter = 20 * time.Second
	deadline := time.Now().Add(10 * time.Second)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > staleAfter {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", lockPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// RefreshLogin exchanges the refresh token for a new token pair and persists
// the rotation
func RefreshLogin(login *StoredLogin, skipCertCheck bool) (*StoredLogin, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", login.RefreshToken)
	form.Set("client_id", "openrun-cli")

	client := NewHttpClient(login.TokenEndpoint, "", skipCertCheck)
	resp, err := client.PostForm("", form)
	if err != nil {
		return nil, err
	}
	login.AccessToken = resp.AccessToken
	login.AccessExpiry = time.Now().Add(time.Duration(resp.ExpiresIn)*time.Second - 30*time.Second)
	if resp.RefreshToken != "" {
		login.RefreshToken = resp.RefreshToken
	}
	if resp.Principal != "" {
		login.Principal = resp.Principal
	}
	if err := SaveLogin(login); err != nil {
		return nil, err
	}
	return login, nil
}

// OAuthTokenResponse is the token endpoint response the CLI consumes
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Principal    string `json:"principal"`
}

// PostForm posts a form-encoded body to the client's base url plus path and
// decodes the OAuth token response
func (h *HttpClient) PostForm(apiPath string, form url.Values) (*OAuthTokenResponse, error) {
	u, err := url.Parse(h.serverUri)
	if err != nil {
		return nil, err
	}
	if apiPath != "" {
		u.Path = strings.TrimSuffix(u.Path, "/") + apiPath
	}
	request, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, fmt.Errorf("%s: %s", oauthErr.Error, oauthErr.Description)
		}
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	if len(body) == 0 {
		// RFC 7009 revocation returns an empty 200
		return &OAuthTokenResponse{}, nil
	}
	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}
