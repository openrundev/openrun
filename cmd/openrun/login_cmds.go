// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// openrun login: OAuth 2.1 authorization-code + PKCE flow as the
// pre-registered openrun-cli public client. The browser opens the server's
// login page; the CLI catches the redirect on a loopback listener, exchanges
// the code, and stores the tokens in the OS keychain (file fallback under
// $OPENRUN_HOME/config). Access tokens auto-refresh on later CLI calls.

func initLoginCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+3)
	flags = append(flags, commonFlags...)
	flags = append(flags,
		newStringFlag("server", "s", "The server url (https://host[:port]). Default is server_uri from the client config", ""),
		newStringFlag("scopes", "", "Requested scopes, comma or space separated. Default *", "*"),
		newBoolFlag("no-browser", "n", "Print the login url instead of opening a browser", false),
	)
	return &cli.Command{
		Name:  "login",
		Usage: "Log in to a remote OpenRun server (browser flow, tokens stored in the OS keychain)",
		Flags: flags,
		UsageText: `Examples:
  Log in:                openrun login --server https://openrun.example.com
  Without a browser:     openrun login --server https://openrun.example.com --no-browser`,
		Action: func(cCtx *cli.Context) error {
			serverUrl := strings.TrimSuffix(cmp.Or(cCtx.String("server"), clientConfig.ServerUri), "/")
			if !strings.HasPrefix(serverUrl, "https://") && !strings.HasPrefix(serverUrl, "http://") {
				return fmt.Errorf("login requires a remote server url (--server https://host); server_uri is %q", serverUrl)
			}
			return runLoginFlow(cCtx, clientConfig, serverUrl)
		},
	}
}

func initLogoutCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("server", "s", "The server url. Default is server_uri from the client config", ""))
	return &cli.Command{
		Name:  "logout",
		Usage: "Log out from a remote OpenRun server (revokes the grant, clears stored tokens)",
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			serverUrl := strings.TrimSuffix(cmp.Or(cCtx.String("server"), clientConfig.ServerUri), "/")
			login := system.LoadLogin(serverUrl)
			if login == nil {
				printStdout(cCtx, "No stored login for %s\n", serverUrl)
				return nil
			}
			if login.RefreshToken != "" && login.TokenEndpoint != "" {
				revokeEndpoint := strings.Replace(login.TokenEndpoint, "/oauth/token", "/oauth/revoke", 1)
				form := url.Values{}
				form.Set("token", login.RefreshToken)
				client := system.NewHttpClient(revokeEndpoint, "", clientConfig.Client.SkipCertCheck)
				if _, err := client.PostForm("", form); err != nil {
					fmt.Fprintf(cCtx.App.ErrWriter, "Warning: server-side revocation failed: %s\n", err) //nolint:errcheck
				}
			}
			system.DeleteLogin(serverUrl)
			printStdout(cCtx, "Logged out from %s\n", serverUrl)
			return nil
		},
	}
}

// oauthServerMetadata is the subset of the RFC 8414 document the CLI needs
type oauthServerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func fetchJSON(client *http.Client, fetchUrl string, out any) error {
	resp, err := client.Get(fetchUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", fetchUrl, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func runLoginFlow(cCtx *cli.Context, clientConfig *types.ClientConfig, serverUrl string) error {
	httpClient := system.NewPlainHttpClient(clientConfig.Client.SkipCertCheck)

	// Discover the resource and the AS endpoints from the well-known docs
	var prm struct {
		Resource string `json:"resource"`
	}
	if err := fetchJSON(httpClient, serverUrl+"/.well-known/oauth-protected-resource/rest", &prm); err != nil {
		return fmt.Errorf("server does not advertise the rest API surface (is [api.rest] enable set?): %w", err)
	}
	var metadata oauthServerMetadata
	if err := fetchJSON(httpClient, serverUrl+"/.well-known/oauth-authorization-server", &metadata); err != nil {
		return fmt.Errorf("error fetching authorization server metadata: %w", err)
	}

	// PKCE pair and state
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Loopback listener for the redirect (RFC 8252: 127.0.0.1, any port)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close() //nolint:errcheck
	redirectUri := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch in callback")
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("callback missing code: %s", r.URL.RawQuery)
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h3>Login complete</h3>You can close this window and return to the terminal.</body></html>") //nolint:errcheck
		codeCh <- code
	})}
	go server.Serve(listener) //nolint:errcheck
	defer server.Close()      //nolint:errcheck

	scopes := strings.Join(strings.FieldsFunc(cCtx.String("scopes"),
		func(r rune) bool { return r == ',' || r == ' ' }), " ")
	authorizeUrl := metadata.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"openrun-cli"},
		"redirect_uri":          {redirectUri},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {prm.Resource},
		"scope":                 {scopes},
	}.Encode()

	if cCtx.Bool("no-browser") || !openBrowser(authorizeUrl) {
		printStdout(cCtx, "Open this url in a browser to log in:\n\n%s\n\n", authorizeUrl)
	} else {
		printStdout(cCtx, "Opening the login page in the browser (use --no-browser to print the url instead)\n")
	}

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return err
	case <-time.After(180 * time.Second):
		return fmt.Errorf("timed out waiting for the browser login")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectUri)
	form.Set("client_id", "openrun-cli")
	form.Set("code_verifier", verifier)
	tokenClient := system.NewHttpClient(metadata.TokenEndpoint, "", clientConfig.Client.SkipCertCheck)
	tokenResp, err := tokenClient.PostForm("", form)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	login := &system.StoredLogin{
		ServerUrl:     serverUrl,
		Principal:     tokenResp.Principal,
		AccessToken:   tokenResp.AccessToken,
		AccessExpiry:  time.Now().Add(time.Duration(tokenResp.ExpiresIn)*time.Second - 30*time.Second),
		RefreshToken:  tokenResp.RefreshToken,
		TokenEndpoint: metadata.TokenEndpoint,
	}
	if err := system.SaveLogin(login); err != nil {
		return fmt.Errorf("error storing login: %w", err)
	}
	printStdout(cCtx, "Logged in to %s as %s\n", serverUrl, cmp.Or(tokenResp.Principal, "(unknown)"))
	return nil
}

// openBrowser tries to open the url in the default browser, returning false
// when no opener is available (headless environments)
func openBrowser(openUrl string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", openUrl)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", openUrl)
	default:
		cmd = exec.Command("xdg-open", openUrl)
	}
	return cmd.Start() == nil
}
