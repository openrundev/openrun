// Copyright (c) OpenRun Authors
// SPDX-License-Identifier: Apache-2.0

// Package authflow runs the federated login flows end to end: a real
// openrun server built from the working tree, a mock OIDC provider and a
// SAML identity provider in-process, the real CLI (openrun login) and a
// headless Chromium driving the browser half. The server runs on localhost
// (apps, issuer, provider callbacks) with the auth callback domain
// login.other.test, a different site, so the browser's SameSite handling
// of the login-origin cookies is exercised; Chromium resolves that name to
// loopback through --host-resolver-rules, the Go processes never need to.
package authflow

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/samlidp"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/openrundev/openrun/tests/ui/testenv"
	"golang.org/x/crypto/bcrypt"
)

const (
	httpPort    = 25923
	httpsPort   = 25924
	loginDomain = "login.other.test" // the auth callback domain, a different site from localhost
	oidcUser    = "jane.doe@example.com"
	samlUser    = "alice"
	samlPass    = "alice-password"
	samlEmail   = "alice@example.com"
)

var (
	env       *testenv.Env
	browser   *rod.Browser
	skipMsg   string
	oidc      *mockoidc.MockOIDC
	idpURL    string // the SAML IdP base url
	serverURL = fmt.Sprintf("https://localhost:%d", httpsPort)
	loginURL  = fmt.Sprintf("https://%s:%d", loginDomain, httpsPort)
	// insecure talks to the test server's self-signed listener
	insecure = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
)

func TestMain(m *testing.M) {
	code, err := setupAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authflow test setup failed:", err)
		code = 1
	}
	os.Exit(code)
}

func setupAndRun(m *testing.M) (int, error) {
	binPath := os.Getenv("OPENRUN_TEST_BROWSER")
	if binPath == "" {
		var found bool
		binPath, found = launcher.LookPath()
		if !found {
			skipMsg = "no Chromium-based browser found, set OPENRUN_TEST_BROWSER"
			return m.Run(), nil
		}
	}

	var err error
	oidc, err = mockoidc.Run()
	if err != nil {
		return 1, fmt.Errorf("mock oidc: %w", err)
	}
	defer oidc.Shutdown() //nolint:errcheck

	idp, stopIdP, err := startSAMLIdP()
	if err != nil {
		return 1, err
	}
	defer stopIdP()
	spCert, spKey, cleanupKeys, err := writeSPKeyPair()
	if err != nil {
		return 1, err
	}
	defer cleanupKeys()

	env, err = testenv.Start(httpPort, testenv.Options{
		HTTPSPort: httpsPort,
		SecurityExtra: fmt.Sprintf(`callback_url = "%s"
auth_callback_domain = "%s"
sso_allow_private_hosts = true`, serverURL, loginDomain),
		SystemExtra: `default_domain = "localhost"`,
		ExtraConfig: fmt.Sprintf(`[api]
external_url = "%s"

[api.rest]
enable = true
auth = ["oidc_test", "saml_test", "saml_signed"]

[auth.oidc_test]
key = "%s"
secret = "%s"
discovery_url = "%s"
scopes = ["openid", "email", "profile"]

[saml.test]
metadata_url = "%s/metadata"

[saml.signed]
metadata_url = "%s/metadata"
sp_key_file = "%s"
sp_cert_file = "%s"
`, serverURL, oidc.ClientID, oidc.ClientSecret, oidc.DiscoveryEndpoint(), idpURL, idpURL, spKey, spCert),
	})
	if err != nil {
		return 1, err
	}
	defer env.Stop()

	for _, provider := range []string{"saml_test", "saml_signed"} {
		if err := registerSP(idp, provider); err != nil {
			return 1, err
		}
	}
	if out, err := env.CLI("app", "create", "--approve", testenv.TestappSource(), "/plainapp"); err != nil {
		return 1, fmt.Errorf("creating app: %v\n%s", err, out)
	}

	u, err := launcher.New().Bin(binPath).Headless(true).
		Set("host-resolver-rules", "MAP "+loginDomain+" 127.0.0.1").
		Set("ignore-certificate-errors").
		Launch()
	if err != nil {
		return 1, fmt.Errorf("launching browser: %w", err)
	}
	browser = rod.New().ControlURL(u)
	if err := browser.Connect(); err != nil {
		return 1, fmt.Errorf("connecting to browser: %w", err)
	}
	defer browser.Close() //nolint:errcheck

	return m.Run(), nil
}

// startSAMLIdP runs a crewjam samlidp server on a loopback port with one
// user. The SP is registered once the openrun server is up (registerSP)
func startSAMLIdP() (*samlidp.Server, func(), error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	idpURL = "http://" + ln.Addr().String()
	// The stock login form posts to /login, which only answers JSON; this
	// one posts the credentials with the pending request back to /sso, so
	// the IdP establishes the session and completes the flow in one step
	loginForm := template.Must(template.New("login").Parse(`<html><body><p>{{.Toast}}</p>
<form method="post" action="` + idpURL + `/sso">
<input type="text" name="user" /><input type="password" name="password" />
<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />
<input type="hidden" name="RelayState" value="{{.RelayState}}" />
<input type="submit" value="Log In" /></form></body></html>`))
	idp, err := samlidp.New(samlidp.Options{
		URL:               url.URL{Scheme: "http", Host: ln.Addr().String()},
		Key:               key,
		Certificate:       cert,
		Store:             &samlidp.MemoryStore{},
		LoginFormTemplate: loginForm,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("saml idp: %w", err)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(samlPass), bcrypt.MinCost)
	if err != nil {
		return nil, nil, err
	}
	if err := idp.Store.Put("/users/"+samlUser, samlidp.User{Name: samlUser, HashedPassword: hashed,
		Email: samlEmail, Groups: []string{"dev"}, CommonName: "Alice", GivenName: "Alice", Surname: "Tester"}); err != nil {
		return nil, nil, err
	}
	server := &http.Server{Handler: idp}
	go server.Serve(ln)                        //nolint:errcheck
	return idp, func() { server.Close() }, nil //nolint:errcheck
}

// writeSPKeyPair writes a self-signed SP certificate and key for the
// [saml.signed] provider (signed AuthnRequests, decryption key)
func writeSPKeyPair() (certFile, keyFile string, cleanup func(), err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "openrun sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	dir, err := os.MkdirTemp("", "openrun-authflow-sp-")
	if err != nil {
		return "", "", nil, err
	}
	certFile, keyFile = filepath.Join(dir, "sp.crt"), filepath.Join(dir, "sp.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", "", nil, err
	}
	return certFile, keyFile, func() { os.RemoveAll(dir) }, nil //nolint:errcheck
}

// registerSP fetches the openrun SP metadata of a provider and registers
// it at the IdP
func registerSP(idp *samlidp.Server, provider string) error {
	resp, err := insecure.Get(serverURL + "/_openrun/sso/" + provider + "/metadata")
	if err != nil {
		return fmt.Errorf("sp metadata: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sp metadata: %d %s", resp.StatusCode, body)
	}
	if provider == "saml_signed" && !strings.Contains(string(body), `AuthnRequestsSigned="true"`) {
		return fmt.Errorf("signed sp metadata must announce signed requests: %s", body)
	}
	req, err := http.NewRequest(http.MethodPut, idpURL+"/services/"+provider, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("registering sp: %w", err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("registering sp: %d", resp.StatusCode)
	}
	return nil
}

// oidcTestUser is the mock provider's user with a userinfo document that
// carries the subject: goth's OIDC provider requires "sub" there, and the
// stock MockUser userinfo omits it
type oidcTestUser struct{ *mockoidc.MockUser }

func (u oidcTestUser) Userinfo(scope []string) ([]byte, error) {
	info, err := u.MockUser.Userinfo(scope)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(info, &claims); err != nil {
		return nil, err
	}
	claims["sub"] = u.Subject
	return json.Marshal(claims)
}

// queueOIDCUser makes the next provider login return the test user
func queueOIDCUser() {
	user := mockoidc.DefaultUser()
	user.Email = oidcUser
	oidc.QueueUser(oidcTestUser{user})
}

/* ---------- helpers ---------- */

// remoteClientConfig writes a CLI client config for the remote server and
// returns the CLI environment using it
func remoteClientConfig(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(env.HomeDir, "remote_client_"+t.Name()+".toml")
	config := fmt.Sprintf("server_uri = %q\n[client]\nskip_cert_check = true\n", serverURL)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	// Later entries win for duplicate keys in exec's Env
	return append(env.CLIEnv(), "CL_CONFIG_FILE="+path)
}

// cliLogin starts openrun login --no-browser and returns the printed
// authorize url and a wait function for the command's result
func cliLogin(t *testing.T, cliEnv []string, mechanism string) (string, func() (string, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	cmd := exec.CommandContext(ctx, env.BinPath, "login", "--no-browser", "--auth", mechanism)
	cmd.Env = cliEnv
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var rest bytes.Buffer
	scanner := bufio.NewScanner(stdout)
	authorizeURL := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "https://") {
			authorizeURL = line
			break
		}
	}
	if authorizeURL == "" {
		cancel()
		cmd.Wait() //nolint:errcheck
		t.Fatalf("login did not print the authorize url: %s", stderr.String())
	}
	wait := func() (string, error) {
		defer cancel()
		io.Copy(&rest, stdout) //nolint:errcheck
		err := cmd.Wait()
		return rest.String() + stderr.String(), err
	}
	return authorizeURL, wait
}

// page wraps a rod page with waits that fail the test on timeout
type page struct {
	*rod.Page
	t *testing.T
}

func newPage(t *testing.T, incognito bool) *page {
	t.Helper()
	b := browser
	if incognito {
		var err error
		if b, err = browser.Incognito(); err != nil {
			t.Fatal(err)
		}
	}
	p, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() }) //nolint:errcheck
	return &page{Page: p.Timeout(30 * time.Second), t: t}
}

func (p *page) open(target string) {
	p.t.Helper()
	if err := p.Navigate(target); err != nil {
		p.t.Fatalf("navigate %s: %v", target, err)
	}
	if err := p.WaitLoad(); err != nil {
		p.t.Fatalf("load %s: %v", target, err)
	}
}

// waitURLPrefix waits until the page url starts with prefix (redirect chains)
func (p *page) waitURLPrefix(prefix string) {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := p.Info(); err == nil && strings.HasPrefix(info.URL, prefix) {
			if err := p.WaitLoad(); err != nil {
				p.t.Fatalf("load %s: %v", info.URL, err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	info, _ := p.Info()
	p.t.Fatalf("page did not reach %s, at %s:\n%s", prefix, info.URL, p.html())
}

func (p *page) url() string {
	info, err := p.Info()
	if err != nil {
		p.t.Fatal(err)
	}
	return info.URL
}

func (p *page) html() string {
	html, err := p.HTML()
	if err != nil {
		return ""
	}
	return html
}

func (p *page) mustContain(substr string) {
	p.t.Helper()
	if html := p.html(); !strings.Contains(html, substr) {
		p.t.Fatalf("page at %s lacks %q:\n%s", p.url(), substr, html)
	}
}

// samlIdPLogin fills the crewjam IdP login form (reached by the SSO redirect)
func (p *page) samlIdPLogin() {
	p.t.Helper()
	p.waitURLPrefix(idpURL + "/sso")
	p.MustElement(`input[name="user"]`).MustInput(samlUser)
	p.MustElement(`input[name="password"]`).MustInput(samlPass)
	p.MustElement(`input[type="submit"], button[type="submit"]`).MustClick()
}

// consentPage waits for the AS consent page on the login origin and
// returns the pending request id and the consent nonce it carries
func (p *page) consentPage() (authz, nonce string) {
	p.t.Helper()
	p.waitURLPrefix(loginURL + "/_openrun/oauth/authorize/continue?authz=")
	p.MustElement(`form[action$="/oauth/authorize/consent"] button[type="submit"]`)
	html := p.html()
	a := regexp.MustCompile(`name="authz" value="([^"]+)"`).FindStringSubmatch(html)
	n := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(html)
	if a == nil || n == nil {
		p.t.Fatalf("consent page without authz/nonce:\n%s", html)
	}
	return a[1], n[1]
}

func (p *page) approveConsent() {
	p.t.Helper()
	p.MustElement(`form[action$="/oauth/authorize/consent"] button[type="submit"]`).MustClick()
}

// crossSiteConsentPost submits the consent form from a document on the
// app site: the Lax binding cookie must not accompany it, so the AS must
// refuse even with the right record id and nonce
func (p *page) crossSiteConsentPost(authz, nonce string) {
	p.t.Helper()
	p.open(serverURL + "/plainapp")
	p.mustContain("Test app body")
	_, err := p.Eval(fmt.Sprintf(`() => {
		const form = document.createElement("form");
		form.method = "POST";
		form.action = %q;
		for (const [name, value] of Object.entries({authz: %q, nonce: %q, or_scope: "*"})) {
			const input = document.createElement("input");
			input.name = name; input.value = value; form.appendChild(input);
		}
		document.body.appendChild(form);
		form.submit();
	}`, loginURL+"/_openrun/oauth/authorize/consent", authz, nonce))
	if err != nil {
		p.t.Fatal(err)
	}
	p.waitURLPrefix(loginURL + "/_openrun/oauth/authorize/consent")
	// The cross-origin check (Sec-Fetch-Site) refuses first; a client that
	// got past it would still lack the binding cookie
	if html := p.html(); !strings.Contains(html, "Cross origin") && !strings.Contains(html, "another browser") {
		p.t.Fatalf("cross-site consent post must be refused, got:\n%s", html)
	}
}

/* ---------- tests ---------- */

// cliLoginFlow runs openrun login through the browser with the given
// federated mechanism, idpLogin handling the provider's own login step
func cliLoginFlow(t *testing.T, mechanism, expectPrincipal string, idpLogin func(*page)) {
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	cliEnv := remoteClientConfig(t)
	authorizeURL, wait := cliLogin(t, cliEnv, mechanism)

	// The CLI discovered the AS endpoints: the authorize url is on the
	// login origin, not the issuer
	if !strings.HasPrefix(authorizeURL, loginURL+"/_openrun/oauth/authorize?") {
		t.Fatalf("authorize url must be on the login origin, got %s", authorizeURL)
	}
	p := newPage(t, true)
	p.open(authorizeURL)
	idpLogin(p)
	authz, nonce := p.consentPage()
	p.mustContain("<dd>" + expectPrincipal + "</dd>")
	continueURL := p.url()

	// Another browser given the continue link is refused outright
	other := newPage(t, true)
	other.open(continueURL)
	other.mustContain("another browser")

	// A cross-site post of the consent form from the app site (same
	// browser, cookies and all) is refused: the Lax binding cookie stays home
	p.crossSiteConsentPost(authz, nonce)

	// The owning browser approves and the CLI completes the login
	p.open(continueURL)
	p.approveConsent()
	p.waitURLPrefix("http://127.0.0.1:")
	out, err := wait()
	if err != nil || !strings.Contains(out, "Logged in to "+serverURL+" as "+expectPrincipal) {
		t.Fatalf("login: %v\n%s", err, out)
	}

	// The stored login works for remote commands
	list := exec.Command(env.BinPath, "app", "list")
	list.Env = cliEnv
	listOut, err := list.CombinedOutput()
	if err != nil || !strings.Contains(string(listOut), "/plainapp") {
		t.Fatalf("remote app list: %v\n%s", err, listOut)
	}
	logout := exec.Command(env.BinPath, "logout")
	logout.Env = cliEnv
	if out, err := logout.CombinedOutput(); err != nil || !strings.Contains(string(out), "Logged out") {
		t.Fatalf("logout: %v\n%s", err, out)
	}
}

func TestCLILoginOIDC(t *testing.T) {
	queueOIDCUser()
	cliLoginFlow(t, "oidc_test", "oidc_test:"+oidcUser, func(*page) {
		// The mock provider approves without a login page
	})
}

func TestCLILoginSAML(t *testing.T) {
	cliLoginFlow(t, "saml_test", "saml_test:"+samlEmail, func(p *page) { p.samlIdPLogin() })
}

// The provider with an SP keypair signs the redirect-binding AuthnRequest
// (query string signature) and the flow completes the same way
func TestCLILoginSAMLSignedRequests(t *testing.T) {
	cliLoginFlow(t, "saml_signed", "saml_signed:"+samlEmail, func(p *page) {
		if u := p.url(); !strings.Contains(u, "SigAlg=") || !strings.Contains(u, "Signature=") {
			t.Fatalf("redirect to the IdP must carry the query signature: %s", u)
		}
		p.samlIdPLogin()
	})
}

// appLoginFlow opens an app whose auth is the federated mechanism: the
// pre-existing app login path, with the completion redirect host check
func appLoginFlow(t *testing.T, auth, appPath string, idpLogin func(*page)) {
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if out, err := env.CLI("app", "create", "--approve", "--auth", auth, testenv.TestappSource(), appPath); err != nil {
		t.Fatalf("creating app: %v\n%s", err, out)
	}
	p := newPage(t, true)
	p.open(serverURL + appPath)
	idpLogin(p)
	p.waitURLPrefix(serverURL + appPath)
	p.mustContain("Test app body")
	// The session persists: a second visit needs no provider round trip
	p.open(serverURL + appPath)
	p.mustContain("Test app body")
}

func TestAppLoginOIDC(t *testing.T) {
	queueOIDCUser()
	appLoginFlow(t, "oidc_test", "/oidcapp", func(*page) {})
}

func TestAppLoginSAML(t *testing.T) {
	appLoginFlow(t, "saml_test", "/samlapp", func(p *page) { p.samlIdPLogin() })
}

// Background requests reaching an app without a session, while the user
// is completing the login in another tab, must not start a second login:
// that overwrote the pre-auth cookie of the login in flight and failed it
// with "error matching session state" (openrundev/openrun#116). A service
// worker made it happen on every login: the browser refetches the worker
// script on each navigation into its scope.

// swappSource builds the test app which registers a service worker: the
// standard test app plus a worker script served from the app root
// (static_root), a no-op worker without a fetch handler, so navigations
// into its scope go to the network as usual while the browser refetches the
// script (a background request) to check for updates
func swappSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(testenv.TestappSource())); err != nil {
		t.Fatal(err)
	}
	worker := "self.addEventListener('install', () => self.skipWaiting());\n"
	if err := os.WriteFile(filepath.Join(dir, "static_root", "sw.js"), []byte(worker), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// incognito returns a browser context of its own (cookies shared by the
// pages created in it, separate from the other tests)
func incognito(t *testing.T) *rod.Browser {
	t.Helper()
	b, err := browser.Incognito()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newContextPage opens a page in the given browser context
func newContextPage(t *testing.T, b *rod.Browser) *page {
	t.Helper()
	p, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() }) //nolint:errcheck
	return &page{Page: p.Timeout(30 * time.Second), t: t}
}

// evalString runs page script returning a string (promises are awaited)
func (p *page) evalString(js string) string {
	p.t.Helper()
	res, err := p.Eval(js)
	if err != nil {
		p.t.Fatalf("eval: %v", err)
	}
	return res.Value.Str()
}

// fetchStatus fetches the url from the page (a cors-mode fetch with the
// context's cookies) and returns the status, or the error message
func (p *page) fetchStatus(target string) string {
	p.t.Helper()
	return p.evalString(fmt.Sprintf(`() => fetch(%q, {credentials: "include"}).then(r => String(r.status), e => "error: " + e.message)`, target))
}

// A fetch from a tab without a session gets a plain 401 while a navigation
// starts the login; the headers of the refusal change nothing in the browser
func TestAppBackgroundRequestWithoutSession(t *testing.T) {
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if out, err := env.CLI("app", "create", "--approve", "--auth", "oidc_test", testenv.TestappSource(), "/oidcbg"); err != nil {
		t.Fatalf("creating app: %v\n%s", err, out)
	}
	// The refusal, as a browser's fetch sends it
	req, _ := http.NewRequest(http.MethodGet, serverURL+"/oidcbg/", nil)
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	resp, err := insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Cache-Control") != "no-store" ||
		len(resp.Cookies()) != 0 || resp.Header.Get("Location") != "" {
		t.Fatalf("background request: %d %v", resp.StatusCode, resp.Header)
	}
	// A navigation without fetch metadata (plain http deployments) starts
	// the login on the Accept header
	req, _ = http.NewRequest(http.MethodGet, serverURL+"/oidcbg/", nil)
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	resp, err = insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/_openrun/auth/oidc_test/login?state=") {
		t.Fatalf("navigation: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	b := incognito(t)
	other := newContextPage(t, b)
	other.open(serverURL + "/plainapp")
	other.mustContain("Test app body")
	if status := other.fetchStatus(serverURL + "/oidcbg/"); status != "401" {
		t.Fatalf("fetch without a session: %s, want 401", status)
	}
	queueOIDCUser()
	tab := newContextPage(t, b)
	tab.open(serverURL + "/oidcbg")
	tab.waitURLPrefix(serverURL + "/oidcbg")
	tab.mustContain("Test app body")
	if status := other.fetchStatus(serverURL + "/oidcbg/"); status != "200" {
		t.Fatalf("fetch with the session: %s, want 200", status)
	}
}

// A poller of a tab whose session expired fires while the user is at the
// IdP in another tab: the login must still complete
func TestAppLoginSurvivesBackgroundFetch(t *testing.T) {
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if out, err := env.CLI("app", "create", "--approve", "--auth", "saml_test", testenv.TestappSource(), "/samlbg"); err != nil {
		t.Fatalf("creating app: %v\n%s", err, out)
	}
	b := incognito(t)
	tab := newContextPage(t, b)
	tab.open(serverURL + "/samlbg")
	tab.waitURLPrefix(idpURL + "/sso") // the login is in flight, the pre-auth cookie is set

	other := newContextPage(t, b)
	other.open(serverURL + "/plainapp")
	other.mustContain("Test app body")
	for range 3 {
		if status := other.fetchStatus(serverURL + "/samlbg/"); status != "401" {
			t.Fatalf("fetch during the login: %s, want 401", status)
		}
	}

	// The tab is in the background since the other page opened; rod's
	// input waits for an animation frame, which only a foreground page gets
	if _, err := tab.Activate(); err != nil {
		t.Fatal(err)
	}
	tab.samlIdPLogin()
	tab.waitURLPrefix(serverURL + "/samlbg")
	tab.mustContain("Test app body")
	if status := other.fetchStatus(serverURL + "/samlbg/"); status != "200" {
		t.Fatalf("fetch after the login: %s, want 200", status)
	}
}

// The reported case: a service worker registered by the app. Its script
// update fetch (which the browser issues on every navigation into the
// scope, here triggered explicitly) must not start a login, and the login
// the user completes meanwhile must succeed
func TestAppLoginSurvivesServiceWorkerUpdate(t *testing.T) {
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if out, err := env.CLI("app", "create", "--approve", "--auth", "saml_test", swappSource(t), "/swapp"); err != nil {
		t.Fatalf("creating app: %v\n%s", err, out)
	}
	b := incognito(t)
	tab := newContextPage(t, b)
	tab.open(serverURL + "/swapp")
	tab.samlIdPLogin()
	tab.waitURLPrefix(serverURL + "/swapp")
	tab.mustContain("Test app body")

	// The app registers its worker while signed in
	registered := tab.evalString(`() => navigator.serviceWorker.register("/swapp/sw.js", {scope: "/swapp/"})
		.then(reg => reg.scope, e => "error: " + e.name + ": " + e.message)`)
	if registered != serverURL+"/swapp/" {
		t.Fatalf("service worker registration: %s", registered)
	}
	// The worker is active once installed (skipWaiting)
	active := tab.evalString(`() => new Promise(resolve => {
		const deadline = Date.now() + 10000;
		const check = () => navigator.serviceWorker.getRegistration("/swapp/").then(reg => {
			if (reg && reg.active) { resolve("active"); }
			else if (Date.now() > deadline) { resolve("not active: " + JSON.stringify(reg && {installing: !!reg.installing, waiting: !!reg.waiting})); }
			else { setTimeout(check, 100); }
		}, e => resolve("error: " + e.message));
		check();
	})`)
	if active != "active" {
		t.Fatalf("service worker: %s", active)
	}

	// The session expires (every cookie of the context goes, the IdP's
	// too, so the login needs the IdP form again); the next visit starts
	// a login and the user is at the IdP
	if err := b.SetCookies(nil); err != nil {
		t.Fatal(err)
	}
	tab.open(serverURL + "/swapp")
	tab.waitURLPrefix(idpURL + "/sso")

	// Meanwhile the worker's script update fetch reaches the app without a
	// session: refused, so the worker keeps its script and the pre-auth
	// cookie of the login in flight is untouched
	other := newContextPage(t, b)
	other.open(serverURL + "/plainapp")
	update := `() => navigator.serviceWorker.getRegistration("/swapp/")
		.then(reg => reg ? reg.update().then(() => "updated", e => "rejected: " + e.name) : "no registration")`
	if result := other.evalString(update); !strings.HasPrefix(result, "rejected") {
		t.Fatalf("worker update during the login: %s, want a rejection", result)
	}

	if _, err := tab.Activate(); err != nil {
		t.Fatal(err)
	}
	tab.samlIdPLogin()
	tab.waitURLPrefix(serverURL + "/swapp")
	tab.mustContain("Test app body")
	// With the session back the update goes through
	if result := other.evalString(update); result != "updated" {
		t.Fatalf("worker update after the login: %s", result)
	}
}
