// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/builder"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/server/list_apps"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/openrundev/openrun/internal/app/appfs"
	_ "github.com/openrundev/openrun/internal/app/store" // Register db plugin
	_ "github.com/openrundev/openrun/plugins"            // Register builtin plugins
)

const (
	DEFAULT_CERT_FILE = "default.crt"
	DEFAULT_KEY_FILE  = "default.key"
	APPSPECS          = "appspecs"
)

//go:embed appspecs
var embedAppTypes embed.FS

var appTypes map[string]types.SpecFiles

func init() {
	id, err := ksuid.NewRandom()
	if err != nil {
		panic(err)
	}
	types.CurrentServerId = types.ServerId(types.ID_PREFIX_SERVER + id.String())

	// Read app type config embedded in the binary
	appTypes = make(map[string]types.SpecFiles)
	entries, err := embedAppTypes.ReadDir(APPSPECS)
	if err != nil {
		return
	}

	for _, dir := range entries {
		// Loop through all directories in app specs, each is an app type
		if !dir.IsDir() || strings.HasPrefix(dir.Name(), ".") || dir.Name() == "dummy" {
			continue
		}
		files, err := embedAppTypes.ReadDir(path.Join(APPSPECS, dir.Name()))
		if err != nil {
			panic(err)
		}

		appType := make(types.SpecFiles)
		for _, file := range files {
			// Loop through all files in the app_type directory
			if file.IsDir() {
				continue
			}
			data, err := embedAppTypes.ReadFile(path.Join(APPSPECS, dir.Name(), file.Name()))
			if err != nil {
				panic(err)
			}
			appType[file.Name()] = string(data)
		}

		appTypes[dir.Name()] = appType
	}
}

func (s *Server) GetAppSpec(name types.AppSpec) types.SpecFiles {
	// Add custom app type config from conf folder

	specName, err := system.CleanFilename(string(name))
	if err != nil {
		return appTypes[string(name)]
	}

	customSpecsDir := path.Clean((path.Join(os.ExpandEnv("$OPENRUN_HOME/config"), APPSPECS, specName)))
	entries, err := os.ReadDir(customSpecsDir)
	if err != nil {
		// Use bundled app if present
		return appTypes[specName]
	}

	newAppType := make(types.SpecFiles)
	for _, file := range entries {
		// Loop through all files in the app_type directory
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(path.Join(customSpecsDir, file.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s : %s\n", file.Name(), err)
			continue
		}
		newAppType[file.Name()] = string(data)
	}

	return newAppType
}

// Server is the instance of the OpenRun Server
type Server struct {
	*types.Logger
	// staticConfig is the openrun.toml config as loaded at startup. It is
	// immutable after NewServer and must only be referenced by startup paths
	// and the dynamic config merge; everything else reads s.Config(), which
	// includes the dynamic overrides
	staticConfig *types.ServerConfig
	db           *metadata.Metadata
	httpServer   *http.Server
	httpsServer  *http.Server
	udsServer    *http.Server
	handler      *Handler
	apps         *AppStore
	authHandler  *AdminBasicAuth
	oAuthManager *OAuthManager
	samlManager  *SAMLManager
	notifyClose  chan types.AppPathDomain
	// secretsManager is swapped when a dynamic config change modifies the
	// [secret] config; read it through secretsMgr(), never capture the
	// manager (or one of its method values) in a long-lived object
	secretsManager atomic.Pointer[system.SecretManager]
	listAppsApp    *app.App
	mu             sync.RWMutex
	auditDB        *sql.DB
	auditDbType    system.DBType
	auditEvents    chan *types.AuditEvent
	auditFlush     chan chan struct{}
	auditStop      chan struct{}
	auditDone      chan struct{}

	// authFailureTimes tracks the last audit event time per unique auth
	// failure, to rate limit the events inserted for repeated failures
	authFailureMu    sync.Mutex
	authFailureTimes map[string]time.Time
	accessLogger     *zerolog.Logger
	syncTimer        *time.Ticker
	syncStop         chan struct{}
	tlsErrorLogger   *RateLimitedErrorLogger
	configMu         sync.RWMutex
	dynamicConfig    *types.DynamicConfig
	effectiveConfig  atomic.Pointer[types.ServerConfig]
	rbacManager      *rbac.RBACManager
	csrfMiddleware   *http.CrossOriginProtection
	telemetry        *telemetry.Providers

	forwardAuthHTTPClient *http.Client
	builderManager        *builder.Manager

	staleContainerCleanupTicker *time.Ticker
	staleContainerCleanupStop   chan struct{}

	// deployTxnMu guards activeDeployTxns: the deploy transactions of
	// operations currently in flight, whose containers must not be treated as
	// stale by the container sweeper.
	deployTxnMu      sync.Mutex
	activeDeployTxns map[*container.DeployTxn]bool

	stopRequested   chan struct{}
	stopRequestOnce sync.Once
	stopOnce        sync.Once
	stopErr         error
}

// NewServer creates a new instance of the OpenRun Server
func NewServer(config *types.ServerConfig) (*Server, error) {
	metadataDir := os.ExpandEnv("$OPENRUN_HOME/metadata")
	if err := os.MkdirAll(metadataDir, 0700); err != nil {
		return nil, fmt.Errorf("error creating metadata directory %s : %w", metadataDir, err)
	}

	l := types.NewLogger(&config.Log)
	l.Info().Str("version", types.GetVersion()).Str("commit", types.GetCommit()).Msg("Initializing server")

	// Setup secrets manager
	secretsManager, err := system.NewSecretManager(context.Background(), config.Secret, config.AppConfig.Security.DefaultSecretsProvider, config)
	if err != nil {
		return nil, err
	}

	// Update secrets in the config (including telemetry headers, which are
	// resolved before being passed to the OTLP exporter).
	err = updateConfigSecrets(config, secretsManager.EvalTemplate)
	if err != nil {
		return nil, err
	}

	// Initialize telemetry after secrets are resolved so OTLP headers can use
	// {{ secret ... }} references. A failure here is logged but does not block
	// server startup; observability is non-essential.
	telemetryProviders, err := telemetry.Setup(context.Background(), config, l)
	if err != nil {
		l.Error().Err(err).Msg("OpenTelemetry initialization failed; continuing without telemetry")
	}
	telemetryCleanup := true
	defer func() {
		if telemetryCleanup {
			_ = telemetryProviders.Shutdown(context.Background())
		}
	}()

	db, err := metadata.NewMetadata(l, config)
	if err != nil {
		return nil, err
	}

	// Bind the db secret provider to the metadata database. Done after the
	// metadata init since the db connection config can itself use secrets.
	// Nonfatal at startup: a key mismatch must not crash loop the server
	bindDBSecretStore(context.Background(), l, secretsManager, db) //nolint:errcheck

	server := &Server{
		Logger:        l,
		staticConfig:  config,
		db:            db,
		telemetry:     telemetryProviders,
		stopRequested: make(chan struct{}),
	}
	server.secretsManager.Store(secretsManager)
	server.forwardAuthHTTPClient = newForwardAuthHTTPClient(config)
	db.AppNotifyFunc = server.appNotifyHandler
	db.ConfigNotifyFunc = server.configNotifyHandler
	server.apps = NewAppStore(l, server)
	server.authHandler = NewAdminBasicAuth(l, config)
	server.notifyClose = make(chan types.AppPathDomain)

	csrfMiddleware := http.NewCrossOriginProtection()
	csrfMiddleware.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Cross origin check failed - CSRF protection", http.StatusForbidden)
	}))
	server.csrfMiddleware = csrfMiddleware

	// Setup OAuth auth
	server.oAuthManager = NewOAuthManager(l, config, db)
	var newSessionSecret, newSessionBlockKey []byte
	if newSessionSecret, err = passwd.GenerateRandomKey(32); err != nil {
		return nil, err
	}
	if newSessionBlockKey, err = passwd.GenerateRandomKey(32); err != nil {
		return nil, err
	}
	if newSessionSecret, err = server.KVInitConstant(context.Background(), types.COOKIE_SESSION_SECRET_KV, newSessionSecret); err != nil {
		return nil, err
	}
	if newSessionBlockKey, err = server.KVInitConstant(context.Background(), types.COOKIE_SESSION_BLOCK_KEY_KV, newSessionBlockKey); err != nil {
		return nil, err
	}
	if err = server.oAuthManager.Setup(newSessionSecret, newSessionBlockKey); err != nil {
		return nil, err
	}

	// Setup SAML auth
	server.samlManager = NewSAMLManager(l, config, server.oAuthManager.cookieStore, db)
	if err = server.samlManager.Setup(context.Background()); err != nil {
		return nil, err
	}

	if err = server.initAuditDB(config.Metadata.AuditDBConnection); err != nil {
		return nil, fmt.Errorf("error initializing audit db: %w", err)
	}

	server.initAccessLogger(config)

	if config.System.ContainerCommand == "auto" {
		config.System.ContainerCommand = container.LookupContainerCommand(true)
		// if command is empty string, that means either containers are disabled in config or no container command found
	}

	server.Trace().Str("cmd", config.System.ContainerCommand).Msg("Container management command")
	go server.handleAppClose()

	initOpenRunPlugin(server)
	initAdminPlugin(server)
	initBuilderPlugin(server)

	server.dynamicConfig, err = server.db.GetConfig()
	if err != nil && !errors.Is(err, metadata.ErrConfigNotFound) {
		return nil, fmt.Errorf("error getting dynamic config: %w", err)
	}

	if server.dynamicConfig == nil || server.dynamicConfig.VersionId == "" {
		// Initialize dynamic config if not already done
		if server.dynamicConfig == nil {
			server.dynamicConfig = &types.DynamicConfig{}
		}
		server.dynamicConfig.VersionId = "ver_" + ksuid.New().String()
		err = server.db.InitConfig(context.Background(), "admin", server.dynamicConfig)
		if err != nil {
			if !errors.Is(err, metadata.ErrConfigAlreadyExists) {
				return nil, fmt.Errorf("error init dynamic config: %w", err)
			} else {
				server.dynamicConfig, err = server.db.GetConfig()
				if err != nil {
					return nil, fmt.Errorf("error getting dynamic config: %w", err)
				}
			}
		}
		err = server.db.NotifyConfigUpdate()
		if err != nil {
			return nil, fmt.Errorf("error notifying other instances about new dynamic config: %w", err)
		}
	}

	err = server.SaveDynamicConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error saving dynamic config: %w", err)
	}

	// Merge the dynamic config entries over the static config and register any
	// dynamically configured oauth/saml providers. Bad persisted entries must
	// not prevent server startup, so errors are logged and the server continues
	// with the static config
	if err = server.applyDynamicConfig(context.Background(), server.dynamicConfig, false); err != nil {
		l.Error().Err(err).Msg("error applying dynamic config entries, continuing with static config")
	}

	server.rbacManager, err = rbac.NewRBACHandler(l, &server.dynamicConfig.RBAC, config)
	if err != nil {
		return nil, fmt.Errorf("error initializing rbac manager: %w", err)
	}

	// Start the idle shutdown check
	server.syncTimer = time.NewTicker(time.Minute) // run sync every minute
	server.syncStop = make(chan struct{})
	go server.syncRunner()
	server.startStaleContainerCleanup()
	telemetryCleanup = false
	return server, nil
}

func (s *Server) GetDynamicConfig() types.DynamicConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return *s.dynamicConfig // return a copy of the dynamic config
}

// Config returns the effective server config: the static openrun.toml config
// with the dynamic config entries and settings merged in, dynamic taking
// precedence. This is the canonical config accessor; the returned config is
// a published snapshot and must never be modified. Startup paths which run
// before the dynamic config is loaded see the static config
func (s *Server) Config() *types.ServerConfig {
	if effective := s.effectiveConfig.Load(); effective != nil {
		return effective
	}
	return s.staticConfig
}

// secretsMgr returns the current secrets manager. The manager is replaced
// when a dynamic config change modifies the [secret] config, so callers must
// not hold on to the returned value
func (s *Server) secretsMgr() *system.SecretManager {
	return s.secretsManager.Load()
}

// AppEvalTemplate resolves {{secret}} references for apps through the current
// secrets manager. Apps hold this server method instead of a manager-bound
// method value, so a dynamic secret provider change (key rotation, new
// provider) takes effect for already cached apps without a reload
func (s *Server) AppEvalTemplate(appSecrets [][]string, defaultProvider, input string) (string, error) {
	return s.secretsMgr().AppEvalTemplate(appSecrets, defaultProvider, input)
}

// applyDynamicConfig recomputes the effective config from the static config
// and the dynamic entries/settings, then applies the runtime side effects of
// changed sections: OAuth/SAML provider re-registration and list-apps app
// invalidation. Called at startup and on every dynamic config change (API
// update, restore, cross-instance notification). With failOnBindError, a db
// secret provider bind failure rejects the whole update (used for runtime
// updates: a bad key reference must not silently swap in a disabled
// provider); at startup the bind failure is nonfatal, same as NewServer's
// own bind
func (s *Server) applyDynamicConfig(ctx context.Context, config *types.DynamicConfig, failOnBindError bool) error {
	// The merge always starts from the static config, so deleted dynamic
	// values revert to their static state
	effective, err := mergeDynamicConfig(s.Logger, s.staticConfig, config, s.secretsMgr().EvalTemplate)
	if err != nil {
		return err
	}

	previous := s.Config()

	// The secret providers are initialized with their config, so a change
	// rebuilds the manager. Building it validates the provider names and
	// settings, so it runs first: a bad entry fails the whole update before
	// any other side effect (the schema validation cannot catch these, secret
	// provider properties are free form)
	var secretsManager *system.SecretManager
	if !reflect.DeepEqual(previous.Secret, effective.Secret) ||
		previous.AppConfig.Security.DefaultSecretsProvider != effective.AppConfig.Security.DefaultSecretsProvider {
		secretsManager, err = system.NewSecretManager(ctx, effective.Secret,
			effective.AppConfig.Security.DefaultSecretsProvider, effective)
		if err != nil {
			return fmt.Errorf("error initializing secret providers: %w", err)
		}
		// Re-bind the db provider of the rebuilt manager to the metadata
		// database, same as at startup: without this, stored-secret
		// operations fail after any dynamic [secret] config change
		if err := bindDBSecretStore(ctx, s.Logger, secretsManager, s.db); err != nil && failOnBindError {
			return fmt.Errorf("error initializing embedded secrets store (db provider), rejecting config update: %w", err)
		}
	}

	s.effectiveConfig.Store(effective)
	if secretsManager != nil {
		s.secretsManager.Store(secretsManager)
	}

	if !reflect.DeepEqual(previous.Auth, effective.Auth) {
		if err := s.oAuthManager.UpdateProviders(effective.Auth); err != nil {
			return fmt.Errorf("error updating oauth providers: %w", err)
		}
	}
	if !reflect.DeepEqual(previous.SAML, effective.SAML) {
		s.samlManager.UpdateProviders(ctx, effective.SAML)
	}

	if !reflect.DeepEqual(previous.System, effective.System) ||
		previous.Security.AppDefaultAuthType != effective.Security.AppDefaultAuthType ||
		!reflect.DeepEqual(previous.AppConfig, effective.AppConfig) ||
		!reflect.DeepEqual(previous.NodeConfig, effective.NodeConfig) {
		// The list-apps app bakes in the title/domain/auth settings at build
		// time; drop it so the next request rebuilds it with the new values
		s.mu.Lock()
		s.listAppsApp = nil
		s.mu.Unlock()
	}
	return nil
}

func (s *Server) SaveDynamicConfig(ctx context.Context) error {
	targetDir := os.ExpandEnv("$OPENRUN_HOME/config")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("error creating config directory %s : %s", targetDir, err)
	}

	targetPath := path.Join(targetDir, "dynamic_config.json")
	configJson, err := json.MarshalIndent(s.dynamicConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling dynamic config: %w", err)
	}
	err = os.WriteFile(targetPath, configJson, 0600)
	if err != nil {
		return fmt.Errorf("error writing dynamic config: %w", err)
	}
	return nil
}

func (s *Server) updateDynamicConfigCache(ctx context.Context, newConfig *types.DynamicConfig) error {
	// The RBAC manager is updated first so its caches rebuild, but a rejected
	// update must not leave the rejected request's RBAC rules live: if a
	// later step fails (for example the db secret provider bind validation),
	// the previous RBAC config is restored. The restore also clears the
	// partial state UpdateRBACConfig leaves behind when it fails midway
	prevRBAC := &s.dynamicConfig.RBAC
	restoreRBAC := func() {
		if restoreErr := s.rbacManager.UpdateRBACConfig(prevRBAC); restoreErr != nil {
			s.Error().Err(restoreErr).Msg("error restoring previous rbac config after rejected config update")
		}
	}
	if err := s.rbacManager.UpdateRBACConfig(&newConfig.RBAC); err != nil {
		restoreRBAC()
		return fmt.Errorf("error updating rbac config: %w", err)
	}
	if err := s.applyDynamicConfig(ctx, newConfig, true); err != nil {
		restoreRBAC()
		return fmt.Errorf("error applying dynamic config entries: %w", err)
	}
	s.dynamicConfig = newConfig
	if err := s.SaveDynamicConfig(ctx); err != nil {
		return fmt.Errorf("error saving dynamic config: %w", err)
	}
	return nil
}

func (s *Server) UpdateDynamicConfig(ctx context.Context, newConfig *types.DynamicConfig, force bool) (*types.DynamicConfig, error) {
	// config:update is admin equivalent: the dynamic config includes the RBAC config
	if err := s.enforceGlobalPerm(ctx, types.PermissionConfigUpdate, ""); err != nil {
		return nil, err
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	currentVersionId := s.dynamicConfig.VersionId
	if currentVersionId != newConfig.VersionId && !force {
		// stale update
		return nil, fmt.Errorf("config version id mismatch, expected %s, got %s", currentVersionId, newConfig.VersionId)
	}

	newConfig.VersionId = "ver_" + ksuid.New().String()
	err := s.updateDynamicConfigCache(ctx, newConfig)
	if err != nil {
		return nil, fmt.Errorf("error updating dynamic config: %w", err)
	}

	err = s.db.UpdateConfig(ctx, system.GetContextUserId(ctx), currentVersionId, newConfig)
	if err != nil {
		return nil, fmt.Errorf("error updating dynamic config: %w", err)
	}

	err = s.db.NotifyConfigUpdate()
	if err != nil {
		return nil, fmt.Errorf("error notifying other instances about new dynamic config: %w", err)
	}
	return newConfig, nil
}

func (s *Server) appNotifyHandler(updatePayload types.AppUpdatePayload) {
	if updatePayload.ServerId == types.CurrentServerId {
		s.Trace().Str("server_id", string(updatePayload.ServerId)).Msg("Ignoring app update notification from self")
		return
	}
	s.Debug().Str("server_id", string(updatePayload.ServerId)).Msgf(
		"Received app update notification from %s for %s", updatePayload.ServerId, updatePayload.AppPathDomains)
	s.apps.ClearAppsNoNotify(updatePayload.AppPathDomains)
}

func (s *Server) configNotifyHandler(updatePayload types.ConfigUpdatePayload) {
	if updatePayload.ServerId == types.CurrentServerId {
		s.Trace().Str("server_id", string(updatePayload.ServerId)).Msg("Ignoring config update notification from self")
		return
	}
	s.Debug().Str("server_id", string(updatePayload.ServerId)).Msgf(
		"Received config update notification from %s", updatePayload.ServerId)
	dynamicConfig, err := s.db.GetConfig() // get the latest dynamic config from database
	if err != nil {
		s.Error().Err(err).Msg("error getting dynamic config")
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	err = s.updateDynamicConfigCache(context.Background(), dynamicConfig)
	if err != nil {
		s.Error().Err(err).Msg("error updating dynamic config")
		return
	}
}

// bindDBSecretStore connects the db secret provider of manager to the
// metadata database. A newly built SecretManager cannot serve stored secrets
// until this runs, so every path that builds a manager after the metadata
// database is up (startup, dynamic config rebuild) must call this. A failure
// (for example a master key which does not match the stored secrets) leaves
// the db provider disabled (operations on it return the bind error, other
// providers keep working); the error is logged here and also returned so
// runtime config updates can reject the change
func bindDBSecretStore(ctx context.Context, logger *types.Logger, manager *system.SecretManager, db *metadata.Metadata) error {
	err := manager.BindDBStores(ctx, db)
	if err != nil {
		logger.Error().Err(err).Msg("embedded secrets store (db provider) initialization failed; db secrets will be unavailable")
	}
	return err
}

// updateConfigSecrets updates the secrets in the server config using the evalSecret function
func updateConfigSecrets(config *types.ServerConfig, evalSecret func(string) (string, error)) error {
	var err error
	config.Metadata.DBConnection, err = evalSecret(config.Metadata.DBConnection)
	if err != nil {
		return err
	}
	config.Metadata.AuditDBConnection, err = evalSecret(config.Metadata.AuditDBConnection)
	if err != nil {
		return err
	}
	// TODO : eval store and fs db connections secrets

	for name, auth := range config.Auth {
		if auth.Key, err = evalSecret(auth.Key); err != nil {
			return err
		}

		if auth.Secret, err = evalSecret(auth.Secret); err != nil {
			return err
		}
		config.Auth[name] = auth
	}

	// git_auth entries are not resolved here: they can reference the db
	// secret provider, which is bound only after the metadata database is
	// initialized. loadGitKey resolves them at use time instead

	for name, pluginConfig := range config.Plugins {
		for key, value := range pluginConfig {
			valString, ok := value.(string)
			if ok {
				if valString, err = evalSecret(valString); err != nil {
					return err
				}
				pluginConfig[key] = valString
			}
		}
		config.Plugins[name] = pluginConfig
	}

	for key, val := range config.NodeConfig {
		if valStr, ok := val.(string); ok {
			if valStr, err = evalSecret(valStr); err != nil {
				return err
			}
			val = valStr
		}
		config.NodeConfig[key] = val
	}

	for k, v := range config.Telemetry.Headers {
		resolved, err := evalSecret(v)
		if err != nil {
			return fmt.Errorf("resolving telemetry header %q: %w", k, err)
		}
		config.Telemetry.Headers[k] = resolved
	}

	return nil
}

// handleAppClose listens for app close notifications and removes the app from the store
func (s *Server) handleAppClose() {
	for {
		select {
		case appPathDomain := <-s.notifyClose:
			s.apps.ClearApps([]types.AppPathDomain{appPathDomain})
			s.Debug().Str("app", appPathDomain.String()).Msg("App closed")
		case <-s.stopRequested:
			s.Debug().Msg("App close handler stopped")
			return
		}
	}
}

// setupAdminAccount sets up the basic auth password for admin account. If admin user is unset,
// that means admin account is not enabled. If AdminPasswordBcrypt is set, it will be used as
// the password hash for the admin account. If AdminPasswordBcrypt is not set, a random password
// will be generated for that server startup. The generated password will be printed to stdout.
func (s *Server) setupAdminAccount() (string, error) {
	if s.Config().AdminUser == "" {
		s.Warn().Msg("No admin username specified, skipping admin account setup")
		return "", nil
	}

	if s.Config().Security.AdminPasswordBcrypt != "" {
		s.Info().Msgf("Using admin password bcrypt hash from configuration")
		return "", nil
	}

	s.Debug().Msg("Generating admin password")
	var err error
	password, err := passwd.GeneratePassword()
	if err != nil {
		return "", err
	}

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), passwd.BCRYPT_COST)
	if err != nil {
		return "", err
	}

	s.Config().Security.AdminPasswordBcrypt = string(bcryptHash)
	return password, nil
}

// Start starts the OpenRun Server
func (s *Server) Start() error {
	s.handler = NewTCPHandler(s.Logger, s.Config(), s)
	// Builder config problems must not block startup: the builder config is
	// dynamically editable, so a bad entry has to be fixable through the
	// console. The error is logged and surfaces again on builder use
	if err := s.initBuilder(); err != nil {
		s.Error().Err(err).Msg("app_builder config error, the builder will not work until fixed")
	} else if err := s.builderManager.Start(context.Background()); err != nil {
		s.Error().Err(err).Msg("Error starting app builder")
	}
	serverUri := strings.TrimSpace(os.ExpandEnv(s.Config().ServerUri))
	if serverUri == "" {
		return errors.New("server_uri is not set")
	}

	// Change to OPENRUN_HOME directory, helps avoid length limit on UDS file (around 104 chars)
	clHome := os.Getenv("OPENRUN_HOME")
	err := os.Chdir(clHome)
	if err != nil {
		return fmt.Errorf("error changing to OPENRUN_HOME directory: %w", err)
	}

	if err := os.MkdirAll(path.Join(clHome, "mounts"), 0700); err != nil {
		return fmt.Errorf("error creating directory %s : %s", "mounts", err)
	}

	// Start unix domain socket server
	if !strings.HasPrefix(serverUri, "http://") && !strings.HasPrefix(serverUri, "https://") {
		if strings.HasPrefix(serverUri, clHome) {
			serverUri = path.Join(".", serverUri[len(clHome):]) // use relative path
		}

		// Unix domain sockets is enabled
		socketDir := path.Dir(serverUri)
		if err := os.MkdirAll(socketDir, 0700); err != nil {
			return fmt.Errorf("error creating directory %s : %s", socketDir, err)
		}

		udsHandler := NewUDSHandler(s.Logger, s.Config(), s)
		socket, listenErr := net.Listen("unix", serverUri)
		if listenErr != nil {
			s.Debug().Err(listenErr).Msgf("Error creating socket file, trying to dial socket file %s", serverUri)
			probeConn, errDial := net.Dial("unix", serverUri)
			if errDial == nil {
				probeConn.Close() //nolint:errcheck
			}
			if errDial != nil {
				s.Debug().Err(errDial).Msg("Error dialling UDS, trying to remove socket file")
				// Cannot dial also, so it's safe to delete the socket file
				if removeErr := os.Remove(serverUri); removeErr != nil {
					return fmt.Errorf("error removing socket file %s : %s. Original error %s", serverUri, removeErr, listenErr)
				}
				var err error
				socket, err = net.Listen("unix", serverUri)
				if err != nil {
					return fmt.Errorf("error creating socket after deleting old file  %s : %s. Original error %s", serverUri, err, listenErr)
				}
			} else {
				return fmt.Errorf("error creating socket, another server already running %s : %s", serverUri, listenErr)
			}
		}

		s.udsServer = &http.Server{
			WriteTimeout: 180 * time.Second,
			ReadTimeout:  180 * time.Second,
			IdleTimeout:  30 * time.Second,
			Handler: telemetry.WrapServerHandler(udsHandler.router, telemetry.ServerHandlerOption{
				Operation: "openrun.uds",
				Public:    false, // UDS is admin-only, peer is authenticated by file permissions
			}),
		}

		s.Info().Str("address", serverUri).Msg("Starting unix domain socket server")
		go func() {
			if err := s.udsServer.Serve(socket); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Error().Err(err).Msg("UDS server error")
				if s.httpServer != nil {
					s.httpServer.Shutdown(context.Background()) //nolint:errcheck
				}
				if s.httpsServer != nil {
					s.httpsServer.Shutdown(context.Background()) //nolint:errcheck
				}
				os.Exit(1)
			}
		}()
	} else {
		s.Info().Msg("Unix domain sockets are disabled")
	}

	// Start HTTP and HTTPS servers
	if s.Config().Http.Port >= 0 {
		s.httpServer = &http.Server{
			WriteTimeout: 180 * time.Second,
			ReadTimeout:  180 * time.Second,
			IdleTimeout:  30 * time.Second,
			Handler: telemetry.WrapServerHandler(s.handler.router, telemetry.ServerHandlerOption{
				Operation: "openrun.http",
				Public:    true, // public HTTP listener; do not extract incoming traceparent
				TraceOnlyPrefixes: []string{
					types.INTERNAL_URL_PREFIX + "/", // app traffic is traced at the app layer with app redaction policy
				},
				ExtraSkipPaths: []string{
					types.WEBHOOK_URL_PREFIX + "/", // webhook URLs may include secrets in the path
				},
			}),
		}
	}

	if s.Config().Https.Port >= 0 {
		var err error
		s.httpsServer, err = s.setupHTTPSServer()
		if err != nil {
			return err
		}

	}

	generatedPass, err := s.setupAdminAccount()
	if err != nil {
		return err
	}
	if generatedPass != "" {
		fmt.Printf("Admin user    : %s\n", s.Config().AdminUser)
		fmt.Printf("Admin password: %s\n", generatedPass)
	}

	if s.httpServer != nil {
		addr := fmt.Sprintf("%s:%d", system.MapServerHost(s.Config().Http.Host), s.Config().Http.Port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s.Config().Http.Port = listener.Addr().(*net.TCPAddr).Port
		addr = fmt.Sprintf("%s:%d", system.MapServerHost(s.Config().Http.Host), s.Config().Http.Port)
		s.Info().Str("address", addr).Msg("Starting HTTP server")

		go func() {
			if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Error().Err(err).Msg("HTTP server error")
				if s.httpsServer != nil {
					s.httpsServer.Shutdown(context.Background()) //nolint:errcheck
				}
				if s.udsServer != nil {
					s.udsServer.Shutdown(context.Background()) //nolint:errcheck
				}
				os.Exit(1)
			}
		}()
	}

	if s.httpsServer != nil {
		addr := fmt.Sprintf("%s:%d", system.MapServerHost(s.Config().Https.Host), s.Config().Https.Port)
		listener, err := tls.Listen("tcp", addr, s.httpsServer.TLSConfig)
		if err != nil {
			return err
		}
		s.Config().Https.Port = listener.Addr().(*net.TCPAddr).Port
		addr = fmt.Sprintf("%s:%d", system.MapServerHost(s.Config().Https.Host), s.Config().Https.Port)
		s.Info().Str("address", addr).Msg("Starting HTTPS server")
		go func() {
			if err := s.httpsServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Error().Err(err).Msg("HTTPS server error")
				if s.httpServer != nil {
					s.httpServer.Shutdown(context.Background()) //nolint:errcheck
				}
				if s.udsServer != nil {
					s.udsServer.Shutdown(context.Background()) //nolint:errcheck
				}
				os.Exit(1)
			}
		}()
	}
	return nil
}

func (s *Server) setupHTTPSServer() (*http.Server, error) {
	var tlsConfig *tls.Config
	var mkcertPath string
	if s.Config().Https.MkcertPath != "disable" {
		if s.Config().Https.MkcertPath == "" {
			mkcertPath = system.FindExec("mkcert")
		} else {
			mkcertPath = s.Config().Https.MkcertPath
		}
	}

	if mkcertPath != "" {
		s.Info().Msgf("mkcert path %s", mkcertPath)
	}
	var mkcertsLock sync.Mutex
	if err := os.MkdirAll(os.ExpandEnv(s.Config().Https.CertLocation), 0700); err != nil {
		return nil, fmt.Errorf("error creating cert directory %s : %s",
			os.ExpandEnv(s.Config().Https.CertLocation), err)
	}

	if s.Config().Https.ServiceEmail != "" {
		// Certmagic is enabled
		if s.Config().Https.UseStaging {
			// Use Let's Encrypt staging server
			certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		}
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = s.Config().Https.ServiceEmail
		certmagic.DefaultACME.DisableHTTPChallenge = true
		certmagic.Default.Storage = s.db.GetCertStorage() // Use the database backed storage

		magicConfig := certmagic.NewDefault()
		magicConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if name == s.Config().System.DefaultDomain || name == "localhost" || name == "127.0.0.1" {
					return nil
				}

				allDomains, err := s.apps.GetAllDomains()
				if err != nil {
					return err
				}
				if allDomains[name] {
					return nil
				}
				return fmt.Errorf("unknown domain %s", name)
			},
		}
		tlsConfig = magicConfig.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
		tlsConfig.GetCertificate = magicConfig.GetCertificate
		tlsConfig.MinVersion = tls.VersionTLS12
	} else {
		// Certmagic is disabled, use certs from disk or create self signed ones
		tlsConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				domain := hello.ServerName

				if domain != "" && s.Config().Https.EnableCertLookup {
					certFilePath := path.Join(os.ExpandEnv(s.Config().Https.CertLocation), domain+".crt")
					certKeyPath := path.Join(os.ExpandEnv(s.Config().Https.CertLocation), domain+".key")
					// Check if certificate and key files exist on disk for the domain
					_, certErr := os.Stat(certFilePath)
					_, keyErr := os.Stat(certKeyPath)

					if mkcertPath != "" && (certErr != nil || keyErr != nil) {
						// If mkcerts is enabled and certificate or key files do not exist, generate them
						// Locking is global, not per domain
						mkcertsLock.Lock()
						defer mkcertsLock.Unlock()
						_, certErr = os.Stat(certFilePath)
						_, keyErr = os.Stat(certKeyPath)
						if certErr != nil || keyErr != nil {
							s.Info().Msgf("Generating mkcert certificate for domain %s", domain)
							cmd := exec.Command(mkcertPath, "-cert-file", certFilePath, "-key-file", certKeyPath, domain)
							if err := cmd.Run(); err != nil {
								return nil, fmt.Errorf("error generating certificate using mkcert: %w", err)
							}
							_, certErr = os.Stat(certFilePath)
							_, keyErr = os.Stat(certKeyPath)
						}
					}

					// If certificate and key files exist, load them
					if certErr == nil && keyErr == nil {
						cert, err := tls.LoadX509KeyPair(certFilePath, certKeyPath)
						return &cert, err
					}
				}

				certFilePath := path.Join(os.ExpandEnv(s.Config().Https.CertLocation), DEFAULT_CERT_FILE)
				certKeyPath := path.Join(os.ExpandEnv(s.Config().Https.CertLocation), DEFAULT_KEY_FILE)

				_, certErr := os.Stat(certFilePath)
				_, keyErr := os.Stat(certKeyPath)
				if certErr != nil || keyErr != nil {
					s.Info().Msgf("Generating default self signed certificate")
					err := GenerateSelfSignedCertificate(certFilePath, certKeyPath, 365*24*time.Hour)
					if err != nil {
						return nil, fmt.Errorf("error generating self signed certificate: %w", err)
					}
				}

				cert, err := tls.LoadX509KeyPair(certFilePath, certKeyPath)
				return &cert, err
			},
		}
	}

	if !s.Config().Https.DisableClientCerts {
		// Request client certificates, verification is done in the handler
		tlsConfig.ClientAuth = tls.RequestClientCert
		for name, clientCertConfig := range s.Config().ClientAuth {
			rootCAs, err := loadRootCAs(clientCertConfig.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("error loading root CAs pem file %s for %s: %w", clientCertConfig.CACertFile, name, err)
			}
			s.Config().ClientAuth[name] = types.ClientCertConfig{
				CACertFile: clientCertConfig.CACertFile,
				RootCAs:    rootCAs,
			}
		}
	}

	// Create a rate-limited error logger for TLS handshake errors
	rateLimitedWriter := NewRateLimitedErrorLogger(os.Stderr)
	s.tlsErrorLogger = rateLimitedWriter // retained so Stop can end its cleanup goroutine
	errorLog := log.New(rateLimitedWriter, "", log.LstdFlags)

	server := &http.Server{
		WriteTimeout: 180 * time.Second,
		ReadTimeout:  180 * time.Second,
		IdleTimeout:  30 * time.Second,
		Handler: telemetry.WrapServerHandler(s.handler.router, telemetry.ServerHandlerOption{
			Operation: "openrun.https",
			Public:    true, // public HTTPS listener; do not extract incoming traceparent
			TraceOnlyPrefixes: []string{
				types.INTERNAL_URL_PREFIX + "/", // app traffic is traced at the app layer with app redaction policy
			},
			ExtraSkipPaths: []string{
				types.WEBHOOK_URL_PREFIX + "/", // webhook URLs may include secrets in the path
			},
		}),
		TLSConfig: tlsConfig,
		ErrorLog:  errorLog,
	}
	return server, nil
}

func loadRootCAs(rootCertFile string) (*x509.CertPool, error) {
	rootPEM, err := os.ReadFile(rootCertFile)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate %s", rootCertFile)
	}

	return roots, nil
}

// Stop stops the OpenRun Server
func (s *Server) Stop(ctx context.Context) error {
	s.stopOnce.Do(func() {
		s.Info().Msg("Stopping service")
		// Signal stopRequested so goroutines selecting on it (handleAppClose,
		// StopNotify waiters) exit even when Stop is called directly
		s.RequestStop()
		if s.staleContainerCleanupStop != nil {
			close(s.staleContainerCleanupStop)
			s.staleContainerCleanupStop = nil
		}
		if s.syncStop != nil {
			s.syncTimer.Stop()
			close(s.syncStop)
		}
		if s.builderManager != nil {
			s.builderManager.Stop()
		}

		var err1, err2, err3 error
		if s.httpServer != nil {
			err1 = s.httpServer.Shutdown(ctx)
		}
		if s.httpsServer != nil {
			err2 = s.httpsServer.Shutdown(ctx)
		}
		if s.udsServer != nil {
			err3 = s.udsServer.Shutdown(ctx)
		}
		// Stop the audit writer after the HTTP servers have drained so queued
		// audit events from in-flight requests are written out
		s.stopAuditWriter()
		if s.auditDB != nil {
			s.auditDB.Close() //nolint:errcheck
		}
		if s.tlsErrorLogger != nil {
			s.tlsErrorLogger.Stop()
		}
		err4 := s.telemetry.Shutdown(ctx)

		// Close the metadata DB last, after the HTTP servers have drained, so
		// in-flight requests do not fail against a closed database
		s.db.Close()

		s.stopErr = cmp.Or(err1, err2, err3, err4)
	})
	return s.stopErr
}

func (s *Server) RequestStop() {
	s.stopRequestOnce.Do(func() {
		close(s.stopRequested)
	})
}

func (s *Server) StopNotify() <-chan struct{} {
	return s.stopRequested
}

func (s *Server) GetListAppsApp(ctx context.Context) (*app.App, error) {
	s.mu.RLock()
	if s.listAppsApp != nil {
		s.mu.RUnlock()
		return s.listAppsApp, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listAppsApp != nil {
		// Another caller initialized the app while this one waited on the lock
		return s.listAppsApp, nil
	}

	var err error
	embedReadFS := appfs.NewEmbedReadFS(s.Logger, list_apps.EmbedListApps)
	_, err = embedReadFS.Stat("app.star")
	if err != nil {
		return nil, fmt.Errorf("list_apps not available in binary")
	}

	sourceFS, err := appfs.NewSourceFs("", embedReadFS, false)
	if err != nil {
		return nil, err
	}

	merged := s.Config()
	authnType := types.AppAuthnType(merged.Security.AppDefaultAuthType)
	if authnType == "" {
		authnType = types.AppAuthnSystem
	}
	appEntry := types.AppEntry{
		Id:        types.AppId("app_prd_app_list"),
		Path:      "/",
		Domain:    merged.System.DefaultDomain,
		SourceUrl: "-",
		UserID:    "admin",
		Settings:  types.AppSettings{},
		Metadata: types.AppMetadata{
			Name:      "List Apps",
			AuthnType: authnType,
			Loads:     []string{"openrun.in"},
			Permissions: []types.Permission{
				{Plugin: "openrun.in", Method: "list_apps"},
			},
			ParamValues: map[string]string{
				"title":            merged.System.ListAppsTitle,
				"show_hosted_with": strconv.FormatBool(merged.System.ShowHostedWith),
			},
		},
	}

	subLogger := s.Logger.With().Str("id", string(appEntry.Id)).Logger()
	appLogger := types.Logger{Logger: &subLogger}
	s.listAppsApp, err = app.NewApp(sourceFS, nil, &appLogger, &appEntry, &merged.System,
		merged.Plugins, merged.AppConfig, s.notifyClose, s.AppEvalTemplate,
		s.InsertAuditEvent, merged, s.rbacManager, []*types.Binding{})
	if err != nil {
		return nil, err
	}

	_, err = s.listAppsApp.Reload(ctx, true, true, types.DryRunFalse, app.ReloadOptions{ReloadContainer: true, Verify: false})
	if err != nil {
		return nil, err
	}

	return s.listAppsApp, nil
}

func (s *Server) ParseGlob(appGlob string) ([]types.AppInfo, error) {
	appsInfo, err := s.apps.GetAllAppsInfo()
	if err != nil {
		return nil, err
	}

	matched, err := rbac.ParseGlobFromInfo(appGlob, appsInfo)
	if err != nil {
		return nil, err
	}

	return matched, nil
}

// AuthorizeList checks if the user has access to list the specified app.
// When RBAC enforcement is active for the calling app (RBAC config enabled and the
// caller has rbac: auth), the app:read permission gates listing (with the owner
// rule). Otherwise, list visibility falls back to whether the app uses the same
// authentication type as used by the caller
func (s *Server) AuthorizeList(ctx context.Context, userId string, app *types.AppInfo, groups []string) (bool, error) {
	if s.rbacManager.APIEnforced(ctx) {
		// Grant checks for stage/preview apps are done against the main app path
		grantPathDomain := mainAppPathDomain(app.AppPathDomain, app.MainApp, app.LinkedAppPath)
		return s.rbacManager.AuthorizeAPI(ctx, types.PermissionRead, grantPathDomain, app.UserID)
	}

	appAuthStr := string(app.Auth)
	appAuthStr, _, err := s.checkAuthModifiers(appAuthStr)
	if err != nil {
		return false, err
	}

	if userId != "" && userId == types.ADMIN_USER {
		// Admin user is always authorized
		return true, nil
	}

	appAuthStr = strings.TrimPrefix(appAuthStr, rbac.RBAC_AUTH_PREFIX)
	appAuth := types.AppAuthnType(appAuthStr)
	if appAuth == types.AppAuthnDefault {
		// Strip the rbac: prefix from the resolved default too, so the provider
		// comparison below matches the userId's provider (e.g. "okta"), matching
		// how authenticateAndServeApp resolves the auth type.
		resolved := strings.TrimPrefix(s.Config().Security.AppDefaultAuthType, rbac.RBAC_AUTH_PREFIX)
		appAuth = types.AppAuthnType(resolved)
	}
	appAuthStr, _, err = s.checkAuthModifiers(string(appAuth))
	if err != nil {
		return false, err
	}
	appAuth = types.AppAuthnType(appAuthStr)

	// Verify user_id as set in authenticateAndServeApp
	if appAuth == "" || appAuth == types.AppAuthnNone {
		// No auth required for this app, authorize access
		return true, nil
	} else if appAuth == types.AppAuthnSystem {
		return userId != "" && userId == types.ADMIN_USER, nil
	} else if appAuth == "cert" || strings.HasPrefix(string(appAuth), "cert_") {
		return userId == string(appAuth), nil
	} else {
		provider, _, ok := strings.Cut(string(userId), ":")
		if !ok {
			s.Warn().Str("user_id", userId).Msg("Unknown user_id format")
			return false, nil
		}
		// Check Oauth provider is the same as the app's provider
		return provider == string(appAuth), nil
	}
}

// KVInitConstant initializes a constant value in the DB. If the value already exists, it returns the existing value.
// If the value does not exist, it inserts the new value and returns it. If another server inserts the value concurrently,
// it fetches the value from the DB and returns it.
func (s *Server) KVInitConstant(ctx context.Context, keyName string, newValue []byte) ([]byte, error) {
	keyName = types.CONSTANT_KV_PREFIX + keyName
	dbValue, err := s.db.FetchKVBlob(ctx, keyName)
	if err == nil {
		// Value already exists in DB, use it
		return dbValue, nil
	}
	err = s.db.StoreKVBlob(ctx, keyName, newValue, nil)
	if err == nil {
		// New value inserted, return it
		return newValue, nil
	}

	// Failed to insert, maybe concurrent insert from another server, get the value from the DB
	dbValue, err = s.db.FetchKVBlob(ctx, keyName)
	if err != nil {
		return nil, fmt.Errorf("error fetching constant value: %w", err)
	}
	return dbValue, nil
}

func (s *Server) CleanupVersions() {
	// Cleanup old versions of apps
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Error().Msgf("error in cleanup versions: %v", r)
			}
		}()

		apps, err := s.apps.GetAllAppsInfo()
		if err != nil {
			s.Error().Err(err).Msg("error getting all apps info")
			return
		}

		for _, app := range apps {
			err := s.db.CleanupAppVersions(app)
			if err != nil {
				s.Error().Err(err).Msgf("error cleaning up versions for app %s", app.AppPathDomain)
			}
		}

		err = s.db.CleanupFiles()
		if err != nil {
			s.Error().Err(err).Msg("error cleaning up files")
		}
	}()
}

// KVStore is an interface for a key-value store. Implemented by metadata.Metadata
type KVStore interface {
	FetchKV(ctx context.Context, key string) (map[string]any, error)
	FetchKVBlob(ctx context.Context, key string) ([]byte, error)
	StoreKV(ctx context.Context, key string, value map[string]any, expireAt *time.Time) error
	StoreKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error
	UpsertKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error

	UpdateKV(ctx context.Context, key string, value map[string]any) error
	UpdateKVBlob(ctx context.Context, key string, value []byte) error
	DeleteKV(ctx context.Context, key string) error
}
