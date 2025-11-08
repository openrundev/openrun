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
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-chi/chi/middleware"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/rbac"
	"github.com/openrundev/openrun/internal/server/list_apps"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
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

	customSpecsDir := path.Clean((path.Join(os.ExpandEnv("$OPENRUN_HOME/config"), APPSPECS, string(name))))
	entries, err := os.ReadDir(customSpecsDir)
	if err != nil {
		// Use bundled app if present
		return appTypes[string(name)]
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
	config         *types.ServerConfig
	db             *metadata.Metadata
	httpServer     *http.Server
	httpsServer    *http.Server
	udsServer      *http.Server
	handler        *Handler
	apps           *AppStore
	authHandler    *AdminBasicAuth
	oAuthManager   *OAuthManager
	samlManager    *SAMLManager
	notifyClose    chan types.AppPathDomain
	secretsManager *system.SecretManager
	listAppsApp    *app.App
	mu             sync.RWMutex
	auditDB        *sql.DB
	auditDbType    system.DBType
	syncTimer      *time.Ticker
	configMu       sync.RWMutex
	dynamicConfig  *types.DynamicConfig
	rbacManager    *rbac.RBACManager
	csrfMiddleware *http.CrossOriginProtection
}

// NewServer creates a new instance of the OpenRun Server
func NewServer(config *types.ServerConfig) (*Server, error) {
	metadataDir := os.ExpandEnv("$OPENRUN_HOME/metadata")
	if err := os.MkdirAll(metadataDir, 0700); err != nil {
		return nil, fmt.Errorf("error creating metadata directory %s : %w", metadataDir, err)
	}

	l := types.NewLogger(&config.Log)
	db, err := metadata.NewMetadata(l, config)
	if err != nil {
		return nil, err
	}

	server := &Server{
		Logger: l,
		config: config,
		db:     db,
	}
	db.AppNotifyFunc = server.appNotifyHandler
	db.ConfigNotifyFunc = server.configNotifyHandler
	server.apps = NewAppStore(l, server)
	server.authHandler = NewAdminBasicAuth(l, config)
	server.notifyClose = make(chan types.AppPathDomain)

	// Setup secrets manager
	server.secretsManager, err = system.NewSecretManager(context.Background(), config.Secret, config.AppConfig.Security.DefaultSecretsProvider)
	if err != nil {
		return nil, err
	}

	// Update secrets in the config
	err = updateConfigSecrets(server.config, server.secretsManager.EvalTemplate)
	if err != nil {
		return nil, err
	}

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

	if config.Log.AccessLogging {
		accessLogger := types.RollingFileLogger(&config.Log, "access.log")
		customLogger := log.New(accessLogger, "", log.LstdFlags)
		middleware.DefaultLogger = middleware.RequestLogger(
			&middleware.DefaultLogFormatter{Logger: customLogger, NoColor: true})
	} else {
		middleware.DefaultLogger = func(next http.Handler) http.Handler {
			return next // no-op, logging is disabled
		}
	}

	if config.System.ContainerCommand == "auto" {
		config.System.ContainerCommand = server.lookupContainerCommand()
		// if command is empty string, that means either containers are disabled in config or no container command found
	}

	server.Trace().Str("cmd", config.System.ContainerCommand).Msg("Container management command")
	go server.handleAppClose()

	initOpenRunPlugin(server)
	initAdminPlugin(server)

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

	server.rbacManager, err = rbac.NewRBACHandler(l, &server.dynamicConfig.RBAC, config)
	if err != nil {
		return nil, fmt.Errorf("error initializing rbac manager: %w", err)
	}

	// Start the idle shutdown check
	server.syncTimer = time.NewTicker(time.Minute) // run sync every minute
	go server.syncRunner()
	return server, nil
}

func (s *Server) GetDynamicConfig() types.DynamicConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return *s.dynamicConfig // return a copy of the dynamic config
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
	err := s.rbacManager.UpdateRBACConfig(&newConfig.RBAC) // update the rbac config so that it updates its caches
	if err != nil {
		return fmt.Errorf("error updating rbac config: %w", err)
	}
	s.dynamicConfig = newConfig
	err = s.SaveDynamicConfig(ctx)
	if err != nil {
		return fmt.Errorf("error saving dynamic config: %w", err)
	}
	return nil
}

func (s *Server) UpdateDynamicConfig(ctx context.Context, newConfig *types.DynamicConfig, force bool) (*types.DynamicConfig, error) {
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

// updateConfigSecrets updates the secrets in the server config using the evalSecret function
func updateConfigSecrets(config *types.ServerConfig, evalSecret func(string) (string, error)) error {
	var err error
	for name, auth := range config.Auth {
		if auth.Key, err = evalSecret(auth.Key); err != nil {
			return err
		}

		if auth.Secret, err = evalSecret(auth.Secret); err != nil {
			return err
		}
		config.Auth[name] = auth
	}

	for name, gitAuth := range config.GitAuth {
		if gitAuth.Password, err = evalSecret(gitAuth.Password); err != nil {
			return err
		}
		config.GitAuth[name] = gitAuth
	}

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

	return nil
}

const (
	DOCKER_COMMAND = "docker"
	PODMAN_COMMAND = "podman"
)

// handleAppClose listens for app close notifications and removes the app from the store
func (s *Server) handleAppClose() {
	for appPathDomain := range s.notifyClose {
		s.apps.ClearApps([]types.AppPathDomain{appPathDomain})
		s.Debug().Str("app", appPathDomain.String()).Msg("App closed")
	}
	s.Debug().Msg("App close handler stopped")
}

const (
	kubeHostEnv = "KUBERNETES_SERVICE_HOST"
	kubePortEnv = "KUBERNETES_SERVICE_PORT"
)

func (s *Server) lookupContainerCommand() string {
	// Check if running in Kubernetes
	_, hasHost := os.LookupEnv(kubeHostEnv)
	_, hasPort := os.LookupEnv(kubePortEnv)
	if hasHost || hasPort {
		return types.CONTAINER_KUBERNETES
	}

	podmanExec := system.FindExec(PODMAN_COMMAND)
	if podmanExec != "" {
		return podmanExec
	}
	dockerExec := system.FindExec(DOCKER_COMMAND)
	if dockerExec != "" {
		return dockerExec
	}
	return ""
}

// setupAdminAccount sets up the basic auth password for admin account. If admin user is unset,
// that means admin account is not enabled. If AdminPasswordBcrypt is set, it will be used as
// the password hash for the admin account. If AdminPasswordBcrypt is not set, a random password
// will be generated for that server startup. The generated password will be printed to stdout.
func (s *Server) setupAdminAccount() (string, error) {
	if s.config.AdminUser == "" {
		s.Warn().Msg("No admin username specified, skipping admin account setup")
		return "", nil
	}

	if s.config.Security.AdminPasswordBcrypt != "" {
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

	s.config.Security.AdminPasswordBcrypt = string(bcryptHash)
	return password, nil
}

// Start starts the OpenRun Server
func (s *Server) Start() error {
	s.handler = NewTCPHandler(s.Logger, s.config, s)
	serverUri := strings.TrimSpace(os.ExpandEnv(s.config.ServerUri))
	if serverUri == "" {
		return errors.New("server_uri is not set")
	}

	// Change to OPENRUN_HOME directory, helps avoid length limit on UDS file (around 104 chars)
	clHome := os.Getenv("OPENRUN_HOME")
	err := os.Chdir(clHome)
	if err != nil {
		return fmt.Errorf("error changing to OPENRUN_HOME directory: %w", err)
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

		udsHandler := NewUDSHandler(s.Logger, s.config, s)
		socket, listenErr := net.Listen("unix", serverUri)
		if listenErr != nil {
			s.Debug().Err(listenErr).Msgf("Error creating socket file, trying to dial socket file %s", serverUri)
			_, errDial := net.Dial("unix", serverUri)
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
			Handler:      udsHandler.router,
		}

		s.Info().Str("address", serverUri).Msg("Starting unix domain socket server")
		go func() {
			if err := s.udsServer.Serve(socket); err != nil {
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
	if s.config.Http.Port >= 0 {
		s.httpServer = &http.Server{
			WriteTimeout: 180 * time.Second,
			ReadTimeout:  180 * time.Second,
			IdleTimeout:  30 * time.Second,
			Handler:      s.handler.router,
		}
	}

	if s.config.Https.Port >= 0 {
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
		fmt.Printf("Admin user    : %s\n", s.config.AdminUser)
		fmt.Printf("Admin password: %s\n", generatedPass)
	}

	if s.httpServer != nil {
		addr := fmt.Sprintf("%s:%d", system.MapServerHost(s.config.Http.Host), s.config.Http.Port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s.config.Http.Port = listener.Addr().(*net.TCPAddr).Port
		addr = fmt.Sprintf("%s:%d", system.MapServerHost(s.config.Http.Host), s.config.Http.Port)
		s.Info().Str("address", addr).Msg("Starting HTTP server")

		go func() {
			if err := s.httpServer.Serve(listener); err != nil {
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
		addr := fmt.Sprintf("%s:%d", system.MapServerHost(s.config.Https.Host), s.config.Https.Port)
		listener, err := tls.Listen("tcp", addr, s.httpsServer.TLSConfig)
		if err != nil {
			return err
		}
		s.config.Https.Port = listener.Addr().(*net.TCPAddr).Port
		addr = fmt.Sprintf("%s:%d", system.MapServerHost(s.config.Https.Host), s.config.Https.Port)
		s.Info().Str("address", addr).Msg("Starting HTTPS server")
		go func() {
			if err := s.httpsServer.Serve(listener); err != nil {
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
	if s.config.Https.MkcertPath != "disable" {
		if s.config.Https.MkcertPath == "" {
			mkcertPath = system.FindExec("mkcert")
		} else {
			mkcertPath = s.config.Https.MkcertPath
		}
	}

	s.Info().Msgf("mkcert path %s", mkcertPath)
	var mkcertsLock sync.Mutex
	if err := os.MkdirAll(os.ExpandEnv(s.config.Https.CertLocation), 0700); err != nil {
		return nil, fmt.Errorf("error creating cert directory %s : %s",
			os.ExpandEnv(s.config.Https.CertLocation), err)
	}

	if s.config.Https.ServiceEmail != "" {
		// Certmagic is enabled
		if s.config.Https.UseStaging {
			// Use Let's Encrypt staging server
			certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		}
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = s.config.Https.ServiceEmail
		certmagic.DefaultACME.DisableHTTPChallenge = true
		// Customize the storage directory
		customStorageDir := os.ExpandEnv(s.config.Https.StorageLocation)
		certmagic.Default.Storage = &certmagic.FileStorage{Path: customStorageDir}

		magicConfig := certmagic.NewDefault()
		magicConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if name == s.config.System.DefaultDomain || name == "localhost" || name == "127.0.0.1" {
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

				if domain != "" && s.config.Https.EnableCertLookup {
					certFilePath := path.Join(os.ExpandEnv(s.config.Https.CertLocation), domain+".crt")
					certKeyPath := path.Join(os.ExpandEnv(s.config.Https.CertLocation), domain+".key")
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

				certFilePath := path.Join(os.ExpandEnv(s.config.Https.CertLocation), DEFAULT_CERT_FILE)
				certKeyPath := path.Join(os.ExpandEnv(s.config.Https.CertLocation), DEFAULT_KEY_FILE)

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

	if !s.config.Https.DisableClientCerts {
		// Request client certificates, verification is done in the handler
		tlsConfig.ClientAuth = tls.RequestClientCert
		for name, clientCertConfig := range s.config.ClientAuth {
			rootCAs, err := loadRootCAs(clientCertConfig.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("error loading root CAs pem file %s for %s: %w", clientCertConfig.CACertFile, name, err)
			}
			s.config.ClientAuth[name] = types.ClientCertConfig{
				CACertFile: clientCertConfig.CACertFile,
				RootCAs:    rootCAs,
			}
		}
	}

	server := &http.Server{
		WriteTimeout: 180 * time.Second,
		ReadTimeout:  180 * time.Second,
		IdleTimeout:  30 * time.Second,
		Handler:      s.handler.router,
		TLSConfig:    tlsConfig,
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
	s.Info().Msg("Stopping service")
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

	return cmp.Or(err1, err2, err3)
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

	authnType := types.AppAuthnType(s.config.Security.AppDefaultAuthType)
	if authnType == "" {
		authnType = types.AppAuthnSystem
	}
	appEntry := types.AppEntry{
		Id:        types.AppId("app_prd_app_list"),
		Path:      "/",
		Domain:    s.config.System.DefaultDomain,
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
		},
	}

	subLogger := s.Logger.With().Str("id", string(appEntry.Id)).Logger()
	appLogger := types.Logger{Logger: &subLogger}
	s.listAppsApp, err = app.NewApp(sourceFS, nil, &appLogger, &appEntry, &s.config.System,
		s.config.Plugins, s.config.AppConfig, s.notifyClose, s.secretsManager.AppEvalTemplate,
		s.InsertAuditEvent, s.config, s.rbacManager)
	if err != nil {
		return nil, err
	}

	_, err = s.listAppsApp.Reload(ctx, true, true, types.DryRunFalse)
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

// AuthorizeList checks if the user has access to perform list operation on the specified app
// For RBAC mode, uses RBAC permissions. For non-RBAC mode, look at whether app is using
// same authentication types as used by the caller
func (s *Server) AuthorizeList(userId string, app *types.AppInfo, groups []string) (bool, error) {
	appAuthStr := string(app.Auth)
	if s.rbacManager.RbacConfig.Enabled {
		// RBAC auth is enabled, verify access
		return s.rbacManager.AuthorizeInt(userId, app.AppPathDomain, appAuthStr, types.PermissionList, groups, false)
	}

	if userId != "" && userId == types.ADMIN_USER {
		// Admin user is always authorized
		return true, nil
	}

	appAuthStr = strings.TrimPrefix(appAuthStr, rbac.RBAC_AUTH_PREFIX)
	appAuth := types.AppAuthnType(appAuthStr)
	if appAuth == types.AppAuthnDefault {
		appAuth = types.AppAuthnType(s.config.Security.AppDefaultAuthType)
	}

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

// KVStore is an interface for a key-value store. Implemented by metadata.Metadata
type KVStore interface {
	FetchKV(ctx context.Context, key string) (map[string]any, error)
	StoreKV(ctx context.Context, key string, value map[string]any, expireAt *time.Time) error
	StoreKVBlob(ctx context.Context, key string, value []byte, expireAt *time.Time) error

	UpdateKV(ctx context.Context, key string, value map[string]any) error
	UpdateKVBlob(ctx context.Context, key string, value []byte) error
	DeleteKV(ctx context.Context, key string) error
}
