// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

func parseAppPath(inp string) (types.AppPathDomain, error) {
	domain := ""
	path := ""
	if strings.Contains(inp, ":") {
		split := strings.Split(inp, ":")
		if len(split) != 2 {
			return types.AppPathDomain{}, fmt.Errorf("invalid app path %s, expected one \":\"", inp)
		}
		domain = split[0]
		path = split[1]
	} else {
		path = inp
	}

	path = normalizePath(path)
	if path[0] != '/' {
		return types.AppPathDomain{}, fmt.Errorf("invalid app path %s, expected path to start with \"/\"", inp)
	}
	return types.AppPathDomain{Domain: domain, Path: path}, nil
}

func normalizePath(inp string) string {
	// remove trailing slash
	inp = strings.TrimRight(inp, "/")
	if len(inp) == 0 {
		return "/"
	}
	return inp
}

func (s *Server) CreateApp(ctx context.Context, appPath string,
	approve, dryRun bool, appRequest *types.CreateAppRequest) (*types.AppCreateResponse, error) {

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	repoCache, err := NewRepoCache(s)
	if err != nil {
		return nil, err
	}
	defer repoCache.Cleanup()

	result, err := s.CreateAppTx(ctx, tx, appPath, approve, dryRun, appRequest, repoCache)
	if err != nil {
		return nil, err
	}

	if dryRun {
		return result, nil
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.apps.ResetAllAppCache()
	return result, nil
}

func (s *Server) CreateAppTx(ctx context.Context, currentTx types.Transaction, appPath string,
	approve, dryRun bool, appRequest *types.CreateAppRequest, repoCache *RepoCache) (*types.AppCreateResponse, error) {
	appPathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, err
	}
	if err := validatePathForCreate(appPathDomain.Path); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	if appPathDomain.Domain != "" && appPathDomain.Domain[len(appPathDomain.Domain)-1] == '.' {
		// If domain ends with a dot, append the default domain
		if s.config.System.DefaultDomain == "" {
			return nil, types.CreateRequestError("Domain cannot end with a dot since default_domain is not configured", http.StatusBadRequest)
		}
		appPathDomain.Domain += s.config.System.DefaultDomain
	}

	matchedApp, err := s.CheckAppValid(appPathDomain.Domain, appPathDomain.Path)
	if err != nil {
		return nil, types.CreateRequestError(
			fmt.Sprintf("error matching app: %s", err), http.StatusInternalServerError)
	}
	if matchedApp != "" {
		return nil, types.CreateRequestError(
			fmt.Sprintf("App already exists at %s", matchedApp), http.StatusBadRequest)
	}

	sourceUrl := appRequest.SourceUrl
	splitSource := strings.Split(sourceUrl, "#")
	if len(splitSource) > 1 {
		// If source url has a hash, the part after the hash is the star base path
		sourceUrl = splitSource[0]
		if appRequest.AppConfig == nil {
			appRequest.AppConfig = make(map[string]string)
		}
		appRequest.AppConfig["star_base"] = "\"" + splitSource[1] + "\""
	}

	var appEntry types.AppEntry
	appEntry.Path = appPathDomain.Path
	appEntry.Domain = appPathDomain.Domain
	appEntry.SourceUrl = sourceUrl
	appEntry.IsDev = appRequest.IsDev
	if appRequest.AppAuthn != "" {
		if !s.ssoAuth.ValidateAuthType(string(appRequest.AppAuthn)) {
			return nil, fmt.Errorf("invalid authentication type %s", appRequest.AppAuthn)
		}
		appEntry.Settings.AuthnType = appRequest.AppAuthn
	} else {
		appEntry.Settings.AuthnType = types.AppAuthnDefault
	}
	// Set the default for write access by staging and preview apps
	appEntry.Settings.StageWriteAccess = s.config.Security.StageEnableWriteAccess
	appEntry.Settings.PreviewWriteAccess = s.config.Security.PreviewEnableWriteAccess

	appEntry.Metadata.VersionMetadata = types.VersionMetadata{
		Version: 0,
	}

	appEntry.Metadata.Spec = appRequest.Spec // validated in createApp
	appEntry.Metadata.ParamValues = appRequest.ParamValues
	appEntry.Metadata.ContainerOptions = appRequest.ContainerOptions
	appEntry.Metadata.ContainerArgs = appRequest.ContainerArgs
	appEntry.Metadata.ContainerVolumes = appRequest.ContainerVolumes
	appEntry.Metadata.AppConfig = appRequest.AppConfig
	appEntry.UserID = system.GetContextUserId(ctx)

	auditResult, err := s.createApp(ctx, currentTx, &appEntry, approve, dryRun, appRequest.GitBranch, appRequest.GitCommit, appRequest.GitAuthName, appRequest, repoCache)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	return auditResult, nil
}

func (s *Server) createApp(ctx context.Context, tx types.Transaction,
	appEntry *types.AppEntry, approve, dryRun bool, branch, commit, gitAuth string, applyInfo *types.CreateAppRequest, repoCache *RepoCache) (*types.AppCreateResponse, error) {
	if !system.IsGit(appEntry.SourceUrl) {
		if appEntry.SourceUrl != types.NO_SOURCE {
			// Make sure the source path is absolute
			var err error
			appEntry.SourceUrl, err = filepath.Abs(appEntry.SourceUrl)
			if err != nil {
				return nil, err
			}
		} else if appEntry.IsDev {
			return nil, fmt.Errorf("cannot create dev mode app with no source url")
		}
	}

	genId, err := ksuid.NewRandom()
	if err != nil {
		return nil, err
	}

	idStr := strings.ToLower(genId.String()) // Lowercase the ID, helps use the ID in container names

	if appEntry.IsDev {
		appEntry.Id = types.AppId(types.ID_PREFIX_APP_DEV + idStr)
	} else {
		appEntry.Id = types.AppId(types.ID_PREFIX_APP_PROD + idStr)
	}

	if appEntry.Metadata.Spec != "" {
		specFiles := s.GetAppSpec(appEntry.Metadata.Spec)
		if specFiles == nil {
			return nil, fmt.Errorf("invalid app spec %s", appEntry.Metadata.Spec)
		}

		appEntry.Metadata.SpecFiles = &specFiles
	} else {
		tf := make(types.SpecFiles)
		appEntry.Metadata.SpecFiles = &tf
	}

	if err := s.db.CreateApp(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	// Create the stage app entry if not dev
	stageAppEntry := *appEntry
	workEntry := appEntry
	if !appEntry.IsDev {
		stageAppEntry.Path = appEntry.Path + types.STAGE_SUFFIX
		stageAppEntry.Id = types.AppId(types.ID_PREFIX_APP_STAGE + string(appEntry.Id)[len(types.ID_PREFIX_APP_PROD):])
		stageAppEntry.MainApp = appEntry.Id
		stageAppEntry.Metadata.VersionMetadata.Version = 1

		if tx.Tx != nil {
			// Save the apply info in the app metadata (if called from apply context)
			stageAppEntry.Metadata.VersionMetadata.ApplyInfo, err = json.Marshal(applyInfo)
			if err != nil {
				return nil, err
			}
		}
		if err := s.db.CreateApp(ctx, tx, &stageAppEntry); err != nil {
			return nil, err
		}
		workEntry = &stageAppEntry // Work on the stage app for prod apps, it will be promoted later
	}

	if system.IsGit(workEntry.SourceUrl) {
		// Checkout the git repo locally and load into database
		if err := s.loadSourceFromGit(ctx, tx, workEntry, branch, commit, gitAuth, repoCache); err != nil {
			return nil, fmt.Errorf("failed to load source %s from git: %w. Wrong org/repo name can show as auth error."+
				" Use --git-auth for private repos, --branch to change branch", workEntry.SourceUrl, err)
		}
	} else if !workEntry.IsDev {
		// App is loaded from disk (not git) and not in dev mode, load files into DB
		if err := s.loadSourceFromDisk(ctx, tx, workEntry); err != nil {
			return nil, fmt.Errorf("failed to read source %s: %w", workEntry.SourceUrl, err)
		}
	}

	// Create the in memory app object
	application, err := s.setupApp(workEntry, tx)
	if err != nil {
		return nil, err
	}

	s.Debug().Msgf("Created app %s %s", workEntry.Path, workEntry.Id)
	auditResult, err := s.auditApp(ctx, tx, application, approve)
	if err != nil {
		return nil, fmt.Errorf("App %s audit failed: %s", workEntry.Id, err)
	}

	// Persist the source url
	if err := s.db.UpdateSourceUrl(ctx, tx, workEntry); err != nil {
		return nil, err
	}

	// Persist the metadata so that any git info is saved
	if err := s.db.UpdateAppMetadata(ctx, tx, workEntry); err != nil {
		return nil, err
	}

	// Persist the settings
	if err := s.db.UpdateAppSettings(ctx, tx, workEntry); err != nil {
		return nil, err
	}

	results := []types.ApproveResult{*auditResult}
	if !workEntry.IsDev {
		// Update the prod app metadata, promote from stage
		if err = s.promoteApp(ctx, tx, &stageAppEntry, appEntry); err != nil {
			return nil, err
		}

		prodApp, err := s.setupApp(appEntry, tx)
		if err != nil {
			return nil, err
		}

		prodAuditResult, err := s.auditApp(ctx, tx, prodApp, approve)
		if err != nil {
			return nil, fmt.Errorf("App %s audit failed: %s", appEntry.Id, err)
		}
		results = append(results, *prodAuditResult)
	}

	ret := &types.AppCreateResponse{
		AppPathDomain:  appEntry.AppPathDomain(),
		HttpUrl:        s.getAppHttpUrl(appEntry),
		HttpsUrl:       s.getAppHttpsUrl(appEntry),
		DryRun:         dryRun,
		ApproveResults: results,
		OrigSourceUrl:  appEntry.Settings.OrigSourceUrl,
		SourceUrl:      appEntry.SourceUrl,
	}

	return ret, nil
}

// getAppHttpUrl returns the HTTP URL for accessing the app
func (s *Server) getAppHttpUrl(appEntry *types.AppEntry) string {
	if s.config.Http.Port <= 0 {
		return ""
	}
	domain := cmp.Or(appEntry.Domain, s.config.System.DefaultDomain)
	return fmt.Sprintf("%s://%s:%d%s", "http", domain, s.config.Http.Port, appEntry.Path)
}

// getAppHttpsUrl returns the HTTPS URL for accessing the app
func (s *Server) getAppHttpsUrl(appEntry *types.AppEntry) string {
	if s.config.Https.Port <= 0 {
		return ""
	}
	domain := cmp.Or(appEntry.Domain, s.config.System.DefaultDomain)
	return fmt.Sprintf("%s://%s:%d%s", "https", domain, s.config.Https.Port, appEntry.Path)
}

func (s *Server) setupApp(appEntry *types.AppEntry, tx types.Transaction) (*app.App, error) {
	subLogger := s.With().Str("id", string(appEntry.Id)).Str("path", appEntry.Path).Logger()
	appLogger := types.Logger{Logger: &subLogger}
	var sourceFS *appfs.SourceFs
	if !appEntry.IsDev {
		// Prod mode, use DB as source
		fileStore := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
		dbFs, err := metadata.NewDbFs(s.Logger, fileStore, *appEntry.Metadata.SpecFiles)
		if err != nil {
			return nil, err
		}
		sourceFS, err = appfs.NewSourceFs("", dbFs, false)
		if err != nil {
			return nil, err
		}
	} else {
		// Dev mode, use local disk as source
		var err error
		sourceFS, err = appfs.NewSourceFs(appEntry.SourceUrl,
			&appfs.DiskWriteFS{DiskReadFS: appfs.NewDiskReadFS(&appLogger, appEntry.SourceUrl, *appEntry.Metadata.SpecFiles)},
			appEntry.IsDev)
		if err != nil {
			return nil, err
		}
	}

	appPath := fmt.Sprintf(os.ExpandEnv("$OPENRUN_HOME/run/app/%s"), appEntry.Id)
	workFS := appfs.NewWorkFs(appPath,
		&appfs.DiskWriteFS{
			DiskReadFS: appfs.NewDiskReadFS(&appLogger, appPath, *appEntry.Metadata.SpecFiles),
		})
	return app.NewApp(sourceFS, workFS, &appLogger, appEntry, &s.config.System,
		s.config.Plugins, s.config.AppConfig, s.notifyClose, s.secretsManager.AppEvalTemplate,
		s.InsertAuditEvent, s.config)
}

func (s *Server) GetAppApi(ctx context.Context, appPath string) (*types.AppGetResponse, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	pathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, err
	}

	appEntry, error := s.db.GetAppTx(ctx, tx, pathDomain)
	if error != nil {
		return nil, error
	}

	return &types.AppGetResponse{
		AppEntry: *appEntry,
	}, nil
}

func (s *Server) GetAppEntry(ctx context.Context, tx types.Transaction, pathDomain types.AppPathDomain) (*types.AppEntry, error) {
	return s.db.GetAppTx(ctx, tx, pathDomain)
}

func (s *Server) GetApp(pathDomain types.AppPathDomain, init bool) (*app.App, error) {
	application, err := s.apps.GetApp(pathDomain)
	if err != nil {
		// App not found in cache, get from DB
		appEntry, err := s.db.GetApp(pathDomain)
		if err != nil {
			return nil, err
		}

		application, err = s.setupApp(appEntry, types.Transaction{})
		if err != nil {
			return nil, err
		}
		s.apps.AddApp(application)
	}

	if !init {
		return application, nil
	}

	// Initialize the app
	if err := application.Initialize(types.DryRunFalse); err != nil {
		return nil, fmt.Errorf("error initializing app: %w", err)
	}

	return application, nil
}

func (s *Server) DeleteApps(ctx context.Context, appPathGlob string, dryRun bool) (*types.AppDeleteResponse, error) {
	filteredApps, err := s.FilterApps(appPathGlob, false)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, appInfo := range filteredApps {
		if err := s.db.DeleteApp(ctx, tx, appInfo.Id); err != nil {
			return nil, err
		}
	}

	ret := &types.AppDeleteResponse{
		DryRun:  dryRun,
		AppInfo: filteredApps,
	}

	if dryRun {
		return ret, nil
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// Remove from in memory app cache
	for _, appInfo := range filteredApps {
		if err := s.apps.ClearLinkedApps(appInfo.AppPathDomain); err != nil {
			return nil, fmt.Errorf("error deleting app: %s", err)
		}
	}

	return ret, nil
}

func (s *Server) authenticateAndServeApp(w http.ResponseWriter, r *http.Request, app *app.App) {
	var err error
	appAuth := app.Settings.AuthnType
	if appAuth == "" || appAuth == types.AppAuthnDefault {
		appAuth = types.AppAuthnType(s.config.Security.AppDefaultAuthType)
	}

	if appAuth == "" { // no default auth type set, default to system admin user auth
		appAuth = types.AppAuthnSystem
	}

	userId := ""
	appAuthString := string(appAuth)
	if appAuth == types.AppAuthnNone {
		// No authentication required
		userId = types.ANONYMOUS_USER
	} else if appAuth == types.AppAuthnSystem {
		// Use system admin user for authentication
		authStatus := s.authHandler.authenticate(r.Header.Get("Authorization"))
		if !authStatus {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, REALM))
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}
		userId = types.ADMIN_USER // not using the actual user id, just a admin placeholder
	} else if appAuthString == "cert" || strings.HasPrefix(appAuthString, "cert_") {
		// Use client certificate authentication
		if s.config.Https.DisableClientCerts {
			http.Error(w, "Client certificates are disabled in openrun.config, update https.disable_client_certs", http.StatusInternalServerError)
			return
		}
		err = s.verifyClientCerts(r, appAuthString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		userId = appAuthString
	} else {
		// Use SSO auth
		if !s.ssoAuth.ValidateProviderName(appAuthString) {
			http.Error(w, "Unsupported authentication provider: "+appAuthString, http.StatusInternalServerError)
			return
		}

		// Redirect to the auth provider if not logged in
		userId, err = s.ssoAuth.CheckAuth(w, r, appAuthString, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if userId == "" {
			return // Already redirected to auth provider
		}
	}

	// Create a new context with the user ID
	s.Trace().Msgf("Authenticated user %s", userId)
	ctx := context.WithValue(r.Context(), types.USER_ID, userId)
	ctx = context.WithValue(ctx, types.APP_ID, string(app.Id))

	contextShared := ctx.Value(types.SHARED)
	if contextShared != nil {
		// allow audit middleware to access the user id
		cs := contextShared.(*ContextShared)
		cs.UserId = userId
		cs.AppId = string(app.Id)
	}
	r = r.WithContext(ctx)

	// Authentication successful, serve the app
	app.ServeHTTP(w, r)
}

// verifyClientCerts verifies the client certificate, whether it is signed by one
// of the root CAs in the authName config
func (s *Server) verifyClientCerts(r *http.Request, authName string) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("client certificate required")
	}

	requestCert := r.TLS.PeerCertificates[0]
	clientConfig, ok := s.config.ClientAuth[authName]
	if !ok {
		return fmt.Errorf("client auth config not found for %s", authName)
	}

	opts := x509.VerifyOptions{
		Roots:         clientConfig.RootCAs,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range r.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := requestCert.Verify(opts); err != nil {
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	return nil
}

func (s *Server) MatchApp(hostHeader, matchPath string) (types.AppInfo, error) {
	s.Trace().Msgf("MatchApp %s %s", hostHeader, matchPath)
	apps, domainMap, err := s.apps.GetAppsFullInfo()
	if err != nil {
		return types.AppInfo{}, err
	}
	matchPath = normalizePath(matchPath)
	if hostHeader == "127.0.0.1" {
		hostHeader = "localhost"
	}

	if !domainMap[hostHeader] {
		// Request to unknown domain, match against default domain
		hostHeader = s.config.System.DefaultDomain
	}

	for _, appInfo := range apps {
		appDomain := cmp.Or(appInfo.Domain, s.config.System.DefaultDomain)
		if hostHeader != appDomain {
			// Host header does not match
			continue
		}

		if strings.HasPrefix(matchPath, appInfo.Path) {
			if len(appInfo.Path) == 1 || len(appInfo.Path) == len(matchPath) || matchPath[len(appInfo.Path)] == '/' {
				if appInfo.Path == "/" && strings.HasPrefix(matchPath, "/"+types.STAGE_SUFFIX) {
					// Do not match /_cl_stage to /
					continue
				}
				s.Debug().Msgf("Matched app %s for path %s", appInfo, matchPath)
				return appInfo, nil
			}
		}
	}

	return types.AppInfo{}, errors.New("no matching app found")
}

func (s *Server) CheckAppValid(domain, matchPath string) (string, error) {
	paths, err := s.db.GetAppsForDomain(domain)
	if err != nil {
		return "", err
	}
	matchedApp := ""
	for _, path := range paths {
		// If /test is in use, do not allow /test/other
		if strings.HasPrefix(matchPath, path) {
			if len(path) == 1 || len(path) == len(matchPath) || matchPath[len(path)] == '/' {
				matchedApp = types.AppPathDomain{Domain: domain, Path: path}.String()
				s.Debug().Msgf("Matched app %s for path %s", matchedApp, matchPath)
				break
			}
		}

		// If /test/other is in use, do not allow /test
		if strings.HasPrefix(path, matchPath) {
			if len(matchPath) == 1 || len(path) == len(matchPath) || path[len(matchPath)] == '/' {
				matchedApp = types.AppPathDomain{Domain: domain, Path: path}.String()
				s.Debug().Msgf("Matched app %s for path %s", matchedApp, matchPath)
				break
			}
		}
	}

	return matchedApp, nil
}

func (s *Server) auditApp(ctx context.Context, tx types.Transaction, app *app.App, approve bool) (*types.ApproveResult, error) {
	auditResult, err := app.Audit()
	if err != nil {
		return nil, err
	}

	if approve {
		app.AppEntry.Metadata.Loads = auditResult.NewLoads
		app.AppEntry.Metadata.Permissions = auditResult.NewPermissions
		s.Info().Msgf("Approved app %s %s: %+v %+v", app.Path, app.Domain, auditResult.NewLoads, auditResult.NewPermissions)
	}

	if err := s.db.UpdateAppMetadata(ctx, tx, app.AppEntry); err != nil {
		return nil, err
	}

	return auditResult, nil
}

func (s *Server) CompleteTransaction(ctx context.Context, tx types.Transaction, entries []types.AppPathDomain, dryRun bool, op string) error {
	if dryRun {
		return nil
	}

	if tx.Tx != nil { // Used when called in a context where the transaction is handled by the caller
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Update the in memory cache
	if entries != nil {
		if err := s.apps.ClearAppsAudit(ctx, entries, op); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) getStageApp(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry) (*types.AppEntry, error) {
	if appEntry.IsDev {
		return nil, fmt.Errorf("cannot get stage for dev app %s", appEntry.AppPathDomain())
	}
	if strings.HasSuffix(appEntry.Path, types.STAGE_SUFFIX) {
		return nil, fmt.Errorf("app is already a stage app %s", appEntry.AppPathDomain())
	}

	stageAppPath := types.AppPathDomain{Domain: appEntry.Domain, Path: appEntry.Path + types.STAGE_SUFFIX}
	stageAppEntry, err := s.db.GetAppTx(ctx, tx, stageAppPath)
	if err != nil {
		return nil, err
	}

	return stageAppEntry, nil
}

func parseGithubUrl(sourceUrl string, usingSSH bool) (repo, folder string, err error) {
	if !strings.HasSuffix(sourceUrl, "/") {
		sourceUrl = sourceUrl + "/"
	}

	if strings.HasPrefix(sourceUrl, "git@") {
		// Using git url format
		split := strings.SplitN(sourceUrl, "/", 3)
		if len(split) != 3 {
			return "", "", fmt.Errorf("invalid github url: %s, expected git@github.com:orgName/repoName or git@github.com:orgName/repoName/folder", sourceUrl)
		}

		return fmt.Sprintf("%s/%s", split[0], split[1]), split[2], nil
	}

	if !strings.HasPrefix(sourceUrl, "http://") && !strings.HasPrefix(sourceUrl, "https://") {
		sourceUrl = "https://" + sourceUrl
	}

	url, err := url.Parse(sourceUrl)
	if err != nil {
		return "", "", err
	}

	split := strings.SplitN(url.Path, "/", 4)
	if len(split) == 4 {
		if usingSSH {
			// Use git url like git@github.com:openrundev/openrun.git
			gitUrl := fmt.Sprintf("git@%s:%s/%s.git", url.Host, split[1], split[2])
			return gitUrl, split[3], nil
		}
		return fmt.Sprintf("%s://%s/%s/%s", url.Scheme, url.Host, split[1], split[2]), split[3], nil
	}

	return "", "", fmt.Errorf("invalid github url: %s, expected github.com/orgName/repoName or github.com/orgName/repoName/folder", sourceUrl)
}

type gitAuthEntry struct {
	user     string
	key      []byte
	password string
	usingSSH bool
}

// loadGitKey gets the git key from the config and loads the key from disk
func (s *Server) loadGitKey(gitAuth string) (*gitAuthEntry, error) {
	if gitAuth == "" {
		return &gitAuthEntry{
			user:     "",
			key:      []byte{},
			password: "",
			usingSSH: false, // default to non-SSH git url if no auth is specified
		}, nil
	}
	authEntry, ok := s.config.GitAuth[gitAuth]
	if !ok {
		return nil, fmt.Errorf("git auth entry %s not found in server config", gitAuth)
	}

	var err error
	gitKey := []byte{}
	user := authEntry.UserID
	usingSSH := false
	if authEntry.KeyFilePath != "" {
		gitKey, err = os.ReadFile(authEntry.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("error reading git key %s: %w", authEntry.KeyFilePath, err)
		}
		user = cmp.Or(authEntry.UserID, "git") // https://github.com/src-d/go-git/issues/637, default user to "git"
		usingSSH = true
	}

	return &gitAuthEntry{
		user:     user,
		key:      gitKey,
		password: authEntry.Password,
		usingSSH: usingSSH,
	}, nil
}

func (s *Server) loadSourceFromGit(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry, branch, commit, gitAuth string, repoCache *RepoCache) error {
	gitAuth = cmp.Or(gitAuth, appEntry.Settings.GitAuthName)
	branch = cmp.Or(branch, appEntry.Metadata.VersionMetadata.GitBranch, "main")

	repo, folder, message, hash, err := repoCache.CheckoutRepo(appEntry.SourceUrl, branch, commit, gitAuth, appEntry.IsDev)
	if err != nil {
		return err
	}

	if system.IsGit(appEntry.SourceUrl) && appEntry.IsDev {
		// Dev app from git, we need to point the app to the local checkout location
		sourcePath := repo
		if folder != "" {
			sourcePath = path.Join(repo, folder)
		}
		// App metadata points to the local checkout location
		appEntry.Settings.OrigSourceUrl = appEntry.SourceUrl
		appEntry.SourceUrl = sourcePath
	}

	// Update the git info into the appEntry, the caller needs to persist it into the app metadata
	// This function will persist it into the app_version metadata
	appEntry.Metadata.VersionMetadata.GitCommit = hash
	appEntry.Metadata.VersionMetadata.GitMessage = message
	if commit != "" {
		appEntry.Metadata.VersionMetadata.GitBranch = ""
	} else {
		appEntry.Metadata.VersionMetadata.GitBranch = branch
	}
	appEntry.Settings.GitAuthName = gitAuth

	s.Info().Msgf("Cloned git repo %s %s:%s folder %s to %s, commit %s: %s", repo,
		appEntry.Metadata.VersionMetadata.GitBranch, appEntry.Metadata.VersionMetadata.GitCommit, folder, repo, hash, message)
	checkoutFolder := repo
	if folder != "" {
		checkoutFolder = path.Join(repo, folder)
	}

	s.Info().Msgf("Loading app sources from %s", checkoutFolder)
	// Walk the local directory and add all files to the database
	fileStore := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
	highestVersion, err := fileStore.GetHighestVersion(ctx, tx, appEntry.Id)
	if err != nil {
		return err
	}
	prevVersion := appEntry.Metadata.VersionMetadata.Version
	if highestVersion == 0 {
		prevVersion = 0 // No previous version, start at 0
	}
	appEntry.Metadata.VersionMetadata.PreviousVersion = prevVersion
	appEntry.Metadata.VersionMetadata.Version = highestVersion + 1
	if err := fileStore.AddAppVersionDisk(ctx, tx, appEntry.Metadata, checkoutFolder); err != nil {
		return err
	}

	return nil
}

func (s *Server) loadSourceFromDisk(ctx context.Context, tx types.Transaction, appEntry *types.AppEntry) error {
	s.Info().Msgf("Loading app sources from %s", appEntry.SourceUrl)
	appEntry.Metadata.VersionMetadata.GitBranch = ""
	appEntry.Metadata.VersionMetadata.GitCommit = ""
	appEntry.Settings.GitAuthName = ""
	appEntry.Metadata.VersionMetadata.GitMessage = ""

	fileStore := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
	highestVersion, err := fileStore.GetHighestVersion(ctx, tx, appEntry.Id)
	if err != nil {
		return fmt.Errorf("error getting highest version: %w", err)
	}
	prevVersion := appEntry.Metadata.VersionMetadata.Version
	if highestVersion == 0 {
		prevVersion = 0 // No previous version, set to 0
	}

	appEntry.Metadata.VersionMetadata.PreviousVersion = prevVersion
	appEntry.Metadata.VersionMetadata.Version = highestVersion + 1
	// Walk the local directory and add all files to the database
	if err := fileStore.AddAppVersionDisk(ctx, tx, appEntry.Metadata, appEntry.SourceUrl); err != nil {
		return err
	}
	return nil
}

func (s *Server) FilterApps(appappPathGlob string, includeInternal bool) ([]types.AppInfo, error) {
	apps, err := s.db.GetAllApps(includeInternal)
	if err != nil {
		return nil, err
	}

	linkedApps := make(map[string][]types.AppInfo)
	var mainApps []types.AppInfo
	if includeInternal {
		mainApps = make([]types.AppInfo, 0, len(apps))

		for _, appInfo := range apps {
			if appInfo.MainApp != "" {
				linkedApps[string(appInfo.MainApp)] = append(linkedApps[string(appInfo.MainApp)], appInfo)
			} else {
				mainApps = append(mainApps, appInfo)
			}
		}
	} else {
		mainApps = apps
	}
	// Filter based on path spec. This is done on the main apps path only.
	filteredApps, err := ParseGlobFromInfo(appappPathGlob, mainApps)
	if err != nil {
		return nil, err
	}

	if !includeInternal {
		return filteredApps, nil
	}

	// Include staging and preview apps for prod apps
	result := make([]types.AppInfo, 0, 2*len(filteredApps))
	for _, appInfo := range filteredApps {
		result = append(result, appInfo)
		result = append(result, linkedApps[string(appInfo.Id)]...)
	}

	return result, nil
}

func (s *Server) GetApps(ctx context.Context, appPathGlob string, internal bool) ([]types.AppResponse, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	filteredApps, err := s.FilterApps(appPathGlob, internal)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	ret := make([]types.AppResponse, 0, len(filteredApps))
	for _, app := range filteredApps {
		retApp, err := s.GetApp(app.AppPathDomain, false)
		if err != nil {
			return nil, types.CreateRequestError(err.Error(), http.StatusInternalServerError)
		}

		stagedChanges := false
		if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_PROD) {
			stageApp, err := s.getStageApp(ctx, tx, retApp.AppEntry)
			if err != nil {
				return nil, err
			}
			if stageApp.Metadata.VersionMetadata.Version != retApp.AppEntry.Metadata.VersionMetadata.Version {
				// staging app is at different version than prod app
				stagedChanges = true
			}
		}
		ret = append(ret, types.AppResponse{AppEntry: *retApp.AppEntry, StagedChanges: stagedChanges})
	}
	return ret, nil
}

func (s *Server) PreviewApp(ctx context.Context, mainAppPath, commitId string, approve, dryRun bool) (*types.AppPreviewResponse, error) {
	mainAppPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	repoCache, err := NewRepoCache(s)
	if err != nil {
		return nil, err
	}
	defer repoCache.Cleanup()

	mainAppEntry, err := s.db.GetAppTx(ctx, tx, mainAppPathDomain)
	if err != nil {
		return nil, err
	}

	if !system.IsGit(mainAppEntry.SourceUrl) {
		return nil, fmt.Errorf("cannot preview app %s, source is not git", mainAppPath)
	}

	previewAppEntry := *mainAppEntry
	previewAppEntry.Path = mainAppEntry.Path + types.PREVIEW_SUFFIX + "_" + commitId
	previewAppEntry.MainApp = mainAppEntry.Id
	previewAppEntry.Id = types.AppId(types.ID_PREFIX_APP_PREVIEW + string(mainAppEntry.Id)[len(types.ID_PREFIX_APP_PROD):])
	previewAppEntry.UserID = system.GetContextUserId(ctx)

	// Check if it already exists
	if _, err = s.db.GetAppTx(ctx, tx, previewAppEntry.AppPathDomain()); err == nil {
		return nil, fmt.Errorf("preview app %s already exists", previewAppEntry.AppPathDomain())
	}

	previewAppEntry.Metadata.VersionMetadata = types.VersionMetadata{
		Version: 0,
	}

	if err := s.db.CreateApp(ctx, tx, &previewAppEntry); err != nil {
		return nil, err
	}

	// Checkout the git repo locally and load into database
	if err := s.loadSourceFromGit(ctx, tx, &previewAppEntry, "", commitId, previewAppEntry.Settings.GitAuthName, repoCache); err != nil {
		return nil, fmt.Errorf("failed to load source %s from git: %w", previewAppEntry.SourceUrl, err)
	}

	// Create the in memory app object
	application, err := s.setupApp(&previewAppEntry, tx)
	if err != nil {
		return nil, err
	}

	s.Debug().Msgf("Created preview app %s %s", previewAppEntry.Path, previewAppEntry.Id)
	auditResult, err := s.auditApp(ctx, tx, application, approve)
	if err != nil {
		return nil, fmt.Errorf("app %s audit failed: %s", previewAppEntry.Id, err)
	}

	// Persist the metadata so that any git info is saved
	if err := s.db.UpdateAppMetadata(ctx, tx, &previewAppEntry); err != nil {
		return nil, err
	}

	// Persist the settings
	if err := s.db.UpdateAppSettings(ctx, tx, &previewAppEntry); err != nil {
		return nil, err
	}

	ret := &types.AppPreviewResponse{
		DryRun:        dryRun,
		HttpUrl:       s.getAppHttpUrl(&previewAppEntry),
		HttpsUrl:      s.getAppHttpsUrl(&previewAppEntry),
		ApproveResult: *auditResult,
		Success:       true,
	}

	if auditResult.NeedsApproval && !approve {
		ret.Success = false // Needs approval but not approved, do not create the preview app
		return ret, nil
	}

	if dryRun {
		return ret, nil
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	s.apps.ResetAllAppCache() // Clear the cache so that the new app is loaded next time
	return ret, nil
}
