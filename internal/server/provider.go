// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/openrundev/openrun/pkg/binding"
)

const (
	providerDownloadTimeout = 5 * time.Minute
	providerMaxDownloadSize = 512 * 1024 * 1024
	// providerDescribeTimeout bounds the Describe RPC during install and
	// startup registration, so a provider that handshakes but hangs cannot
	// block server startup.
	providerDescribeTimeout = 30 * time.Second
)

// providerPlatform is the "os/arch" key used in the provider checksums map.
func providerPlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// expandProviderSourceURL substitutes the {version}, {os}, {arch} and {ext}
// placeholders in a provider source URL. {ext} is ".exe" on Windows and empty
// elsewhere, matching the release asset naming.
func expandProviderSourceURL(sourceURL, version string) string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	r := strings.NewReplacer("{version}", version, "{os}", runtime.GOOS, "{arch}", runtime.GOARCH, "{ext}", ext)
	return r.Replace(sourceURL)
}

// parseProviderVersion splits a config install entry of the form "vX.Y.Z" or
// "vX.Y.Z@sha256:HEX[,HEX...]" into version and the accepted digests. Multiple
// digests support mixed-architecture deployments: each replica's download must
// match one of them.
func parseProviderVersion(entry string) (version string, sha256Hexes []string) {
	version, digests, found := strings.Cut(entry, "@sha256:")
	if !found {
		return entry, nil
	}
	return version, splitDigests(digests)
}

// splitDigests splits a comma-separated digest list, trimming whitespace.
func splitDigests(digests string) []string {
	if digests == "" {
		return nil
	}
	parts := strings.Split(digests, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// digestMatches reports whether checksum is in the accepted digest set.
func digestMatches(pins []string, checksum string) bool {
	return slices.ContainsFunc(pins, func(pin string) bool {
		return strings.EqualFold(pin, checksum)
	})
}

// providerSourceURL returns the source url for a provider install: the
// requested url, or the kind's release url template with {provider}
// substituted ({version}/{os}/{arch} stay, they are expanded per fetch).
// Installing from the template requires an explicit version.
func (s *Server) providerSourceURL(kind *providerKind, request *types.ProviderInstallRequest) (string, error) {
	if request.SourceURL != "" {
		return request.SourceURL, nil
	}
	if request.Version == "" {
		return "", fmt.Errorf("either source_url or version is required")
	}
	template := kind.config(s).releaseURLTemplate
	if template == "" {
		template = kind.defaultReleaseURL
	}
	return strings.ReplaceAll(template, "{provider}", request.Name), nil
}

func isProviderURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// fetchProviderBinary reads the provider binary from an https URL or a local
// (server-side) file path, returning its contents and hex sha256. Plain http
// is refused unless the kind's unsafe_allow_http config is set: the
// downloaded bytes are executed as the server user, so a tamperable transport
// is not accepted.
func (s *Server) fetchProviderBinary(ctx context.Context, kind *providerKind, source string) ([]byte, string, error) {
	if strings.HasPrefix(source, "http://") && !kind.config(s).unsafeAllowHTTP {
		return nil, "", fmt.Errorf("plain http provider source %s is not allowed, use https (or set %s for isolated dev setups)",
			source, kind.config(s).allowHTTPKey)
	}
	var data []byte
	if isProviderURL(source) {
		reqCtx, cancel := context.WithTimeout(ctx, providerDownloadTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, source, nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("error downloading provider from %s: %w", source, err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("error downloading provider from %s: status %s", source, resp.Status)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, providerMaxDownloadSize+1))
		if err != nil {
			return nil, "", fmt.Errorf("error downloading provider from %s: %w", source, err)
		}
		if len(data) > providerMaxDownloadSize {
			return nil, "", fmt.Errorf("provider binary from %s exceeds max size", source)
		}
	} else {
		var err error
		data, err = os.ReadFile(source)
		if err != nil {
			return nil, "", fmt.Errorf("error reading provider binary %s: %w", source, err)
		}
	}

	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// stageProviderBinary writes the provider executable to a unique staging path
// in the kind's cache dir. The staged file is validated (Describe) before it
// replaces any previously working executable via promoteProviderBinary, so a
// failed install or upgrade never destroys a working provider. Unique names
// also keep concurrent installs of the same provider from clobbering each
// other.
func (s *Server) stageProviderBinary(kind *providerKind, name string, data []byte) (string, error) {
	cacheDir := kind.kindCacheDir(s)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("error creating provider cache dir %s: %w", cacheDir, err)
	}
	staged, err := os.CreateTemp(cacheDir, ".staged-"+name+"-*")
	if err != nil {
		return "", fmt.Errorf("error creating staged provider file: %w", err)
	}
	stagedPath := staged.Name()
	if _, err := staged.Write(data); err != nil {
		staged.Close()        //nolint:errcheck
		os.Remove(stagedPath) //nolint:errcheck
		return "", fmt.Errorf("error writing staged provider binary: %w", err)
	}
	if err := staged.Close(); err != nil {
		os.Remove(stagedPath) //nolint:errcheck
		return "", fmt.Errorf("error writing staged provider binary: %w", err)
	}
	if err := os.Chmod(stagedPath, 0o700); err != nil { //nolint:gosec // provider must be executable
		os.Remove(stagedPath) //nolint:errcheck
		return "", err
	}
	return stagedPath, nil
}

// promoteProviderBinary moves a validated staged binary into its final path.
func (s *Server) promoteProviderBinary(stagedPath, execPath string) error {
	if runtime.GOOS == "windows" {
		// Windows cannot rename over an existing file.
		os.Remove(execPath) //nolint:errcheck
	}
	if err := os.Rename(stagedPath, execPath); err != nil {
		os.Remove(stagedPath) //nolint:errcheck
		return fmt.Errorf("error renaming provider binary: %w", err)
	}
	return nil
}

// describeProvider launches a binding provider executable and calls Describe,
// returning the provider version and served service types. sha256Hex, when
// set, is verified against the executable before it runs.
func (s *Server) describeProvider(ctx context.Context, execPath, sha256Hex string) (string, []binding.ServiceTypeInfo, error) {
	secureConfig, err := bindings.ProviderSecureConfig(sha256Hex)
	if err != nil {
		return "", nil, err
	}
	provider, err := binding.LaunchProvider(binding.LaunchConfig{
		ExecPath:     execPath,
		Logger:       bindings.NewProviderHCLogger(s.Logger, "describe"),
		SecureConfig: secureConfig,
	})
	if err != nil {
		return "", nil, fmt.Errorf("error launching provider %s: %w", execPath, err)
	}
	defer provider.Kill()
	describeCtx, cancel := context.WithTimeout(ctx, providerDescribeTimeout)
	defer cancel()
	return provider.Describe(describeCtx)
}

// isConfigManagedProvider reports whether the provider is declared in the
// kind's install server config; those providers are managed through the
// config and cannot be modified with the provider CLI/API.
func (s *Server) isConfigManagedProvider(kind *providerKind, name string) bool {
	_, ok := kind.config(s).install[name]
	return ok
}

// providerModifyError returns the error rejecting an imperative provider
// install/uninstall when the deployment manages providers declaratively:
// either globally (the kind's disable_install) or for one config-declared
// provider. operation is "install" or "uninstall", for the error text.
func (s *Server) providerModifyError(kind *providerKind, name, operation string) error {
	config := kind.config(s)
	if config.disableInstall {
		return fmt.Errorf("provider %s is disabled on this server (%s), providers are managed through the server config",
			operation, config.disableInstallKey)
	}
	if s.isConfigManagedProvider(kind, name) {
		return fmt.Errorf("provider %s is managed through the %s server config, update the config instead",
			name, config.configSection)
	}
	return nil
}

// InstallProvider installs or updates an out-of-process provider: the binary
// is fetched, verified, registered in the metadata database (the source of
// truth) and materialized into the local cache dir. Other replicas reconcile
// from the database on notification. The provider kind is carried in the
// request name: "plugin/store" installs a Starlark plugin provider, a bare
// name (or "binding/<name>") a binding provider.
func (s *Server) InstallProvider(ctx context.Context, request *types.ProviderInstallRequest) (*types.BindingProvider, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderManage, ""); err != nil {
		return nil, err
	}
	kind, name, err := parseProviderName(request.Name)
	if err != nil {
		return nil, err
	}
	request.Name = name
	if err := s.providerModifyError(kind, name, "install"); err != nil {
		return nil, err
	}
	return s.installProvider(ctx, kind, request, system.GetContextUserId(ctx))
}

// installProvider is InstallProvider without the RBAC and config-managed
// checks, also used by the startup path for config-declared install entries.
// request.Name is the bare provider name; the kind is passed explicitly.
func (s *Server) installProvider(ctx context.Context, kind *providerKind, request *types.ProviderInstallRequest, createdBy string) (*types.BindingProvider, error) {
	s.providerMutex.Lock()
	defer s.providerMutex.Unlock()
	if request.Name == "" {
		return nil, fmt.Errorf("provider name is required")
	}
	if strings.ContainsAny(request.Name, "/\\ ") {
		return nil, fmt.Errorf("invalid provider name %q", request.Name)
	}
	sourceURL, err := s.providerSourceURL(kind, request)
	if err != nil {
		return nil, err
	}
	// The (possibly defaulted) source url is what gets recorded in the
	// database, so other replicas re-fetch from the same place.
	request.SourceURL = sourceURL

	source := expandProviderSourceURL(request.SourceURL, request.Version)
	data, checksum, err := s.fetchProviderBinary(ctx, kind, source)
	if err != nil {
		return nil, err
	}
	if pins := splitDigests(request.Sha256); len(pins) > 0 && !digestMatches(pins, checksum) {
		return nil, fmt.Errorf("provider %s checksum mismatch from %s: pinned %s got %s",
			request.Name, source, request.Sha256, checksum)
	}

	// Stage and validate the binary before it replaces any previously working
	// executable: a failed install or upgrade must not destroy a working
	// provider.
	stagedPath, err := s.stageProviderBinary(kind, request.Name, data)
	if err != nil {
		return nil, err
	}
	removeStaged := true
	defer func() {
		if removeStaged {
			os.Remove(stagedPath) //nolint:errcheck
		}
	}()

	providerVersion, capabilities, manifest, err := kind.describe(s, ctx, stagedPath, checksum)
	if err != nil {
		return nil, fmt.Errorf("error describing provider: %w", err)
	}
	if len(capabilities) == 0 {
		return nil, fmt.Errorf("provider %s serves no %s", request.Name, kind.capabilityLabel)
	}
	if request.Version == "" {
		request.Version = providerVersion
	} else if providerVersion != "" && providerVersion != request.Version {
		// A mislabeled artifact (or stale mirror) must not be recorded under
		// the requested version: replicas would install different binaries
		// under one DB version.
		return nil, fmt.Errorf("provider %s version mismatch: requested %s but the binary reports %s",
			request.Name, request.Version, providerVersion)
	}

	provider := &types.BindingProvider{
		Name:         request.Name,
		Type:         kind.typeName,
		Version:      request.Version,
		SourceURL:    request.SourceURL,
		Checksums:    map[string]string{providerPlatform(): checksum},
		ServiceTypes: capabilities,
		Manifest:     manifest,
		CreatedBy:    createdBy,
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Preserve checksums recorded by replicas on other platforms when updating
	// to the same version of an existing provider.
	if existing, getErr := s.db.GetBindingProvider(ctx, tx, kind.typeName, request.Name); getErr == nil && existing.Version == provider.Version {
		for platform, sum := range existing.Checksums {
			if _, ok := provider.Checksums[platform]; !ok {
				provider.Checksums[platform] = sum
			}
		}
		provider.CreatedBy = existing.CreatedBy
	}

	// Reject capabilities claimed by another installed provider of the same
	// kind. This is a same-transaction read, so sequential conflicting
	// installs from any replica are caught; simultaneous commits on different
	// replicas are not (that needs a uniqueness constraint, tracked as a
	// follow-up). A name collision with a provider of another kind is also
	// rejected: the registry's primary key is the name.
	otherProviders, err := s.db.ListBindingProviders(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, other := range otherProviders {
		if other.Name == request.Name {
			if other.Type != kind.typeName {
				return nil, fmt.Errorf("provider name %s is already used by a %s provider", request.Name, other.Type)
			}
			continue
		}
		if other.Type != kind.typeName {
			continue
		}
		for _, capability := range capabilities {
			if slices.Contains(other.ServiceTypes, capability) {
				return nil, fmt.Errorf("%s %s is already provided by %s", kind.capabilityLabel, capability, other.Name)
			}
		}
	}

	if err := s.db.UpsertBindingProvider(ctx, tx, provider); err != nil {
		return nil, err
	}

	// The binary is validated: move it into place and swap the registrations
	// atomically (capabilities dropped by this version are removed in the
	// same swap).
	execPath := kind.execPath(s, request.Name)
	if err := s.promoteProviderBinary(stagedPath, execPath); err != nil {
		return nil, err
	}
	removeStaged = false
	if err := kind.register(provider, execPath, checksum); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		kind.unregister(request.Name)
		return nil, err
	}

	if err := s.db.NotifyProviderUpdate(kind.typeName, request.Name, false); err != nil {
		s.Error().Err(err).Msg("error notifying provider update")
	}
	s.Info().Str("provider", kind.qualifiedName(request.Name)).Str("version", provider.Version).
		Strs(strings.ReplaceAll(kind.capabilityLabel, " ", "_"), capabilities).Msg("Installed provider")
	return provider, nil
}

// UninstallProvider removes a provider. For binding providers, fails if
// services of its types still exist, unless force is set. The provider kind
// is carried in the name ("plugin/store", bare names mean binding).
func (s *Server) UninstallProvider(ctx context.Context, name string, force bool) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderManage, ""); err != nil {
		return err
	}
	kind, bareName, err := parseProviderName(name)
	if err != nil {
		return err
	}
	if err := s.providerModifyError(kind, bareName, "uninstall"); err != nil {
		return err
	}
	s.providerMutex.Lock()
	defer s.providerMutex.Unlock()

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	provider, err := s.db.GetBindingProvider(ctx, tx, kind.typeName, bareName)
	if err != nil {
		return err
	}

	if !force {
		for _, capability := range provider.ServiceTypes {
			count, err := kind.usageCount(s, ctx, tx, capability)
			if err != nil {
				return err
			}
			if count > 0 {
				return fmt.Errorf("%d %s service(s) exist, delete them first or use --force", count, capability)
			}
		}
	}

	if err := s.db.DeleteBindingProvider(ctx, tx, kind.typeName, bareName); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	kind.unregister(bareName)
	os.Remove(kind.execPath(s, bareName)) //nolint:errcheck
	if err := s.db.NotifyProviderUpdate(kind.typeName, bareName, true); err != nil {
		s.Error().Err(err).Msg("error notifying provider update")
	}
	s.Info().Str("provider", kind.qualifiedName(bareName)).Msg("Uninstalled provider")
	return nil
}

// ListProviders returns the installed providers of all kinds. Source url
// credentials (userinfo of an authenticated mirror) are redacted: provider:read
// holders must not learn mirror credentials.
func (s *Server) ListProviders(ctx context.Context) ([]*types.BindingProvider, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderRead, ""); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	providers, err := s.db.ListBindingProviders(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, provider := range providers {
		provider.SourceURL = redactURLCredentials(provider.SourceURL)
	}
	return providers, nil
}

// redactURLCredentials strips the userinfo from an http(s) url.
func redactURLCredentials(source string) string {
	if !isProviderURL(source) {
		return source
	}
	u, err := url.Parse(source)
	if err != nil || u.User == nil {
		return source
	}
	u.User = url.User("xxxxx")
	return u.String()
}

// setupProviders is called during server startup: it registers dev providers
// from the config, discovers preinstalled binding providers, installs
// config-declared providers of every kind, and reconciles all
// database-registered providers into the local cache dirs. Failures are
// logged, not fatal: a provider that cannot be materialized leaves its
// capabilities unregistered, and operations against them fail with a clear
// error.
func (s *Server) setupProviders(ctx context.Context) {
	for name, devConfig := range s.staticConfig.Bindings.DevProviders {
		execPath := os.ExpandEnv(devConfig.Path)
		version, serviceTypes, err := s.describeProvider(ctx, execPath, "")
		if err != nil {
			s.Error().Err(err).Str("provider", name).Str("path", execPath).Msg("error describing dev binding provider")
			continue
		}
		for _, t := range serviceTypes {
			if err := bindings.RegisterRemoteBinding("dev:"+name, t.ServiceType, execPath, ""); err != nil {
				s.Error().Err(err).Str("provider", name).Msg("error registering dev binding provider")
				continue
			}
		}
		s.Warn().Str("provider", name).Str("path", execPath).Str("version", version).
			Msg("Registered DEV binding provider from local path, checksum verification is disabled")
	}

	for name, devConfig := range s.staticConfig.PluginProviders.DevProviders {
		execPath := os.ExpandEnv(devConfig.Path)
		if err := app.RegisterExternalProvider(name, execPath, ""); err != nil {
			s.Error().Err(err).Str("provider", name).Str("path", execPath).Msg("error registering dev plugin provider")
			continue
		}
		s.Warn().Str("provider", name).Str("path", execPath).
			Msg("Registered DEV plugin provider from local path, checksum verification is disabled")
	}

	s.registerPreinstalledProviders(ctx)

	// Install providers declared in the config: the declarative path for
	// config-managed (Kubernetes/Helm) deployments, where every replica runs
	// this on startup. The install is skipped when the database row already
	// matches the declared version; concurrent installs from replicas starting
	// together are benign (same content, idempotent upsert).
	for _, kindName := range slices.Sorted(maps.Keys(providerKinds)) {
		kind := providerKinds[kindName]
		install := kind.config(s).install
		for _, name := range slices.Sorted(maps.Keys(install)) {
			version := install[name]
			if err := s.ensureConfigProvider(ctx, kind, name, version); err != nil {
				s.Error().Err(err).Str("provider", kind.qualifiedName(name)).Str("version", version).
					Msg("error installing config-declared provider")
			}
		}
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		s.Error().Err(err).Msg("error listing providers")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	providers, err := s.db.ListBindingProviders(ctx, tx)
	if err != nil {
		s.Error().Err(err).Msg("error listing providers")
		return
	}
	for _, provider := range providers {
		kind, err := providerKindFor(provider.Type)
		if err != nil {
			s.Error().Err(err).Str("provider", provider.Name).Msg("error reconciling provider")
			continue
		}
		if err := s.reconcileProvider(ctx, kind, provider); err != nil {
			s.Error().Err(err).Str("provider", kind.qualifiedName(provider.Name)).Msg("error reconciling provider")
		}
	}
}

// registerPreinstalledProviders discovers provider executables pre-placed in
// each kind's preinstalled dir (bindings.preinstalled_dir /
// plugin_providers.preinstalled_dir) and registers their capabilities,
// without database registration or downloads. This is the Kubernetes OCI
// image distribution path: init containers copy each provider binary from
// its per-provider image into a shared volume before the server starts, so
// integrity comes from the image digests that placed the files. The sha256
// computed here is still pinned in the registration, so every launch verifies
// the file has not changed since discovery. Preinstalled providers register
// before database reconcile: a database-installed provider claiming the same
// capabilities fails reconcile with a logged conflict.
func (s *Server) registerPreinstalledProviders(ctx context.Context) {
	for _, kindName := range slices.Sorted(maps.Keys(providerKinds)) {
		kind := providerKinds[kindName]
		dir := os.ExpandEnv(kind.preinstalledDir(s))
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			s.Error().Err(err).Str("dir", dir).Msg("error reading preinstalled providers dir")
			continue
		}
		for _, entry := range entries {
			name, found := strings.CutPrefix(entry.Name(), kind.binaryPrefix)
			name = strings.TrimSuffix(name, ".exe")
			if !found || name == "" || entry.IsDir() {
				continue
			}
			execPath := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(execPath)
			if err != nil {
				s.Error().Err(err).Str("path", execPath).Msg("error reading preinstalled provider")
				continue
			}
			sum := sha256.Sum256(data)
			checksum := hex.EncodeToString(sum[:])

			version, capabilities, err := kind.registerPreinstalled(s, ctx, name, execPath, checksum)
			if err != nil {
				s.Error().Err(err).Str("provider", kind.qualifiedName(name)).Str("path", execPath).
					Msg("error registering preinstalled provider")
				continue
			}
			s.Info().Str("provider", kind.qualifiedName(name)).Str("path", execPath).Str("version", version).
				Strs(strings.ReplaceAll(kind.capabilityLabel, " ", "_"), capabilities).
				Msg("Registered preinstalled provider")
		}
	}
}

// ensureConfigProvider installs one config-declared install entry if the
// database does not already have it at the declared version. The following
// reconcile pass materializes the binary into the local cache when needed.
func (s *Server) ensureConfigProvider(ctx context.Context, kind *providerKind, name, entry string) error {
	version, pins := parseProviderVersion(entry)

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	existing, getErr := s.db.GetBindingProvider(ctx, tx, kind.typeName, name)
	tx.Rollback() //nolint:errcheck
	if getErr == nil && existing.Version == version {
		// A changed digest pin forces a reinstall even at the same version.
		if len(pins) == 0 || digestMatches(pins, existing.Checksums[providerPlatform()]) {
			return nil
		}
	}

	s.Info().Str("provider", kind.qualifiedName(name)).Str("version", version).Msg("Installing config-declared provider")
	_, err = s.installProvider(ctx, kind, &types.ProviderInstallRequest{Name: name, Version: version, Sha256: strings.Join(pins, ",")}, "config")
	return err
}

// reconcileProvider materializes one database-registered provider into the
// local cache dir (verifying the recorded checksum) and registers its
// capabilities.
func (s *Server) reconcileProvider(ctx context.Context, kind *providerKind, provider *types.BindingProvider) error {
	s.providerMutex.Lock()
	defer s.providerMutex.Unlock()
	execPath := kind.execPath(s, provider.Name)
	expected, hasChecksum := provider.Checksums[providerPlatform()]
	// verifiedSha is the checksum registrations verify at every launch.
	verifiedSha := expected

	current := ""
	if data, err := os.ReadFile(execPath); err == nil {
		sum := sha256.Sum256(data)
		current = hex.EncodeToString(sum[:])
	}

	if !hasChecksum || current != expected {
		// Cache miss (new/updated provider, fresh node) or corrupted cache:
		// re-fetch from the recorded source.
		source := expandProviderSourceURL(provider.SourceURL, provider.Version)
		data, checksum, err := s.fetchProviderBinary(ctx, kind, source)
		if err != nil {
			return err
		}
		if hasChecksum && checksum != expected {
			return fmt.Errorf("provider %s checksum mismatch from %s: expected %s got %s",
				provider.Name, source, expected, checksum)
		}
		if !hasChecksum {
			// First materialization on this platform: record the checksum so
			// later reconciles on this platform verify against it.
			tx, err := s.db.BeginTransaction(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			if provider.Checksums == nil {
				provider.Checksums = map[string]string{}
			}
			provider.Checksums[providerPlatform()] = checksum
			if err := s.db.UpsertBindingProvider(ctx, tx, provider); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		stagedPath, err := s.stageProviderBinary(kind, provider.Name, data)
		if err != nil {
			return err
		}
		if err := s.promoteProviderBinary(stagedPath, execPath); err != nil {
			return err
		}
		verifiedSha = checksum
	}

	if err := kind.register(provider, execPath, verifiedSha); err != nil {
		return err
	}
	s.Debug().Str("provider", kind.qualifiedName(provider.Name)).Str("version", provider.Version).Msg("Reconciled provider")
	return nil
}

// resolveServiceBinding returns the builder for a service type. When the type
// is not registered but an installed binding provider serves it — e.g. this
// replica missed the pg_notify broadcast for an install — the provider is
// reconciled on demand before failing.
func (s *Server) resolveServiceBinding(ctx context.Context, serviceType string) (bindings.ServiceBindingBuilder, error) {
	if builder, ok := bindings.GetServiceBinding(serviceType); ok {
		return builder, nil
	}
	if s.reconcileForServiceType(ctx, serviceType) {
		if builder, ok := bindings.GetServiceBinding(serviceType); ok {
			return builder, nil
		}
	}
	return nil, fmt.Errorf("unknown service type: %s", serviceType)
}

// reconcileForServiceType reconciles the installed binding provider serving
// the given service type, if there is one. Returns true when a reconcile ran
// successfully.
func (s *Server) reconcileForServiceType(ctx context.Context, serviceType string) bool {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return false
	}
	providers, err := s.db.ListBindingProviders(ctx, tx)
	tx.Rollback() //nolint:errcheck
	if err != nil {
		return false
	}
	for _, provider := range providers {
		if provider.Type != "binding" {
			continue
		}
		if slices.Contains(provider.ServiceTypes, serviceType) {
			s.Info().Str("provider", provider.Name).Str("service_type", serviceType).
				Msg("Service type not registered, reconciling installed binding provider on demand")
			if err := s.reconcileProvider(ctx, providerKinds["binding"], provider); err != nil {
				s.Error().Err(err).Str("provider", provider.Name).Msg("error reconciling binding provider on demand")
				return false
			}
			return true
		}
	}
	return false
}

// providerNotifyHandler handles provider update notifications from other
// server replicas: reconcile the named provider from the database, or
// unregister it if deleted.
func (s *Server) providerNotifyHandler(payload types.ProviderUpdatePayload) {
	if payload.ServerId == types.CurrentServerId {
		s.Trace().Str("server_id", string(payload.ServerId)).Msg("Ignoring provider update notification from self")
		return
	}
	kind, err := providerKindFor(payload.Type)
	if err != nil {
		s.Error().Err(err).Str("provider", payload.Name).Msg("error handling provider update notification")
		return
	}
	s.Debug().Str("provider", kind.qualifiedName(payload.Name)).Bool("deleted", payload.Deleted).Msg("Received provider update notification")

	ctx := context.Background()
	if payload.Deleted {
		kind.unregister(payload.Name)
		os.Remove(kind.execPath(s, payload.Name)) //nolint:errcheck
		return
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		s.Error().Err(err).Msg("error reconciling provider")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	provider, err := s.db.GetBindingProvider(ctx, tx, kind.typeName, payload.Name)
	if err != nil {
		s.Error().Err(err).Str("provider", kind.qualifiedName(payload.Name)).Msg("error reconciling provider")
		return
	}
	// Unregister first: the provider's capability list or binary may have changed.
	kind.unregister(payload.Name)
	if err := s.reconcileProvider(ctx, kind, provider); err != nil {
		s.Error().Err(err).Str("provider", kind.qualifiedName(payload.Name)).Msg("error reconciling provider")
	}
}
