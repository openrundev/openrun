// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/openrundev/openrun/pkg/binding"
)

const (
	providerDownloadTimeout = 5 * time.Minute
	providerMaxDownloadSize = 512 * 1024 * 1024
)

// providerPlatform is the "os/arch" key used in the provider checksums map.
func providerPlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// providerCacheDir is the node-local directory where installed provider
// executables are materialized from the metadata database.
func (s *Server) providerCacheDir() string {
	cacheDir := s.staticConfig.Bindings.CacheDir
	if cacheDir == "" {
		cacheDir = "$OPENRUN_HOME/bindings"
	}
	return os.ExpandEnv(cacheDir)
}

func (s *Server) providerExecPath(name string) string {
	execName := "openrun-binding-" + name
	if runtime.GOOS == "windows" {
		execName += ".exe"
	}
	return filepath.Join(s.providerCacheDir(), execName)
}

// expandProviderSourceURL substitutes the {version}, {os} and {arch}
// placeholders in a provider source URL.
func expandProviderSourceURL(sourceURL, version string) string {
	r := strings.NewReplacer("{version}", version, "{os}", runtime.GOOS, "{arch}", runtime.GOARCH)
	return r.Replace(sourceURL)
}

func isProviderURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// fetchProviderBinary reads the provider binary from an http(s) URL or a local
// (server-side) file path, returning its contents and hex sha256.
func fetchProviderBinary(ctx context.Context, source string) ([]byte, string, error) {
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

// writeProviderBinary atomically writes the provider executable into the cache dir.
func (s *Server) writeProviderBinary(name string, data []byte) (string, error) {
	cacheDir := s.providerCacheDir()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("error creating bindings cache dir %s: %w", cacheDir, err)
	}
	execPath := s.providerExecPath(name)
	tmpPath := execPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o700); err != nil { //nolint:gosec // provider must be executable
		return "", fmt.Errorf("error writing provider binary %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return "", fmt.Errorf("error renaming provider binary: %w", err)
	}
	return execPath, nil
}

// describeProvider launches the provider executable and calls Describe,
// returning the provider version and served service types.
func (s *Server) describeProvider(ctx context.Context, execPath string) (string, []binding.ServiceTypeInfo, error) {
	provider, err := binding.LaunchProvider(binding.LaunchConfig{
		ExecPath: execPath,
		Logger:   bindings.NewProviderHCLogger(s.Logger, "describe"),
	})
	if err != nil {
		return "", nil, fmt.Errorf("error launching provider %s: %w", execPath, err)
	}
	defer provider.Kill()
	return provider.Describe(ctx)
}

// InstallProvider installs or updates an out-of-process binding provider: the
// binary is fetched, verified, registered in the metadata database (the source
// of truth) and materialized into the local cache dir. Other replicas
// reconcile from the database on notification.
func (s *Server) InstallProvider(ctx context.Context, request *types.ProviderInstallRequest) (*types.BindingProvider, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderManage, ""); err != nil {
		return nil, err
	}
	if request.Name == "" || request.SourceURL == "" {
		return nil, fmt.Errorf("provider name and source url are required")
	}
	if strings.ContainsAny(request.Name, "/\\ ") {
		return nil, fmt.Errorf("invalid provider name %q", request.Name)
	}

	source := expandProviderSourceURL(request.SourceURL, request.Version)
	data, checksum, err := fetchProviderBinary(ctx, source)
	if err != nil {
		return nil, err
	}
	execPath, err := s.writeProviderBinary(request.Name, data)
	if err != nil {
		return nil, err
	}

	providerVersion, serviceTypes, err := s.describeProvider(ctx, execPath)
	if err != nil {
		os.Remove(execPath) //nolint:errcheck
		return nil, fmt.Errorf("error describing provider: %w", err)
	}
	if len(serviceTypes) == 0 {
		os.Remove(execPath) //nolint:errcheck
		return nil, fmt.Errorf("provider %s serves no service types", request.Name)
	}
	if request.Version == "" {
		request.Version = providerVersion
	}

	typeNames := make([]string, 0, len(serviceTypes))
	for _, t := range serviceTypes {
		typeNames = append(typeNames, t.ServiceType)
	}

	provider := &types.BindingProvider{
		Name:         request.Name,
		Version:      request.Version,
		SourceURL:    request.SourceURL,
		Checksums:    map[string]string{providerPlatform(): checksum},
		ServiceTypes: typeNames,
		CreatedBy:    system.GetContextUserId(ctx),
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Preserve checksums recorded by replicas on other platforms when updating
	// to the same version of an existing provider.
	if existing, getErr := s.db.GetBindingProvider(ctx, tx, request.Name); getErr == nil && existing.Version == provider.Version {
		for platform, sum := range existing.Checksums {
			if _, ok := provider.Checksums[platform]; !ok {
				provider.Checksums[platform] = sum
			}
		}
		provider.CreatedBy = existing.CreatedBy
	}

	if err := s.db.UpsertBindingProvider(ctx, tx, provider); err != nil {
		os.Remove(execPath) //nolint:errcheck
		return nil, err
	}

	// Register before commit so a registration conflict (e.g. a built-in
	// service type) aborts the install.
	for _, serviceType := range typeNames {
		if err := bindings.RegisterRemoteBinding(request.Name, serviceType, execPath); err != nil {
			bindings.UnregisterProviderBindings(request.Name)
			os.Remove(execPath) //nolint:errcheck
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		bindings.UnregisterProviderBindings(request.Name)
		return nil, err
	}

	if err := s.db.NotifyProviderUpdate(request.Name, false); err != nil {
		s.Error().Err(err).Msg("error notifying provider update")
	}
	s.Info().Str("provider", request.Name).Str("version", provider.Version).Strs("service_types", typeNames).Msg("Installed binding provider")
	return provider, nil
}

// UninstallProvider removes a binding provider. Fails if services of its
// types still exist, unless force is set.
func (s *Server) UninstallProvider(ctx context.Context, name string, force bool) error {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderManage, ""); err != nil {
		return err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	provider, err := s.db.GetBindingProvider(ctx, tx, name)
	if err != nil {
		return err
	}

	if !force {
		for _, serviceType := range provider.ServiceTypes {
			count, err := s.db.CountServices(ctx, tx, serviceType)
			if err != nil {
				return err
			}
			if count > 0 {
				return fmt.Errorf("%d %s service(s) exist, delete them first or use --force", count, serviceType)
			}
		}
	}

	if err := s.db.DeleteBindingProvider(ctx, tx, name); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	bindings.UnregisterProviderBindings(name)
	os.Remove(s.providerExecPath(name)) //nolint:errcheck
	if err := s.db.NotifyProviderUpdate(name, true); err != nil {
		s.Error().Err(err).Msg("error notifying provider update")
	}
	s.Info().Str("provider", name).Msg("Uninstalled binding provider")
	return nil
}

// ListProviders returns the installed binding providers.
func (s *Server) ListProviders(ctx context.Context) ([]*types.BindingProvider, error) {
	if err := s.enforceGlobalPerm(ctx, types.PermissionProviderRead, ""); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	return s.db.ListBindingProviders(ctx, tx)
}

// setupBindingProviders is called during server startup: it registers dev
// providers from the config and reconciles all database-registered providers
// into the local cache dir. Failures are logged, not fatal: a provider that
// cannot be materialized leaves its service types unregistered, and operations
// against them fail with a clear error.
func (s *Server) setupBindingProviders(ctx context.Context) {
	for name, devConfig := range s.staticConfig.Bindings.DevProviders {
		execPath := os.ExpandEnv(devConfig.Path)
		version, serviceTypes, err := s.describeProvider(ctx, execPath)
		if err != nil {
			s.Error().Err(err).Str("provider", name).Str("path", execPath).Msg("error describing dev binding provider")
			continue
		}
		for _, t := range serviceTypes {
			if err := bindings.RegisterRemoteBinding("dev:"+name, t.ServiceType, execPath); err != nil {
				s.Error().Err(err).Str("provider", name).Msg("error registering dev binding provider")
				continue
			}
		}
		s.Warn().Str("provider", name).Str("path", execPath).Str("version", version).
			Msg("Registered DEV binding provider from local path, checksum verification is disabled")
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		s.Error().Err(err).Msg("error listing binding providers")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	providers, err := s.db.ListBindingProviders(ctx, tx)
	if err != nil {
		s.Error().Err(err).Msg("error listing binding providers")
		return
	}
	for _, provider := range providers {
		if err := s.reconcileProvider(ctx, provider); err != nil {
			s.Error().Err(err).Str("provider", provider.Name).Msg("error reconciling binding provider")
		}
	}
}

// reconcileProvider materializes one database-registered provider into the
// local cache dir (verifying the recorded checksum) and registers its service
// types.
func (s *Server) reconcileProvider(ctx context.Context, provider *types.BindingProvider) error {
	execPath := s.providerExecPath(provider.Name)
	expected, hasChecksum := provider.Checksums[providerPlatform()]

	current := ""
	if data, err := os.ReadFile(execPath); err == nil {
		sum := sha256.Sum256(data)
		current = hex.EncodeToString(sum[:])
	}

	if !hasChecksum || current != expected {
		// Cache miss (new/updated provider, fresh node) or corrupted cache:
		// re-fetch from the recorded source.
		source := expandProviderSourceURL(provider.SourceURL, provider.Version)
		data, checksum, err := fetchProviderBinary(ctx, source)
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
		if _, err := s.writeProviderBinary(provider.Name, data); err != nil {
			return err
		}
	}

	for _, serviceType := range provider.ServiceTypes {
		if err := bindings.RegisterRemoteBinding(provider.Name, serviceType, execPath); err != nil {
			return err
		}
	}
	s.Debug().Str("provider", provider.Name).Str("version", provider.Version).Msg("Reconciled binding provider")
	return nil
}

// providerNotifyHandler handles provider update notifications from other
// server replicas: reconcile the named provider from the database, or
// unregister it if deleted.
func (s *Server) providerNotifyHandler(payload types.ProviderUpdatePayload) {
	if payload.ServerId == types.CurrentServerId {
		s.Trace().Str("server_id", string(payload.ServerId)).Msg("Ignoring provider update notification from self")
		return
	}
	s.Debug().Str("provider", payload.Name).Bool("deleted", payload.Deleted).Msg("Received provider update notification")

	ctx := context.Background()
	if payload.Deleted {
		bindings.UnregisterProviderBindings(payload.Name)
		os.Remove(s.providerExecPath(payload.Name)) //nolint:errcheck
		return
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		s.Error().Err(err).Msg("error reconciling binding provider")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	provider, err := s.db.GetBindingProvider(ctx, tx, payload.Name)
	if err != nil {
		s.Error().Err(err).Str("provider", payload.Name).Msg("error reconciling binding provider")
		return
	}
	// Unregister first: the provider's service type list or binary may have changed.
	bindings.UnregisterProviderBindings(payload.Name)
	if err := s.reconcileProvider(ctx, provider); err != nil {
		s.Error().Err(err).Str("provider", payload.Name).Msg("error reconciling binding provider")
	}
}
