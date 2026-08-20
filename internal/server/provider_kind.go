// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/types"
)

// providerKind describes one kind of out-of-process provider. The install,
// reconcile and notification machinery (provider.go) is shared across kinds;
// each kind supplies its naming, config, validation (Describe) and
// registration behavior. Current kinds are "binding" (service binding
// providers) and "plugin" (Starlark plugin providers); further kinds plug in
// by adding an entry to providerKinds.
//
// The kind of a provider is carried in its name: install and uninstall accept
// "<type>/<name>" (e.g. "plugin/store", "binding/mongodb"), and a bare name
// means "binding" for backward compatibility.
type providerKind struct {
	// typeName is the kind identifier, stored in the provider_type database
	// column and used as the name prefix ("plugin/store").
	typeName string
	// binaryPrefix is the provider executable naming convention, e.g.
	// "openrun-binding-" or "openrun-plugin-".
	binaryPrefix string
	// defaultCacheDir is the node-local cache dir when the config does not
	// set one ($-vars are expanded).
	defaultCacheDir string
	// defaultReleaseURL is the release_url_template fallback.
	defaultReleaseURL string
	// capabilityLabel names what the provider serves, for messages:
	// "service types" for bindings, "modules" for plugins.
	capabilityLabel string

	// config returns the kind's provider config from the server config.
	config func(s *Server) providerKindConfig

	// preinstalledDir is the kind's directory of pre-placed provider
	// executables ("" when not configured); see registerPreinstalledProviders.
	preinstalledDir func(s *Server) string

	// registerPreinstalled validates one pre-placed executable (verifying
	// checksum on launch) and registers its capabilities under the
	// "preinstalled:" owner name, returning the provider version and
	// capability names.
	registerPreinstalled func(s *Server, ctx context.Context, name, execPath, checksum string) (string, []string, error)

	// describe launches the executable (verifying sha256Hex when set) and
	// returns the provider version, its capability names (service types or
	// module names), and the kind-specific manifest to persist in the
	// database row ("" when the kind needs none).
	describe func(s *Server, ctx context.Context, execPath, sha256Hex string) (string, []string, string, error)

	// register (re-)registers a provider from its database row; execPath is
	// the materialized binary and verifiedSha the checksum enforced on every
	// launch.
	register func(provider *types.BindingProvider, execPath, verifiedSha string) error

	// unregister removes the provider's registrations.
	unregister func(name string)

	// usageCount returns how many objects depend on one capability, for the
	// uninstall check ("N <capability> service(s) exist").
	usageCount func(s *Server, ctx context.Context, tx types.Transaction, capability string) (int, error)
}

// providerKindConfig is the kind's slice of the server config.
type providerKindConfig struct {
	cacheDir           string
	releaseURLTemplate string
	install            map[string]string
	unsafeAllowHTTP    bool
	disableInstall     bool
	// configSection and allowHTTPKey name the kind's config entries in error
	// messages, e.g. "[bindings.install]" and "bindings.unsafe_allow_http".
	configSection     string
	disableInstallKey string
	allowHTTPKey      string
}

var providerKinds = map[string]*providerKind{
	"binding": {
		typeName:          "binding",
		binaryPrefix:      "openrun-binding-",
		defaultCacheDir:   "$OPENRUN_HOME/bindings",
		defaultReleaseURL: "https://github.com/openrundev/bindings/releases/download/{provider}%2F{version}/openrun-binding-{provider}-{os}-{arch}{ext}",
		capabilityLabel:   "service types",
		config: func(s *Server) providerKindConfig {
			c := s.staticConfig.Bindings
			return providerKindConfig{
				cacheDir:           c.CacheDir,
				releaseURLTemplate: c.ReleaseURLTemplate,
				install:            c.Install,
				unsafeAllowHTTP:    c.UnsafeAllowHTTP,
				disableInstall:     c.DisableInstall,
				configSection:      "[bindings.install]",
				disableInstallKey:  "bindings.disable_install",
				allowHTTPKey:       "bindings.unsafe_allow_http",
			}
		},
		describe: func(s *Server, ctx context.Context, execPath, sha256Hex string) (string, []string, string, error) {
			version, serviceTypes, err := s.describeProvider(ctx, execPath, sha256Hex)
			if err != nil {
				return "", nil, "", err
			}
			typeNames := make([]string, 0, len(serviceTypes))
			for _, t := range serviceTypes {
				typeNames = append(typeNames, t.ServiceType)
			}
			return version, typeNames, "", nil
		},
		register: func(provider *types.BindingProvider, execPath, verifiedSha string) error {
			return bindings.ReplaceProviderBindings(provider.Name, provider.ServiceTypes, execPath, verifiedSha)
		},
		unregister: bindings.UnregisterProviderBindings,
		usageCount: func(s *Server, ctx context.Context, tx types.Transaction, capability string) (int, error) {
			return s.db.CountServices(ctx, tx, capability)
		},
		preinstalledDir: func(s *Server) string {
			return s.staticConfig.Bindings.PreinstalledDir
		},
		registerPreinstalled: func(s *Server, ctx context.Context, name, execPath, checksum string) (string, []string, error) {
			version, serviceTypes, err := s.describeProvider(ctx, execPath, checksum)
			if err != nil {
				return "", nil, err
			}
			typeNames := make([]string, 0, len(serviceTypes))
			for _, t := range serviceTypes {
				typeNames = append(typeNames, t.ServiceType)
			}
			return version, typeNames, bindings.ReplaceProviderBindings("preinstalled:"+name, typeNames, execPath, checksum)
		},
	},
	"plugin": {
		typeName:          "plugin",
		binaryPrefix:      "openrun-plugin-",
		defaultCacheDir:   "$OPENRUN_HOME/plugins",
		defaultReleaseURL: "https://github.com/openrundev/plugins/releases/download/{provider}%2F{version}/openrun-plugin-{provider}-{os}-{arch}{ext}",
		capabilityLabel:   "modules",
		config: func(s *Server) providerKindConfig {
			c := s.staticConfig.PluginProviders
			return providerKindConfig{
				cacheDir:           c.CacheDir,
				releaseURLTemplate: c.ReleaseURLTemplate,
				install:            c.Install,
				unsafeAllowHTTP:    c.UnsafeAllowHTTP,
				disableInstall:     c.DisableInstall,
				configSection:      "[plugin_providers.install]",
				disableInstallKey:  "plugin_providers.disable_install",
				allowHTTPKey:       "plugin_providers.unsafe_allow_http",
			}
		},
		describe: func(s *Server, ctx context.Context, execPath, sha256Hex string) (string, []string, string, error) {
			describeCtx, cancel := context.WithTimeout(ctx, providerDescribeTimeout)
			defer cancel()
			return app.DescribeExternalProviderManifest(describeCtx, execPath, sha256Hex)
		},
		register: func(provider *types.BindingProvider, execPath, verifiedSha string) error {
			return app.RegisterExternalProviderManifest(provider.Name, execPath, verifiedSha, provider.Manifest)
		},
		unregister: app.UnregisterExternalProvider,
		usageCount: func(s *Server, ctx context.Context, tx types.Transaction, capability string) (int, error) {
			// Apps loading a module hold their own provider processes; there
			// is no database-tracked dependent object to count. Uninstall
			// unregisters the modules, and running apps keep their processes
			// until reload.
			return 0, nil
		},
		preinstalledDir: func(s *Server) string {
			return s.staticConfig.PluginProviders.PreinstalledDir
		},
		registerPreinstalled: func(s *Server, ctx context.Context, name, execPath, checksum string) (string, []string, error) {
			describeCtx, cancel := context.WithTimeout(ctx, providerDescribeTimeout)
			defer cancel()
			version, moduleNames, manifest, err := app.DescribeExternalProviderManifest(describeCtx, execPath, checksum)
			if err != nil {
				return "", nil, err
			}
			return version, moduleNames, app.RegisterExternalProviderManifest("preinstalled:"+name, execPath, checksum, manifest)
		},
	},
}

// providerKindFor returns the kind for a provider type name, defaulting to
// "binding" for the empty string (rows and messages predating provider
// types).
func providerKindFor(typeName string) (*providerKind, error) {
	if typeName == "" {
		typeName = "binding"
	}
	kind, ok := providerKinds[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown provider type %q, valid types: binding, plugin", typeName)
	}
	return kind, nil
}

// parseProviderName splits a possibly type-qualified provider name
// ("plugin/store", "binding/mongodb", or bare "mongodb" meaning binding)
// into its kind and bare name.
func parseProviderName(input string) (*providerKind, string, error) {
	typeName, name, qualified := strings.Cut(input, "/")
	if !qualified {
		kind, err := providerKindFor("")
		return kind, input, err
	}
	kind, err := providerKindFor(typeName)
	if err != nil {
		return nil, "", err
	}
	if name == "" || strings.Contains(name, "/") {
		return nil, "", fmt.Errorf("invalid provider name %q, expected <type>/<name>", input)
	}
	return kind, name, nil
}

// kindCacheDir is the kind's node-local provider cache directory.
func (k *providerKind) kindCacheDir(s *Server) string {
	cacheDir := k.config(s).cacheDir
	if cacheDir == "" {
		cacheDir = k.defaultCacheDir
	}
	return os.ExpandEnv(cacheDir)
}

// execPath is the materialized executable path for a provider of this kind.
func (k *providerKind) execPath(s *Server, name string) string {
	execName := k.binaryPrefix + name
	if runtime.GOOS == "windows" {
		execName += ".exe"
	}
	return filepath.Join(k.kindCacheDir(s), execName)
}

// qualifiedName is the display name: bare for bindings (backward
// compatibility with existing tooling), type-qualified otherwise.
func (k *providerKind) qualifiedName(name string) string {
	if k.typeName == "binding" {
		return name
	}
	return k.typeName + "/" + name
}
