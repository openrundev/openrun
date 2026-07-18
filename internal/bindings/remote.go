// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/openrundev/openrun/internal/types"
	"github.com/openrundev/openrun/pkg/binding"
)

// remoteOwners maps service types registered by out-of-process providers to
// the owning provider name. Service types in ServiceBindings but not here are
// compiled-in bindings.
var remoteOwners = map[string]string{}

// RegisterRemoteBinding registers a service type served by an out-of-process
// binding provider executable. The builder is cheap: the provider process is
// launched lazily by InitializeService and killed by CloseService, so dry runs
// (which build binding instances but open no connections) spawn nothing.
// Compiled-in bindings always win: registering a service type they serve is an
// error, as is a type already registered by a different provider.
func RegisterRemoteBinding(providerName, serviceType, execPath string) error {
	initMutex.Lock()
	defer initMutex.Unlock()
	if owner, ok := remoteOwners[serviceType]; ok && owner != providerName {
		return fmt.Errorf("service type %s is already served by provider %s", serviceType, owner)
	}
	if _, ok := ServiceBindings[serviceType]; ok && remoteOwners[serviceType] == "" {
		return fmt.Errorf("service type %s is served by a built-in binding", serviceType)
	}
	remoteOwners[serviceType] = providerName
	ServiceBindings[serviceType] = func() ServiceBinding {
		return &remoteServiceBinding{serviceType: serviceType, execPath: execPath}
	}
	return nil
}

// UnregisterProviderBindings removes all service types registered by the named
// provider. Compiled-in bindings are never unregistered.
func UnregisterProviderBindings(providerName string) {
	initMutex.Lock()
	defer initMutex.Unlock()
	for serviceType, owner := range remoteOwners {
		if owner == providerName {
			delete(remoteOwners, serviceType)
			delete(ServiceBindings, serviceType)
		}
	}
}

// remoteServiceBinding implements ServiceBinding by proxying calls to a
// provider process over gRPC (hashicorp/go-plugin).
//
// Error handling contract: application-level failures cross the wire in
// response payloads and surface as *binding.ProviderError; any other error is
// a transport failure (the provider crashed or broke protocol). Transport
// failures after a successful InitializeService are retried once after
// respawning the provider and replaying InitializeService. This matters for
// rollback: bindingAccountManager calls DeleteArtifact/RevokeGrants on the
// same instance that did the work, and the provider having crashed is the
// likely reason a rollback is running at all — without the respawn, artifacts
// would leak on the target service.
type remoteServiceBinding struct {
	serviceType string
	execPath    string

	mu       sync.Mutex
	logger   *types.Logger
	provider *binding.Provider
	// Saved InitializeService arguments, replayed on respawn.
	serviceConfig map[string]string
	runtime       ServiceBindingRuntime
	initialized   bool
}

var _ ServiceBinding = (*remoteServiceBinding)(nil)

func (b *remoteServiceBinding) launch() (*binding.Provider, error) {
	logLevel := "INFO"
	if b.logger != nil && b.logger.Logger != nil {
		logLevel = strings.ToUpper(b.logger.GetLevel().String())
	}
	return binding.LaunchProvider(binding.LaunchConfig{
		ExecPath: b.execPath,
		Logger:   NewProviderHCLogger(b.logger, b.serviceType),
		LogLevel: logLevel,
	})
}

// GetAccountEnv returns the account env names for the service type. Static
// info, callable before InitializeService: if the provider process is not
// running, a short-lived one is launched for the call.
func (b *remoteServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	b.mu.Lock()
	provider := b.provider
	b.mu.Unlock()
	if provider != nil {
		return provider.GetAccountEnv(ctx, b.serviceType)
	}

	tempProvider, err := b.launch()
	if err != nil {
		return nil, nil, fmt.Errorf("error launching binding provider %s: %w", b.execPath, err)
	}
	defer tempProvider.Kill()
	return tempProvider.GetAccountEnv(ctx, b.serviceType)
}

func (b *remoteServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.initialized {
		return fmt.Errorf("service binding already initialized")
	}
	b.logger = logger
	b.serviceConfig = serviceConfig
	b.runtime = runtime

	provider, err := b.launch()
	if err != nil {
		return fmt.Errorf("error launching binding provider %s: %w", b.execPath, err)
	}
	if err := provider.InitializeService(ctx, b.serviceType, serviceConfig,
		binding.ServiceBindingRuntime{LocalhostBindingHostname: runtime.LocalhostBindingHostname}); err != nil {
		provider.Kill()
		return err
	}
	b.provider = provider
	b.initialized = true
	return nil
}

func (b *remoteServiceBinding) CloseService(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.provider == nil {
		return nil
	}
	err := b.provider.CloseService(ctx)
	b.provider.Kill()
	b.provider = nil
	b.initialized = false
	var providerError *binding.ProviderError
	if err != nil && !errors.As(err, &providerError) {
		// The process is being killed anyway; a transport error on close is not
		// actionable for the caller.
		return nil
	}
	return err
}

// call invokes fn against the running provider. On a transport failure it
// respawns the provider, replays InitializeService, and retries fn once.
// Application errors (*binding.ProviderError) are returned as-is, unwrapped to
// a plain error string so callers and logs see the provider's message.
func (b *remoteServiceBinding) call(ctx context.Context, fn func(p *binding.Provider) error) error {
	b.mu.Lock()
	provider := b.provider
	initialized := b.initialized
	b.mu.Unlock()
	if !initialized || provider == nil {
		return fmt.Errorf("service binding not initialized")
	}

	err := fn(provider)
	var providerError *binding.ProviderError
	if err == nil || errors.As(err, &providerError) {
		return err
	}

	// Transport failure: respawn and retry once.
	b.mu.Lock()
	if b.logger != nil {
		b.logger.Warn().Err(err).Str("service_type", b.serviceType).Msg("binding provider transport error, respawning provider")
	}
	provider.Kill()
	newProvider, launchErr := b.launch()
	if launchErr != nil {
		b.provider = nil
		b.initialized = false
		b.mu.Unlock()
		return fmt.Errorf("binding provider failed (%s) and could not be respawned: %w", err, launchErr)
	}
	if initErr := newProvider.InitializeService(ctx, b.serviceType, b.serviceConfig,
		binding.ServiceBindingRuntime{LocalhostBindingHostname: b.runtime.LocalhostBindingHostname}); initErr != nil {
		newProvider.Kill()
		b.provider = nil
		b.initialized = false
		b.mu.Unlock()
		return fmt.Errorf("binding provider failed (%s) and could not be reinitialized: %w", err, initErr)
	}
	b.provider = newProvider
	b.mu.Unlock()

	return fn(newProvider)
}

func (b *remoteServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	var account map[string]string
	var artifacts []Artifact
	err := b.call(ctx, func(p *binding.Provider) error {
		var derivedFrom *binding.BindingMetadata
		if derivedFromMetadata != nil {
			m := metadataToSDK(*derivedFromMetadata)
			derivedFrom = &m
		}
		sdkAccount, sdkArtifacts, err := p.GenerateAccount(ctx, bindingId, bindingPath, metadataToSDK(bindingMetadata), derivedFrom, isStaging)
		account = sdkAccount
		artifacts = artifactsFromSDK(sdkArtifacts)
		return err
	})
	return account, artifacts, err
}

func (b *remoteServiceBinding) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	return b.call(ctx, func(p *binding.Provider) error {
		return p.DeleteArtifact(ctx, binding.Artifact{Type: binding.ArtifactType(artifact.Type), Name: artifact.Name})
	})
}

func (b *remoteServiceBinding) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata types.BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	var result GrantApplyResult
	err := b.call(ctx, func(p *binding.Provider) error {
		sdkResult, err := p.ApplyGrants(ctx, account, metadataToSDK(bindingMetadata), metadataToSDK(derivedFromMetadata), reapplyAll)
		result = GrantApplyResult{
			GrantsApplied:  grantsFromSDK(sdkResult.GrantsApplied),
			Granted:        grantsFromSDK(sdkResult.Granted),
			PendingRevokes: grantsFromSDK(sdkResult.PendingRevokes),
		}
		return err
	})
	return result, err
}

func (b *remoteServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata types.BindingMetadata, revokes, regrants []types.BindingGrant) error {
	return b.call(ctx, func(p *binding.Provider) error {
		return p.RevokeGrants(ctx, account, metadataToSDK(derivedFromMetadata), grantsToSDK(revokes), grantsToSDK(regrants))
	})
}

func (b *remoteServiceBinding) RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error) {
	var result map[string]any
	err := b.call(ctx, func(p *binding.Provider) error {
		var err error
		result, err = p.RunCommand(ctx, metadataToSDK(bindingMetadata), command)
		return err
	})
	return result, err
}

// Conversions between the server's internal types and the SDK's. The structs
// are identical in shape; the SDK keeps its own copies so the wire contract
// (the proto) stays the only coupling between server and providers.

func metadataToSDK(m types.BindingMetadata) binding.BindingMetadata {
	return binding.BindingMetadata{
		Grants:        m.Grants,
		GrantsApplied: grantsToSDK(m.GrantsApplied),
		Config:        m.Config,
		Account:       m.Account,
		ApplyInfo:     m.ApplyInfo,
	}
}

func grantsToSDK(grants []types.BindingGrant) []binding.BindingGrant {
	if grants == nil {
		return nil
	}
	ret := make([]binding.BindingGrant, 0, len(grants))
	for _, g := range grants {
		ret = append(ret, binding.BindingGrant{GrantType: binding.GrantType(g.GrantType), GrantTarget: g.GrantTarget})
	}
	return ret
}

func grantsFromSDK(grants []binding.BindingGrant) []types.BindingGrant {
	if grants == nil {
		return nil
	}
	ret := make([]types.BindingGrant, 0, len(grants))
	for _, g := range grants {
		ret = append(ret, types.BindingGrant{GrantType: types.GrantType(g.GrantType), GrantTarget: g.GrantTarget})
	}
	return ret
}

func artifactsFromSDK(artifacts []binding.Artifact) []Artifact {
	ret := make([]Artifact, 0, len(artifacts))
	for _, a := range artifacts {
		ret = append(ret, Artifact{Type: ArtifactType(a.Type), Name: a.Name})
	}
	return ret
}

// NewProviderHCLogger builds the hclog.Logger go-plugin uses on the host side:
// provider log lines (hclog JSON on the provider's stderr) and go-plugin
// lifecycle messages are routed into the server's zerolog log.
func NewProviderHCLogger(logger *types.Logger, serviceType string) hclog.Logger {
	output := &zerologWriter{logger: logger, serviceType: serviceType}
	level := hclog.Info
	if logger != nil && logger.Logger != nil {
		if l := hclog.LevelFromString(logger.GetLevel().String()); l != hclog.NoLevel {
			level = l
		}
	}
	return hclog.New(&hclog.LoggerOptions{
		Name:   "provider." + serviceType,
		Level:  level,
		Output: output,
	})
}

type zerologWriter struct {
	logger      *types.Logger
	serviceType string
}

func (w *zerologWriter) Write(p []byte) (int, error) {
	if w.logger != nil && w.logger.Logger != nil {
		w.logger.Info().Str("service_type", w.serviceType).Msg(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}
