// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"context"
)

const BindingHostnameDisable = "disable"

// ServiceBindingRuntime carries server-side runtime settings a binding may
// need when connecting to the service.
type ServiceBindingRuntime struct {
	// LocalhostBindingHostname is the hostname apps should use to reach a
	// service running on the server host (e.g. host.docker.internal when apps
	// run in containers). Empty when apps run directly on the host.
	LocalhostBindingHostname string
}

type ArtifactType string

const (
	ArtifactRole     ArtifactType = "role"
	ArtifactSchema   ArtifactType = "schema"
	ArtifactUser     ArtifactType = "user"
	ArtifactDatabase ArtifactType = "database"
	ArtifactLogin    ArtifactType = "login" // SQL Server server-level login backing a database user
)

// Artifact identifies one object created on the service by GenerateAccount,
// such as a role/schema (postgres) or user/database (mysql). The caller tracks
// the created artifacts and passes them back to DeleteArtifact to undo the
// creation on rollback.
type Artifact struct {
	Type ArtifactType
	Name string
}

// GrantApplyResult is the outcome of ApplyGrants. ApplyGrants only executes the
// additive part of a grant change; revokes are computed but not executed, so a
// caller can defer them until after its metadata transaction commits (a running
// app may see extra grants during the operation, but never loses a grant from an
// operation that is later rolled back).
type GrantApplyResult struct {
	// GrantsApplied is the set of grants now in effect on the service for the
	// account, to be recorded in the binding metadata. Grants pending revoke are
	// still included; the caller removes them from the metadata after RevokeGrants
	// succeeds.
	GrantsApplied []BindingGrant
	// Granted lists the grants newly applied on the service by this call. If the
	// caller's metadata transaction is rolled back, these are the grants to
	// compensate via RevokeGrants.
	Granted []BindingGrant
	// PendingRevokes lists grants that are applied on the service but no longer
	// desired. The caller executes them via RevokeGrants after its metadata
	// transaction commits.
	PendingRevokes []BindingGrant
}

// ServiceBinding is the interface a binding provider implements for each
// service type it serves. The method contracts match the OpenRun server's
// internal service binding interface; see the method comments for the
// semantics the server relies on.
type ServiceBinding interface {
	// GetAccountEnv returns the names of the env values included in the
	// account info for this binding: the always-present params first, then the
	// optional params. This is static info: it must be callable on an
	// uninitialized instance, before InitializeService.
	GetAccountEnv(ctx context.Context) ([]string, []string, error)

	// Initialize the service with the given config. This is called when the service binding is created.
	InitializeService(ctx context.Context, logger *Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error

	// Close the service connection. This is called when the service binding is no longer needed.
	CloseService(ctx context.Context) error

	// Generate the account based on the binding config. This is called once when the binding is created, after the service is initialized.
	// The account and its backing artifacts (role/schema, user/database) are created on the endpoint specified in the service config
	// and are persisted immediately. The artifacts that were created are returned in creation order; pre-existing objects that the
	// account merely references (like the base binding's schema for a derived binding) must not be included. If creation fails
	// partway and already-created artifacts cannot be rolled back internally, they are returned along with the error so the
	// caller can clean them up.
	GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata BindingMetadata,
		derivedFromMetadata *BindingMetadata, isStaging bool) (map[string]string, []Artifact, error)

	// Delete one artifact previously reported as created by GenerateAccount. Called to undo a creation when an
	// operation is rolled back, and when the binding is deleted (with the artifacts recorded at creation time,
	// in reverse creation order). The implementation must delete only the named artifact, but a container
	// artifact (schema/database) may have accumulated objects since it was created and must be dropped along
	// with its contents. Deleting an artifact that no longer exists must be harmless.
	DeleteArtifact(ctx context.Context, artifact Artifact) error

	// Apply the grants to the account. This is called when the binding is created, after the account is generated.
	// It can be called again if the grants are changed. Only new grants are executed (and persisted immediately);
	// grants that need to be removed are returned in PendingRevokes without being executed, for the caller to run
	// via RevokeGrants once its metadata transaction commits.
	ApplyGrants(ctx context.Context, account map[string]string,
		bindingMetadata, derivedFromMetadata BindingMetadata, reapplyAll bool) (GrantApplyResult, error)

	// Revoke the given grants from the account, then re-apply the regrants. Called with the PendingRevokes of an
	// earlier ApplyGrants after the caller's metadata transaction commits (regrants = the grants that remain
	// desired), or with the Granted list to compensate when the transaction is rolled back (regrants = the grants
	// that were applied before the operation). The regrants restore privileges that an overlapping revoke removes
	// (e.g. revoking read:t1 while read:* remains would otherwise drop SELECT on t1). Revoking a grant that is not
	// currently applied must be harmless.
	RevokeGrants(ctx context.Context, account map[string]string,
		derivedFromMetadata BindingMetadata, revokes, regrants []BindingGrant) error

	// Run a command on the endpoint specified in the service config as the binding account.
	RunCommand(ctx context.Context, bindingMetadata BindingMetadata, command string) (map[string]any, error)

	// CheckHealth verifies the service is healthy: connect to the endpoint with the admin credentials
	// from the service config and run a no-op operation (ping / select 1). A nil return means the
	// service is reachable and accepting the admin credentials; any failure is returned as the error.
	CheckHealth(ctx context.Context) error

	// CheckBindingHealth verifies the binding account is healthy: connect to the endpoint AS the
	// binding account (bindingMetadata.Account) and run a no-op operation. This proves the generated
	// credentials still work, e.g. that the account was not dropped or disabled out-of-band.
	CheckBindingHealth(ctx context.Context, bindingMetadata BindingMetadata) error
}

// Builder creates a new, uninitialized ServiceBinding instance.
type Builder func() ServiceBinding

// ServiceTypeInfo describes one service type served by a provider, reported to
// the server through the Describe RPC.
type ServiceTypeInfo struct {
	ServiceType         string
	SupportedGrantTypes []GrantType
	RequiredConfigKeys  []string
	OptionalConfigKeys  []string
}
