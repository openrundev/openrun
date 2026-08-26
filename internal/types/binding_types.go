// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Binding is a binding entry in the metadata database
// A binding is a link between a service and a source service
type Binding struct {
	Id               string          `json:"id"`           // the id of the binding
	Path             string          `json:"path"`         // the path of the binding
	Source           string          `json:"source"`       // service id, or the base binding path
	ServiceType      string          `json:"service_type"` // the type of the service
	ServiceName      string          `json:"service_name"` // the name of the service
	ServiceIsDefault bool            `json:"-"`
	DerivedFrom      string          `json:"derived_from"` // the base binding path this is derived from
	StagedMetadata   BindingMetadata `json:"staged_metadata"`
	Metadata         BindingMetadata `json:"metadata"`
	CreatedBy        string          `json:"created_by"`         // user who created the binding
	CreatedBySyncId  string          `json:"created_by_sync_id"` // id of the sync entry which created this binding, empty for imperative/apply creates; used by sync prune
	CreateTime       time.Time       `json:"create_time"`
	UpdateTime       time.Time       `json:"update_time"`

	// ServiceConfig is the live config of the binding's service, populated when
	// the binding is loaded for app use (GetBindingWithAccount) so the container
	// layer sees service config updates on the next app reload. Not persisted
	// with the binding and never serialized.
	ServiceConfig map[string]string `json:"-"`

	// StagingServiceConfig is the live config of the linked staging service
	// (service.Staging), when one is set: staged apps use it instead of
	// ServiceConfig (e.g. a sqlite staging service replicating to a different
	// litestream config). Nil when no staging service is linked; populated
	// like ServiceConfig, never serialized.
	StagingServiceConfig map[string]string `json:"-"`
}

type BindingMetadata struct {
	Grants        []string          `json:"grants"`
	GrantsApplied []BindingGrant    `json:"grants_applied"`
	Config        map[string]string `json:"config"`
	Account       map[string]string `json:"account,omitempty"`
	Artifacts     []BindingArtifact `json:"artifacts,omitempty"`
	ApplyInfo     []byte            `json:"apply_info"`
}

// BindingArtifact records one object created on the backend service for the
// binding account (a role/schema, user/database, ...), in creation order.
// Recorded when the account is generated so the objects can be dropped when
// the binding is deleted.
type BindingArtifact struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type GrantType string

const (
	GrantTypeRead   GrantType = "READ"
	GrantTypeCreate GrantType = "CREATE"
	GrantTypeFull   GrantType = "FULL"
)

const (
	GrantTargetAll = "*"
)

func ParseGrant(grant string, supportedGrantTypes []GrantType) (BindingGrant, error) {
	grantType, grantTarget, ok := strings.Cut(grant, ":")
	if !ok || grantType == "" {
		return BindingGrant{}, fmt.Errorf("invalid grant format, expected type:<target>, got: %s", grant)
	}
	grantType = strings.ToUpper(strings.TrimSpace(grantType))
	if !slices.Contains(supportedGrantTypes, GrantType(grantType)) {
		supportedGrantTypesStr := make([]string, len(supportedGrantTypes))
		for i, gt := range supportedGrantTypes {
			supportedGrantTypesStr[i] = string(gt)
		}
		return BindingGrant{}, fmt.Errorf("unsupported grant type: %s, supported types: %s", grantType, strings.Join(supportedGrantTypesStr, ", "))
	}
	return BindingGrant{
		GrantType:   GrantType(grantType),
		GrantTarget: strings.TrimSpace(grantTarget),
	}, nil
}

type BindingGrant struct {
	GrantType   GrantType `json:"grant_type"`
	GrantTarget string    `json:"grant_target"`
}

func (g BindingGrant) String() string {
	return fmt.Sprintf("%s:%s", g.GrantType, g.GrantTarget)
}
