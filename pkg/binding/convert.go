// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	pb "github.com/openrundev/openrun/pkg/binding/proto"
)

func metadataToProto(m BindingMetadata) *pb.BindingMetadata {
	return &pb.BindingMetadata{
		Grants:        m.Grants,
		GrantsApplied: grantsToProto(m.GrantsApplied),
		Config:        m.Config,
		Account:       m.Account,
		ApplyInfo:     m.ApplyInfo,
	}
}

func metadataFromProto(m *pb.BindingMetadata) BindingMetadata {
	if m == nil {
		return BindingMetadata{}
	}
	return BindingMetadata{
		Grants:        m.Grants,
		GrantsApplied: grantsFromProto(m.GrantsApplied),
		Config:        m.Config,
		Account:       m.Account,
		ApplyInfo:     m.ApplyInfo,
	}
}

func grantsToProto(grants []BindingGrant) []*pb.BindingGrant {
	ret := make([]*pb.BindingGrant, 0, len(grants))
	for _, g := range grants {
		ret = append(ret, &pb.BindingGrant{GrantType: string(g.GrantType), GrantTarget: g.GrantTarget})
	}
	return ret
}

func grantsFromProto(grants []*pb.BindingGrant) []BindingGrant {
	if grants == nil {
		return nil
	}
	ret := make([]BindingGrant, 0, len(grants))
	for _, g := range grants {
		ret = append(ret, BindingGrant{GrantType: GrantType(g.GetGrantType()), GrantTarget: g.GetGrantTarget()})
	}
	return ret
}

func artifactsToProto(artifacts []Artifact) []*pb.Artifact {
	ret := make([]*pb.Artifact, 0, len(artifacts))
	for _, a := range artifacts {
		ret = append(ret, &pb.Artifact{Type: string(a.Type), Name: a.Name})
	}
	return ret
}

func artifactsFromProto(artifacts []*pb.Artifact) []Artifact {
	ret := make([]Artifact, 0, len(artifacts))
	for _, a := range artifacts {
		ret = append(ret, Artifact{Type: ArtifactType(a.GetType()), Name: a.GetName()})
	}
	return ret
}
