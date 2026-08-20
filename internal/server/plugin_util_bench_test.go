// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

// Benchmarks comparing candidate struct -> plugin-value conversions for
// server plugin returns, on a representative row (types.AppInfo). The
// downstream bridge (map -> starlark) cost is identical for all candidates
// and excluded.
//
// Run with: go test -bench BenchmarkStructValue -run xx ./internal/server/

func benchAppInfo() types.AppInfo {
	return types.AppInfo{
		AppPathDomain:  types.AppPathDomain{Path: "/apps/example", Domain: "example.com"},
		Name:           "my application",
		Id:             "app_prd_00000000000000000000",
		IsDev:          false,
		MainApp:        "",
		LinkedAppPath:  "example.com:/",
		Auth:           types.AppAuthnDefault,
		SourceUrl:      "github.com/example/repo",
		Spec:           "proxy",
		Version:        42,
		GitSha:         "a44272ff00000000",
		GitMessage:     "update links",
		Branch:         "main",
		StarBase:       "spec",
		UpdateTime:     time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC),
		RetainVersions: 5,
		AppliedSyncId:  "sync_123",
		UserID:         "admin",
	}
}

// jsonRoundTrip is the previous conversion (kept here for comparison only).
func jsonRoundTrip(p any) (any, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- candidate 3: hand-written converter ---

func handWrittenValue(a types.AppInfo) map[string]any {
	return map[string]any{
		"Path":           a.Path,
		"Domain":         a.Domain,
		"Name":           a.Name,
		"Id":             string(a.Id),
		"IsDev":          a.IsDev,
		"MainApp":        string(a.MainApp),
		"LinkedAppPath":  a.LinkedAppPath,
		"Auth":           string(a.Auth),
		"SourceUrl":      a.SourceUrl,
		"Spec":           string(a.Spec),
		"Version":        a.Version,
		"GitSha":         a.GitSha,
		"GitMessage":     a.GitMessage,
		"Branch":         a.Branch,
		"StarBase":       a.StarBase,
		"UpdateTime":     a.UpdateTime,
		"RetainVersions": a.RetainVersions,
		"AppliedSyncId":  a.AppliedSyncId,
		"UserID":         a.UserID,
	}
}

func BenchmarkStructValue(b *testing.B) {
	row := benchAppInfo()

	b.Run("json_roundtrip", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := jsonRoundTrip(row); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("struct_value", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := structValue(row); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("hand_written", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = handWrittenValue(row)
		}
	})
}
