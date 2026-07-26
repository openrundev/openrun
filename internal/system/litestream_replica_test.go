// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/types"
)

func TestRecordReplicaObject(t *testing.T) {
	t.Parallel()

	now := time.Now()
	found := map[string]*LitestreamReplicaDB{}

	// Observed litestream 0.5 remote layout: <db>/<0000-level>/<min>-<max>.ltx
	recordReplicaObject(found, "data.db/0000/0000000000000001-0000000000000003.ltx", now.Add(-time.Minute), 100)
	recordReplicaObject(found, "data.db/0009/0000000000000001-0000000000000002.ltx", now, 500)
	// Nested database path
	recordReplicaObject(found, "tenants/acme.db/0000/0000000000000001-0000000000000001.ltx", now, 50)
	// Alternate layout with an ltx path segment
	recordReplicaObject(found, "extra.db/ltx/0/0000000000000001-000000000000000a.ltx", now, 70)
	// Non-LTX objects are ignored
	recordReplicaObject(found, "data.db/.litestream/position", now, 10)
	recordReplicaObject(found, "stray.txt", now, 10)

	if len(found) != 3 {
		t.Fatalf("found = %v, want 3 databases", found)
	}
	dataDB := found["data.db"]
	if dataDB == nil || dataDB.MaxTXID != 3 || dataDB.Size != 600 {
		t.Fatalf("data.db = %+v", dataDB)
	}
	if !dataDB.LastUpdated.Equal(now) {
		t.Fatalf("data.db last updated = %v, want %v", dataDB.LastUpdated, now)
	}
	if found["tenants/acme.db"] == nil {
		t.Fatalf("nested db missing: %v", found)
	}
	if extra := found["extra.db"]; extra == nil || extra.MaxTXID != 10 {
		t.Fatalf("extra.db = %+v", found["extra.db"])
	}
}

func TestLitestreamReplicaURL(t *testing.T) {
	t.Parallel()

	s3URL, err := LitestreamReplicaURL(types.LitestreamConfig{
		Bucket: "b", Endpoint: "http://127.0.0.1:9000", Region: "us-east-1", ForcePathStyle: true,
	}, "prefix/bindings/bnd_1/prod/data.db")
	if err != nil {
		t.Fatalf("LitestreamReplicaURL: %v", err)
	}
	want := "s3://b/prefix/bindings/bnd_1/prod/data.db?endpoint=http%3A%2F%2F127.0.0.1%3A9000&forcePathStyle=true&region=us-east-1"
	if s3URL != want {
		t.Fatalf("url = %q, want %q", s3URL, want)
	}

	fileURL, err := LitestreamReplicaURL(types.LitestreamConfig{Type: "file", Path: "/backups"}, "metadata/meta.db")
	if err != nil {
		t.Fatalf("LitestreamReplicaURL file: %v", err)
	}
	if fileURL != "file:///backups/metadata/meta.db" {
		t.Fatalf("file url = %q", fileURL)
	}
}
