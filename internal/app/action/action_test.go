// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"path/filepath"
	"testing"
)

func TestUploadedFilePathStaysInTempDir(t *testing.T) {
	tempDir := t.TempDir()

	got, err := uploadedFilePath(tempDir, "report.txt")
	if err != nil {
		t.Fatalf("uploadedFilePath returned error: %v", err)
	}
	if filepath.Dir(got) != tempDir {
		t.Fatalf("uploadedFilePath dir = %q, want %q", filepath.Dir(got), tempDir)
	}
	if filepath.Base(got) != "report.txt" {
		t.Fatalf("uploadedFilePath base = %q, want report.txt", filepath.Base(got))
	}

	rel, err := filepath.Rel(tempDir, got)
	if err != nil {
		t.Fatalf("filepath.Rel returned error: %v", err)
	}
	if rel != "report.txt" {
		t.Fatalf("uploadedFilePath escaped temp dir: %q", got)
	}
}

func TestUploadedFilePathRejectsUnsafeNames(t *testing.T) {
	tempDir := t.TempDir()

	for _, name := range []string{
		"",
		".",
		"..",
		"../evil.txt",
		"nested/evil.txt",
		"/tmp/evil.txt",
		`..\evil.txt`,
		`C:\fakepath\evil.txt`,
		"C:evil.txt",
		"evil.txt\x00",
	} {
		if _, err := uploadedFilePath(tempDir, name); err == nil {
			t.Fatalf("uploadedFilePath(%q) should fail", name)
		}
	}
}
