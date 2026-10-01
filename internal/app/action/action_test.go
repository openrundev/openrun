// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"
)

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
