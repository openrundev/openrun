// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"path/filepath"
	"testing"
)

func TestCleanRelativePath(t *testing.T) {
	t.Run("accepts relative paths", func(t *testing.T) {
		tests := map[string]string{
			"Dockerfile":        "Dockerfile",
			"./Dockerfile":      "Dockerfile",
			"sub/Containerfile": "sub/Containerfile",
			`sub\Containerfile`: "sub/Containerfile",
		}

		for input, want := range tests {
			got, err := CleanRelativePath(input)
			if err != nil {
				t.Fatalf("CleanRelativePath(%q) returned error: %v", input, err)
			}
			if got != want {
				t.Fatalf("CleanRelativePath(%q) = %q, want %q", input, got, want)
			}
		}
	})

	t.Run("rejects traversal and absolute paths", func(t *testing.T) {
		for _, input := range []string{
			"",
			".",
			"..",
			"../Dockerfile",
			"sub/../../Dockerfile",
			"/Dockerfile",
			`..\Dockerfile`,
			"C:/Dockerfile",
			`C:\Dockerfile`,
			"Dockerfile\x00",
		} {
			if _, err := CleanRelativePath(input); err == nil {
				t.Fatalf("CleanRelativePath(%q) should fail", input)
			}
		}
	})
}

func TestCleanRelativeLocalPath(t *testing.T) {
	got, err := CleanRelativeLocalPath(`sub\Containerfile`)
	if err != nil {
		t.Fatalf("CleanRelativeLocalPath returned error: %v", err)
	}
	if want := filepath.Join("sub", "Containerfile"); got != want {
		t.Fatalf("CleanRelativeLocalPath = %q, want %q", got, want)
	}
}

func TestCleanFilename(t *testing.T) {
	t.Run("accepts plain filenames", func(t *testing.T) {
		for _, name := range []string{"report.txt", "my report.txt", ".env"} {
			got, err := CleanFilename(name)
			if err != nil {
				t.Fatalf("CleanFilename(%q) returned error: %v", name, err)
			}
			if got != name {
				t.Fatalf("CleanFilename(%q) = %q, want %q", name, got, name)
			}
		}
	})

	t.Run("rejects traversal and path components", func(t *testing.T) {
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
			if _, err := CleanFilename(name); err == nil {
				t.Fatalf("CleanFilename(%q) should fail", name)
			}
		}
	})

	t.Run("rejects windows reserved device names on windows", func(t *testing.T) {
		if filepath.Separator != '\\' {
			t.Skip("windows-only check")
		}
		for _, name := range []string{"NUL", "CON", "PRN", "AUX", "COM1", "LPT1", "nul.txt"} {
			if _, err := CleanFilename(name); err == nil {
				t.Fatalf("CleanFilename(%q) should fail on windows", name)
			}
		}
	})
}

func TestPathInDir(t *testing.T) {
	tempDir := t.TempDir()

	got, err := PathInDir(tempDir, "report.txt")
	if err != nil {
		t.Fatalf("PathInDir returned error: %v", err)
	}
	if filepath.Dir(got) != tempDir {
		t.Fatalf("PathInDir dir = %q, want %q", filepath.Dir(got), tempDir)
	}
	if filepath.Base(got) != "report.txt" {
		t.Fatalf("PathInDir base = %q, want report.txt", filepath.Base(got))
	}

	if _, err := PathInDir(tempDir, "../report.txt"); err == nil {
		t.Fatal("PathInDir should reject traversal")
	}
}

func TestPathWithinDir(t *testing.T) {
	tempDir := t.TempDir()

	inside, err := PathWithinDir(tempDir, filepath.Join(tempDir, "nested", "file.txt"))
	if err != nil {
		t.Fatalf("PathWithinDir returned error: %v", err)
	}
	if !inside {
		t.Fatal("PathWithinDir should accept child path")
	}

	inside, err = PathWithinDir(tempDir, filepath.Join(tempDir, "..", "file.txt"))
	if err != nil {
		t.Fatalf("PathWithinDir returned error: %v", err)
	}
	if inside {
		t.Fatal("PathWithinDir should reject parent path")
	}
}
