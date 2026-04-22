// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// CleanRelativePath returns a slash-separated relative path that cannot escape
// its containing directory.
//
// For example, `sub\file.txt` is returned as `sub/file.txt`. Use this for
// logical paths such as fs.FS names, URL/static paths, metadata paths, and tar
// header names.
//
// Backslashes in the input are treated as path separators on every platform so
// that configs authored on Windows or Unix are validated identically. The
// trade-off is that a legitimate Unix filename containing a backslash will be
// re-interpreted as a multi-component path; callers that need to preserve
// such names should not route them through this function.
func CleanRelativePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("path cannot contain NUL bytes")
	}
	// Reject host-native absolute paths (e.g. "C:\\foo" on Windows) before any
	// normalization, in case the platform parser disagrees with our slash
	// rewrite below.
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("path must be relative")
	}

	normalized := strings.ReplaceAll(name, "\\", "/")
	if path.IsAbs(normalized) || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("path must be relative")
	}

	if slices.Contains(strings.Split(normalized, "/"), "..") {
		return "", fmt.Errorf("path must not contain parent directory elements")
	}

	cleanName := path.Clean(normalized)
	if cleanName == "." {
		return "", fmt.Errorf("path must stay within its root")
	}

	return cleanName, nil
}

// CleanRelativeLocalPath returns a platform-local relative path that cannot
// escape its containing directory. On Windows, filepath.IsLocal additionally
// rejects reserved device names such as NUL, CON, COM1, etc.
//
// For example, `sub\file.txt` is returned as `sub/file.txt` on Unix and
// `sub\file.txt` on Windows. Use this when the result is passed to filepath,
// os, or host commands.
func CleanRelativeLocalPath(name string) (string, error) {
	cleanName, err := CleanRelativePath(name)
	if err != nil {
		return "", err
	}

	localPath := filepath.FromSlash(cleanName)
	if !filepath.IsLocal(localPath) {
		return "", fmt.Errorf("path must stay within its root")
	}

	return localPath, nil
}

// CleanFilename returns a single filename with no directory components.
//
// As with CleanRelativePath, backslashes are treated as path separators on
// every platform so that filenames are validated portably. On Windows the
// result is also checked against reserved device names (NUL, CON, COM1, ...).
func CleanFilename(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("filename cannot be empty")
	}
	if strings.ContainsRune(filename, 0) {
		return "", fmt.Errorf("filename cannot contain NUL bytes")
	}

	normalized := strings.ReplaceAll(filename, "\\", "/")
	if strings.Contains(normalized, "/") || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("filename must not contain path components")
	}
	if normalized == "." || normalized == ".." {
		return "", fmt.Errorf("filename must not be a directory reference")
	}
	// filepath.IsLocal rejects Windows reserved device names like NUL or CON
	// (this is a no-op on non-Windows platforms).
	if !filepath.IsLocal(normalized) {
		return "", fmt.Errorf("filename is not a valid local name")
	}

	return normalized, nil
}

// PathInDir joins relPath under root after validating that relPath is local.
//
// Because CleanRelativeLocalPath enforces filepath.IsLocal, the resulting
// joined path is guaranteed to be lexically inside root. This is a lexical
// guarantee only: it does not resolve symlinks. For symlink-safe access use
// os.Root from the standard library.
func PathInDir(root, relPath string) (string, error) {
	localRelPath, err := CleanRelativeLocalPath(relPath)
	if err != nil {
		return "", err
	}

	return filepath.Join(root, localRelPath), nil
}

// CleanAbsolutePath returns an absolute, cleaned local filesystem path. If the
// path exists, symlinks are resolved.
func CleanAbsolutePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("path cannot contain NUL bytes")
	}

	absPath, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	absPath = filepath.Clean(absPath)
	if resolvedPath, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolvedPath
	}
	return absPath, nil
}

// PathWithinDir reports whether targetPath is lexically inside root.
//
// This is a purely lexical check: symlinks under root that point outside root
// are not detected. For symlink-safe access prefer os.Root from the standard
// library.
func PathWithinDir(root, targetPath string) (bool, error) {
	relToRoot, err := filepath.Rel(root, targetPath)
	if err != nil {
		return false, err
	}

	if relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return false, nil
	}
	return true, nil
}

func hasWindowsDrivePrefix(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}

	c := name[0]
	return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')
}
