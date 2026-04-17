// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openrundev/openrun/internal/system"
)

// sourceOutputAbsPath returns an absolute filesystem path for an output file
// that belongs under sourceRoot.
//
// outputRel must be a source-relative path such as
// "static/gen/esm/bundle.js". Parent directory references, absolute paths, and
// other paths rejected by system.CleanRelativeLocalPath are returned as errors.
// The returned absolute path is intended for tools that need a host filesystem
// path, such as esbuild's Outfile option.
func sourceOutputAbsPath(sourceRoot, outputRel string) (string, error) {
	root, localRel, err := cleanSourceOutputPath(sourceRoot, outputRel)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, localRel), nil
}

// ensureSourceOutputDir validates an output path, creates its parent
// directories under sourceRoot, and returns the absolute output file path.
//
// Parent directory creation uses os.OpenRoot and Root.MkdirAll so symlinks
// inside sourceRoot cannot redirect the write location outside the source tree.
// sourceRoot itself must be a real non-empty filesystem path because this helper
// is used for external watcher processes that write directly to disk.
//
// For example, given sourceRoot "/repo/app" and outputRel
// "static/gen/css/style.css", this creates "static/gen/css" inside the opened
// source root and returns "/repo/app/static/gen/css/style.css".
func ensureSourceOutputDir(sourceRoot, outputRel string, perm os.FileMode) (string, error) {
	if sourceRoot == "" {
		return "", fmt.Errorf("source root cannot be empty")
	}

	rootPath, localRel, err := cleanSourceOutputPath(sourceRoot, outputRel)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(rootPath, perm); err != nil {
		return "", fmt.Errorf("error creating source root directory %s : %w", rootPath, err)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close() //nolint:errcheck

	dirName := filepath.Dir(localRel)
	if dirName != "." {
		if err := root.MkdirAll(dirName, perm); err != nil {
			return "", fmt.Errorf("error creating source output directory %s : %w", filepath.ToSlash(dirName), err)
		}
	}
	return filepath.Join(rootPath, localRel), nil
}

// cleanSourceRelativeOutput converts an absolute output path back to a
// slash-separated source-relative path.
//
// This is used after tools produce absolute output paths so the result can be
// written through appfs.WritableSourceFs. Both sourceRoot and outputPath are
// resolved through existing symlinks before the relative path is computed, which
// handles platform aliases such as "/var" and "/private/var" on macOS. If the
// output path is outside sourceRoot, the returned relative path is rejected by
// system.CleanRelativePath.
func cleanSourceRelativeOutput(sourceRoot, outputPath string) (string, error) {
	root, err := cleanSourceRoot(sourceRoot)
	if err != nil {
		return "", err
	}

	target, err := cleanSourcePath(outputPath)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	return system.CleanRelativePath(filepath.ToSlash(rel))
}

// cleanSourceOutputPath resolves sourceRoot and validates outputRel as a
// platform-local relative path.
//
// The returned root is absolute and resolved through existing symlinks. The
// returned localRel is safe to pass to filepath and os.Root methods.
func cleanSourceOutputPath(sourceRoot, outputRel string) (root string, localRel string, err error) {
	root, err = cleanSourceRoot(sourceRoot)
	if err != nil {
		return "", "", err
	}
	localRel, err = system.CleanRelativeLocalPath(outputRel)
	if err != nil {
		return "", "", err
	}
	return root, localRel, nil
}

// cleanSourceRoot returns sourceRoot as an absolute path resolved through
// existing symlinks.
func cleanSourceRoot(sourceRoot string) (string, error) {
	return cleanSourcePath(sourceRoot)
}

// cleanSourcePath returns name as an absolute path with every existing path
// component resolved through symlinks.
//
// Missing trailing components are preserved. This lets callers normalize a path
// for an output file before the file or its parent directories exist.
func cleanSourcePath(name string) (string, error) {
	cleanName, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}

	var missing []string
	for {
		resolvedName, err := filepath.EvalSymlinks(cleanName)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolvedName = filepath.Join(resolvedName, missing[i])
			}
			return resolvedName, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(cleanName)
		if parent == cleanName {
			return filepath.Abs(name)
		}
		missing = append(missing, filepath.Base(cleanName))
		cleanName = parent
	}
}
