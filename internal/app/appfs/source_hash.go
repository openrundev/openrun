// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// ContentSha returns the hex sha256 of data, the hash app files are stored
// under
func ContentSha(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GlobMatch returns true if the file name matches any of the patterns
func GlobMatch(patterns []string, fileName string) (bool, error) {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, fileName)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// SourceFileHash returns the hash of an app's source identity: the sorted file
// names with their content shas, followed by the spec files the source does
// not override. Files matching excludeGlob are left out (files used only by
// the hypermedia UI, whose change should not rebuild the container). Every
// source FS implementation hashes through here, so an app's source hashes
// the same whether it is read from the database or from disk
func SourceFileHash(files map[string]string, specFiles types.SpecFiles, excludeGlob []string) (string, error) {
	fileNames := make([]string, 0, len(files))
	for name := range files {
		matched, err := GlobMatch(excludeGlob, name)
		if err != nil {
			return "", err
		}
		if !matched {
			fileNames = append(fileNames, name)
		}
	}
	slices.Sort(fileNames)

	hashBuilder := strings.Builder{}
	for _, name := range fileNames {
		hashBuilder.WriteString(name)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(files[name])
		hashBuilder.WriteByte(0)
	}

	specFileNames := make([]string, 0, len(specFiles))
	for name := range specFiles {
		matched, err := GlobMatch(excludeGlob, name)
		if err != nil {
			return "", err
		}
		if !matched {
			specFileNames = append(specFileNames, name)
		}
	}
	slices.Sort(specFileNames)
	for _, name := range specFileNames {
		if _, ok := files[name]; ok {
			continue // the source overrides the spec file
		}
		hashBuilder.WriteString(name)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(ContentSha([]byte(specFiles[name])))
		hashBuilder.WriteByte(0)
	}

	return ContentSha([]byte(hashBuilder.String())), nil
}

// WalkSourceFiles calls fn with the clean relative path of every regular file
// under the app source directory dir, skipping the .git directory (the same
// file set the metadata file store loads into the database). Symlinks are
// rejected
func WalkSourceFiles(dir string, fn func(fsys fs.FS, name string) error) error {
	fsys := os.DirFS(dir)
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, inErr error) error {
		if inErr != nil {
			return fmt.Errorf("file walk on %s failed for path %s: %w", dir, p, inErr)
		}
		if d.IsDir() {
			if p == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed in app sources: %s", p)
		}
		if d.Type().Type() != 0 {
			return nil // skip non-regular entries
		}
		cleanPath, err := system.CleanRelativePath(p)
		if err != nil {
			return fmt.Errorf("invalid app source path %s: %w", p, err)
		}
		return fn(fsys, cleanPath)
	})
}

// WriteSourceTempDir creates a temp directory holding the app source for a
// container build: the files handed to write, plus the spec files the source
// does not contain. The caller removes the directory after the build
func WriteSourceTempDir(specFiles types.SpecFiles, write func(writeFile func(name string, data []byte) error) (map[string]bool, error)) (string, error) {
	tmpDir, err := os.MkdirTemp("", "cl_source")
	if err != nil {
		return "", fmt.Errorf("error creating temp source dir: %w", err)
	}
	writeFile := func(name string, data []byte) error {
		filePath := path.Join(tmpDir, name)
		if err := os.MkdirAll(path.Dir(filePath), 0700); err != nil {
			return fmt.Errorf("error creating directory %s : %w", path.Dir(filePath), err)
		}
		if err := os.WriteFile(filePath, data, 0700); err != nil {
			return fmt.Errorf("error writing file %s : %w", filePath, err)
		}
		return nil
	}
	written, err := write(writeFile)
	if err != nil {
		os.RemoveAll(tmpDir) //nolint:errcheck
		return "", err
	}
	for name := range specFiles {
		if written[name] {
			continue // the source overrides the spec file
		}
		if err := writeFile(name, []byte(specFiles[name])); err != nil {
			os.RemoveAll(tmpDir) //nolint:errcheck
			return "", err
		}
	}
	return tmpDir, nil
}
