// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"fmt"
	"os"
	"path/filepath"
)

func Example_sourceOutputAbsPath() {
	sourceRoot, err := os.MkdirTemp("", "openrun-source-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(sourceRoot) //nolint:errcheck

	target, err := sourceOutputAbsPath(sourceRoot, "static/gen/esm/app.js")
	if err != nil {
		panic(err)
	}

	cleanRoot, err := cleanSourceRoot(sourceRoot)
	if err != nil {
		panic(err)
	}
	rel, err := filepath.Rel(cleanRoot, target)
	if err != nil {
		panic(err)
	}

	fmt.Println(filepath.IsAbs(target))
	fmt.Println(filepath.ToSlash(rel))
	// Output:
	// true
	// static/gen/esm/app.js
}

func Example_ensureSourceOutputDir() {
	sourceRoot, err := os.MkdirTemp("", "openrun-source-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(sourceRoot) //nolint:errcheck

	target, err := ensureSourceOutputDir(sourceRoot, STYLE_FILE_PATH, 0700)
	if err != nil {
		panic(err)
	}

	cleanRoot, err := cleanSourceRoot(sourceRoot)
	if err != nil {
		panic(err)
	}
	rel, err := filepath.Rel(cleanRoot, target)
	if err != nil {
		panic(err)
	}
	_, err = os.Stat(filepath.Dir(target))

	fmt.Println(filepath.ToSlash(rel))
	fmt.Println(err == nil)
	// Output:
	// static/gen/css/style.css
	// true
}

func Example_cleanSourceRelativeOutput() {
	sourceRoot, err := os.MkdirTemp("", "openrun-source-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(sourceRoot) //nolint:errcheck

	cleanRoot, err := cleanSourceRoot(sourceRoot)
	if err != nil {
		panic(err)
	}
	outputPath := filepath.Join(cleanRoot, "static", "gen", "css", "style.css")

	rel, err := cleanSourceRelativeOutput(sourceRoot, outputPath)
	if err != nil {
		panic(err)
	}

	fmt.Println(rel)
	// Output:
	// static/gen/css/style.css
}
