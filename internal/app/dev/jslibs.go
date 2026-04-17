// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"fmt"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/evanw/esbuild/pkg/cli"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/types"
)

var npmPackageNamePattern = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*$`)

func NewLibrary(url string) *types.JSLibrary {
	j := types.JSLibrary{
		LibType:           types.Library,
		DirectUrl:         url,
		SanitizedFileName: sanitizeFileName(url),
	}
	return &j
}

func NewLibraryESM(packageName string, version string, esbuildArgs []string) *types.JSLibrary {
	args := [10]string{}
	if esbuildArgs != nil {
		copy(args[:], esbuildArgs)
	}

	j := types.JSLibrary{
		LibType:           types.ESModule,
		PackageName:       packageName,
		Version:           version,
		EsbuildArgs:       args,
		SanitizedFileName: sanitizeFileName(packageName) + "-" + version + ".js",
	}
	return &j
}

type JsLibManager struct {
	types.JSLibrary
}

func (j *JsLibManager) Setup(dev *AppDev, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs) (string, error) {
	if j.LibType == types.Library { //nolint:staticcheck
		targetFile := path.Join(types.LIB_PATH, j.SanitizedFileName)
		if err := dev.downloadFile(j.DirectUrl, sourceFS, targetFile); err != nil {
			return "", fmt.Errorf("error downloading %s : %s", j.DirectUrl, err)
		}
		return targetFile, nil
	} else if j.LibType == types.ESModule {
		return j.setupEsbuild(dev, sourceFS, workFS)
	} else {
		return "", fmt.Errorf("invalid library type : %s", j.LibType)
	}
}

func (j *JsLibManager) setupEsbuild(dev *AppDev, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs) (string, error) {
	targetRel := path.Join(types.ESM_PATH, j.SanitizedFileName)
	targetFile, err := sourceOutputAbsPath(sourceFS.Root, targetRel)
	if err != nil {
		return "", err
	}

	sourceFile, err := j.generateSourceFile(workFS)
	if err != nil {
		return "", err
	}

	esbuildArgs := []string{sourceFile, "--bundle", "--format=esm"}

	args := []string{}
	for _, arg := range j.EsbuildArgs {
		if arg == "" {
			break
		}
		args = append(args, arg)
	}
	esbuildArgs = append(esbuildArgs, args...)
	dev.Trace().Msgf("esbuild args : %v", esbuildArgs)

	// Parse the build options from the esbuild args
	options, err := cli.ParseBuildOptions(esbuildArgs)
	if err != nil {
		return "", fmt.Errorf("error parsing esbuild args : %s", err)
	}
	//options.AbsWorkingDir = sourceFS.Root this fails if the source dir is not absolute
	options.Outfile = targetFile
	options.Write = false

	if dev.systemConfig.NodePath != "" {
		if dev.systemConfig.NodePath == "disable" {
			dev.Warn().Msg("node_modules path is disabled, esbuild is not being run")
			return "", nil
		}

		// Add node paths to the esbuild options to customize the node_module location
		var nodePaths []string
		if runtime.GOOS == "windows" {
			nodePaths = strings.Split(dev.systemConfig.NodePath, ";")
		} else {
			nodePaths = strings.Split(dev.systemConfig.NodePath, ":")
		}
		options.NodePaths = nodePaths
	}

	// Run esbuild to generate the output file
	result := api.Build(options)
	dev.Trace().Msgf("esbuild options : %+v", options)
	if len(result.Errors) > 0 {
		// Return the target file name. The caller can check if the file exists to determine if the
		// setup was successful even though this step failed
		dev.Error().Msgf("error building %s : %v", j.PackageName, result.Warnings)
		return targetRel, fmt.Errorf("error building %s : %v", j.PackageName, result.Errors)
	}
	if len(result.Warnings) > 0 {
		dev.Warn().Msgf("warning building %s : %v", j.PackageName, result.Warnings)
	}

	for _, file := range result.OutputFiles {
		target, err := cleanSourceRelativeOutput(sourceFS.Root, file.Path)
		if err != nil {
			return "", err
		}
		dev.Trace().Msgf("esbuild output file : %s %s", file.Path, target)
		if err := sourceFS.Write(target, file.Contents); err != nil {
			return "", fmt.Errorf("error writing esbuild output file %s : %s", file.Path, err)
		}
	}
	return targetRel, nil
}

func (j *JsLibManager) generateSourceFile(workFS *appfs.WorkFs) (string, error) {
	if err := validatePackageName(j.PackageName); err != nil {
		return "", err
	}

	sourceFileName := j.SanitizedFileName
	sourceContent := fmt.Sprintf("export * from %s", strconv.Quote(j.PackageName))
	if err := workFS.Write(sourceFileName, []byte(sourceContent)); err != nil {
		return "", fmt.Errorf("error writing source file %s : %s", sourceFileName, err)
	}
	return path.Join(workFS.Root, sourceFileName), nil
}

func sanitizeFileName(input string) string {
	output := path.Base(input)
	output = strings.ReplaceAll(output, "@", "")
	return output
}

func validatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 214 {
		return fmt.Errorf("package name %q is too long", name)
	}
	if !npmPackageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package name %q", name)
	}
	return nil
}
