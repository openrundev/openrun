// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// maxVersionFileView caps the file size served to the version files viewer;
// larger files are covered by the zip download
const maxVersionFileView = 1024 * 1024

// ExportAppVersion returns the declarative config of one app as a formatted
// app() call, the per-app equivalent of Export. env selects the prod ("" or
// "prod") or staging ("stage") declaration and version a specific version of
// that environment (empty = active). Staging versions export with the main
// app path, since that is the declaration they promote to. The output uses
// exact service/git auth references and includes the git commit - it
// describes one concrete version. Param values are masked as <param:NAME>
// placeholders unless the caller holds app:update, the same visibility rule
// as the edit form
func (s *Server) ExportAppVersion(ctx context.Context, mainAppPath, env, version string) (string, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return "", err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return "", err
	}

	exportMeta := appEntry.Metadata
	if appEntry.IsDev {
		if (env != "" && env != "prod") || version != "" {
			return "", fmt.Errorf("dev apps serve from source, environments and versions are not tracked")
		}
	} else {
		targetEntry := appEntry
		switch env {
		case "", "prod":
		case "stage":
			targetEntry, err = s.getStageApp(ctx, tx, appEntry)
			if err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("invalid env %q, expected prod or stage", env)
		}
		exportMeta = targetEntry.Metadata
		if version != "" {
			versionInt, err := strconv.Atoi(version)
			if err != nil {
				return "", fmt.Errorf("invalid version %q", version)
			}
			if versionInt != targetEntry.Metadata.VersionMetadata.Version {
				fileStore, err := metadata.NewFileStore(targetEntry.Id, versionInt, s.db, tx)
				if err != nil {
					return "", err
				}
				appVersion, err := fileStore.GetAppVersion(ctx, tx, versionInt)
				if err != nil {
					return "", fmt.Errorf("version %d not found: %w", versionInt, err)
				}
				if appVersion.Metadata == nil {
					return "", fmt.Errorf("version %d has no metadata", versionInt)
				}
				exportMeta = *appVersion.Metadata
			}
		}
	}

	// Export with the main entry's identity (path, id) so staging versions
	// render with the path the declaration promotes to
	entryCopy := *appEntry
	entryCopy.Metadata = exportMeta

	allBindings, err := s.db.ListBindings(ctx, tx, "")
	if err != nil {
		return "", err
	}
	bindingsByPath := make(map[string]*types.Binding, len(allBindings))
	for _, binding := range allBindings {
		bindingsByPath[binding.Path] = binding
	}

	builder := newExportBuilder(types.ExportOptions{
		ServiceRef:  types.ExportRefExact,
		GitAuthRef:  types.ExportRefExact,
		ExactCommit: true,
	})
	req := s.exportApp(ctx, tx, &entryCopy, bindingsByPath, builder)

	if len(req.ParamValues) > 0 && s.enforceAppPermEntry(ctx, types.PermissionUpdate, appEntry) != nil {
		// Name-stable masking: diffs over masked outputs still align, and a
		// masked line only changes when the param set itself changes
		masked := make(map[string]string, len(req.ParamValues))
		for key := range req.ParamValues {
			masked[key] = "<param:" + key + ">"
		}
		req.ParamValues = masked
	}

	body, formatWarnings := formatConfig(nil, []*types.CreateAppRequest{req})
	var sb strings.Builder
	for _, warning := range append(builder.warnings, formatWarnings...) {
		sb.WriteString("# WARNING: ")
		sb.WriteString(warning)
		sb.WriteString("\n")
	}
	sb.WriteString(body)
	return sb.String(), nil
}

// parseExportVersionSpec splits an "env:version" spec ("prod:14", "stage:",
// "prod") into its parts. An empty version means the active version
func parseExportVersionSpec(spec string) (string, string, error) {
	env, version, _ := strings.Cut(spec, ":")
	switch env {
	case "prod", "stage":
		return env, version, nil
	}
	return "", "", fmt.Errorf("invalid version spec %q, expected env:version like prod:14 or stage:15", spec)
}

// ExportAppDiff compares two versions of an app as their export outputs,
// aligned line by line. from/to are "env:version" specs; an empty version is
// that environment's active version. The result rows have kind "same", "del"
// (left only) or "add" (right only) with 1-based line numbers (0 = no line
// on that side), plus the changed line count
func (s *Server) ExportAppDiff(ctx context.Context, mainAppPath, from, to string) (map[string]any, error) {
	fromEnv, fromVersion, err := parseExportVersionSpec(from)
	if err != nil {
		return nil, err
	}
	toEnv, toVersion, err := parseExportVersionSpec(to)
	if err != nil {
		return nil, err
	}

	left, err := s.ExportAppVersion(ctx, mainAppPath, fromEnv, fromVersion)
	if err != nil {
		return nil, fmt.Errorf("error exporting %s: %w", from, err)
	}
	right, err := s.ExportAppVersion(ctx, mainAppPath, toEnv, toVersion)
	if err != nil {
		return nil, fmt.Errorf("error exporting %s: %w", to, err)
	}

	rows, changed := diffLines(left, right)
	return map[string]any{
		"rows":    rows,
		"changed": changed,
	}, nil
}

// diffLines aligns two texts line by line using an LCS diff. Unchanged lines
// become one "same" row; lines only on the left become "del" rows and lines
// only on the right "add" rows, keeping the two sides line-aligned when
// rendered as parallel panes with spacer rows
func diffLines(left, right string) ([]map[string]any, int) {
	a := splitDiffLines(left)
	b := splitDiffLines(right)

	// Standard LCS length table; export outputs are small (tens of lines)
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	rows := make([]map[string]any, 0, max(len(a), len(b)))
	changed := 0
	addRow := func(kind string, leftLine int, leftText string, rightLine int, rightText string) {
		rows = append(rows, map[string]any{
			"kind":       kind,
			"left_line":  leftLine,
			"left_text":  leftText,
			"right_line": rightLine,
			"right_text": rightText,
		})
		if kind != "same" {
			changed++
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			addRow("same", i+1, a[i], j+1, b[j])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			addRow("del", i+1, a[i], 0, "")
			i++
		default:
			addRow("add", 0, "", j+1, b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		addRow("del", i+1, a[i], 0, "")
	}
	for ; j < len(b); j++ {
		addRow("add", 0, "", j+1, b[j])
	}
	return rows, changed
}

func splitDiffLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// VersionFileContent returns one file's content from an app version, for the
// version files viewer. Binary content and files over 1MB return a clear
// error instead - the zip download covers those. Use the stage path for
// staging versions, matching VersionFiles
func (s *Server) VersionFileContent(ctx context.Context, mainAppPath, version, name string) (string, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return "", err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return "", err
	}
	if appEntry.IsDev {
		return "", fmt.Errorf("version commands not supported for dev app")
	}

	versionInt := appEntry.Metadata.VersionMetadata.Version
	if version != "" {
		if versionInt, err = strconv.Atoi(version); err != nil {
			return "", fmt.Errorf("invalid version %q", version)
		}
	}

	fileStore, err := metadata.NewFileStore(appEntry.Id, versionInt, s.db, tx)
	if err != nil {
		return "", err
	}
	files, err := fileStore.GetAppFiles(ctx, tx)
	if err != nil {
		return "", err
	}
	var file *types.AppFile
	for i := range files {
		if files[i].Name == name {
			file = &files[i]
			break
		}
	}
	if file == nil {
		return "", fmt.Errorf("file %s not found in version %d", name, versionInt)
	}
	if file.Size > maxVersionFileView {
		return "", fmt.Errorf("file %s is too large to preview (%d bytes); download the zip to view it", name, file.Size)
	}

	content, compressionType, err := fileStore.GetFileByShaTx(ctx, tx, file.Etag)
	if err != nil {
		return "", fmt.Errorf("error reading %s: %w", name, err)
	}
	if compressionType != "" {
		if compressionType != appfs.COMPRESSION_TYPE {
			return "", fmt.Errorf("unsupported compression type %s for %s", compressionType, name)
		}
		if content, err = io.ReadAll(brotli.NewReader(bytes.NewReader(content))); err != nil {
			return "", fmt.Errorf("error decompressing %s: %w", name, err)
		}
	}
	if bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		return "", fmt.Errorf("%s is a binary file; download the zip to view it", name)
	}
	return string(content), nil
}
