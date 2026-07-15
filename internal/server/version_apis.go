// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

func (s *Server) VersionList(ctx context.Context, mainAppPath string) (*types.AppVersionListResponse, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return nil, err
	}
	if appEntry.IsDev {
		return nil, fmt.Errorf("version commands not supported for dev app")
	}

	fileStore, err := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
	if err != nil {
		return nil, err
	}
	versions, err := fileStore.GetAppVersions(ctx, tx)
	if err != nil {
		return nil, err
	}

	for i, v := range versions {
		if v.Version == appEntry.Metadata.VersionMetadata.Version {
			versions[i].Active = true
		}
	}

	return &types.AppVersionListResponse{Versions: versions}, nil
}

func (s *Server) VersionFiles(ctx context.Context, mainAppPath, version string) (*types.AppVersionFilesResponse, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return nil, err
	}

	if appEntry.IsDev {
		return nil, fmt.Errorf("version commands not supported for dev app")
	}
	var versionInt int

	if version == "" {
		versionInt = appEntry.Metadata.VersionMetadata.Version
	} else {
		versionInt, err = strconv.Atoi(version)
		if err != nil {
			return nil, err
		}
	}

	fileStore, err := metadata.NewFileStore(appEntry.Id, versionInt, s.db, tx)
	if err != nil {
		return nil, err
	}
	files, err := fileStore.GetAppFiles(ctx, tx)
	if err != nil {
		return nil, err
	}

	return &types.AppVersionFilesResponse{Files: files}, nil
}

// VersionFilesZip returns a producer that writes one app version's files as
// a zip, plus the download file name. Authorization (app:read), the version
// resolution and the file listing happen eagerly; the producer runs later,
// at response-write time, streaming the zip to the client (chunked) with
// backpressure - the archive is never fully held in memory or staged to
// disk. Use the stage path for staging versions
func (s *Server) VersionFilesZip(ctx context.Context, mainAppPath, version string) (func(w io.Writer) error, string, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, "", err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, "", err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionRead, appEntry); err != nil {
		return nil, "", err
	}

	if appEntry.IsDev {
		return nil, "", fmt.Errorf("version commands not supported for dev app")
	}
	versionInt := appEntry.Metadata.VersionMetadata.Version
	if version != "" {
		if versionInt, err = strconv.Atoi(version); err != nil {
			return nil, "", err
		}
	}

	fileStore, err := metadata.NewFileStore(appEntry.Id, versionInt, s.db, tx)
	if err != nil {
		return nil, "", err
	}
	files, err := fileStore.GetAppFiles(ctx, tx)
	if err != nil {
		return nil, "", err
	}

	appId := appEntry.Id
	producer := func(w io.Writer) error {
		// The plugin-call transaction above is closed by the time the body is
		// produced: read each file in its own short auto-commit transaction
		// (GetFileBySha) so a stalled client never pins a db transaction.
		// Version files are content-addressed and immutable, so the reads stay
		// consistent with the eager listing
		streamStore, err := metadata.NewFileStore(appId, versionInt, s.db, types.Transaction{})
		if err != nil {
			return err
		}
		writer := zip.NewWriter(w)
		for _, file := range files {
			// Etag is the content sha in the shared file store; stored files
			// may be brotli compressed (same handling as DbFs.ReadFile)
			content, compressionType, err := streamStore.GetFileBySha(file.Etag)
			if err != nil {
				return fmt.Errorf("error reading %s: %w", file.Name, err)
			}
			if compressionType != "" {
				if compressionType != appfs.COMPRESSION_TYPE {
					return fmt.Errorf("unsupported compression type %s for %s", compressionType, file.Name)
				}
				if content, err = io.ReadAll(brotli.NewReader(bytes.NewReader(content))); err != nil {
					return fmt.Errorf("error decompressing %s: %w", file.Name, err)
				}
			}
			dest, err := writer.Create(file.Name)
			if err != nil {
				return err
			}
			if _, err := dest.Write(content); err != nil {
				return err
			}
		}
		return writer.Close()
	}

	name := zipNameSanitizer.ReplaceAllString(strings.Trim(appPathDomain.String(), "/"), "_")
	if name == "" {
		name = "app"
	}
	return producer, fmt.Sprintf("%s-v%d.zip", name, versionInt), nil
}

func (s *Server) VersionSwitch(ctx context.Context, mainAppPath string, dryRun bool, version string) (*types.AppVersionSwitchResponse, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppEntryTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppPermEntry(ctx, types.PermissionUpdate, appEntry); err != nil {
		return nil, err
	}

	if appEntry.IsDev {
		return nil, fmt.Errorf("version commands not supported for dev app")
	}
	var versionInt int
	fileStore, err := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, tx)
	if err != nil {
		return nil, err
	}

	versionLower := strings.ToLower(version)
	switch versionLower {
	case "revert":
		versionInt = appEntry.Metadata.VersionMetadata.PreviousVersion

		if versionInt == 0 {
			return nil, fmt.Errorf("no version found to revert to")
		}
	case "next":
		versions, err := fileStore.GetAppVersions(ctx, tx)
		if err != nil {
			return nil, err
		}
		nextVersion := math.MaxInt64
		for _, v := range versions {
			if v.Version < nextVersion && v.Version > appEntry.Metadata.VersionMetadata.Version {
				// Find the next valid version which is present
				nextVersion = v.Version
			}
		}

		if nextVersion == math.MaxInt64 {
			return nil, fmt.Errorf("no next version found")
		}
		versionInt = nextVersion
	case "previous":
		versions, err := fileStore.GetAppVersions(ctx, tx)
		if err != nil {
			return nil, err
		}
		prevVersion := 0
		for _, v := range versions {
			if v.Version > prevVersion && v.Version < appEntry.Metadata.VersionMetadata.Version {
				// Find the previous valid version which is present
				prevVersion = v.Version
			}
		}

		if prevVersion == 0 {
			return nil, fmt.Errorf("no previous version found")
		}
		versionInt = prevVersion
	default:
		versionInt, err = strconv.Atoi(version)
		if err != nil {
			return nil, err
		}
	}

	newVersion, err := fileStore.GetAppVersion(ctx, tx, versionInt)
	if err != nil {
		return nil, fmt.Errorf("error getting version %d: %w", versionInt, err)
	}

	fromVersion := appEntry.Metadata.VersionMetadata.Version
	appEntry.Metadata = *newVersion.Metadata
	appEntry.Metadata.VersionMetadata.PreviousVersion = fromVersion
	if err = s.db.UpdateAppMetadata(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	ret := &types.AppVersionSwitchResponse{
		DryRun:      dryRun,
		FromVersion: fromVersion,
		ToVersion:   versionInt,
	}
	if dryRun {
		// Don't commit the transaction if its a dry run
		return ret, nil
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	err = s.apps.ClearAppsAudit(ctx, []types.AppPathDomain{appPathDomain}, "version_switch")
	if err != nil {
		return nil, err
	}
	return ret, nil
}
