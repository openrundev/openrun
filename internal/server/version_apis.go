// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

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
	defer tx.Rollback()

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
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
	defer tx.Rollback()

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
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

func (s *Server) VersionSwitch(ctx context.Context, mainAppPath string, dryRun bool, version string) (*types.AppVersionSwitchResponse, error) {
	appPathDomain, err := parseAppPath(mainAppPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
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

	s.apps.ClearAppsAudit(ctx, []types.AppPathDomain{appPathDomain}, "version-switch")
	return ret, nil
}
