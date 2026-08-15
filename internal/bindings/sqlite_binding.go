// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/types"
	"k8s.io/apimachinery/pkg/api/resource"
)

// SqliteServiceType is the service type name for the sqlite binding. Unlike
// postgres/mysql there is no external endpoint: a binding provides the app a
// persistent named volume (docker) or PVC (kubernetes) holding sqlite database
// files, with optional litestream replication configured on the service.
const SqliteServiceType = "sqlite"

const (
	// SqliteDefaultDir is the default in-container mount directory for the
	// app's sqlite binding (an app has at most one sqlite binding),
	// overridable per binding with the "path" binding config key.
	SqliteDefaultDir = "/data"
	// SqliteDBFile is the default database file inside the binding directory.
	// With litestream enabled every file matching the replication pattern
	// (default *.db, overridable with the "pattern" binding config key) is
	// replicated; this is just the conventional main database name.
	SqliteDBFile = "data.db"
	// SqliteDefaultPattern is the default litestream replication file pattern
	// for the binding directory.
	SqliteDefaultPattern = "*.db"
)

// Sqlite service config keys
const (
	SqliteConfigLitestream = "litestream_config"
	SqliteConfigPathPrefix = "path_prefix"
	SqliteConfigVolumeSize = "volume_size"
)

// SqliteBindingConfigPath is the binding config key overriding the mount
// directory, e.g. binding create --config path=/mydata sqlite /apps/b1 or an
// auto binding source "sqlite;path=/mydata".
const SqliteBindingConfigPath = "path"

// SqliteBindingConfigPattern is the binding config key overriding the
// litestream replication file pattern (default SqliteDefaultPattern), e.g.
// binding create --config pattern=*.sqlite3 sqlite /apps/b1.
const SqliteBindingConfigPattern = "pattern"

type SqliteServiceBinding struct {
	*types.Logger
	serviceConfig map[string]string
}

func init() {
	RegisterServiceBinding(SqliteServiceType, NewSqliteServiceBinding)
}

var _ ServiceBinding = (*SqliteServiceBinding)(nil)

func NewSqliteServiceBinding() ServiceBinding {
	return &SqliteServiceBinding{}
}

func (b *SqliteServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "db_path", "dir"}, []string{}, nil
}

func (b *SqliteServiceBinding) InitializeService(ctx context.Context, logger *types.Logger, serviceConfig map[string]string, runtime ServiceBindingRuntime) error {
	b.Logger = logger
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), nil,
		[]string{SqliteConfigLitestream, SqliteConfigPathPrefix, SqliteConfigVolumeSize}); err != nil {
		return err
	}

	if configName := serviceConfig[SqliteConfigLitestream]; configName != "" {
		if !slices.Contains(runtime.LitestreamConfigNames, configName) {
			return fmt.Errorf("litestream config %q is not defined in the server config; "+
				"add a [litestream.%s] entry or use one of: %v", configName, configName, runtime.LitestreamConfigNames)
		}
		if slices.Contains(runtime.LitestreamFileConfigNames, configName) {
			return fmt.Errorf("litestream config %q uses the file replica type, which is host-local and "+
				"not usable from app containers; use an s3 config for sqlite services", configName)
		}
	}

	if volumeSize := serviceConfig[SqliteConfigVolumeSize]; volumeSize != "" {
		if _, err := resource.ParseQuantity(volumeSize); err != nil {
			return fmt.Errorf("invalid volume_size %q: %w", volumeSize, err)
		}
	}

	b.serviceConfig = serviceConfig
	return nil
}

func (b *SqliteServiceBinding) CloseService(ctx context.Context) error {
	return nil
}

// SqliteBindingDir resolves the in-container data directory for a sqlite
// binding from its binding config: the "path" key when set (validated as an
// absolute clean path), SqliteDefaultDir otherwise.
func SqliteBindingDir(bindingConfig map[string]string) (string, error) {
	dir := bindingConfig[SqliteBindingConfigPath]
	if dir == "" {
		return SqliteDefaultDir, nil
	}
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" || !path.IsAbs(dir) || path.Clean(dir) != dir {
		return "", fmt.Errorf("invalid sqlite binding path %q: must be an absolute clean path like /mydata",
			bindingConfig[SqliteBindingConfigPath])
	}
	return dir, nil
}

// SqliteBindingPattern resolves the litestream replication file pattern for a
// sqlite binding from its binding config: the "pattern" key when set
// (validated as a file glob relative to the binding directory),
// SqliteDefaultPattern otherwise.
func SqliteBindingPattern(bindingConfig map[string]string) (string, error) {
	pattern := bindingConfig[SqliteBindingConfigPattern]
	if pattern == "" {
		return SqliteDefaultPattern, nil
	}
	if strings.HasPrefix(pattern, "/") {
		return "", fmt.Errorf("invalid sqlite binding pattern %q: must be relative to the binding directory", pattern)
	}
	if _, err := path.Match(pattern, "probe"); err != nil {
		return "", fmt.Errorf("invalid sqlite binding pattern %q: %w", pattern, err)
	}
	return pattern, nil
}

// SqliteAccountForDir returns the account map for a sqlite binding mounted at
// dir: the directory the volume is mounted at, the default database path in
// it and the file url. The values are deterministic; the volume itself is
// created lazily by the container layer at app start.
func SqliteAccountForDir(dir string) map[string]string {
	dbPath := dir + "/" + SqliteDBFile
	return map[string]string{
		"url":     "file:" + dbPath,
		"db_path": dbPath,
		"dir":     dir,
	}
}

func (b *SqliteServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata types.BindingMetadata,
	derivedFromMetadata *types.BindingMetadata, isStaging bool) (map[string]string, []Artifact, error) {
	if derivedFromMetadata != nil {
		return nil, nil, fmt.Errorf("sqlite bindings do not support derived bindings; bind the base binding directly")
	}
	dir, err := SqliteBindingDir(bindingMetadata.Config)
	if err != nil {
		return nil, nil, err
	}
	// Validate the replication pattern at create time; it is read from the
	// binding config by the container layer when rendering the sidecar config
	if _, err := SqliteBindingPattern(bindingMetadata.Config); err != nil {
		return nil, nil, err
	}
	// No external side effects: the account is computed, the backing volume is
	// created by the container layer when an app using the binding starts.
	return SqliteAccountForDir(dir), nil, nil
}

func (b *SqliteServiceBinding) DeleteArtifact(ctx context.Context, artifact Artifact) error {
	return fmt.Errorf("sqlite bindings create no artifacts, cannot delete %s %s", artifact.Type, artifact.Name)
}

func (b *SqliteServiceBinding) ApplyGrants(ctx context.Context, account map[string]string,
	bindingMetadata, derivedFromMetadata types.BindingMetadata, reapplyAll bool) (GrantApplyResult, error) {
	return GrantApplyResult{}, fmt.Errorf("sqlite bindings do not support grants")
}

func (b *SqliteServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata types.BindingMetadata, revokes, regrants []types.BindingGrant) error {
	return fmt.Errorf("sqlite bindings do not support grants")
}

func (b *SqliteServiceBinding) RunCommand(ctx context.Context, bindingMetadata types.BindingMetadata, command string) (map[string]any, error) {
	return nil, fmt.Errorf("run command is not supported for sqlite bindings: the database file is only reachable inside the app container")
}

// CheckHealth is a no-op success: sqlite has no external endpoint to probe.
// The backing volume is owned by the container layer and only exists while an
// app uses the binding.
func (b *SqliteServiceBinding) CheckHealth(ctx context.Context) error {
	return nil
}

// CheckBindingHealth validates the binding's computed configuration (mount
// path and replication pattern); there is no account or endpoint to connect
// to.
func (b *SqliteServiceBinding) CheckBindingHealth(ctx context.Context, bindingMetadata types.BindingMetadata) error {
	if _, err := SqliteBindingDir(bindingMetadata.Config); err != nil {
		return err
	}
	if _, err := SqliteBindingPattern(bindingMetadata.Config); err != nil {
		return err
	}
	return nil
}
