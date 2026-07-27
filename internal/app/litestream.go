// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/openrundev/openrun/internal/bindings"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

// litestreamBindingEnv returns the replica environment name for this app:
// staged and prod apps replicate to separate locations (they have separate
// volumes and accounts).
func litestreamBindingEnv(appId types.AppId) string {
	if strings.HasPrefix(string(appId), types.ID_PREFIX_APP_PROD) {
		return "prod"
	}
	return "staged"
}

// litestreamDB is one replicated sqlite binding on the app.
type litestreamDB struct {
	binding    *types.Binding
	config     types.LitestreamConfig
	configName string
	// containerConfig is config with a localhost endpoint rewritten to the
	// hostname containers use to reach the host (host.docker.internal); used
	// for the rendered sidecar config and restore URLs, while server-side
	// replica listings keep the original endpoint
	containerConfig types.LitestreamConfig
	targetDir       string // the binding's volume mount dir
	pattern         string // replication file pattern within targetDir
	replicaPrefix   string // key prefix for this binding's databases
}

// litestreamDBs collects the app's sqlite binding when it has litestream
// enabled on its service (an app has at most one sqlite binding). A binding
// whose service references an undefined config, or a file-type config
// (host-local, unreachable from containers), is skipped with a warning: the
// app keeps serving, replication status reports it as misconfigured.
func (h *ContainerHandler) litestreamDBs() []litestreamDB {
	if h.app.IsDev {
		// dev apps run from local source with their own lifecycle; litestream
		// replication applies to staged/prod deployments
		return nil
	}
	if strings.HasPrefix(string(h.app.Id), types.ID_PREFIX_APP_PREVIEW) {
		// preview creation rejects sqlite bindings; backstop here so a preview
		// can never replicate into the staged replica location
		return nil
	}
	var ret []litestreamDB
	env := litestreamBindingEnv(h.app.Id)
	useProdAccount := env == "prod"
	for _, binding := range h.bindings {
		if binding.ServiceType != bindings.SqliteServiceType {
			continue
		}
		serviceConfig := sqliteBindingServiceConfig(binding, useProdAccount)
		configName := serviceConfig[bindings.SqliteConfigLitestream]
		if configName == "" {
			continue
		}
		lsConfig, ok := h.serverConfig.Litestream[configName]
		if !ok {
			h.Warn().Msgf("sqlite binding %s references litestream config %q which is not defined in the "+
				"server config; skipping replication for app %s", binding.Path, configName, h.app.Id)
			continue
		}
		if lsConfig.Type == system.LitestreamReplicaTypeFile {
			h.Warn().Msgf("sqlite binding %s uses litestream config %q with the file replica type, which is "+
				"not supported for app bindings; skipping replication for app %s", binding.Path, configName, h.app.Id)
			continue
		}
		containerConfig := lsConfig
		if lsConfig.ContainerEndpoint != "" {
			containerConfig.Endpoint = lsConfig.ContainerEndpoint
		} else {
			containerConfig.Endpoint = container.RewriteLocalhostEndpoint(lsConfig.Endpoint,
				h.serverConfig.System.ContainerCommand)
		}
		bindingConfig := binding.StagedMetadata.Config
		if useProdAccount {
			bindingConfig = binding.Metadata.Config
		}
		pattern, err := bindings.SqliteBindingPattern(bindingConfig)
		if err != nil {
			// The pattern is validated at binding create; a bad stored value
			// falls back to the default instead of dropping replication
			h.Warn().Err(err).Msgf("sqlite binding %s has an invalid replication pattern, using %q for app %s",
				binding.Path, bindings.SqliteDefaultPattern, h.app.Id)
			pattern = bindings.SqliteDefaultPattern
		}
		ret = append(ret, litestreamDB{
			binding:         binding,
			config:          lsConfig,
			configName:      configName,
			containerConfig: containerConfig,
			targetDir:       sqliteBindingAccountDir(binding, useProdAccount),
			pattern:         pattern,
			replicaPrefix: system.LitestreamBindingPrefix(lsConfig,
				serviceConfig[bindings.SqliteConfigPathPrefix], binding.Id, env),
		})
	}
	return ret
}

// renderLitestreamConfig renders the sidecar's litestream.yml for the app's
// replicated bindings. Credentials are never in the file: litestream reads
// LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY from the
// environment. Every file matching the binding's pattern (default *.db,
// "pattern" binding config key) under each binding's directory is discovered
// and replicated via the directory watcher; litestream's local bookkeeping
// goes to a dot-directory that the default pattern ignores. logLevel sets the
// sidecar's own log level (logging.litestream_log_level, defaulting to the
// server's logging.level).
func renderLitestreamConfig(dbs []litestreamDB, logLevel string) string {
	var b strings.Builder
	if logLevel != "" {
		fmt.Fprintf(&b, "logging:\n  level: %s\n", strings.ToLower(logLevel))
	}
	first := dbs[0].config
	if first.SnapshotInterval != "" || first.Retention != "" {
		b.WriteString("snapshot:\n")
		if first.SnapshotInterval != "" {
			fmt.Fprintf(&b, "  interval: %s\n", first.SnapshotInterval)
		}
		if first.Retention != "" {
			fmt.Fprintf(&b, "  retention: %s\n", first.Retention)
		}
	}
	b.WriteString("dbs:\n")
	for _, db := range dbs {
		fmt.Fprintf(&b, "  - dir: %s\n", db.targetDir)
		fmt.Fprintf(&b, "    pattern: %q\n", db.pattern)
		b.WriteString("    watch: true\n")
		b.WriteString("    recursive: true\n")
		fmt.Fprintf(&b, "    meta-dir: %s/.litestream\n", db.targetDir)
		if db.config.CheckpointInterval != "" {
			fmt.Fprintf(&b, "    checkpoint-interval: %s\n", db.config.CheckpointInterval)
		}
		if db.config.MinCheckpointPageCount > 0 {
			fmt.Fprintf(&b, "    min-checkpoint-page-count: %d\n", db.config.MinCheckpointPageCount)
		}
		if db.config.TruncatePageN != nil {
			fmt.Fprintf(&b, "    truncate-page-n: %d\n", *db.config.TruncatePageN)
		}
		b.WriteString("    replica:\n")
		b.WriteString("      type: s3\n")
		fmt.Fprintf(&b, "      bucket: %s\n", db.config.Bucket)
		fmt.Fprintf(&b, "      path: %s\n", db.replicaPrefix)
		if db.config.Region != "" {
			fmt.Fprintf(&b, "      region: %s\n", db.config.Region)
		}
		if db.containerConfig.Endpoint != "" {
			fmt.Fprintf(&b, "      endpoint: %s\n", db.containerConfig.Endpoint)
		}
		if db.config.ForcePathStyle {
			b.WriteString("      force-path-style: true\n")
		}
		if db.config.SyncInterval != "" {
			fmt.Fprintf(&b, "      sync-interval: %s\n", db.config.SyncInterval)
		}
		if db.config.StorageClass != "" {
			fmt.Fprintf(&b, "      storage-class: %s\n", db.config.StorageClass)
		}
		if db.config.SseKmsKeyId != "" {
			fmt.Fprintf(&b, "      sse-kms-key-id: %s\n", db.config.SseKmsKeyId)
		}
	}
	return b.String()
}

// litestreamSpec builds the app's replication companion spec (config, image,
// credentials, shared volumes), without the restore list: restores need a
// replica listing, which buildLitestreamRestores adds only on the deploy
// paths that start containers. Returns nil when no binding has litestream
// enabled. Deterministic and I/O free, so getAppHash can fold ConfigHash into
// the app version hash (config changes roll the app).
func (h *ContainerHandler) litestreamSpec() *container.LitestreamAppSpec {
	dbs := h.litestreamDBs()
	if len(dbs) == 0 {
		return nil
	}

	image := dbs[0].config.SidecarImage
	if image == "" {
		image = container.DefaultLitestreamImage
	}
	env := map[string]string{}
	if dbs[0].config.AccessKeyId != "" {
		env["LITESTREAM_ACCESS_KEY_ID"] = dbs[0].config.AccessKeyId
	}
	if dbs[0].config.SecretAccessKey != "" {
		env["LITESTREAM_SECRET_ACCESS_KEY"] = dbs[0].config.SecretAccessKey
	}

	mounts := make([]container.LitestreamMount, 0, len(dbs))
	for _, db := range dbs {
		mounts = append(mounts, container.LitestreamMount{
			VolumeName: container.GenVolumeName(h.app.Id, sqliteVolumeKey(db.binding.Id)),
			TargetDir:  db.targetDir,
		})
	}

	configYAML := renderLitestreamConfig(dbs, h.serverConfig.Log.EffectiveLitestreamLevel())
	configHash, err := getValuesHash(configYAML, image, env["LITESTREAM_ACCESS_KEY_ID"], env["LITESTREAM_SECRET_ACCESS_KEY"])
	if err != nil {
		// getValuesHash only fails on hash writer errors, which do not happen
		configHash = ""
	}

	return &container.LitestreamAppSpec{
		Image:      image,
		ConfigYAML: configYAML,
		ConfigHash: configHash,
		Env:        env,
		Mounts:     mounts,
	}
}

// buildLitestreamRestores enumerates each binding's replica and fills in the
// per-database restore list (litestream restore is per-file). An empty
// replica (first deploy of a binding) yields no restores. A listing failure
// fails the deploy: starting with an empty database while a replica exists
// would fork the data's history.
func (h *ContainerHandler) buildLitestreamRestores(ctx context.Context, spec *container.LitestreamAppSpec) error {
	dbs := h.litestreamDBs()
	for _, db := range dbs {
		replicaDBs, err := system.ListLitestreamReplicaDBs(ctx, db.config, db.replicaPrefix)
		if err != nil {
			return fmt.Errorf("error listing litestream replica for binding %s (config %s): %w",
				db.binding.Path, db.configName, err)
		}
		for _, replicaDB := range replicaDBs {
			// The restore runs inside a container: use the container-reachable
			// endpoint in the URL
			replicaURL, err := system.LitestreamReplicaURL(db.containerConfig, path.Join(db.replicaPrefix, replicaDB.SubPath))
			if err != nil {
				return err
			}
			spec.Restores = append(spec.Restores, container.LitestreamRestore{
				ReplicaURL: replicaURL,
				OutputPath: path.Join(db.targetDir, replicaDB.SubPath),
			})
		}
	}
	if len(spec.Restores) > 0 {
		h.Info().Msgf("Litestream restore candidates for app %s: %d database(s)", h.app.Id, len(spec.Restores))
	}
	return nil
}

// ensureLitestream runs the docker/podman litestream steps: the per-database
// restore (withRestore, on fresh deploys after volumes exist) and the
// replication sidecar. No-op for kubernetes (handled in the pod spec) and for
// apps without litestream-enabled sqlite bindings.
func (h *ContainerHandler) ensureLitestream(ctx context.Context, withRestore bool) error {
	if h.isKubernetes {
		return nil
	}
	spec := h.litestreamSpec()
	if spec == nil {
		return nil
	}
	runner, ok := container.AsLitestreamRunner(h.manager)
	if !ok {
		return fmt.Errorf("container manager does not support litestream replication")
	}
	if withRestore {
		if err := h.buildLitestreamRestores(ctx, spec); err != nil {
			return err
		}
		if err := runner.RunLitestreamRestores(ctx, h.app.Id, spec); err != nil {
			return err
		}
		if len(spec.Restores) > 0 {
			// Restored files were written as root by the litestream image;
			// make them writable for the app image's (possibly non-root) user
			if initializer, ok := container.AsVolumeInitializer(h.manager); ok {
				for _, mount := range spec.Mounts {
					if err := initializer.InitVolumePermissions(ctx, container.ImageName(spec.Image), mount.VolumeName, mount.TargetDir); err != nil {
						return err
					}
				}
			}
		}
	}
	return runner.EnsureLitestreamSidecar(ctx, h.app.AppEntry, spec)
}

// sqlitePermsImage returns the image used for the sqlite volume permissions
// chmod. With replication enabled the litestream image is used (always has a
// chmod binary and is pulled anyway), so distroless app images work; without
// replication the app's own image is the only one guaranteed present.
func (h *ContainerHandler) sqlitePermsImage() container.ImageName {
	if spec := h.litestreamSpec(); spec != nil {
		return container.ImageName(spec.Image)
	}
	return h.GenImageName
}

// stopLitestreamSidecar gently stops the app's replication sidecar on idle
// shutdown: SIGTERM triggers litestream's final shutdown sync, so the last
// pre-shutdown writes are replicated before the sidecar exits. The sidecar is
// restarted by ensureLitestream when the app is started again. No-op on
// kubernetes (the sidecar lives in the app pod) and for apps without
// litestream-enabled sqlite bindings.
func (h *ContainerHandler) stopLitestreamSidecar(ctx context.Context) error {
	if h.isKubernetes || len(h.litestreamDBs()) == 0 {
		return nil
	}
	runner, ok := container.AsLitestreamRunner(h.manager)
	if !ok {
		return nil
	}
	return runner.StopLitestreamSidecar(ctx, h.app.Id)
}

// LitestreamSidecarName returns the app's litestream sidecar container name
// when replication is enabled (docker/podman only), for active-container
// tracking so the stale container cleanup loop does not stop it.
func (h *ContainerHandler) LitestreamSidecarName() (container.ContainerName, bool) {
	if h.isKubernetes || len(h.litestreamDBs()) == 0 {
		return "", false
	}
	return container.LitestreamSidecarName(h.app.Id), true
}
