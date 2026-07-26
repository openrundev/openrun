// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/openrundev/openrun/internal/types"
)

// LitestreamReplicaDB describes one database found in a litestream replica
// location: its path relative to the listed prefix (e.g. "data.db" or
// "tenants/acme.db") plus activity derived from the LTX object listing.
type LitestreamReplicaDB struct {
	SubPath     string    `json:"sub_path"`
	MaxTXID     uint64    `json:"max_txid"`
	LastUpdated time.Time `json:"last_updated"`
	Size        int64     `json:"size"`
}

// LitestreamEffectivePrefix returns the replica key prefix for a sub path,
// applying the config's path_prefix (or the per-service override when set).
func LitestreamEffectivePrefix(config types.LitestreamConfig, pathPrefixOverride string, subPath string) string {
	prefix := config.PathPrefix
	if pathPrefixOverride != "" {
		prefix = pathPrefixOverride
	}
	return path.Join(prefix, subPath)
}

// LitestreamBindingPrefix is the replica key prefix for one sqlite binding:
// keyed by the stable binding id (not the path, which can be deleted and
// recreated) and the environment (prod/staged). Data follows the binding:
// re-attaching a base binding to a new app restores into the new app's fresh
// volume.
func LitestreamBindingPrefix(config types.LitestreamConfig, pathPrefixOverride, bindingId, env string) string {
	return LitestreamEffectivePrefix(config, pathPrefixOverride, path.Join("bindings", bindingId, env))
}

// LitestreamReplicaURL returns the replica URL for one database, in the form
// the litestream CLI accepts for restore (s3://bucket/path?endpoint=...).
// Credentials are never part of the URL; they are passed via the
// LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY env variables.
func LitestreamReplicaURL(config types.LitestreamConfig, replicaPath string) (string, error) {
	switch config.Type {
	case "", "s3":
		u := url.URL{Scheme: "s3", Host: config.Bucket, Path: "/" + strings.TrimPrefix(replicaPath, "/")}
		query := url.Values{}
		if config.Endpoint != "" {
			query.Set("endpoint", config.Endpoint)
		}
		if config.Region != "" {
			query.Set("region", config.Region)
		}
		if config.ForcePathStyle {
			query.Set("forcePathStyle", "true")
		}
		u.RawQuery = query.Encode()
		return u.String(), nil
	case LitestreamReplicaTypeFile:
		return "file://" + filepath.ToSlash(filepath.Join(config.Path, filepath.FromSlash(replicaPath))), nil
	default:
		return "", fmt.Errorf("unknown litestream replica type %q", config.Type)
	}
}

// newLitestreamS3Client builds an S3 client for replica listing, matching the
// connection settings litestream itself uses (static credentials, custom
// endpoint, path-style addressing).
func newLitestreamS3Client(ctx context.Context, config types.LitestreamConfig) (*awss3.Client, error) {
	region := config.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if config.AccessKeyId != "" || config.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(config.AccessKeyId, config.SecretAccessKey, "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("error loading s3 config: %w", err)
	}
	return awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		if config.Endpoint != "" {
			o.BaseEndpoint = aws.String(config.Endpoint)
		}
		o.UsePathStyle = config.ForcePathStyle
	}), nil
}

// ListLitestreamReplicaDBs lists the databases replicated under replicaPrefix
// (a full key prefix inside the bucket / file root). A database is recognized
// by its "<subpath>/ltx/<level>/<min>-<max>.ltx" objects; the returned info
// aggregates the latest activity per database.
func ListLitestreamReplicaDBs(ctx context.Context, config types.LitestreamConfig, replicaPrefix string) ([]LitestreamReplicaDB, error) {
	switch config.Type {
	case "", "s3":
		return listS3ReplicaDBs(ctx, config, replicaPrefix)
	case LitestreamReplicaTypeFile:
		return listFileReplicaDBs(config, replicaPrefix)
	default:
		return nil, fmt.Errorf("unknown litestream replica type %q", config.Type)
	}
}

func listS3ReplicaDBs(ctx context.Context, config types.LitestreamConfig, replicaPrefix string) ([]LitestreamReplicaDB, error) {
	client, err := newLitestreamS3Client(ctx, config)
	if err != nil {
		return nil, err
	}

	prefix := strings.TrimPrefix(replicaPrefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	found := map[string]*LitestreamReplicaDB{}
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket: aws.String(config.Bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error listing litestream replica objects at %s: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			var lastModified time.Time
			if obj.LastModified != nil {
				lastModified = *obj.LastModified
			}
			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}
			recordReplicaObject(found, strings.TrimPrefix(key, prefix), lastModified, size)
		}
	}
	return collectReplicaDBs(found), nil
}

func listFileReplicaDBs(config types.LitestreamConfig, replicaPrefix string) ([]LitestreamReplicaDB, error) {
	root := filepath.Join(config.Path, filepath.FromSlash(replicaPrefix))
	found := map[string]*LitestreamReplicaDB{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // best effort listing
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr
		}
		recordReplicaObject(found, filepath.ToSlash(rel), info.ModTime(), info.Size())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error listing litestream file replica at %s: %w", root, err)
	}
	return collectReplicaDBs(found), nil
}

// recordReplicaObject folds one replica object (key relative to the listed
// prefix) into the per-database aggregation. Remote LTX keys observed from
// litestream 0.5 look like "<db-subpath>/<level>/<mintxid>-<maxtxid>.ltx"
// where level is a zero-padded 4-digit compaction level directory (0000 =
// L0, the highest level holds snapshots). An "ltx" path segment between the
// database and the level directory ("<db-subpath>/ltx/<level>/...", the
// local bookkeeping layout) is also accepted in case a litestream version
// mirrors it remotely.
func recordReplicaObject(found map[string]*LitestreamReplicaDB, relKey string, lastModified time.Time, size int64) {
	dir, file := path.Split(relKey)
	dir = strings.TrimSuffix(dir, "/")
	levelDir := path.Base(dir)
	subPath := path.Dir(dir)
	if path.Base(subPath) == "ltx" {
		subPath = path.Dir(subPath)
	}
	if subPath == "." || subPath == "/" || subPath == "" || !isLTXLevelDir(levelDir) {
		return
	}
	txid, ok := maxTXIDFromLTXName(file)
	if !ok {
		return
	}

	info := found[subPath]
	if info == nil {
		info = &LitestreamReplicaDB{SubPath: subPath}
		found[subPath] = info
	}
	info.Size += size
	if lastModified.After(info.LastUpdated) {
		info.LastUpdated = lastModified
	}
	if txid > info.MaxTXID {
		info.MaxTXID = txid
	}
}

// isLTXLevelDir reports whether name is a compaction level directory: all
// digits, zero-padded to 4 in the observed 0.5 layout ("0000") but plain
// numbers ("0") are accepted too.
func isLTXLevelDir(name string) bool {
	if len(name) == 0 || len(name) > 4 {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// maxTXIDFromLTXName parses the max TXID from an LTX object file name of the
// form "<mintxid>-<maxtxid>.ltx" (TXIDs are zero-padded hex).
func maxTXIDFromLTXName(name string) (uint64, bool) {
	base, ok := strings.CutSuffix(name, ".ltx")
	if !ok {
		return 0, false
	}
	_, maxPart, ok := strings.Cut(base, "-")
	if !ok {
		return 0, false
	}
	txid, err := strconv.ParseUint(maxPart, 16, 64)
	if err != nil {
		return 0, false
	}
	return txid, true
}

func collectReplicaDBs(found map[string]*LitestreamReplicaDB) []LitestreamReplicaDB {
	ret := make([]LitestreamReplicaDB, 0, len(found))
	for _, info := range found {
		ret = append(ret, *info)
	}
	slices.SortFunc(ret, func(a, b LitestreamReplicaDB) int {
		return strings.Compare(a.SubPath, b.SubPath)
	})
	return ret
}
