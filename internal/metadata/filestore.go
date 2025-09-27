// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

const (
	COMPRESSION_THRESHOLD = 0 // files above this size are stored compressed. The chi Compress middleware does not have a threshold,
	// so the threshold is set to zero here
	BROTLI_COMPRESSION_LEVEL = 9 // https://paulcalvano.com/2018-07-25-brotli-compression-how-much-will-it-reduce-your-content/ seems
	// to indicate that level 9 is a good default.

	defaultUser = "admin"
)

type FileStore struct {
	appId    types.AppId
	version  int
	metadata *Metadata
	db       *sql.DB
	initTx   types.Transaction // This is the transaction for the initial setup of the app, before it is committed to the database.
	// After app is committed to database, this is not used, auto-commit transactions are used for reads
	fileCache *FileCache
}

func NewFileStore(appId types.AppId, version int, metadata *Metadata, tx types.Transaction) (*FileStore, error) {
	var fileCache *FileCache
	var err error
	if metadata.dbType != system.DB_TYPE_SQLITE {
		fileCache, err = InitFileCache(metadata.Logger, metadata.config)
		if err != nil {
			return nil, fmt.Errorf("error initializing file cache: %w", err)
		}
	}
	return &FileStore{appId: appId, version: version, metadata: metadata, db: metadata.db, initTx: tx, fileCache: fileCache}, nil
}

func (f *FileStore) IncrementAppVersion(ctx context.Context, tx types.Transaction, metadata *types.AppMetadata) error {
	currentVersion := metadata.VersionMetadata.Version
	nextVersion, err := f.GetHighestVersion(ctx, tx, f.appId)
	if err != nil {
		return fmt.Errorf("error getting highest version: %w", err)
	}
	nextVersion++

	metadata.VersionMetadata.PreviousVersion = currentVersion
	metadata.VersionMetadata.Version = nextVersion
	metadataJson, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	if _, err := tx.ExecContext(ctx, system.RebindQuery(f.metadata.dbType, `insert into app_versions (appid, previous_version, version, metadata, user_id, create_time) values (?, ?, ?, ?, ?, `+system.FuncNow(f.metadata.dbType)+")"),
		f.appId, currentVersion, nextVersion, metadataJson, defaultUser); err != nil {
		return fmt.Errorf("error inserting app version: %w", err)
	}

	if _, err := tx.ExecContext(ctx, system.RebindQuery(f.metadata.dbType, `insert into app_files (appid, version, name, sha, uncompressed_size, create_time) select appid, ?, name, sha, uncompressed_size, `+system.FuncNow(f.metadata.dbType)+" from app_files where appid = ? and version = ?"),
		nextVersion, f.appId, currentVersion); err != nil {
		return fmt.Errorf("error copying app files: %w", err)
	}

	return nil
}

func (f *FileStore) AddAppVersionDisk(ctx context.Context, tx types.Transaction, metadata types.AppMetadata, checkoutDir string) error {
	metadataJson, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	if _, err := tx.ExecContext(ctx, system.RebindQuery(f.metadata.dbType, `insert into app_versions (appid, previous_version, version, metadata, user_id, create_time) values (?, ?, ?, ?, ?, `+system.FuncNow(f.metadata.dbType)+")"),
		f.appId, metadata.VersionMetadata.PreviousVersion, metadata.VersionMetadata.Version, metadataJson, defaultUser); err != nil {
		return fmt.Errorf("error inserting app version: %w", err)
	}

	var insertFileStmt *sql.Stmt
	if insertFileStmt, err = tx.PrepareContext(ctx, system.RebindQuery(f.metadata.dbType, system.InsertIgnorePrefix(f.metadata.dbType)+" into files (sha, compression_type, content, create_time) values (?, ?, ?, "+system.FuncNow(f.metadata.dbType)+") "+system.InsertIgnoreSuffix(f.metadata.dbType))); err != nil {
		return err
	}
	defer insertFileStmt.Close() //nolint:errcheck

	var insertAppFileStmt *sql.Stmt
	if insertAppFileStmt, err = tx.PrepareContext(ctx, system.RebindQuery(f.metadata.dbType, `insert into app_files (appid, version, name, sha, uncompressed_size, create_time) values (?, ?, ?, ?, ?, `+system.FuncNow(f.metadata.dbType)+")")); err != nil {
		return err
	}
	defer insertAppFileStmt.Close() //nolint:errcheck

	if checkoutDir == types.NO_SOURCE {
		// No source code to add
		return nil
	}

	fsys := os.DirFS(checkoutDir)

	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, inErr error) error {
		if inErr != nil {
			return fmt.Errorf("file walk on %s failed for path %s: %w", checkoutDir, path, inErr)
		}
		if d.IsDir() && path == ".git" {
			// Skip .git directory completely
			return fs.SkipDir
		}

		if d.IsDir() {
			// Ignore directory paths
			return nil
		}

		// Walk the file system, read one file at a time
		file, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck

		buf, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		// Use forward slash as path separator
		path = strings.ReplaceAll(path, "\\", "/")

		var byteBuf bytes.Buffer
		hash := sha256.Sum256(buf)
		hashHex := hex.EncodeToString(hash[:])
		compressionType := ""
		storeBuf := buf
		if len(buf) > COMPRESSION_THRESHOLD {
			compressionType = appfs.COMPRESSION_TYPE
			byteBuf.Reset()
			br := brotli.NewWriterLevel(&byteBuf, BROTLI_COMPRESSION_LEVEL)

			if _, err := br.Write(buf); err != nil {
				br.Close() //nolint:errcheck
				return err
			}
			if err := br.Close(); err != nil {
				return err
			}
			storeBuf = byteBuf.Bytes()
		}

		// Compressed data is written to files table. Ignore if sha is already present
		// File contents, if same across versions and also across apps, are shared
		if _, err = insertFileStmt.ExecContext(ctx, hashHex, compressionType, storeBuf); err != nil {
			return fmt.Errorf("error inserting file: %w", err)
		}

		if _, err := insertAppFileStmt.ExecContext(ctx, f.appId, metadata.VersionMetadata.Version, path, hashHex, len(buf)); err != nil {
			return fmt.Errorf("error inserting app file: %w", err)
		}

		return nil
	})
}

func (f *FileStore) GetFileBySha(sha string) ([]byte, string, error) {
	var tx types.Transaction
	if f.initTx.IsInitialized() {
		tx = f.initTx
	} else {
		var err error
		tx, err = f.metadata.BeginTransaction(context.Background())
		if err != nil {
			return nil, "", fmt.Errorf("error starting transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck
	}

	return f.GetFileByShaTx(context.Background(), tx, sha)
}

func (f *FileStore) GetFileByShaTx(ctx context.Context, tx types.Transaction, sha string) ([]byte, string, error) {
	if f.fileCache != nil {
		content, compressionType, err := f.fileCache.GetCachedFile(ctx, sha)
		if err == nil {
			f.metadata.Trace().Msgf("Got file from cache: %s", sha)
			return content, compressionType, nil
		}
		if err != nil && err != sql.ErrNoRows {
			return nil, "", fmt.Errorf("error getting cached file: %w", err)
		}
	}

	stmt, err := tx.PrepareContext(ctx, system.RebindQuery(f.metadata.dbType, "SELECT compression_type, content FROM files where sha = ?"))
	if err != nil {
		return nil, "", fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	row := stmt.QueryRow(sha)
	var compressionType string
	var content []byte
	if err := row.Scan(&compressionType, &content); err != nil {
		return nil, "", fmt.Errorf("error querying file table: %w", err)
	}

	if f.fileCache != nil {
		f.metadata.Trace().Msgf("Adding file to cache: %s", sha)
		err = f.fileCache.AddCache(ctx, sha, compressionType, content)
		if err != nil {
			return nil, "", fmt.Errorf("error adding file to cache: %w", err)
		}
	}

	return content, compressionType, nil
}

func (f *FileStore) getFileInfo() (map[string]DbFileInfo, error) {
	var tx types.Transaction
	if f.initTx.IsInitialized() {
		tx = f.initTx
	} else {
		var err error
		tx, err = f.metadata.BeginTransaction(context.Background())
		if err != nil {
			return nil, fmt.Errorf("error starting transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck
	}
	return f.getFileInfoTx(context.Background(), tx)
}

func (f *FileStore) getFileInfoTx(ctx context.Context, tx types.Transaction) (map[string]DbFileInfo, error) {
	stmt, err := tx.PrepareContext(ctx, system.RebindQuery(f.metadata.dbType, `select name, sha, uncompressed_size, create_time from app_files where appid = ? and version = ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	rows, err := stmt.Query(f.appId, f.version)
	if err != nil {
		return nil, fmt.Errorf("error querying files: %w", err)
	}
	fileInfo := make(map[string]DbFileInfo)
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var name, sha string
		var size int64
		var modTime time.Time
		err = rows.Scan(&name, &sha, &size, &modTime)
		if err != nil {
			return nil, fmt.Errorf("error querying files: %w", err)
		}
		fileInfo[name] = DbFileInfo{name: name, sha: sha, len: size, modTime: modTime}
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return fileInfo, nil
}

func (f *FileStore) GetHighestVersion(ctx context.Context, tx types.Transaction, appId types.AppId) (int, error) {
	var maxId int
	row := tx.QueryRowContext(ctx, system.RebindQuery(f.metadata.dbType, `select max(version) from app_versions where appid = ?`), appId)
	if err := row.Scan(&maxId); err != nil {
		return 0, nil // No versions found
	}
	return maxId, nil
}

func (f *FileStore) PromoteApp(ctx context.Context, tx types.Transaction, prodAppId types.AppId, metadata *types.AppMetadata) error {
	metadataJson, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, system.RebindQuery(f.metadata.dbType, `insert into app_versions (appid, previous_version, version, metadata, user_id, create_time) values (?, ?, ?, ?, ?, `+system.FuncNow(f.metadata.dbType)+")"),
		prodAppId, metadata.VersionMetadata.PreviousVersion, metadata.VersionMetadata.Version, metadataJson, defaultUser); err != nil {
		return err
	}

	// Use direct queries instead of prepared statements to avoid connection issues
	selectQuery := system.RebindQuery(f.metadata.dbType, `select name, sha, uncompressed_size, create_time from app_files where appid = ? and version = ?`)
	insertQuery := system.RebindQuery(f.metadata.dbType, `insert into app_files (appid, version, name, sha, uncompressed_size, create_time) values (?, ?, ?, ?, ?, `+system.FuncNow(f.metadata.dbType)+")")

	rows, err := tx.Query(selectQuery, f.appId, f.version)
	if err != nil {
		return fmt.Errorf("error querying files: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	// Collect all file data first to avoid keeping the result set open
	type fileData struct {
		name string
		sha  string
		size int64
	}
	var files []fileData

	for rows.Next() {
		var name, sha string
		var size int64
		var modTime time.Time
		err = rows.Scan(&name, &sha, &size, &modTime)
		if err != nil {
			return fmt.Errorf("error scanning file row: %w", err)
		}
		files = append(files, fileData{name: name, sha: sha, size: size})
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("error closing rows: %w", closeErr)
	}

	// Now insert all files
	for _, file := range files {
		if _, err := tx.ExecContext(ctx, insertQuery, prodAppId, metadata.VersionMetadata.Version, file.name, file.sha, file.size); err != nil {
			return fmt.Errorf("error inserting app file during promote: %w", err)
		}
	}

	return nil
}

func (f *FileStore) GetAppVersions(ctx context.Context, tx types.Transaction) ([]types.AppVersion, error) {
	rows, err := tx.Query(system.RebindQuery(f.metadata.dbType, `select version, previous_version, user_id, create_time, metadata from app_versions where appid = ? order by version asc`), f.appId)
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}

	versions := make([]types.AppVersion, 0)
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		v := types.AppVersion{}
		var metadataStr sql.NullString

		err = rows.Scan(&v.Version, &v.PreviousVersion, &v.UserId, &v.CreateTime, &metadataStr)
		if err != nil {
			return nil, fmt.Errorf("error querying apps: %w", err)
		}

		if metadataStr.Valid && metadataStr.String != "" {
			err = json.Unmarshal([]byte(metadataStr.String), &v.Metadata)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
			}
		}

		versions = append(versions, v)
	}

	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return versions, nil
}

func (f *FileStore) GetAppVersion(ctx context.Context, tx types.Transaction, version int) (*types.AppVersion, error) {
	row := tx.QueryRow(system.RebindQuery(f.metadata.dbType, `select version, previous_version, user_id, create_time, metadata from app_versions where appid = ? and version = ?`), f.appId, version)

	v := types.AppVersion{}
	var metadataStr sql.NullString

	err := row.Scan(&v.Version, &v.PreviousVersion, &v.UserId, &v.CreateTime, &metadataStr)
	if err != nil {
		return nil, fmt.Errorf("error querying apps: %w", err)
	}

	if metadataStr.Valid && metadataStr.String != "" {
		err = json.Unmarshal([]byte(metadataStr.String), &v.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
		}
	}

	return &v, nil
}

func (f *FileStore) GetAppFiles(ctx context.Context, tx types.Transaction) ([]types.AppFile, error) {
	files, err := f.getFileInfoTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	fileList := make([]types.AppFile, 0, len(files))
	for _, fileInfo := range files {
		fileList = append(fileList, types.AppFile{
			Name: fileInfo.name,
			Etag: fileInfo.sha,
			Size: fileInfo.len,
		})
	}

	slices.SortFunc(fileList, func(a, b types.AppFile) int {
		return strings.Compare(a.Name, b.Name)
	})

	return fileList, nil
}

func (f *FileStore) Reset() {
	// Unlink the file store from the types.Transaction used during init
	f.initTx = types.Transaction{}
}
