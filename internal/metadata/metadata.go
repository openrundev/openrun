// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/pgxlisten"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	_ "modernc.org/sqlite"
)

const CURRENT_DB_VERSION = 5

// Metadata is the metadata persistence layer
type Metadata struct {
	*types.Logger
	config        *types.ServerConfig
	db            *sql.DB
	dbType        system.DBType
	pgListener    *pgxlisten.Listener
	AppNotifyFunc func(types.AppUpdatePayload)
}

const pg_listen_channel = "openrun_events"

// NewMetadata creates a new metadata persistence layer
func NewMetadata(logger *types.Logger, config *types.ServerConfig) (*Metadata, error) {
	db, dbType, err := system.InitDBConnection(config.Metadata.DBConnection, "metadata", system.DB_SQLITE_POSTGRES)
	if err != nil {
		return nil, fmt.Errorf("error initializing db: %w", err)
	}
	m := &Metadata{
		Logger: logger,
		config: config,
		db:     db,
		dbType: dbType,
	}

	err = m.VersionUpgrade(config)
	if err != nil {
		return nil, err
	}

	if m.dbType == system.DB_TYPE_POSTGRES {
		// Setup listener for app update notifications
		m.pgListener = &pgxlisten.Listener{
			Connect: func(ctx context.Context) (*pgx.Conn, error) {
				return pgx.Connect(ctx, m.config.Metadata.DBConnection)
			},
			LogError: func(innerCtx context.Context, err error) {
				m.Err(err).Msg("error in postgres listener")
			},
			ReconnectDelay: 2 * time.Second,
		}

		var handler pgxlisten.HandlerFunc = func(ctx context.Context, notification *pgconn.Notification, conn *pgx.Conn) error {
			if notification.Payload == "" {
				return nil
			}

			msg := types.NotificationMessage{}
			err := json.Unmarshal([]byte(notification.Payload), &msg)
			if err != nil {
				m.Error().Err(err).Msg("error unmarshalling notification payload")
				return err
			}

			if msg.MessageType == types.MessageTypeAppUpdate {
				updateMsg := types.AppUpdateMessage{}
				err := json.Unmarshal([]byte(notification.Payload), &updateMsg)
				if err != nil {
					m.Error().Err(err).Msg("error unmarshalling app update message")
					return err
				}
				go m.AppNotifyFunc(updateMsg.Payload)
			} else {
				m.Error().Msgf("unknown message type: %s", msg.MessageType)
			}

			return nil
		}

		m.pgListener.Handle(pg_listen_channel, handler)
		go func() {
			err := m.pgListener.Listen(context.Background())
			if err != nil {
				m.Error().Err(err).Msg("error listening for postgres messages")
				return
			}
		}()
	}

	return m, nil
}

// NotifyAppUpdate sends a notification thrrough the postgres listener that an app has been updated
func (m *Metadata) NotifyAppUpdate(appPathDomains []types.AppPathDomain) error {
	if m.dbType != system.DB_TYPE_POSTGRES {
		return nil
	}

	payload := types.AppUpdatePayload{
		AppPathDomains: appPathDomains,
		ServerId:       types.CurrentServerId,
	}

	msg := types.AppUpdateMessage{
		MessageType: types.MessageTypeAppUpdate,
		Payload:     payload,
	}

	payloadBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = m.db.Exec("select pg_notify($1,$2)", pg_listen_channel, string(payloadBytes))
	return err
}

func (m *Metadata) VersionUpgrade(config *types.ServerConfig) error {
	version := 0
	row := m.db.QueryRow("SELECT version, last_upgraded FROM version")
	var dt time.Time
	row.Scan(&version, &dt)

	if version < CURRENT_DB_VERSION && !m.config.Metadata.AutoUpgrade {
		return fmt.Errorf("DB autoupgrade is disabled, exiting. Server %d, DB %d", CURRENT_DB_VERSION, version)
	}

	if !config.Metadata.IgnoreHigherVersion && version > CURRENT_DB_VERSION {
		return fmt.Errorf("DB version is newer than server version, upgrade OpenRun server version. Server %d, DB %d", CURRENT_DB_VERSION, version)
	}

	if version == CURRENT_DB_VERSION {
		m.Info().Msg("DB version is current")
		return nil
	}

	ctx := context.Background()
	tx, err := m.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if version < 1 {
		m.Info().Msg("No version, initializing")
		if _, err := tx.ExecContext(ctx, `create table version (version int, last_upgraded `+system.MapDataType(m.dbType, "datetime")+")"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `insert into version values (1,`+system.FuncNow(m.dbType)+")"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `create table apps(id text, path text, domain text, source_url text, is_dev bool, main_app text, user_id text, create_time `+system.MapDataType(m.dbType, "datetime")+", update_time "+system.MapDataType(m.dbType, "datetime")+", settings json, metadata json, UNIQUE(id), UNIQUE(path, domain))"); err != nil {
			return err
		}
	}

	if version < 2 {
		m.Info().Msg("Upgrading to version 2")
		if err := m.initFileTables(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `update version set version=2, last_upgraded=`+system.FuncNow(m.dbType)); err != nil {
			return err
		}
	}

	if version < 3 {
		m.Info().Msg("Upgrading to version 3")

		if _, err := tx.ExecContext(ctx, `alter table app_versions add column previous_version int default 0`); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `update version set version=3, last_upgraded=`+system.FuncNow(m.dbType)); err != nil {
			return err
		}
	}

	if version < 4 {
		m.Info().Msg("Upgrading to version 4")
		if _, err := tx.ExecContext(ctx, `create table sync(id text, path text, is_scheduled bool, user_id text, create_time `+system.MapDataType(m.dbType, "datetime")+", metadata json, PRIMARY KEY(id))"); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `update version set version=4, last_upgraded=`+system.FuncNow(m.dbType)); err != nil {
			return err
		}
	}

	if version < 5 {
		m.Info().Msg("Upgrading to version 5")
		if _, err := tx.ExecContext(ctx, `alter table sync add column status json`); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `update version set version=5, last_upgraded=`+system.FuncNow(m.dbType)); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (m *Metadata) initFileTables(ctx context.Context, tx types.Transaction) error {
	if _, err := tx.ExecContext(ctx, `create table files (sha text, compression_type text, content `+system.MapDataType(m.dbType, "blob")+`, create_time `+system.MapDataType(m.dbType, "datetime")+", PRIMARY KEY(sha))"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `create table app_versions (appid text, version int, user_id text, metadata json, create_time `+system.MapDataType(m.dbType, "datetime")+", PRIMARY KEY(appid, version))"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `create table app_files (appid text, version int, name text, sha text, uncompressed_size int, create_time `+system.MapDataType(m.dbType, "datetime")+", PRIMARY KEY(appid, version, name))"); err != nil {
		return err
	}

	return nil
}

func (m *Metadata) CreateApp(ctx context.Context, tx types.Transaction, app *types.AppEntry) error {
	settingsJson, err := json.Marshal(app.Settings)
	if err != nil {
		return fmt.Errorf("error marshalling settings: %w", err)
	}
	metadataJson, err := json.Marshal(app.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`INSERT into apps(id, path, domain, main_app, source_url, is_dev, user_id, create_time, update_time, settings, metadata)`+
			` values(?, ?, ?, ?, ?, ?, ?, `+system.FuncNow(m.dbType)+", "+system.FuncNow(m.dbType)+", ?, ?)"),
		app.Id, app.Path, app.Domain, app.MainApp, app.SourceUrl, app.IsDev, app.UserID, settingsJson, metadataJson)
	if err != nil {
		return fmt.Errorf("error inserting app: %w", err)
	}
	return nil
}

func (m *Metadata) GetApp(pathDomain types.AppPathDomain) (*types.AppEntry, error) {
	tx, err := m.BeginTransaction(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return m.GetAppTx(context.Background(), tx, pathDomain)
}

func (m *Metadata) GetAppTx(ctx context.Context, tx types.Transaction, pathDomain types.AppPathDomain) (*types.AppEntry, error) {
	stmt, err := tx.PrepareContext(ctx, system.RebindQuery(m.dbType, `select id, path, domain, main_app, source_url, is_dev, user_id, create_time, update_time, settings, metadata from apps where path = ? and domain = ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	row := stmt.QueryRow(pathDomain.Path, pathDomain.Domain)
	var app types.AppEntry
	var settings, metadata sql.NullString
	err = row.Scan(&app.Id, &app.Path, &app.Domain, &app.MainApp, &app.SourceUrl, &app.IsDev, &app.UserID, &app.CreateTime, &app.UpdateTime, &settings, &metadata)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("app not found")
		}
		m.Error().Err(err).Msgf("query %s %s", pathDomain.Path, pathDomain.Domain)
		return nil, fmt.Errorf("error querying app: %w", err)
	}

	if metadata.Valid && metadata.String != "" {
		err = json.Unmarshal([]byte(metadata.String), &app.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
		}
	}

	if settings.Valid && settings.String != "" {
		err = json.Unmarshal([]byte(settings.String), &app.Settings)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling settings: %w", err)
		}
	}

	if app.Metadata.SpecFiles == nil {
		tf := make(types.SpecFiles)
		app.Metadata.SpecFiles = &tf
	}

	return &app, nil
}

func (m *Metadata) DeleteApp(ctx context.Context, tx types.Transaction, id types.AppId) error {
	if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from app_versions where appid in (select id from apps where id = ? or main_app = ?)`), id, id); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from app_files where appid in (select id from apps where id = ? or main_app = ?)`), id, id); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from apps where id = ? or main_app = ? `), id, id); err != nil {
		return fmt.Errorf("error deleting apps : %w", err)
	}

	// Clean up unused files. This can be done more aggressively, when older versions are deleted.
	// Currently done only when an app is deleted. This cleanup is across apps, not just the deleted app.
	if _, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from files where sha not in (select distinct sha from app_files)`)); err != nil {
		return err
	}

	return nil
}

func (m *Metadata) GetAppsForDomain(domain string) ([]string, error) {
	stmt, err := m.db.Prepare(system.RebindQuery(m.dbType, `select path from apps where domain = ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(domain)
	if err != nil {
		return nil, fmt.Errorf("error querying apps: %w", err)
	}

	paths := make([]string, 0)
	defer rows.Close()
	for rows.Next() {
		var path string
		err = rows.Scan(&path)
		if err != nil {
			return nil, fmt.Errorf("error querying apps: %w", err)
		}
		paths = append(paths, path)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return paths, nil
}

func (m *Metadata) GetAllApps(includeInternal bool) ([]types.AppInfo, error) {
	sqlStr := `select domain, path, is_dev, id, main_app, settings, metadata, source_url from apps`
	if !includeInternal {
		sqlStr += ` where main_app = ''`
	}
	sqlStr += ` order by create_time desc`

	stmt, err := m.db.Prepare(sqlStr)
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf("error querying apps: %w", err)
	}
	apps := make([]types.AppInfo, 0)
	defer rows.Close()
	for rows.Next() {
		var path, domain, id, mainApp, sourceUrl string
		var isDev bool
		var settingsStr, metadataStr sql.NullString
		err = rows.Scan(&domain, &path, &isDev, &id, &mainApp, &settingsStr, &metadataStr, &sourceUrl)
		if err != nil {
			return nil, fmt.Errorf("error querying apps: %w", err)
		}

		var metadata types.AppMetadata
		var settings types.AppSettings

		if metadataStr.Valid && metadataStr.String != "" {
			err = json.Unmarshal([]byte(metadataStr.String), &metadata)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
			}
		}

		if settingsStr.Valid && settingsStr.String != "" {
			err = json.Unmarshal([]byte(settingsStr.String), &settings)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling settings: %w", err)
			}
		}

		apps = append(apps, types.CreateAppInfo(types.AppId(id), metadata.Name, path, domain, isDev,
			types.AppId(mainApp), settings.AuthnType, sourceUrl, metadata.Spec,
			metadata.VersionMetadata.Version, metadata.VersionMetadata.GitCommit, metadata.VersionMetadata.GitMessage,
			metadata.VersionMetadata.GitBranch, types.StripQuotes(metadata.AppConfig["star_base"])))
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}
	return apps, nil
}

// GetLinkedApps gets all the apps linked to the given main app (staging and preview apps)
func (m *Metadata) GetLinkedApps(ctx context.Context, tx types.Transaction, mainAppId types.AppId) ([]*types.AppEntry, error) {
	stmt, err := tx.PrepareContext(ctx, system.RebindQuery(m.dbType, `select id, path, domain, main_app, source_url, is_dev, user_id, create_time, update_time, settings, metadata from apps where main_app = ?`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(mainAppId)
	if err != nil {
		return nil, fmt.Errorf("error querying apps: %w", err)
	}
	apps := make([]*types.AppEntry, 0)
	defer rows.Close()
	for rows.Next() {
		var app types.AppEntry
		var settings, metadata sql.NullString
		err = rows.Scan(&app.Id, &app.Path, &app.Domain, &app.MainApp, &app.SourceUrl, &app.IsDev, &app.UserID, &app.CreateTime, &app.UpdateTime, &settings, &metadata)
		if err != nil {
			if err == sql.ErrNoRows {
				return apps, nil // No linked apps found, return empty slice
			}
			m.Error().Err(err).Msgf("query %s", mainAppId)
			return nil, fmt.Errorf("error querying appy: %w", err)
		}

		if metadata.Valid && metadata.String != "" {
			err = json.Unmarshal([]byte(metadata.String), &app.Metadata)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
			}
		}

		if settings.Valid && settings.String != "" {
			err = json.Unmarshal([]byte(settings.String), &app.Settings)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling settings: %w", err)
			}
		}

		apps = append(apps, &app)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return apps, nil
}

func (m *Metadata) UpdateSourceUrl(ctx context.Context, tx types.Transaction, app *types.AppEntry) error {
	_, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `UPDATE apps set source_url = ? where path = ? and domain = ?`), app.SourceUrl, app.Path, app.Domain)
	if err != nil {
		return fmt.Errorf("error updating app source url: %w", err)
	}
	return nil
}

func (m *Metadata) UpdateAppMetadata(ctx context.Context, tx types.Transaction, app *types.AppEntry) error {
	metadataJson, err := json.Marshal(app.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType, `UPDATE apps set metadata = ? where path = ? and domain = ?`), string(metadataJson), app.Path, app.Domain)
	if err != nil {
		return fmt.Errorf("error updating app metadata: %w", err)
	}

	if strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_PROD) || strings.HasPrefix(string(app.Id), types.ID_PREFIX_APP_STAGE) {
		_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType, `UPDATE app_versions set metadata = ? where appid = ? and version = ?`), string(metadataJson), app.Id, app.Metadata.VersionMetadata.Version)
		if err != nil {
			return fmt.Errorf("error updating app metadata: %w", err)
		}
	}

	return nil
}

func (m *Metadata) UpdateAppSettings(ctx context.Context, tx types.Transaction, app *types.AppEntry) error {
	settingsJson, err := json.Marshal(app.Settings)
	if err != nil {
		return fmt.Errorf("error marshalling settings: %w", err)
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType, `UPDATE apps set settings = ? where path = ? and domain = ?`), string(settingsJson), app.Path, app.Domain)
	if err != nil {
		return fmt.Errorf("error updating app settings: %w", err)
	}

	return nil
}

func (m *Metadata) CreateSync(ctx context.Context, tx types.Transaction, sync *types.SyncEntry) error {
	metadataJson, err := json.Marshal(sync.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}

	statusJson, err := json.Marshal(sync.Status)
	if err != nil {
		return fmt.Errorf("error marshalling status: %w", err)
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType, `INSERT into sync(id, path, is_scheduled, user_id, create_time, metadata, status) values(?, ?, ?, ?, `+system.FuncNow(m.dbType)+", ?, ?)"),
		sync.Id, sync.Path, sync.IsScheduled, sync.UserID, metadataJson, statusJson)
	if err != nil {
		return fmt.Errorf("error inserting sync entry: %w", err)
	}
	return nil
}

func (m *Metadata) DeleteSync(ctx context.Context, tx types.Transaction, id string) error {
	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from sync where id = ?`), id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no sync entry found with id for delete: %s", id)
	}
	return nil
}

// GetSyncEntries gets all the sync entries for the given webhook type
func (m *Metadata) GetSyncEntries(ctx context.Context, tx types.Transaction) ([]*types.SyncEntry, error) {
	stmt, err := tx.PrepareContext(ctx, system.RebindQuery(m.dbType, `select id, path, is_scheduled, user_id, create_time, metadata, status from sync`))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf("error querying sync: %w", err)
	}
	syncEntries := make([]*types.SyncEntry, 0)
	defer rows.Close()
	for rows.Next() {
		var sync types.SyncEntry
		var metadata sql.NullString
		var status sql.NullString
		err = rows.Scan(&sync.Id, &sync.Path, &sync.IsScheduled, &sync.UserID, &sync.CreateTime, &metadata, &status)
		if err != nil {
			if err == sql.ErrNoRows {
				return syncEntries, nil // No entries found, return empty slice
			}
			return nil, fmt.Errorf("error querying sync: %w", err)
		}

		if metadata.Valid && metadata.String != "" {
			err = json.Unmarshal([]byte(metadata.String), &sync.Metadata)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
			}
		}

		if status.Valid && status.String != "" {
			err = json.Unmarshal([]byte(status.String), &sync.Status)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling status: %w", err)
			}
		}

		syncEntries = append(syncEntries, &sync)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, fmt.Errorf("error closing rows: %w", closeErr)
	}

	return syncEntries, nil
}

func (m *Metadata) GetSyncEntry(ctx context.Context, tx types.Transaction, id string) (*types.SyncEntry, error) {
	row := m.db.QueryRow(system.RebindQuery(m.dbType, `select id, path, is_scheduled, user_id, create_time, metadata, status from sync where id = ?`), id)
	var sync types.SyncEntry
	var metadata, status sql.NullString
	err := row.Scan(&sync.Id, &sync.Path, &sync.IsScheduled, &sync.UserID, &sync.CreateTime, &metadata, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("sync entry not found with id: " + id)
		}
		m.Error().Err(err).Msgf("query %s", id)
		return nil, fmt.Errorf("error querying sync entry: %w", err)
	}
	if metadata.Valid && metadata.String != "" {
		err = json.Unmarshal([]byte(metadata.String), &sync.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling metadata: %w", err)
		}
	}
	if status.Valid && status.String != "" {
		err = json.Unmarshal([]byte(status.String), &sync.Status)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling status: %w", err)
		}
	}
	return &sync, nil
}

func (m *Metadata) UpdateSyncStatus(ctx context.Context, tx types.Transaction, id string, status *types.SyncJobStatus) error {
	statusJson, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("error marshalling status: %w", err)
	}

	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType, `UPDATE sync set status = ? where id = ?`), string(statusJson), id)
	if err != nil {
		return fmt.Errorf("error updating app status: %w", err)
	}

	return nil
}

// BeginTransaction starts a new Transaction
func (m *Metadata) BeginTransaction(ctx context.Context) (types.Transaction, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	return types.Transaction{Tx: tx}, err
}

// CommitTransaction commits a transaction
func (m *Metadata) CommitTransaction(tx types.Transaction) error {
	return tx.Commit()
}

// RollbackTransaction rolls back a transaction
func (m *Metadata) RollbackTransaction(tx types.Transaction) error {
	return tx.Rollback()
}
