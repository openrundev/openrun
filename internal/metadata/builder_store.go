// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

func (m *Metadata) CreateBuilderSession(ctx context.Context, tx types.Transaction, session *types.BuilderSession) error {
	_, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`insert into builder_sessions(id, user_id, name, spec, agent, preset, status, workspace_dir, preview_path, publish_path, create_time, update_time) `+
			`values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, `+system.FuncNow(m.dbType)+`, `+system.FuncNow(m.dbType)+`)`),
		session.Id, session.UserID, session.Name, session.Spec, session.Agent, session.Preset, string(session.Status),
		session.WorkspaceDir, session.PreviewPath, session.PublishPath)
	if err != nil {
		return fmt.Errorf("error inserting builder session: %w", err)
	}
	return nil
}

func (m *Metadata) UpdateBuilderSession(ctx context.Context, tx types.Transaction, session *types.BuilderSession) error {
	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`update builder_sessions set status = ?, preview_path = ?, publish_path = ?, update_time = `+system.FuncNow(m.dbType)+` where id = ?`),
		string(session.Status), session.PreviewPath, session.PublishPath, session.Id)
	if err != nil {
		return fmt.Errorf("error updating builder session: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("builder session %s not found", session.Id)
	}
	return nil
}

func (m *Metadata) DeleteBuilderSession(ctx context.Context, tx types.Transaction, id string) error {
	result, err := tx.ExecContext(ctx, system.RebindQuery(m.dbType, `delete from builder_sessions where id = ?`), id)
	if err != nil {
		return fmt.Errorf("error deleting builder session: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("builder session %s not found", id)
	}
	return nil
}

const builderSessionColumns = `id, user_id, name, spec, agent, preset, status, workspace_dir, preview_path, publish_path, create_time, update_time`

func scanBuilderSession(scan func(dest ...any) error) (*types.BuilderSession, error) {
	var session types.BuilderSession
	var status string
	if err := scan(&session.Id, &session.UserID, &session.Name, &session.Spec, &session.Agent, &session.Preset, &status,
		&session.WorkspaceDir, &session.PreviewPath, &session.PublishPath, &session.CreateTime, &session.UpdateTime); err != nil {
		return nil, err
	}
	session.Status = types.BuilderSessionStatus(status)
	return &session, nil
}

func (m *Metadata) GetBuilderSession(ctx context.Context, tx types.Transaction, id string) (*types.BuilderSession, error) {
	query := system.RebindQuery(m.dbType, `select `+builderSessionColumns+` from builder_sessions where id = ?`)
	var row *sql.Row
	if tx.IsInitialized() {
		row = tx.QueryRowContext(ctx, query, id)
	} else {
		row = m.db.QueryRowContext(ctx, query, id)
	}
	session, err := scanBuilderSession(row.Scan)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("builder session %s not found", id)
		}
		return nil, fmt.Errorf("error querying builder session: %w", err)
	}
	return session, nil
}

// ListBuilderSessions returns all sessions, newest first, optionally
// filtered to one user
func (m *Metadata) ListBuilderSessions(ctx context.Context, userID string) ([]*types.BuilderSession, error) {
	query := `select ` + builderSessionColumns + ` from builder_sessions`
	args := []any{}
	if userID != "" {
		query += ` where user_id = ?`
		args = append(args, userID)
	}
	query += ` order by create_time desc, id desc`

	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, query), args...)
	if err != nil {
		return nil, fmt.Errorf("error querying builder sessions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	sessions := make([]*types.BuilderSession, 0)
	for rows.Next() {
		session, err := scanBuilderSession(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("error scanning builder session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (m *Metadata) CreateBuilderActivity(ctx context.Context, tx types.Transaction, activity *types.BuilderActivity) error {
	metadataJson, err := json.Marshal(activity.Metadata)
	if err != nil {
		return fmt.Errorf("error marshalling activity metadata: %w", err)
	}
	_, err = tx.ExecContext(ctx, system.RebindQuery(m.dbType,
		`insert into builder_activity(id, session_id, user_id, create_time, kind, content, metadata) `+
			`values(?, ?, ?, `+system.FuncNow(m.dbType)+`, ?, ?, ?)`),
		activity.Id, activity.SessionId, activity.UserID, activity.Kind, activity.Content, metadataJson)
	if err != nil {
		return fmt.Errorf("error inserting builder activity: %w", err)
	}
	return nil
}

// ListBuilderActivity returns activity rows for a session in insertion order
// (activity ids are time-ordered ksuids). afterId returns rows later than the
// given id, for incremental fetches; limit 0 means no limit
func (m *Metadata) ListBuilderActivity(ctx context.Context, sessionId, afterId string, limit int) ([]*types.BuilderActivity, error) {
	query := `select id, session_id, user_id, create_time, kind, content, metadata from builder_activity where session_id = ?`
	args := []any{sessionId}
	if afterId != "" {
		query += ` and id > ?`
		args = append(args, afterId)
	}
	query += ` order by id`
	if limit > 0 {
		query += fmt.Sprintf(` limit %d`, limit)
	}

	rows, err := m.db.QueryContext(ctx, system.RebindQuery(m.dbType, query), args...)
	if err != nil {
		return nil, fmt.Errorf("error querying builder activity: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	entries := make([]*types.BuilderActivity, 0)
	for rows.Next() {
		var activity types.BuilderActivity
		var metadata sql.NullString
		if err := rows.Scan(&activity.Id, &activity.SessionId, &activity.UserID, &activity.CreateTime,
			&activity.Kind, &activity.Content, &metadata); err != nil {
			return nil, fmt.Errorf("error scanning builder activity: %w", err)
		}
		if metadata.Valid && metadata.String != "" && metadata.String != "null" {
			if err := json.Unmarshal([]byte(metadata.String), &activity.Metadata); err != nil {
				return nil, fmt.Errorf("error unmarshalling activity metadata: %w", err)
			}
		}
		entries = append(entries, &activity)
	}
	return entries, rows.Err()
}
