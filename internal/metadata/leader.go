// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
)

type LeaderElection struct {
	*types.Logger
	metadata              *Metadata
	db                    *sql.DB
	nodeId                string
	hostname              string
	heartbeatLeaseSecs    int
	heartbeatIntervalSecs int
	isLeader              atomic.Bool
	cancel                context.CancelFunc
}

type LeaderState struct {
	LeaderID               string
	Hostname               string
	LastHeartbeatAt        time.Time
	LastLeadershipChangeAt time.Time
}

func NewLeaderElection(logger *types.Logger, metadata *Metadata, config *types.ServerConfig, nodeId string, hostname string) *LeaderElection {
	return &LeaderElection{
		Logger:   logger,
		metadata: metadata, db: metadata.db,
		nodeId:                nodeId,
		hostname:              hostname,
		heartbeatLeaseSecs:    config.System.LeaderElectionLeaseSecs,
		heartbeatIntervalSecs: config.System.LeaderElectionHeartbeatIntervalSecs,
	}
}

func (l *LeaderElection) CreateTables(ctx context.Context, tx types.Transaction) error {
	if l.metadata.dbType == system.DB_TYPE_SQLITE {
		return nil
	}

	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS leader_election (id smallint PRIMARY KEY CHECK (id = 1), `+
		`leader_id text, leader_hostname text, last_heartbeat_at timestamptz, last_leadership_change_at timestamptz)`)
	if err != nil {
		return fmt.Errorf("error creating leader election table: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO leader_election (id) VALUES (1) ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("error inserting leader election row: %w", err)
	}

	return nil
}

func (l *LeaderElection) IsLeader() bool {
	if l.metadata.dbType == system.DB_TYPE_SQLITE {
		return true
	}
	return l.isLeader.Load()
}

func (l *LeaderElection) tryAcquire(ctx context.Context) (*LeaderState, bool, error) {
	row := l.db.QueryRowContext(ctx, `
		UPDATE leader_election
		SET
		  leader_id = $1,
		  leader_hostname = $2,
		  last_heartbeat_at = clock_timestamp(),
		  last_leadership_change_at =
		    CASE
		      WHEN leader_id IS DISTINCT FROM $1 THEN clock_timestamp()
		      ELSE last_leadership_change_at
		    END
		WHERE id = 1
		  AND (
		    last_heartbeat_at IS NULL
		    OR last_heartbeat_at < clock_timestamp() - ($3 * interval '1 second')
		  )
		RETURNING leader_id, leader_hostname, last_heartbeat_at, last_leadership_change_at;
	`, l.nodeId, l.hostname, l.heartbeatLeaseSecs)

	var st LeaderState
	var leaderID string
	err := row.Scan(&leaderID, &st.Hostname, &st.LastHeartbeatAt, &st.LastLeadershipChangeAt)
	if err != nil {
		// No rows returned => did not acquire (WHERE condition failed)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	st.LeaderID = leaderID
	return &st, true, nil
}

func (l *LeaderElection) heartbeat(ctx context.Context) (time.Time, bool, error) {
	row := l.db.QueryRowContext(ctx, `UPDATE leader_election
		SET last_heartbeat_at = clock_timestamp(),
		    leader_hostname = $2
		WHERE id = 1 AND leader_id = $1
		RETURNING last_heartbeat_at;
	`, l.nodeId, l.hostname)

	var t time.Time
	err := row.Scan(&t)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (l *LeaderElection) Stop() {
	if l.cancel != nil {
		l.cancel()
	}
}

func (l *LeaderElection) StartLoop(parentCtx context.Context) {
	if l.metadata.dbType == system.DB_TYPE_SQLITE {
		return
	}

	ctx, cancel := context.WithCancel(parentCtx)
	l.cancel = cancel

	l.Info().Msgf("Starting leader election loop, heartbeat interval: %d seconds, lease %d seconds",
		l.heartbeatIntervalSecs, l.heartbeatLeaseSecs)

	go func() {
		// Try to acquire leadership immediately on startup
		_, acquired, err := l.tryAcquire(ctx)
		if err != nil {
			l.Error().Err(err).Msg("initial try-acquire error")
		} else if acquired {
			l.isLeader.Store(true)
			l.Info().Msg("Became leader")
		}

		t := time.NewTicker(time.Duration(l.heartbeatIntervalSecs) * time.Second)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				l.Info().Msg("Leader election loop stopped")
				return
			case <-t.C:
				if l.isLeader.Load() {
					_, ok, err := l.heartbeat(ctx)
					if err != nil {
						l.Error().Err(err).Msg("heartbeat error")
						continue
					}
					if !ok {
						// Lost leadership
						if l.isLeader.Swap(false) {
							l.Info().Msg("Lost leadership")
						}
					}
				} else {
					_, acquired, err := l.tryAcquire(ctx)
					if err != nil {
						l.Error().Err(err).Msg("try-acquire error")
						continue
					}
					if acquired {
						if !l.isLeader.Swap(true) {
							l.Info().Msg("Became leader")
						}
					}
				}
			}
		}
	}()
}
