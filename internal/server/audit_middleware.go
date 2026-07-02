// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

var ridPrefix string

func init() {
	id, err := ksuid.NewRandom()
	if err != nil {
		panic(err)
	}
	ridPrefix = "rid_" + id.String() + "_"
}

func (s *Server) initAuditDB(connectString string) error {
	var err error
	s.auditDB, s.auditDbType, err = system.InitDBConnection(connectString, "audit", system.DB_SQLITE_POSTGRES)
	if err != nil {
		return err
	}

	if err := s.versionUpgradeAuditDB(); err != nil {
		return err
	}

	s.auditEvents = make(chan *types.AuditEvent, AUDIT_QUEUE_SIZE)
	s.auditFlush = make(chan chan struct{})
	s.auditStop = make(chan struct{})
	s.auditDone = make(chan struct{})
	go s.auditWriterLoop()

	cleanupTicker := time.NewTicker(1 * time.Hour)
	go s.auditCleanupLoop(cleanupTicker)
	return nil
}

const CURRENT_AUDIT_DB_VERSION = 1

func (s *Server) versionUpgradeAuditDB() error {
	version := 0
	row := s.auditDB.QueryRow("SELECT version, last_upgraded FROM audit_version")
	var dt time.Time
	row.Scan(&version, &dt) //nolint:errcheck // ignore error if no version is found

	if !s.config.Metadata.IgnoreHigherVersion && version > CURRENT_AUDIT_DB_VERSION {
		return fmt.Errorf("audit DB version is newer than server version, exiting. Server %d, DB %d", CURRENT_AUDIT_DB_VERSION, version)
	}

	if version == CURRENT_AUDIT_DB_VERSION {
		return nil
	}

	ctx := context.Background()
	tx, err := s.auditDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if version < 1 {
		s.Info().Msg("No audit version, initializing")

		if _, err := tx.ExecContext(ctx, `create table audit_version (version int, last_upgraded `+system.MapDataType(s.auditDbType, "datetime")+`)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `insert into audit_version values (1, `+system.FuncNow(s.auditDbType)+`)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`create table IF NOT EXISTS audit (rid text, app_id text, create_time bigint,` +
			`user_id text, event_type text, operation text, target text, status text, detail text)`); err != nil {
			return err
		}

		if _, err := tx.Exec(`create index IF NOT EXISTS idx_rid_audit ON audit (rid, create_time DESC)`); err != nil {
			return err

		}
		if _, err := tx.Exec(`create index IF NOT EXISTS idx_misc_audit ON audit (app_id, event_type, operation, target, create_time DESC)`); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

const (
	// AUDIT_QUEUE_SIZE is the audit event queue length; when full, enqueue
	// blocks and applies backpressure to the request path
	AUDIT_QUEUE_SIZE = 1000
	// AUDIT_MAX_BATCH_SIZE caps how many events are written per transaction
	AUDIT_MAX_BATCH_SIZE = 200
)

// InsertAuditEvent queues the event for the background audit writer. The write
// happens asynchronously (batched into one transaction per burst) so the
// request path does not block on a database write per event. A copy of the
// event is queued, callers can reuse the struct. Call FlushAuditEvents before
// reading the audit table to see previously queued events.
func (s *Server) InsertAuditEvent(event *types.AuditEvent) error {
	if s.auditEvents == nil {
		// Audit writer is not running (Server built directly in tests), write synchronously
		return s.insertAuditEventDB(event)
	}

	select {
	case <-s.auditDone:
		// Writer has stopped (server shutdown), fall back to a synchronous write
		return s.insertAuditEventDB(event)
	default:
	}

	eventCopy := *event
	select {
	case s.auditEvents <- &eventCopy:
		return nil
	case <-s.auditDone:
		// Writer has stopped (server shutdown), fall back to a synchronous write
		return s.insertAuditEventDB(event)
	}
}

func (s *Server) insertAuditEventDB(event *types.AuditEvent) error {
	_, err := s.auditDB.Exec(system.RebindQuery(s.auditDbType, `insert into audit (rid, app_id, create_time, user_id, event_type, operation, target, status, detail) `+
		`values (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		event.RequestId, event.AppId, event.CreateTime.UnixNano(), event.UserId, event.EventType, event.Operation, event.Target, event.Status, event.Detail)
	return err
}

// FlushAuditEvents blocks until all audit events queued before the call have
// been written to the audit DB. Used before audit queries (read-after-write
// consistency) and during shutdown.
func (s *Server) FlushAuditEvents() {
	if s.auditFlush == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case s.auditFlush <- ack:
		<-ack
	case <-s.auditDone:
		// Writer stopped; the stop path drains the queue before exiting
	}
}

// stopAuditWriter stops the background audit writer after draining any queued
// events. Later InsertAuditEvent calls fall back to synchronous writes.
func (s *Server) stopAuditWriter() {
	if s.auditStop == nil {
		return
	}
	close(s.auditStop)
	<-s.auditDone
}

func (s *Server) auditWriterLoop() {
	defer close(s.auditDone)
	batch := make([]*types.AuditEvent, 0, AUDIT_MAX_BATCH_SIZE)
	for {
		select {
		case event := <-s.auditEvents:
			batch = s.drainAuditEvents(append(batch[:0], event))
			s.writeAuditBatch(batch)
		case ack := <-s.auditFlush:
			s.writeAllQueuedAuditEvents(batch)
			close(ack)
		case <-s.auditStop:
			s.writeAllQueuedAuditEvents(batch)
			return
		}
	}
}

// writeAllQueuedAuditEvents writes everything currently queued, in batches of
// up to AUDIT_MAX_BATCH_SIZE (a single drain pass is capped at the batch size)
func (s *Server) writeAllQueuedAuditEvents(batch []*types.AuditEvent) {
	for {
		batch = s.drainAuditEvents(batch[:0])
		if len(batch) == 0 {
			return
		}
		s.writeAuditBatch(batch)
	}
}

func (s *Server) drainAuditEvents(batch []*types.AuditEvent) []*types.AuditEvent {
	for len(batch) < AUDIT_MAX_BATCH_SIZE {
		select {
		case event := <-s.auditEvents:
			batch = append(batch, event)
		default:
			return batch
		}
	}
	return batch
}

func (s *Server) writeAuditBatch(batch []*types.AuditEvent) {
	if len(batch) == 0 {
		return
	}
	if len(batch) == 1 {
		if err := s.insertAuditEventDB(batch[0]); err != nil {
			s.Error().Err(err).Msg("error inserting audit event")
		}
		return
	}

	err := func() error {
		tx, err := s.auditDB.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck

		stmt, err := tx.Prepare(system.RebindQuery(s.auditDbType, `insert into audit (rid, app_id, create_time, user_id, event_type, operation, target, status, detail) `+
			`values (?, ?, ?, ?, ?, ?, ?, ?, ?)`))
		if err != nil {
			return err
		}
		defer stmt.Close() //nolint:errcheck

		for _, event := range batch {
			if _, err := stmt.Exec(event.RequestId, event.AppId, event.CreateTime.UnixNano(), event.UserId,
				event.EventType, event.Operation, event.Target, event.Status, event.Detail); err != nil {
				return err
			}
		}
		return tx.Commit()
	}()
	if err != nil {
		s.Error().Err(err).Int("events", len(batch)).Msg("error inserting audit event batch")
	}
}

func (s *Server) cleanupEvents() error {
	httpCleanupTime := time.Now().Add(-time.Duration(s.config.System.HttpEventRetentionDays) * 24 * time.Hour).UnixNano()
	nonHttpCleanupTime := time.Now().Add(-time.Duration(s.config.System.NonHttpEventRetentionDays) * 24 * time.Hour).UnixNano()

	httpResult, err := s.auditDB.Exec(system.RebindQuery(s.auditDbType, `delete from audit where event_type = 'http' and create_time < ?`), httpCleanupTime)
	if err != nil {
		return err
	}
	nonHttpResult, err := s.auditDB.Exec(system.RebindQuery(s.auditDbType, `delete from audit where event_type != 'http' and create_time < ?`), nonHttpCleanupTime)
	if err != nil {
		return err
	}

	httpDeleted, err1 := httpResult.RowsAffected()
	nonHttpDeleted, err2 := nonHttpResult.RowsAffected()
	if cmp.Or(err1, err2) != nil {
		return cmp.Or(err1, err2)
	}
	s.Info().Msgf("audit cleanup: http deleted %d, non-http deleted %d", httpDeleted, nonHttpDeleted)
	return nil
}

func (s *Server) auditCleanupLoop(cleanupTicker *time.Ticker) {
	err := s.cleanupEvents()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error cleaning up audit entries %s", err)
		return
	}

	for range cleanupTicker.C {
		err := s.cleanupEvents()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error cleaning up audit entries %s", err)
			break
		}
	}
	fmt.Fprintf(os.Stderr, "background audit cleanup stopped")
}

type ContextShared struct {
	UserId    string
	AppId     string
	Operation string
	Target    string
	DryRun    bool
}

func updateTargetInContext(r *http.Request, target string, dryRun bool) {
	contextShared := r.Context().Value(types.SHARED)
	if contextShared != nil {
		cs := contextShared.(*ContextShared)
		if target != "" {
			cs.Target = target
		}
		cs.DryRun = dryRun
	}
}

func updateOperationInContext(r *http.Request, operation string) {
	contextShared := r.Context().Value(types.SHARED)
	if contextShared != nil {
		cs := contextShared.(*ContextShared)
		cs.Operation = operation
	}
}

var requestCounter uint64

func (server *Server) handleStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add a request id to the context
		rid := ridPrefix + strconv.FormatUint(atomic.AddUint64(&requestCounter, 1), 10)
		contextShared := ContextShared{
			UserId: types.ADMIN_USER,
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, types.REQUEST_ID, rid)
		ctx = context.WithValue(ctx, types.USER_ID, types.ADMIN_USER)
		ctx = context.WithValue(ctx, types.SHARED, &contextShared)
		r = r.WithContext(ctx)

		// Wrap the ResponseWriter
		wrapper := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		startTime := time.Now()
		// Call the next handler
		next.ServeHTTP(wrapper, r)
		duration := time.Since(startTime)

		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			// Don't create audit events for get requests
			return
		}

		redactUrl := false
		if contextShared.AppId != "" {
			appInfo, ok := server.apps.GetAppInfo(types.AppId(contextShared.AppId))
			if !ok {
				return
			}
			app, err := server.apps.GetApp(appInfo.AppPathDomain)
			if err != nil {
				return
			}

			if app.AppConfig.Audit.SkipHttpEvents {
				// http event auditing is disabled for this app
				return
			}
			redactUrl = app.AppConfig.Audit.RedactUrl
		}

		path := r.URL.Path
		if redactUrl {
			path = "<REDACTED>"
		}
		statusCode := wrapper.Status()

		event := types.AuditEvent{
			RequestId:  rid,
			CreateTime: time.Now(),
			UserId:     contextShared.UserId,
			AppId:      types.AppId(contextShared.AppId),
			EventType:  types.EventTypeHTTP,
			Operation:  r.Method,
			Target:     r.Host + ":" + path,
			Status:     fmt.Sprintf("%d", statusCode),
			Detail:     fmt.Sprintf("%s %s %s %d %d", r.Method, r.Host, path, statusCode, duration.Milliseconds()),
		}

		if err := server.InsertAuditEvent(&event); err != nil {
			server.Error().Err(err).Msg("error inserting audit event")
		}
	})
}
