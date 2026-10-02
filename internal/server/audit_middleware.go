// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	s.auditDB, s.auditDbType, err = system.InitDBConnection(s.Logger, connectString, "audit", system.DB_SQLITE_POSTGRES, &s.Config().Metadata, &s.auditDBOwner)
	if err != nil {
		return err
	}

	if err := s.versionUpgradeAuditDB(); err != nil {
		s.auditDB.Close() //nolint:errcheck
		s.auditDB = nil
		_ = s.auditDBOwner.Close()
		return err
	}

	s.auditEvents = make(chan *types.AuditEvent, AUDIT_QUEUE_SIZE)
	s.auditFlush = make(chan chan struct{})
	s.auditStop = make(chan struct{})
	s.auditDone = make(chan struct{})
	go s.auditWriterLoop()

	s.auditCleanup = system.StartPeriodicTask(context.Background(), time.Hour, true, s.auditCleanupPass)
	return nil
}

const CURRENT_AUDIT_DB_VERSION = 2

func (s *Server) versionUpgradeAuditDB() error {
	version := 0
	row := s.auditDB.QueryRow("SELECT version, last_upgraded FROM audit_version")
	var dt time.Time
	row.Scan(&version, &dt) //nolint:errcheck // ignore error if no version is found

	if !s.Config().Metadata.IgnoreHigherVersion && version > CURRENT_AUDIT_DB_VERSION {
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

	if version < 2 {
		s.Info().Msg("Upgrading audit DB to version 2")
		// Index for the retention cleanup deletes and the create_time ordered
		// list queries; the existing indexes lead with rid/app_id and do not help
		if _, err := tx.Exec(`create index IF NOT EXISTS idx_create_time_audit ON audit (create_time DESC)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `update audit_version set version=2, last_upgraded=`+system.FuncNow(s.auditDbType)); err != nil {
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
	case <-s.auditDone:
		// Writer has stopped (server shutdown), fall back to a synchronous write
		return s.insertAuditEventDB(event)
	}

	// The writer may have stopped between the check above and the send, which
	// would leave the event stranded in the queue; drain the queue here if so
	select {
	case <-s.auditDone:
		s.writeAllQueuedAuditEvents(nil)
	default:
	}
	return nil
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
	s.auditStopOnce.Do(func() {
		s.auditCleanup.Stop()
		close(s.auditStop)
	})
	<-s.auditDone
	// Drain events enqueued by writers that raced with the shutdown
	s.writeAllQueuedAuditEvents(nil)
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
		s.Error().Err(err).Int("events", len(batch)).Msg("error inserting audit event batch, retrying individually")
		// Retry events one at a time so one bad event does not drop the batch
		for _, event := range batch {
			if err := s.insertAuditEventDB(event); err != nil {
				s.Error().Err(err).Msg("error inserting audit event")
			}
		}
	}
}

func (s *Server) cleanupEvents(ctx context.Context) error {
	// A retention setting of zero or less disables cleanup for that event class
	var httpDeleted, nonHttpDeleted int64
	if days := s.Config().System.HttpEventRetentionDays; days > 0 {
		cleanupTime := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixNano()
		result, err := s.auditDB.ExecContext(ctx, system.RebindQuery(s.auditDbType, `delete from audit where event_type = 'http' and create_time < ?`), cleanupTime)
		if err != nil {
			return err
		}
		if httpDeleted, err = result.RowsAffected(); err != nil {
			return err
		}
	}

	if days := s.Config().System.NonHttpEventRetentionDays; days > 0 {
		cleanupTime := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixNano()
		result, err := s.auditDB.ExecContext(ctx, system.RebindQuery(s.auditDbType, `delete from audit where event_type != 'http' and create_time < ?`), cleanupTime)
		if err != nil {
			return err
		}
		if nonHttpDeleted, err = result.RowsAffected(); err != nil {
			return err
		}
	}

	s.Info().Msgf("audit cleanup: http deleted %d, non-http deleted %d", httpDeleted, nonHttpDeleted)
	return nil
}

func (s *Server) auditCleanupPass(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	err := s.cleanupEvents(ctx)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		s.Error().Err(err).Msg("error cleaning up audit entries")
	}
	s.pruneApiCredentials(ctx)
}

type ContextShared struct {
	UserId    string
	AppId     string
	Operation string
	Target    string
	DryRun    bool
	// MCP requests (set by the MCP endpoints once the caller is
	// authenticated): the request is audited as mcp events, one per JSON-RPC
	// call, instead of the http event. MCPEndpoint is the kind of endpoint
	// (mcpEndpoint*), MCPOps the calls of the request, MCPDetail what the
	// endpoint adds to the event detail (the client, the credential, the
	// view), MCPError the error of the call where the server knows it
	MCPEndpoint string
	MCPOps      []mcpOp
	MCPDetail   string
	mcpMu       sync.Mutex
	mcpError    string
	mcpAppIds   map[string]string // tool name -> the app the call is for, see setMCPCallApp
}

// The MCP endpoint kinds recorded in the mcp audit events
const (
	mcpEndpointManagement = "management" // /_openrun/mcp
	mcpEndpointApp        = "app"        // the MCP region of an app
	mcpEndpointApps       = "apps"       // /_openrun/app_mcp, the actions of all apps
)

// markMCPRequest records the MCP calls of the request for the audit events
// the status middleware writes when the request is done
func markMCPRequest(ctx context.Context, endpoint string, ops []mcpOp, cred *types.Credential, detail string) {
	cs, ok := ctx.Value(types.SHARED).(*ContextShared)
	if !ok {
		return
	}
	cs.MCPEndpoint = endpoint
	cs.MCPOps = ops
	// Who is calling: the OAuth client holding the token, an API key, or
	// no credential (an endpoint served without a token)
	client := "none"
	if cred != nil {
		client = cmp.Or(cred.OAuthClientId, mcpClientIdAPIKey) + " cred=" + cred.Id
	}
	cs.MCPDetail = strings.TrimSpace("client=" + client + " " + detail)
}

// setMCPError records the failure of an MCP call for its audit event. The
// HTTP status of an MCP response says little: a JSON-RPC error and a tool
// error both come back as 200
func setMCPError(ctx context.Context, message string) {
	if cs, ok := ctx.Value(types.SHARED).(*ContextShared); ok {
		cs.mcpMu.Lock()
		cs.mcpError = message
		cs.mcpMu.Unlock()
	}
}

// setMCPCallApp records the app a tool call is for, for its audit event: on
// an endpoint which serves many apps (the management tools taking an app
// path, the endpoint for the actions of all apps) the request has no app of
// its own
func setMCPCallApp(ctx context.Context, tool string, appId types.AppId) {
	if cs, ok := ctx.Value(types.SHARED).(*ContextShared); ok && appId != "" {
		cs.mcpMu.Lock()
		if cs.mcpAppIds == nil {
			cs.mcpAppIds = map[string]string{}
		}
		cs.mcpAppIds[tool] = string(appId)
		cs.mcpMu.Unlock()
	}
}

// mcpAuditMiddleware reports the outcome of the calls an MCP server of this
// process handles (the management server, the aggregate endpoint) to the
// audit event of the request
func mcpAuditMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		result, err := next(ctx, method, req)
		if err != nil {
			setMCPError(ctx, err.Error())
		} else if callResult, ok := result.(*mcp.CallToolResult); ok && callResult != nil && callResult.IsError {
			message := "tool error"
			if len(callResult.Content) > 0 {
				if text, ok := callResult.Content[0].(*mcp.TextContent); ok {
					message = text.Text
				}
			}
			setMCPError(ctx, message)
		}
		return result, err
	}
}

// insertMCPAuditEvents writes the mcp audit events of an MCP request: one
// per JSON-RPC call (a legacy batch carries several). Notifications are not
// calls and are not recorded. The operation is the JSON-RPC method, the
// target the tool (or resource, prompt) the call names, else the endpoint
func (server *Server) insertMCPAuditEvents(r *http.Request, rid string, cs *ContextShared, path string, statusCode int, duration time.Duration) {
	cs.mcpMu.Lock()
	callError := cs.mcpError
	appIds := maps.Clone(cs.mcpAppIds)
	cs.mcpMu.Unlock()
	status := types.EventStatusSuccess
	if statusCode >= 400 || callError != "" {
		status = types.EventStatusFailure
	}
	for _, op := range cs.MCPOps {
		if op.Method == "" || strings.HasPrefix(op.Method, "notifications/") {
			continue
		}
		detail := fmt.Sprintf("%s %s %s %d %d endpoint=%s", r.Method, r.Host, path, statusCode, duration.Milliseconds(), cs.MCPEndpoint)
		if op.Name != "" {
			detail += " tool=" + op.Name
		}
		if cs.MCPDetail != "" {
			detail += " " + cs.MCPDetail
		}
		if callError != "" {
			if len(callError) > mcpAuditErrorLimit {
				callError = callError[:mcpAuditErrorLimit] + "..."
			}
			detail += " error=" + strconv.Quote(callError)
		}
		event := types.AuditEvent{
			RequestId:  rid,
			CreateTime: time.Now(),
			UserId:     cs.UserId,
			AppId:      types.AppId(cmp.Or(appIds[op.Name], cs.AppId)),
			EventType:  types.EventTypeMCP,
			Operation:  op.Method,
			Target:     cmp.Or(op.Name, r.Host+":"+path),
			Status:     string(status),
			Detail:     detail,
		}
		if err := server.InsertAuditEvent(&event); err != nil {
			server.Error().Err(err).Msg("error inserting mcp audit event")
		}
	}
}

// mcpAuditErrorLimit bounds the error text kept in an mcp audit event
const mcpAuditErrorLimit = 300

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

// newBackgroundOperationContext returns a context for server-initiated work
// (the sync scheduler and other background jobs), carrying a synthesized
// request id and the given user id. There is no HTTP request on these paths,
// so without this the audit events they produce have no request id; with it,
// all events of one run share an id and the audit trace drill-down can show
// everything the run did. The context is marked as a trusted operation: RBAC
// enforcement fails closed for unmarked contexts, and internal background work
// is authorized by the operation that scheduled it (a sync run additionally
// attaches the creator's frozen snapshot, which takes precedence over trust)
func newBackgroundOperationContext(userId string) context.Context {
	return backgroundOperationContext(context.Background(), userId)
}

func backgroundOperationContext(parent context.Context, userId string) context.Context {
	rid := ridPrefix + strconv.FormatUint(atomic.AddUint64(&requestCounter, 1), 10)
	ctx := context.WithValue(parent, types.REQUEST_ID, rid)
	ctx = context.WithValue(ctx, types.USER_ID, userId)
	return system.WithTrustedOperation(ctx)
}

// handleStatus returns a middleware which adds the request id and user id to the
// context and inserts an http audit event for non-GET requests. defaultUser is the
// user recorded when the request does not authenticate a user: the admin user for
// UDS (where the unix file permissions provide auth), empty for TCP.
func (server *Server) handleStatus(defaultUser string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add a request id to the context. A single context node carries
			// the request id, default user and shared audit state instead of a
			// chain of context.WithValue calls (one heap valueCtx each)
			rid := ridPrefix + strconv.FormatUint(atomic.AddUint64(&requestCounter, 1), 10)
			contextShared := &ContextShared{
				UserId: defaultUser,
			}
			r = r.WithContext(&statusContext{
				Context:   r.Context(),
				requestId: rid,
				userId:    defaultUser,
				shared:    contextShared,
			})

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
				// Use the app audit config if available; if the app lookup fails
				// (app deleted or failed to load), still log the event with defaults
				if appInfo, ok := server.apps.GetAppInfo(types.AppId(contextShared.AppId)); ok {
					if app, err := server.apps.GetApp(appInfo.AppPathDomain); err == nil {
						if app.AppConfig.Audit.SkipHttpEvents && contextShared.MCPEndpoint == "" {
							// http event auditing is disabled for this app
							return
						}
						redactUrl = app.AppConfig.Audit.RedactUrl
					}
				}
			}

			path := r.URL.Path
			if redactUrl {
				path = "<REDACTED>"
			}
			statusCode := wrapper.Status()

			if contextShared.MCPEndpoint != "" {
				// An MCP request: mcp events, one per call, in place of the
				// http event. "What did this agent call" is one query
				server.insertMCPAuditEvents(r, rid, contextShared, path, statusCode, duration)
				return
			}

			operation := r.Method
			detail := fmt.Sprintf("%s %s %s %d %d", r.Method, r.Host, path, statusCode, duration.Milliseconds())
			event := types.AuditEvent{
				RequestId:  rid,
				CreateTime: time.Now(),
				UserId:     contextShared.UserId,
				AppId:      types.AppId(contextShared.AppId),
				EventType:  types.EventTypeHTTP,
				Operation:  operation,
				Target:     r.Host + ":" + path,
				Status:     fmt.Sprintf("%d", statusCode),
				Detail:     detail,
			}

			if err := server.InsertAuditEvent(&event); err != nil {
				server.Error().Err(err).Msg("error inserting audit event")
			}
		})
	}
}

// AUTH_FAILURE_EVENT_INTERVAL is the minimum interval between audit events for
// the same failed-auth operation/target/user combination
const AUTH_FAILURE_EVENT_INTERVAL = time.Minute

// insertAuthFailureEvent inserts an audit event for a request which failed
// authentication. Repeated failures are deduped: max one event per
// AUTH_FAILURE_EVENT_INTERVAL for each unique operation/target/user/source-IP
// combination, so that repeated attempts cannot flood the audit DB. The
// client IP is part of the key so failures from different sources stay
// distinguishable (spraying from many real addresses is bounded by the map
// cap; the addresses cannot be spoofed on an established TCP connection)
func (s *Server) insertAuthFailureEvent(r *http.Request, operation, detail string) {
	if s.auditDB == nil {
		// Audit DB is not initialized (Server built directly in tests)
		return
	}
	target := r.Host + ":" + r.URL.Path
	userId := system.GetContextUserId(r.Context())
	clientIP := system.GetClientIP(r, s.Config().Security.TrustedProxies)
	now := time.Now()

	key := operation + "|" + target + "|" + userId + "|" + clientIP
	s.authFailureMu.Lock()
	last, seen := s.authFailureTimes[key]
	if seen && now.Sub(last) < AUTH_FAILURE_EVENT_INTERVAL {
		s.authFailureMu.Unlock()
		return
	}
	if s.authFailureTimes == nil {
		s.authFailureTimes = map[string]time.Time{}
	}
	if len(s.authFailureTimes) > 1000 {
		// Bound the dedup map size by dropping expired entries
		for k, t := range s.authFailureTimes {
			if now.Sub(t) >= AUTH_FAILURE_EVENT_INTERVAL {
				delete(s.authFailureTimes, k)
			}
		}
	}
	s.authFailureTimes[key] = now
	s.authFailureMu.Unlock()

	event := types.AuditEvent{
		RequestId:  system.GetContextRequestId(r.Context()),
		CreateTime: now,
		UserId:     userId,
		AppId:      system.GetContextAppId(r.Context()),
		EventType:  types.EventTypeSystem,
		Operation:  operation,
		Target:     target,
		Status:     string(types.EventStatusFailure),
		Detail:     fmt.Sprintf("%s (remote %s)", detail, r.RemoteAddr),
	}
	if err := s.InsertAuditEvent(&event); err != nil {
		s.Error().Err(err).Msg("error inserting auth failure audit event")
	}
}
