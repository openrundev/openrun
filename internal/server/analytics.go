// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
)

// Management operations are bucketed into resource categories for the
// per-user activity report. Order matters: sync/builder/binding names are
// matched before the app fallback ("reload_apps" is an app op, "create_sync"
// a sync op)
func operationCategory(op string) string {
	switch {
	case strings.Contains(op, "sync"):
		return "sync_ops"
	case strings.Contains(op, "session") || strings.Contains(op, "builder") || strings.Contains(op, "publish"):
		return "builder_ops"
	case strings.Contains(op, "binding") || strings.Contains(op, "service") || strings.Contains(op, "secret"):
		return "binding_ops"
	case strings.Contains(op, "app") || strings.Contains(op, "version") || strings.Contains(op, "approve") || strings.Contains(op, "promote"):
		return "app_ops"
	default:
		return "other_ops"
	}
}

// statusOKExpr returns 0 for successful audit statuses ("Success", 2xx/3xx
// and empty) and 1 otherwise, mirroring the console audit page's styling rule
const statusErrExpr = `case when status = 'Success' or status = '' or status like '2%' or status like '3%' then 0 else 1 end`

// AnalyticsSummary aggregates the audit log for the console analytics page:
// events per UTC day (all event types, with error and management-operation
// counts) and management operations per user, bucketed by resource category.
// The aggregation runs as SQL group-bys so the handler never pages raw events
func (c *openrunPlugin) AnalyticsSummary(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	days := starlark.MakeInt(30)
	if err := starlark.UnpackArgs("analytics_summary", args, kwargs, "days?", &days); err != nil {
		return nil, err
	}
	daysVal, _ := days.Int64()
	if daysVal <= 0 || daysVal > 366 {
		return nil, fmt.Errorf("days has to be between 1 and 366")
	}

	// Same gate as list_audit_events: audit:read covers the audit log
	if err := c.server.enforceGlobalPerm(system.GetRequestContext(thread), types.PermissionAuditRead, ""); err != nil {
		return nil, err
	}

	// The window covers today (UTC) and the days-1 days before it
	now := time.Now().UTC()
	startDay := now.Truncate(24*time.Hour).AddDate(0, 0, -int(daysVal-1))
	cutoff := startDay.UnixNano()

	var dayExpr string
	if c.server.auditDbType == system.DB_TYPE_SQLITE {
		dayExpr = `date(create_time/1000000000, 'unixepoch')`
	} else {
		// Postgres
		dayExpr = `to_char(to_timestamp(create_time/1000000000) AT TIME ZONE 'UTC', 'YYYY-MM-DD')`
	}

	c.server.FlushAuditEvents()

	// Events per day: total volume, failures, the management slice
	// (custom/system events) and the http slice. http is counted
	// explicitly - the audit table also holds 'action' events (which ride
	// alongside their own http request event), so deriving http as
	// total-minus-management would double count Actions traffic
	dailyQuery := `select ` + dayExpr + ` as day, count(*), sum(` + statusErrExpr + `), ` +
		`sum(case when event_type in ('custom', 'system') then 1 else 0 end), ` +
		`sum(case when event_type = 'http' then 1 else 0 end) ` +
		`from audit where create_time >= ? group by day`
	rows, err := c.server.auditDB.Query(system.RebindQuery(c.server.auditDbType, dailyQuery), cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	type dayCounts struct{ total, errors, mgmt, http int64 }
	byDay := map[string]dayCounts{}
	for rows.Next() {
		var day string
		var counts dayCounts
		if err := rows.Scan(&day, &counts.total, &counts.errors, &counts.mgmt, &counts.http); err != nil {
			return nil, err
		}
		byDay[day] = counts
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Management operations per user and operation; the resource-category
	// split happens here since the mapping is name-based
	userQuery := `select user_id, operation, count(*), sum(` + statusErrExpr + `), max(create_time) ` +
		`from audit where create_time >= ? and event_type in ('custom', 'system') group by user_id, operation`
	userRows, err := c.server.auditDB.Query(system.RebindQuery(c.server.auditDbType, userQuery), cutoff)
	if err != nil {
		return nil, err
	}
	defer userRows.Close() //nolint:errcheck

	type userCounts struct {
		categories map[string]int64
		total      int64
		errors     int64
		lastActive int64
	}
	byUser := map[string]*userCounts{}
	for userRows.Next() {
		var userId, op string
		var count, errCount, last int64
		if err := userRows.Scan(&userId, &op, &count, &errCount, &last); err != nil {
			return nil, err
		}
		u := byUser[userId]
		if u == nil {
			u = &userCounts{categories: map[string]int64{}}
			byUser[userId] = u
		}
		u.categories[operationCategory(op)] += count
		u.total += count
		u.errors += errCount
		if last > u.lastActive {
			u.lastActive = last
		}
	}
	if err := userRows.Err(); err != nil {
		return nil, err
	}

	// Zero-filled day series, oldest first, so the chart never has holes
	daily := make([]map[string]any, 0, daysVal)
	var totalEvents, totalErrors, totalMgmt, totalHTTP int64
	for d := startDay; !d.After(now); d = d.AddDate(0, 0, 1) {
		day := d.Format("2006-01-02")
		counts := byDay[day]
		daily = append(daily, map[string]any{
			"date":   day,
			"total":  counts.total,
			"errors": counts.errors,
			"mgmt":   counts.mgmt,
			"http":   counts.http,
		})
		totalEvents += counts.total
		totalErrors += counts.errors
		totalMgmt += counts.mgmt
		totalHTTP += counts.http
	}

	users := make([]map[string]any, 0, len(byUser))
	for userId, u := range byUser {
		users = append(users, map[string]any{
			"user_id":     userId,
			"total":       u.total,
			"errors":      u.errors,
			"app_ops":     u.categories["app_ops"],
			"sync_ops":    u.categories["sync_ops"],
			"builder_ops": u.categories["builder_ops"],
			"binding_ops": u.categories["binding_ops"],
			"other_ops":   u.categories["other_ops"],
			"last_active": time.Unix(0, u.lastActive).UTC().Format(time.RFC3339),
		})
	}
	// Most active users first; user id as the stable tie break
	sort.Slice(users, func(i, j int) bool {
		if users[i]["total"].(int64) != users[j]["total"].(int64) {
			return users[i]["total"].(int64) > users[j]["total"].(int64)
		}
		return users[i]["user_id"].(string) < users[j]["user_id"].(string)
	})

	result, err := starlark_type.ConvertToStarlark(map[string]any{
		"start_date": startDay.Format("2006-01-02"),
		"end_date":   now.Format("2006-01-02"),
		"days":       daysVal,
		"daily":      daily,
		"users":      users,
		"totals": map[string]any{
			"events":       totalEvents,
			"errors":       totalErrors,
			"mgmt":         totalMgmt,
			"http":         totalHTTP,
			"active_users": int64(len(byUser)),
		},
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
