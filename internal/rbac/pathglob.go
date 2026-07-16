// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"

	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/types"
)

// createPathDomain creates a slice of AppPathDomain from a slice of AppInfo
func createPathDomain(apps []types.AppInfo) []types.AppPathDomain {
	ret := make([]types.AppPathDomain, 0, len(apps))
	for _, app := range apps {
		ret = append(ret, app.AppPathDomain)
	}

	return ret
}

// ParseGlobFromInfo parses a path spec in the format of domain:path.  If domain is not specified, it will match empty domain.
// glob patters are supported, *:** matches all apps.
func ParseGlobFromInfo(appPathGlob string, apps []types.AppInfo) ([]types.AppInfo, error) {
	appPathDomain := createPathDomain(apps)
	pathDomains, error := ParseGlob(appPathGlob, appPathDomain)
	if error != nil {
		return nil, error
	}
	found := map[string]bool{}
	for _, pathDomain := range pathDomains {
		found[pathDomain.String()] = true
	}

	ret := make([]types.AppInfo, 0, len(found))
	for _, app := range apps {
		if found[app.String()] {
			ret = append(ret, app)
		}
	}
	return ret, nil
}

func MatchGlob(appPathGlob string, app types.AppPathDomain) (bool, error) {
	apps, err := ParseGlob(appPathGlob, []types.AppPathDomain{app})
	if err != nil {
		return false, err
	}
	return len(apps) > 0, nil
}

// splitGlob normalizes and splits a path spec in the format of domain:path
// into its domain and app path glob patterns. "" and "all" mean all apps
// (*:**); a missing domain part yields domain "" (matches the empty domain)
func splitGlob(appPathGlob string) (domain, app string, err error) {
	if appPathGlob == "" || strings.ToLower(appPathGlob) == "all" {
		appPathGlob = "*:**"
	}
	split := strings.Split(appPathGlob, ":")
	if len(split) > 2 {
		return "", "", fmt.Errorf("path glob has to be in the format of domain:path")
	}
	if len(split) == 2 {
		domain = split[0]
		app = split[1]
	} else {
		app = split[0]
	}

	if app == "*" { //nolint:staticcheck
		app = "/*"
	} else if app == "" {
		app = "/"
	}
	return domain, app, nil
}

// ValidateGlob checks that a grant target entry is well formed, so bad
// patterns are rejected when the config is updated instead of erroring every
// authorization check that evaluates them. An entry is a domain:path app glob,
// a service:<id glob> entry (matched against <type>/<name> service ids) or a
// binding:<path glob> entry (matched against binding paths)
func ValidateGlob(targetGlob string) error {
	if pattern, ok := strings.CutPrefix(targetGlob, TargetServicePrefix); ok {
		if pattern == "" {
			return fmt.Errorf("service target glob cannot be empty")
		}
		if strings.HasPrefix(pattern, "/") {
			return fmt.Errorf("service target glob %q must match service ids like postgres/main, without a leading /", pattern)
		}
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid service target glob %s", pattern)
		}
		return nil
	}
	if pattern, ok := strings.CutPrefix(targetGlob, TargetBindingPrefix); ok {
		if !strings.HasPrefix(pattern, "/") {
			return fmt.Errorf("binding target glob %q must match binding paths, starting with /", pattern)
		}
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid binding target glob %s", pattern)
		}
		return nil
	}
	domain, app, err := splitGlob(targetGlob)
	if err != nil {
		return err
	}
	if !doublestar.ValidatePattern(app) {
		return fmt.Errorf("invalid path glob app value %s", app)
	}
	if domain != "" && !doublestar.ValidatePattern("/"+domain) {
		return fmt.Errorf("invalid path glob domain value %s", domain)
	}
	return nil
}

// targetKind is the namespace a grant target entry (and a scoped permission)
// applies to: app path domains, service ids or binding paths
type targetKind int

const (
	targetKindApp targetKind = iota
	targetKindService
	targetKindBinding
)

// Grant target entry prefixes for the non-app target kinds. A target entry
// like service:postgres/* scopes service:* permissions to matching service
// ids (<type>/<name>, no leading slash); binding:/apps/** scopes binding:*
// permissions to matching binding paths. Entries without these prefixes are
// app path targets ("service" and "binding" are reserved words in the target
// domain position, they cannot be used as app domain patterns)
const (
	TargetServicePrefix = "service:"
	TargetBindingPrefix = "binding:"
)

// parsedTarget is a grant target entry pre-parsed at config update time, so
// grant checks do not re-parse the glob on every authorization. App entries
// match identically to ParseGlob with a single entry
type parsedTarget struct {
	kind          targetKind
	all           bool   // entry matches every target of every kind ("", "all", *:**)
	domainPattern string // app kind: "/" + domain pattern, "" when the glob has no domain part
	pattern       string // app kind: the app path pattern; service/binding kind: the id/path pattern
	err           error  // parse error, returned on every match attempt (fail closed)
}

// parseTarget pre-parses a grant target entry. A malformed entry is captured
// in the returned target's err and fails every match (config validation
// rejects these upfront for grants; this is the backstop for stored values)
func parseTarget(targetGlob string) parsedTarget {
	if targetGlob == "*:**" || targetGlob == "" || strings.ToLower(targetGlob) == "all" {
		return parsedTarget{all: true}
	}
	if pattern, ok := strings.CutPrefix(targetGlob, TargetServicePrefix); ok {
		return parsedTarget{kind: targetKindService, pattern: pattern}
	}
	if pattern, ok := strings.CutPrefix(targetGlob, TargetBindingPrefix); ok {
		return parsedTarget{kind: targetKindBinding, pattern: pattern}
	}
	domain, app, err := splitGlob(targetGlob)
	if err != nil {
		return parsedTarget{err: err}
	}
	target := parsedTarget{kind: targetKindApp, pattern: app}
	if domain != "" {
		target.domainPattern = "/" + domain
	}
	return target
}

// matchesApp reports whether the app at entry is within an app target glob,
// mirroring ParseGlob's matching for a single entry
func (t parsedTarget) matchesApp(entry types.AppPathDomain) (bool, error) {
	if t.err != nil {
		return false, t.err
	}
	if t.all {
		return true, nil
	}
	if t.kind != targetKindApp {
		return false, nil
	}
	appMatch, err := doublestar.Match(t.pattern, entry.Path)
	if err != nil {
		return false, fmt.Errorf("invalid path glob app value %s: %s", t.pattern, err)
	}
	if !appMatch {
		return false, nil
	}
	if t.domainPattern == "" {
		// no domain in the glob: match only the empty domain
		return entry.Domain == "", nil
	}
	domainMatch, err := doublestar.Match(t.domainPattern, "/"+entry.Domain)
	if err != nil {
		return false, fmt.Errorf("invalid path glob domain value %s: %s", t.domainPattern[1:], err)
	}
	return domainMatch, nil
}

// matchesResource reports whether the service id or binding path resourceId is
// within a target entry of the given kind
func (t parsedTarget) matchesResource(kind targetKind, resourceId string) (bool, error) {
	if t.err != nil {
		return false, t.err
	}
	if t.all {
		return true, nil
	}
	if t.kind != kind {
		return false, nil
	}
	match, err := doublestar.Match(t.pattern, resourceId)
	if err != nil {
		return false, fmt.Errorf("invalid target glob value %s: %s", t.pattern, err)
	}
	return match, nil
}

// ParseGlob parses a path spec in the format of domain:path. If domain is not specified, it will match empty domain.
// glob patters are supported, *:** matches all apps.
func ParseGlob(appPathGlob string, apps []types.AppPathDomain) ([]types.AppPathDomain, error) {
	if appPathGlob == "*:**" || appPathGlob == "" || strings.ToLower(appPathGlob) == "all" {
		return apps, nil // all apps match
	}
	domain, app, err := splitGlob(appPathGlob)
	if err != nil {
		return nil, err
	}

	ret := make([]types.AppPathDomain, 0)
	for _, entry := range apps {
		appMatch, err := doublestar.Match(app, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid path glob app value %s: %s", app, err)
		}
		if !appMatch {
			continue
		}
		if domain == "" && entry.Domain == "" {
			ret = append(ret, entry)
		} else {
			domainMatch, err := doublestar.Match("/"+domain, "/"+entry.Domain)
			if err != nil {
				return nil, fmt.Errorf("invalid path glob domain value %s: %s", domain, err)
			}
			if domainMatch {
				ret = append(ret, entry)
			}
		}
	}
	return ret, nil
}
