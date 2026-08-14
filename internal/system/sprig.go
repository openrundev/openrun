// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	htmltemplate "html/template"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
)

// GetFuncMap returns a template.FuncMap that includes all the sprig functions except for env and expandenv.
func GetFuncMap() template.FuncMap {
	funcMap := sprig.FuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")
	funcMap["pathEscape"] = url.PathEscape
	funcMap["pathUnescape"] = url.PathUnescape
	funcMap["queryEscape"] = url.QueryEscape
	funcMap["queryUnescape"] = url.QueryUnescape
	// safeHTML marks a handler-built string as pre-escaped markup, opting it
	// out of html/template's contextual escaping (sprig has no equivalent).
	// Apps that render server-side HTML (markdown previews, rich text) need
	// it; any user input must be escaped while building the string
	funcMap["safeHTML"] = func(s string) htmltemplate.HTML { return htmltemplate.HTML(s) }
	// relTime renders a timestamp as a relative age via HumanDuration,
	// defaulting to a single unit - "1 day ago", "3 hours ago", "recently" -
	// so hours never accumulate past a day ("1540 hours" renders as days).
	// An optional resolution argument widens it: {{ relTime .t 2 }} gives
	// "1 day 3 hours ago". Accepts time.Time or an RFC3339 string
	// (fractional seconds and offsets tolerated); zero times and
	// unparseable values render as "-"
	funcMap["relTime"] = relTime
	return funcMap
}

func relTime(value any, resolution ...int) string {
	var t time.Time
	switch v := value.(type) {
	case time.Time:
		t = v
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
		if err != nil {
			return "-"
		}
		t = parsed
	default:
		return "-"
	}
	if t.IsZero() {
		return "-"
	}
	units := 1
	if len(resolution) > 0 && resolution[0] > 0 {
		units = resolution[0]
	}
	return HumanDuration(time.Since(t), units)
}
