// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	htmltemplate "html/template"
	"net/url"
	"text/template"

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
	return funcMap
}
