// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
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
	return funcMap
}
