// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

// GetFuncMap returns a template.FuncMap that includes all the sprig functions except for env and expandenv.
func GetFuncMap() template.FuncMap {
	funcMap := sprig.FuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")
	return funcMap
}
