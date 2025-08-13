// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

const (
	APP_FILE_NAME         = "app.star"
	APP_CONFIG_KEY        = "app"
	DEFAULT_HANDLER       = "handler"
	ERROR_HANDLER         = "error_handler"
	METHODS_DELIMITER     = ","
	CONFIG_LOCK_FILE_NAME = "config_gen.lock"
	SCHEMA_FILE_NAME      = "schema.star"
	PARAMS_FILE_NAME      = "params.star"
	BUILTIN_PLUGIN_SUFFIX = "in"
	STARLARK_FILE_SUFFIX  = ".star"
	INDEX_FILE            = "index.go.html"
	INDEX_GEN_FILE        = "index_gen.go.html"
	CLACE_GEN_FILE        = "openrun_gen.go.html"
	ACCOUNT_SEPARATOR     = "#"
)

type DeferFunc func() error
type DeferEntry struct {
	Func   DeferFunc
	Strict bool
}
