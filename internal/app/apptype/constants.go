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
	// ACTIONS_FILE_NAME is the optional convention file declaring actions
	// (and permissions) outside app.star, so an app built from a spec can add
	// actions without owning the spec's app.star
	ACTIONS_FILE_NAME = "actions.star"
	// ACTION_PARAMS_FILE_NAME declares the params shown on the action
	// surfaces; when present, only its params are shown (see spec-actions.md)
	ACTION_PARAMS_FILE_NAME = "action_params.star"
	// ACTIONS_KEY and ACTION_PERMISSIONS_KEY are the globals read from actions.star
	ACTIONS_KEY            = "actions"
	ACTION_PERMISSIONS_KEY = "permissions"
	// BUILTIN_PLUGIN_SUFFIX is the standard plugin module suffix:
	// load("store.in", "store"). Resolution prefers a module compiled into
	// the binary and falls back to an external provider serving that name
	BUILTIN_PLUGIN_SUFFIX = "in"
	// EXTERNAL_PLUGIN_SUFFIX explicitly requires the module's external
	// (out-of-process plugin provider) build: load("store.ex", "store")
	EXTERNAL_PLUGIN_SUFFIX = "ex"
	STARLARK_FILE_SUFFIX   = ".star"
	INDEX_FILE             = "index.go.html"
	INDEX_GEN_FILE         = "index_gen.go.html"
	CLACE_GEN_FILE         = "openrun_gen.go.html"
	ACCOUNT_SEPARATOR      = "#"
)

type DeferFunc func() error
type DeferEntry struct {
	Func   DeferFunc
	Strict bool
}
