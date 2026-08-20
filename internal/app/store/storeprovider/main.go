// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Command storeprovider is the out-of-process provider build of the store
// plugin: the same module implementation that is compiled into OpenRun as
// "store.in" (internal/app/store), served as an external provider. It
// validates the external plugin provider mechanism against the full store
// test suite and serves as the reference for building plugin providers.
package main

import (
	"github.com/openrundev/openrun/internal/app/store"
	plugin "github.com/openrundev/openrun/pkg/plugin"
)

var version = "dev" // set with -ldflags "-X main.version=v0.x.y"

func main() {
	plugin.Serve(store.ProviderConfig(version))
}
