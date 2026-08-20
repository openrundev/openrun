// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"fmt"
	"sync"
)

// The embedded provider registry lets a plugin run compiled into the OpenRun
// binary instead of as a separate provider process. A plugin package calls
// RegisterEmbedded from an init function with the same ServeConfig its
// provider executable passes to Serve; a custom OpenRun build then just
// blank-imports the package:
//
//	import _ "example.com/myplugin"
//
// The server picks the registry up at startup and serves each module
// in-process (no gRPC, no serialization) under the same "<module>.in" name
// the external build would serve, so apps do not change between the two.

var (
	embeddedMutex     sync.Mutex
	embeddedProviders = map[string]*ServeConfig{}
)

// RegisterEmbedded registers a provider config to be served in-process by an
// OpenRun binary this package is compiled into. Call it from an init
// function; the config is validated and conflicts (same provider name, or a
// module already served by another embedded provider) panic, so a bad custom
// build fails at startup rather than on a user request.
func RegisterEmbedded(name string, config *ServeConfig) {
	if name == "" {
		panic("plugin.RegisterEmbedded: provider name must not be empty")
	}
	if err := validateConfig(config); err != nil {
		panic(fmt.Sprintf("plugin.RegisterEmbedded %s: %s", name, err))
	}

	embeddedMutex.Lock()
	defer embeddedMutex.Unlock()
	if _, exists := embeddedProviders[name]; exists {
		panic(fmt.Sprintf("plugin.RegisterEmbedded: provider %s is already registered", name))
	}
	for moduleName := range config.Modules {
		for otherName, other := range embeddedProviders {
			if _, ok := other.Modules[moduleName]; ok {
				panic(fmt.Sprintf("plugin.RegisterEmbedded: module %s of provider %s is already served by provider %s", moduleName, name, otherName))
			}
		}
	}
	embeddedProviders[name] = config
}

// EmbeddedProviders returns the registered embedded providers by name.
func EmbeddedProviders() map[string]*ServeConfig {
	embeddedMutex.Lock()
	defer embeddedMutex.Unlock()
	out := make(map[string]*ServeConfig, len(embeddedProviders))
	for name, config := range embeddedProviders {
		out[name] = config
	}
	return out
}
