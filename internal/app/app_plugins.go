// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
)

type AppPlugins struct {
	sync.Mutex

	app          *App
	pluginConfig map[string]types.PluginSettings // pluginName -> accountName -> PluginSettings, from openrun.toml
	accountMap   map[string]string               // pluginName -> accountName, from app account links
}

func NewAppPlugins(app *App, pluginConfig map[string]types.PluginSettings, appAccounts []types.AccountLink) *AppPlugins {
	accountMap := make(map[string]string)
	for _, entry := range appAccounts {
		accountMap[entry.Plugin] = entry.AccountName
	}

	return &AppPlugins{
		app:          app,
		pluginConfig: pluginConfig,
		accountMap:   accountMap,
	}
}

// GetPluginSettings resolves the plugin settings for a plugin path and
// account, applying the same app account-link resolution as GetPlugin. Used
// for external plugin providers, whose instances live in the provider
// process instead of the AppPlugins instance cache.
func (p *AppPlugins) GetPluginSettings(pluginPath, accountName string) types.PluginSettings {
	p.Lock()
	defer p.Unlock()

	accountLookupName := pluginPath
	if accountName != "" {
		accountLookupName = fmt.Sprintf("%s%s%s", pluginPath, apptype.ACCOUNT_SEPARATOR, accountName)
	}

	pluginAccount := pluginPath
	if linked, ok := p.accountMap[accountLookupName]; ok {
		pluginAccount = linked
		if !strings.Contains(pluginAccount, apptype.ACCOUNT_SEPARATOR) {
			pluginAccount = fmt.Sprintf("%s%s%s", pluginPath, apptype.ACCOUNT_SEPARATOR, pluginAccount)
		}
	}

	if settings, ok := p.pluginConfig[pluginAccount]; ok {
		return settings
	}
	return types.PluginSettings{}
}
