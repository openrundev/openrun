// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"strings"
	"sync"

	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/plugin"
	"github.com/openrundev/openrun/internal/types"
)

type AppPlugins struct {
	sync.Mutex
	plugins map[string]any

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
		plugins:      make(map[string]any),
		pluginConfig: pluginConfig,
		accountMap:   accountMap,
	}
}

func (p *AppPlugins) GetPlugin(pluginInfo *plugin.PluginInfo, accountName string) (any, error) {
	p.Lock()
	defer p.Unlock()

	appPlugin, ok := p.plugins[pluginInfo.PluginPath]
	if ok {
		// Already initialized, use that
		return appPlugin, nil
	}

	// If account name is specified, use that to lookup the account map
	accountLookupName := pluginInfo.PluginPath
	if accountName != "" {
		accountLookupName = fmt.Sprintf("%s%s%s", pluginInfo.PluginPath, apptype.ACCOUNT_SEPARATOR, accountName) // store.in#myaccount
	}

	pluginAccount := pluginInfo.PluginPath
	_, ok = p.accountMap[accountLookupName]
	if ok {
		pluginAccount = p.accountMap[accountLookupName]
		// If it is just account name, make it full plugin path
		if !strings.Contains(pluginAccount, apptype.ACCOUNT_SEPARATOR) {
			pluginAccount = fmt.Sprintf("%s%s%s", pluginInfo.PluginPath, apptype.ACCOUNT_SEPARATOR, pluginAccount)
		}
	}

	pluginConfig := types.PluginSettings{}
	if _, ok := p.pluginConfig[pluginAccount]; ok {
		pluginConfig = p.pluginConfig[pluginAccount]
	}

	pluginContext := &types.PluginContext{
		Logger:    p.app.Logger,
		AppId:     p.app.Id,
		StoreInfo: p.app.storeInfo,
		Config:    pluginConfig,
		AppConfig: p.app.AppConfig,
		AppPath:   p.app.Path,
	}
	appPlugin, err := pluginInfo.Builder(pluginContext)
	if err != nil {
		return nil, fmt.Errorf("error creating plugin %s: %w", pluginInfo.FuncName, err)
	}

	p.plugins[pluginInfo.PluginPath] = appPlugin
	return appPlugin, nil
}
