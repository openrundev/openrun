// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/types"
)

func (s *Server) getServerUri() string {
	uri := s.config.Security.CallbackUrl
	if uri == "" {
		if s.config.Https.Port != -1 {
			uri = fmt.Sprintf("https://localhost:%d", s.config.Https.Port)
		} else {
			uri = fmt.Sprintf("http://localhost:%d", s.config.Http.Port)
		}
	}

	return uri
}

func (s *Server) TokenList(ctx context.Context, appPath string) (*types.TokenListResponse, error) {
	appPathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}

	if appEntry.IsDev {
		return nil, fmt.Errorf("token commands not supported for dev app")
	}

	uri := s.getServerUri()
	tokens := []types.AppToken{}
	if appEntry.Settings.WebhookTokens.Reload != "" {
		tokens = append(tokens, types.AppToken{
			Type:  types.WebhookReload,
			Url:   fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookReload, url.QueryEscape(appPath)),
			Token: appEntry.Settings.WebhookTokens.Reload,
		})
	}

	if appEntry.Settings.WebhookTokens.ReloadPromote != "" {
		tokens = append(tokens, types.AppToken{
			Type:  types.WebhookReloadPromote,
			Url:   fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookReloadPromote, url.QueryEscape(appPath)),
			Token: appEntry.Settings.WebhookTokens.ReloadPromote,
		})
	}

	if appEntry.Settings.WebhookTokens.Promote != "" {
		tokens = append(tokens, types.AppToken{
			Type:  types.WebhookPromote,
			Url:   fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookPromote, url.QueryEscape(appPath)),
			Token: appEntry.Settings.WebhookTokens.Promote,
		})
	}

	ret := types.TokenListResponse{Tokens: tokens}
	return &ret, nil
}

func (s *Server) TokenCreate(ctx context.Context, appPath string, webhookType types.WebhookType, dryRun bool) (*types.TokenCreateResponse, error) {
	appPathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}

	secret, err := passwd.GeneratePassword()
	if err != nil {
		return nil, err
	}

	newToken := fmt.Sprintf("cl_tkn_%s", base64.StdEncoding.EncodeToString([]byte(secret)))

	uri := s.getServerUri()
	tokenUrl := ""
	switch webhookType {
	case types.WebhookReload:
		appEntry.Settings.WebhookTokens.Reload = newToken
		tokenUrl = fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookReload, url.QueryEscape(appPath))
	case types.WebhookReloadPromote:
		appEntry.Settings.WebhookTokens.ReloadPromote = newToken
		tokenUrl = fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookReloadPromote, url.QueryEscape(appPath))
	case types.WebhookPromote:
		appEntry.Settings.WebhookTokens.Promote = newToken
		tokenUrl = fmt.Sprintf("%s%s/%s?appPath=%s", uri, types.WEBHOOK_URL_PREFIX, types.WebhookPromote, url.QueryEscape(appPath))
	default:
		return nil, fmt.Errorf("unknown webhook type %s", webhookType)
	}

	// Persist the settings
	if err := s.db.UpdateAppSettings(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	if err = s.CompleteTransaction(ctx, tx, []types.AppPathDomain{appPathDomain}, dryRun, "webhook-create"); err != nil {
		return nil, err
	}

	ret := types.TokenCreateResponse{
		DryRun: dryRun,
		Token: types.AppToken{
			Type:  webhookType,
			Url:   tokenUrl,
			Token: newToken,
		},
	}
	return &ret, nil
}

func (s *Server) TokenDelete(ctx context.Context, appPath string, webhookType types.WebhookType, dryRun bool) (*types.TokenDeleteResponse, error) {
	appPathDomain, err := parseAppPath(appPath)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	appEntry, err := s.db.GetAppTx(ctx, tx, appPathDomain)
	if err != nil {
		return nil, err
	}

	switch webhookType {
	case types.WebhookReload:
		appEntry.Settings.WebhookTokens.Reload = ""
	case types.WebhookReloadPromote:
		appEntry.Settings.WebhookTokens.ReloadPromote = ""
	case types.WebhookPromote:
		appEntry.Settings.WebhookTokens.Promote = ""
	default:
		return nil, fmt.Errorf("unknown webhook type %s", webhookType)
	}

	// Persist the settings
	if err := s.db.UpdateAppSettings(ctx, tx, appEntry); err != nil {
		return nil, err
	}

	if err = s.CompleteTransaction(ctx, tx, []types.AppPathDomain{appPathDomain}, dryRun, "webhook-delete"); err != nil {
		return nil, err
	}

	ret := types.TokenDeleteResponse{
		DryRun: dryRun,
	}
	return &ret, nil
}
