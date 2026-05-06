// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package bindings

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
)

type PostgresServiceBinding struct {
	serviceConfig map[string]string
	bindingConfig map[string]any

	adminConn *sql.DB // The admin connection to the main database, available after InitService
}

func init() {
	RegisterServiceBinding("postgres", NewPostgresServiceBinding)
}

var _ ServiceBinding = (*PostgresServiceBinding)(nil)

func NewPostgresServiceBinding() ServiceBinding {
	return &PostgresServiceBinding{}
}

func (b *PostgresServiceBinding) InitService(ctx context.Context, serviceConfig map[string]string) error {
	if err := verifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}); err != nil {
		return err
	}

	url := serviceConfig["url"]
	adminConn, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}

	if err := adminConn.PingContext(ctx); err != nil {
		return fmt.Errorf("error verifying postgres connection: %w", err)
	}

	b.serviceConfig = serviceConfig
	b.adminConn = adminConn
	return nil
}

func (b *PostgresServiceBinding) InitRootBinding(ctx context.Context, bindingConfig map[string]any) error {
	if len(bindingConfig) != 0 {
		return fmt.Errorf("config keys are not allowed for root binding")
	}
	b.bindingConfig = bindingConfig
	return nil
}

func (b *PostgresServiceBinding) GenerateAccount(ctx context.Context) map[string]any {
	return nil
}
