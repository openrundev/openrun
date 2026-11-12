// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

// A secret key with a ".." segment must not pass the allowed pattern check
// for one secret and then be read from another path by the vault client
func TestVaultSecretKeyTraversalRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			fmt.Fprint(w, `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`) //nolint:errcheck
		case "/v1/secret/data/myapp/db":
			fmt.Fprint(w, `{"data":{"data":{"value":"own-secret"}}}`) //nolint:errcheck
		case "/v1/secret/data/payments/stripe":
			fmt.Fprint(w, `{"data":{"data":{"value":"other-secret"}}}`) //nolint:errcheck
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[]}`) //nolint:errcheck
		}
	}))
	defer srv.Close()

	mgr, err := NewSecretManager(context.Background(), map[string]types.SecretConfig{
		"vault": {"address": srv.URL, "token": "t"},
	}, "vault", &types.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := mgr.AppEvalTemplate([][]string{{"secret/myapp/db"}}, "", `{{secret "secret/myapp/db"}}`, true)
	if err != nil || got != "own-secret" {
		t.Fatalf("approved secret: got %q err %v", got, err)
	}

	tests := []struct {
		perms [][]string
		tmpl  string
	}{
		{[][]string{{"secret/myapp/db"}}, `{{secret "secret/myapp/db" ".." ".." "payments" "stripe"}}`},
		{[][]string{{"regex:^secret/myapp/.*"}}, `{{secret "secret/myapp/../payments/stripe"}}`},
		{[][]string{{"regex:^secret/myapp/.*"}}, `{{secret "secret/myapp/./db"}}`},
		{[][]string{{"secret/myapp/db"}}, `{{secret "secret/myapp/db" ""}}`},
	}
	for _, test := range tests {
		got, err := mgr.AppEvalTemplate(test.perms, "", test.tmpl, true)
		if err == nil || strings.Contains(got, "secret") {
			t.Fatalf("template %s: expected an error, got %q err %v", test.tmpl, got, err)
		}
	}

	// The provider itself refuses a path which is not clean, for callers
	// which do not go through the app permission check
	provider := mgr.providers["vault"]
	for _, p := range []string{"secret/myapp/../payments/stripe", "/secret/myapp/db", "secret//myapp/db", ""} {
		if _, err := provider.GetSecret(context.Background(), p); err == nil {
			t.Fatalf("expected vault path %q to be rejected", p)
		}
	}
}
