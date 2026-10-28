// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
)

// newBufferLogger returns a JSON logger writing to buf at the given level.
func newBufferLogger(buf *bytes.Buffer, level zerolog.Level) *types.Logger {
	l := zerolog.New(buf).Level(level)
	return &types.Logger{Logger: &l}
}

func decodeLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid log line %q: %v", line, err)
		}
		lines = append(lines, entry)
	}
	return lines
}

// certmagic's zap log records land in the OpenRun logger with their level,
// logger name and fields
func TestCertmagicLoggerForwardsToZerolog(t *testing.T) {
	var buf bytes.Buffer
	logger := newCertmagicLogger(newBufferLogger(&buf, zerolog.InfoLevel))

	logger.Named("renew").Error("could not get certificate from issuer",
		zap.String("identifier", "example.com"),
		zap.Error(errors.New("acme: alreadyReplaced")))
	logger.With(zap.Int("attempt", 2)).Warn("retrying")
	logger.Debug("not logged at info level")

	lines := decodeLogLines(t, &buf)
	testutil.AssertEqualsInt(t, "log lines", 2, len(lines))

	testutil.AssertEqualsString(t, "level", "error", lines[0]["level"].(string))
	testutil.AssertEqualsString(t, "component", "certmagic", lines[0]["component"].(string))
	testutil.AssertEqualsString(t, "logger", "renew", lines[0]["logger"].(string))
	testutil.AssertEqualsString(t, "message", "could not get certificate from issuer", lines[0]["message"].(string))
	testutil.AssertEqualsString(t, "identifier", "example.com", lines[0]["identifier"].(string))
	testutil.AssertEqualsString(t, "error", "acme: alreadyReplaced", lines[0]["error"].(string))

	testutil.AssertEqualsString(t, "level", "warn", lines[1]["level"].(string))
	testutil.AssertEqualsInt(t, "attempt", 2, int(lines[1]["attempt"].(float64)))
}

// Certificate failure events are logged at error level with the failure
// details, success events at info
func TestLogCertmagicEvent(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{Logger: newBufferLogger(&buf, zerolog.InfoLevel)}
	ctx := context.Background()

	testutil.AssertNoError(t, s.logCertmagicEvent(ctx, "cert_failed", map[string]any{
		"renewal":    true,
		"identifier": "example.com",
		"issuers":    []string{"acme-v02.api.letsencrypt.org-directory"},
		"error":      errors.New("creating new order: alreadyReplaced"),
	}))
	testutil.AssertNoError(t, s.logCertmagicEvent(ctx, "cert_obtained", map[string]any{
		"renewal":    true,
		"identifier": "example.com",
		"csr_pem":    []byte("-----BEGIN CERTIFICATE REQUEST-----"),
	}))
	testutil.AssertNoError(t, s.logCertmagicEvent(ctx, "tls_get_certificate", map[string]any{}))

	lines := decodeLogLines(t, &buf)
	testutil.AssertEqualsInt(t, "log lines", 2, len(lines))

	testutil.AssertEqualsString(t, "level", "error", lines[0]["level"].(string))
	testutil.AssertEqualsString(t, "event", "cert_failed", lines[0]["event"].(string))
	testutil.AssertEqualsString(t, "error", "creating new order: alreadyReplaced", lines[0]["error"].(string))
	testutil.AssertEqualsBool(t, "renewal", true, lines[0]["renewal"].(bool))
	testutil.AssertEqualsString(t, "message", "certmagic cert failed", lines[0]["message"].(string))

	testutil.AssertEqualsString(t, "level", "info", lines[1]["level"].(string))
	testutil.AssertEqualsString(t, "event", "cert_obtained", lines[1]["event"].(string))
	if _, ok := lines[1]["csr_pem"]; ok {
		t.Fatal("expected PEM blob to be logged as a length, not content")
	}
	testutil.AssertEqualsInt(t, "csr_pem_bytes", 35, int(lines[1]["csr_pem_bytes"].(float64)))
}
