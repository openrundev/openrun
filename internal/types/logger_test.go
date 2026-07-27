// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func bridgeForTest(buf *bytes.Buffer, level zerolog.Level) *slog.Logger {
	zl := zerolog.New(buf).Level(level)
	return slog.New(&slogZerologHandler{logger: zl})
}

// TestSlogBridgeLevels verifies slog records honor the zerolog target level:
// litestream's INFO chatter must be filtered when the litestream level is
// WARN, while WARN and ERROR still get through.
func TestSlogBridgeLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := bridgeForTest(&buf, zerolog.WarnLevel)

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")
	logger.Error("error msg")

	out := buf.String()
	if strings.Contains(out, "debug msg") || strings.Contains(out, "info msg") {
		t.Fatalf("below-level records were not filtered: %s", out)
	}
	if !strings.Contains(out, "warn msg") || !strings.Contains(out, "error msg") {
		t.Fatalf("warn/error records missing: %s", out)
	}
}

// TestSlogBridgeAttrsAndGroups verifies With attributes, record attributes
// and group qualification land as zerolog fields.
func TestSlogBridgeAttrsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := bridgeForTest(&buf, zerolog.InfoLevel)

	logger.With("litestream_db", "metadata").WithGroup("sync").Info("replica sync", "txid", 42)

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not one JSON record: %v (%s)", err, buf.String())
	}
	if record["litestream_db"] != "metadata" {
		t.Fatalf("With attr missing or wrong: %v", record)
	}
	// The group opened after With must not re-qualify the earlier attr, but
	// must qualify the record attr
	if record["sync.txid"] != float64(42) {
		t.Fatalf("grouped record attr missing: %v", record)
	}
	if record["message"] != "replica sync" {
		t.Fatalf("message missing: %v", record)
	}
}

func TestEffectiveLitestreamLevel(t *testing.T) {
	c := &LogConfig{Level: "INFO"}
	if got := c.EffectiveLitestreamLevel(); got != "INFO" {
		t.Fatalf("default should follow level, got %q", got)
	}
	c.LitestreamLogLevel = "WARN"
	if got := c.EffectiveLitestreamLevel(); got != "WARN" {
		t.Fatalf("explicit litestream_log_level should win, got %q", got)
	}
}

func TestParseLogLevel(t *testing.T) {
	for input, want := range map[string]zerolog.Level{
		"ERROR": zerolog.ErrorLevel, "warn": zerolog.WarnLevel, "INFO": zerolog.InfoLevel,
		"Debug": zerolog.DebugLevel, "TRACE": zerolog.TraceLevel,
	} {
		got, ok := ParseLogLevel(input)
		if !ok || got != want {
			t.Fatalf("ParseLogLevel(%q) = %v, %v", input, got, ok)
		}
	}
	if got, ok := ParseLogLevel("bogus"); ok || got != zerolog.InfoLevel {
		t.Fatalf("unknown level should map to INFO with ok=false, got %v, %v", got, ok)
	}
}
