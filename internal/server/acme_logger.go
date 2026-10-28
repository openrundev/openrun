// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// newCertmagicLogger returns a zap logger that forwards certmagic's log
// records into the OpenRun structured logger. Without it certmagic writes to
// stderr through its own default logger, so a failed certificate renewal
// never reaches the OpenRun log files.
func newCertmagicLogger(logger *types.Logger) *zap.Logger {
	return zap.New(&zerologCore{logger: logger.Logger.With().Str("component", "certmagic").Logger()})
}

// zerologCore is a zapcore.Core writing each entry as a zerolog event.
type zerologCore struct {
	logger zerolog.Logger
	fields []zapcore.Field // fields added through With
}

var _ zapcore.Core = (*zerologCore)(nil)

func zapToZerologLevel(level zapcore.Level) zerolog.Level {
	switch {
	case level >= zapcore.ErrorLevel: // Error, DPanic, Panic, Fatal
		return zerolog.ErrorLevel
	case level >= zapcore.WarnLevel:
		return zerolog.WarnLevel
	case level >= zapcore.InfoLevel:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
}

func (c *zerologCore) Enabled(level zapcore.Level) bool {
	return zapToZerologLevel(level) >= c.logger.GetLevel()
}

func (c *zerologCore) With(fields []zapcore.Field) zapcore.Core {
	merged := make([]zapcore.Field, 0, len(c.fields)+len(fields))
	merged = append(merged, c.fields...)
	merged = append(merged, fields...)
	return &zerologCore{logger: c.logger, fields: merged}
}

func (c *zerologCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c *zerologCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	evt := c.logger.WithLevel(zapToZerologLevel(entry.Level))
	if entry.LoggerName != "" {
		evt.Str("logger", entry.LoggerName)
	}
	if entry.Caller.Defined {
		evt.Str(zerolog.CallerFieldName, entry.Caller.TrimmedPath())
	}
	if entry.Stack != "" {
		evt.Str("stack", entry.Stack)
	}

	// Encode the zap fields into a map, so that nested objects and arrays
	// come out as plain values that zerolog can serialize
	enc := zapcore.NewMapObjectEncoder()
	for _, field := range c.fields {
		field.AddTo(enc)
	}
	for _, field := range fields {
		field.AddTo(enc)
	}
	// Deterministic field order keeps the log lines stable
	keys := make([]string, 0, len(enc.Fields))
	for key := range enc.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		evt.Interface(key, enc.Fields[key])
	}
	evt.Msg(entry.Message)
	return nil
}

func (c *zerologCore) Sync() error {
	return nil
}

// logCertmagicEvent is the certmagic OnEvent hook. Certificate outcomes are
// logged at a level matching their severity, so a failed renewal is visible
// in the OpenRun logs regardless of what certmagic itself logs.
func (s *Server) logCertmagicEvent(_ context.Context, event string, data map[string]any) error {
	var evt *zerolog.Event
	switch event {
	case "cert_failed", "cert_ocsp_revoked":
		evt = s.Error()
	case "cert_obtained", "cert_obtaining":
		evt = s.Info()
	default:
		evt = s.Debug()
	}
	evt.Str("component", "certmagic").Str("event", event)
	// Deterministic field order keeps the log lines stable
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch value := data[key].(type) {
		case error:
			evt.Str(key, value.Error())
		case []byte:
			// PEM blobs (csr_pem etc) are not useful in the log
			evt.Int(key+"_bytes", len(value))
		case fmt.Stringer:
			evt.Str(key, value.String())
		default:
			evt.Interface(key, value)
		}
	}
	evt.Msg("certmagic " + strings.ReplaceAll(event, "_", " "))
	return nil
}
