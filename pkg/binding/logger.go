// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// Logger is the logger passed to provider implementations. It mirrors the
// OpenRun server's logger type (a zerolog wrapper) so binding code written
// against the server's internal interface ports without changes.
type Logger struct {
	*zerolog.Logger
}

// NewLogger returns a plain stderr logger at the given level ("WARN", "INFO",
// "DEBUG", "TRACE"; anything else means INFO). Intended for provider tests;
// provider processes get their logger from Serve.
func NewLogger(level string) *Logger {
	logger := zerolog.New(os.Stderr).Level(parseLogLevel(level)).With().Timestamp().Logger()
	return &Logger{&logger}
}

func parseLogLevel(level string) zerolog.Level {
	switch strings.ToUpper(level) {
	case "WARN":
		return zerolog.WarnLevel
	case "DEBUG":
		return zerolog.DebugLevel
	case "TRACE":
		return zerolog.TraceLevel
	default:
		return zerolog.InfoLevel
	}
}

// newServeLogger builds the logger used by a provider process. It writes
// hclog-compatible JSON to stderr: go-plugin captures the provider's stderr on
// the host side and re-emits lines that parse as hclog JSON as structured log
// entries in the server log.
//
// Called only from Serve, in the provider process: it changes zerolog's global
// field names to hclog's, which must never happen inside the server process.
func newServeLogger(level string) *Logger {
	zerolog.TimestampFieldName = "@timestamp"
	zerolog.LevelFieldName = "@level"
	zerolog.MessageFieldName = "@message"
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.000000Z07:00"

	logger := zerolog.New(os.Stderr).Level(parseLogLevel(level)).With().Timestamp().Logger()
	return &Logger{&logger}
}
