// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	*zerolog.Logger
	// slogAt builds a slog.Logger over the same sinks at the given level;
	// set by NewLogger only (hand-built Logger literals leave it nil and
	// SlogAt falls back to slog.Default())
	slogAt func(level zerolog.Level) *slog.Logger
}

// ParseLogLevel maps a config level string to a zerolog level. The second
// return is false for unknown values, which map to INFO.
func ParseLogLevel(level string) (zerolog.Level, bool) {
	switch strings.ToUpper(level) {
	case "ERROR":
		return zerolog.ErrorLevel, true
	case "WARN":
		return zerolog.WarnLevel, true
	case "INFO":
		return zerolog.InfoLevel, true
	case "DEBUG":
		return zerolog.DebugLevel, true
	case "TRACE":
		return zerolog.TraceLevel, true
	default:
		return zerolog.InfoLevel, false
	}
}

// EffectiveLitestreamLevel is the log level for litestream replication logs
// (the embedded metadata replication and the app sidecar containers):
// litestream_log_level when set, else the main level.
func (c *LogConfig) EffectiveLitestreamLevel() string {
	if c.LitestreamLogLevel != "" {
		return c.LitestreamLogLevel
	}
	return c.Level
}

func NewLogger(config *LogConfig) *Logger {
	var writers []io.Writer
	if config.Console {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr})
	}
	if config.File {
		fileWriter := RollingFileLogger(config, "openrun.json")
		if fileWriter != nil {
			writers = append(writers, fileWriter)
		}
	}
	mw := io.MultiWriter(writers...)

	logLevel, ok := ParseLogLevel(config.Level)
	if !ok {
		log.Warn().Str("level", config.Level).Msg("Unknown log level, defaulting to INFO")
	}

	logger := zerolog.New(mw).Level(logLevel).With().Caller().Timestamp().Logger()
	logger.Info().Str("loglevel", logger.GetLevel().String()).Int("maxSizeMB",
		config.MaxSizeMB).Int("backups", config.MaxBackups).Msg("Logger initialized ")

	// Bridge log/slog into the same sinks: dependencies that log via
	// slog.Default() (litestream is embedded as a library) otherwise write
	// plain text to stderr, bypassing the level filter and the log files.
	// The bridge logger has no zerolog caller hook - the slog record's own
	// PC is used, so the caller field points at the dependency's call site.
	slogAt := func(lvl zerolog.Level) *slog.Logger {
		zl := zerolog.New(mw).Level(lvl).With().Timestamp().Logger()
		return slog.New(&slogZerologHandler{logger: zl})
	}
	slog.SetDefault(slogAt(logLevel))

	return &Logger{Logger: &logger, slogAt: slogAt}
}

// SlogAt returns a slog.Logger writing to this logger's sinks at the given
// level ("" = this logger's own level). For hand-built Logger values (tests,
// per-app sub-loggers) it returns slog.Default().
func (l *Logger) SlogAt(level string) *slog.Logger {
	if l.slogAt == nil {
		return slog.Default()
	}
	if level == "" {
		return l.slogAt(l.GetLevel())
	}
	lvl, ok := ParseLogLevel(level)
	if !ok {
		l.Warn().Str("level", level).Msg("Unknown log level, defaulting to INFO")
	}
	return l.slogAt(lvl)
}

// slogZerologHandler forwards slog records to a zerolog logger, preserving
// level filtering (via the target logger's level), attributes and groups.
type slogZerologHandler struct {
	logger zerolog.Logger
	attrs  []qualifiedAttr
	group  string // dotted prefix from WithGroup
}

// qualifiedAttr is a WithAttrs attribute with the group prefix that was open
// when it was added (a later WithGroup must not re-qualify earlier attrs).
type qualifiedAttr struct {
	prefix string
	attr   slog.Attr
}

func slogToZerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level >= slog.LevelError:
		return zerolog.ErrorLevel
	case level >= slog.LevelWarn:
		return zerolog.WarnLevel
	case level >= slog.LevelInfo:
		return zerolog.InfoLevel
	case level >= slog.LevelDebug:
		return zerolog.DebugLevel
	default:
		return zerolog.TraceLevel
	}
}

func (h *slogZerologHandler) Enabled(_ context.Context, level slog.Level) bool {
	return slogToZerologLevel(level) >= h.logger.GetLevel()
}

func (h *slogZerologHandler) Handle(_ context.Context, rec slog.Record) error {
	evt := h.logger.WithLevel(slogToZerologLevel(rec.Level))
	if rec.PC != 0 {
		frames := runtime.CallersFrames([]uintptr{rec.PC})
		if frame, _ := frames.Next(); frame.File != "" {
			evt.Str(zerolog.CallerFieldName, frame.File+":"+strconv.Itoa(frame.Line))
		}
	}
	for _, qa := range h.attrs {
		addSlogAttr(evt, qa.prefix, qa.attr)
	}
	rec.Attrs(func(attr slog.Attr) bool {
		addSlogAttr(evt, h.group, attr)
		return true
	})
	evt.Msg(rec.Message)
	return nil
}

func addSlogAttr(evt *zerolog.Event, prefix string, attr slog.Attr) {
	value := attr.Value.Resolve()
	key := attr.Key
	if prefix != "" && key != "" {
		key = prefix + "." + key
	}
	if value.Kind() == slog.KindGroup {
		groupPrefix := prefix
		if attr.Key != "" {
			groupPrefix = key
		}
		for _, groupAttr := range value.Group() {
			addSlogAttr(evt, groupPrefix, groupAttr)
		}
		return
	}
	if key == "" {
		return
	}
	evt.Interface(key, value.Any())
}

func (h *slogZerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]qualifiedAttr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	for _, attr := range attrs {
		merged = append(merged, qualifiedAttr{prefix: h.group, attr: attr})
	}
	return &slogZerologHandler{logger: h.logger, attrs: merged, group: h.group}
}

func (h *slogZerologHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	group := name
	if h.group != "" {
		group = h.group + "." + name
	}
	return &slogZerologHandler{logger: h.logger, attrs: h.attrs, group: group}
}

func RollingFileLogger(config *LogConfig, logType string) io.Writer {
	dir := os.ExpandEnv("$OPENRUN_HOME/logs")
	if err := os.MkdirAll(dir, 0744); err != nil {
		log.Error().Err(err).Str("path", dir).Msg("cannot create logging directory")
		return nil
	}

	return &lumberjack.Logger{
		Filename:   path.Join(dir, logType),
		MaxBackups: config.MaxBackups,
		MaxSize:    config.MaxSizeMB,
	}
}
