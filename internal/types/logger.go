// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"io"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	*zerolog.Logger
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

	level := strings.ToUpper(config.Level)
	var logLevel zerolog.Level
	switch level {
	case "WARN":
		logLevel = zerolog.WarnLevel
	case "INFO":
		logLevel = zerolog.InfoLevel
	case "DEBUG":
		logLevel = zerolog.DebugLevel
	case "TRACE":
		logLevel = zerolog.TraceLevel
	default:
		log.Warn().Str("level", level).Msg("Unknown log level, defaulting to INFO")
		logLevel = zerolog.InfoLevel
	}

	logger := zerolog.New(mw).Level(logLevel).With().Caller().Timestamp().Logger()
	logger.Info().Str("loglevel", logger.GetLevel().String()).Int("maxSizeMB",
		config.MaxSizeMB).Int("backups", config.MaxBackups).Msg("Logger initialized ")
	return &Logger{&logger}
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
