// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"

	"github.com/openrundev/openrun/internal/types"
	"github.com/rs/zerolog"
)

func TestLogger() *types.Logger {
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
	l := zerolog.New(consoleWriter).Level(zerolog.TraceLevel).With().Caller().Timestamp().Logger()
	return &types.Logger{Logger: &l}
}
