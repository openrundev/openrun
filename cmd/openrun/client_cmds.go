// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

func getClientCommands(clientConfig *types.ClientConfig) ([]*cli.Command, error) {
	flags := []cli.Flag{}
	commands := make([]*cli.Command, 0, 6)
	commands = append(commands, initAppCommand(flags, clientConfig))
	commands = append(commands, initApplyCommand(flags, clientConfig))
	commands = append(commands, initSyncCommand(flags, clientConfig))
	commands = append(commands, initParamCommand(flags, clientConfig))
	commands = append(commands, initVersionCommand(flags, clientConfig))
	commands = append(commands, initWebhookCommand(flags, clientConfig))
	commands = append(commands, initPreviewCommand(flags, clientConfig))
	commands = append(commands, initAccountCommand(flags, clientConfig))
	return commands, nil
}
