// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"

	"github.com/urfave/cli/v2"
)

type cliFlagSpec struct {
	isBool bool
}

// normalizeInterspersedFlags makes command flags work before or after
// positional args. urfave/cli uses the standard flag package, which stops
// parsing flags after the first positional arg.
func normalizeInterspersedFlags(app *cli.App, argv []string) []string {
	if len(argv) <= 1 {
		return argv
	}

	normalized := make([]string, 0, len(argv))
	normalized = append(normalized, argv[0])
	normalized = append(normalized, normalizeCommandArgs(argv[1:], app.Commands, app.Flags)...)
	return normalized
}

// normalizeCommandArgs walks down the selected command path and normalizes
// only the args that belong to each command level.
func normalizeCommandArgs(args []string, commands []*cli.Command, flags []cli.Flag) []string {
	if len(args) == 0 {
		return args
	}

	flagSpecs := buildFlagSpecs(flags)
	subcommandIndex, subcommand := findSubcommandArg(args, commands, flagSpecs)
	if subcommand != nil {
		normalized := make([]string, 0, len(args))
		normalized = append(normalized, normalizeKnownFlags(args[:subcommandIndex], flagSpecs)...)
		normalized = append(normalized, args[subcommandIndex])
		normalized = append(normalized, normalizeCommandArgs(args[subcommandIndex+1:], subcommand.Subcommands, subcommand.Flags)...)
		return normalized
	}

	return normalizeKnownFlags(args, flagSpecs)
}

// findSubcommandArg skips over known flags and their values so a flag value
// that matches a subcommand name is not treated as the next command.
func findSubcommandArg(args []string, commands []*cli.Command, flagSpecs map[string]cliFlagSpec) (int, *cli.Command) {
	for i := 0; i < len(args); {
		if args[i] == "--" {
			return -1, nil
		}
		if _, consumed, ok := parseKnownFlagArg(args, i, flagSpecs); ok {
			i += consumed
			continue
		}
		for _, command := range commands {
			if command.HasName(args[i]) {
				return i, command
			}
		}
		i++
	}
	return -1, nil
}

// normalizeKnownFlags moves recognized flags before positional args while
// preserving the original relative order of flags and positionals.
func normalizeKnownFlags(args []string, flagSpecs map[string]cliFlagSpec) []string {
	flagArgs := make([]string, 0, len(args))
	positionArgs := make([]string, 0, len(args))

	for i := 0; i < len(args); {
		if args[i] == "--" {
			positionArgs = append(positionArgs, args[i:]...)
			break
		}

		if parsed, consumed, ok := parseKnownFlagArg(args, i, flagSpecs); ok {
			flagArgs = append(flagArgs, parsed...)
			i += consumed
			continue
		}

		positionArgs = append(positionArgs, args[i])
		i++
	}

	normalized := make([]string, 0, len(args))
	normalized = append(normalized, flagArgs...)
	normalized = append(normalized, positionArgs...)
	return normalized
}

// buildFlagSpecs records the names visible to the current command level.
// Help is an implicit urfave/cli flag. Shell completion is intentionally not
// included because urfave/cli only enables completion when its token is last.
func buildFlagSpecs(flags []cli.Flag) map[string]cliFlagSpec {
	specs := map[string]cliFlagSpec{}
	for _, flag := range flags {
		addFlagSpec(specs, flag)
	}
	addFlagSpec(specs, cli.HelpFlag)
	return specs
}

func addFlagSpec(specs map[string]cliFlagSpec, flag cli.Flag) {
	if flag == nil {
		return
	}
	_, isBool := flag.(*cli.BoolFlag)
	for _, name := range flag.Names() {
		specs[name] = cliFlagSpec{isBool: isBool}
	}
}

// parseKnownFlagArg returns the argv tokens consumed by a known flag.
// Non-bool flags consume the following token unless they use --flag=value.
// A trailing non-bool flag is left untouched so it does not steal an earlier
// positional arg after normalization.
func parseKnownFlagArg(args []string, index int, specs map[string]cliFlagSpec) ([]string, int, bool) {
	arg := args[index]
	if arg == "-" || !strings.HasPrefix(arg, "-") {
		return nil, 0, false
	}

	prefixLen := 1
	if strings.HasPrefix(arg, "--") {
		prefixLen = 2
	}
	nameWithValue := strings.TrimPrefix(arg, strings.Repeat("-", prefixLen))
	if nameWithValue == "" {
		return nil, 0, false
	}

	name, _, hasInlineValue := strings.Cut(nameWithValue, "=")
	spec, ok := specs[name]
	if !ok {
		return nil, 0, false
	}

	if hasInlineValue || spec.isBool {
		return []string{arg}, 1, true
	}
	if index+1 >= len(args) {
		return nil, 0, false
	}
	return []string{arg, args[index+1]}, 2, true
}
