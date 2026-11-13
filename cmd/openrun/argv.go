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
// positional args, and global flags work anywhere on the command line.
// urfave/cli uses the standard flag package, which stops parsing flags after
// the first positional arg and only accepts app level flags before the
// command name.
func normalizeInterspersedFlags(app *cli.App, argv []string) []string {
	if len(argv) <= 1 {
		return argv
	}

	globalSpecs := buildGlobalFlagSpecs(app.Flags)
	normalized := make([]string, 0, len(argv))
	normalized = append(normalized, argv[0])
	levelArgs, hoisted := normalizeCommandArgs(argv[1:], app.Commands, app.Flags, globalSpecs)
	// Global flags found after a command are placed before the command name,
	// which is the only position urfave/cli accepts them in
	if len(hoisted) > 0 {
		rootFlags, rest := splitLeadingFlags(levelArgs, buildFlagSpecs(app.Flags))
		normalized = append(normalized, rootFlags...)
		normalized = append(normalized, hoisted...)
		normalized = append(normalized, rest...)
		return normalized
	}
	normalized = append(normalized, levelArgs...)
	return normalized
}

// normalizeCommandArgs walks down the selected command path and normalizes
// only the args that belong to each command level. Global flags which are
// not shadowed by a flag of the current command are removed from the level
// and returned as hoisted, so the caller can move them to the root level.
func normalizeCommandArgs(args []string, commands []*cli.Command, flags []cli.Flag, globalSpecs map[string]cliFlagSpec) ([]string, []string) {
	if len(args) == 0 {
		return args, nil
	}

	flagSpecs := buildFlagSpecs(flags)
	subcommandIndex, subcommand := findSubcommandArg(args, commands, flagSpecs, globalSpecs)
	if subcommand != nil {
		levelArgs, hoisted := normalizeKnownFlags(args[:subcommandIndex], flagSpecs, globalSpecs)
		subArgs, subHoisted := normalizeCommandArgs(args[subcommandIndex+1:], subcommand.Subcommands, subcommand.Flags, globalSpecs)
		normalized := make([]string, 0, len(args))
		normalized = append(normalized, levelArgs...)
		normalized = append(normalized, args[subcommandIndex])
		normalized = append(normalized, subArgs...)
		return normalized, append(hoisted, subHoisted...)
	}

	return normalizeKnownFlags(args, flagSpecs, globalSpecs)
}

// findSubcommandArg skips over known flags and their values so a flag value
// that matches a subcommand name is not treated as the next command.
func findSubcommandArg(args []string, commands []*cli.Command, flagSpecs, globalSpecs map[string]cliFlagSpec) (int, *cli.Command) {
	for i := 0; i < len(args); {
		if args[i] == "--" {
			return -1, nil
		}
		if _, consumed, _, ok := parseLevelFlagArg(args, i, flagSpecs, globalSpecs); ok {
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
// preserving the original relative order of flags and positionals. Global
// flags not known to the level are returned separately as hoisted.
func normalizeKnownFlags(args []string, flagSpecs, globalSpecs map[string]cliFlagSpec) ([]string, []string) {
	flagArgs := make([]string, 0, len(args))
	positionArgs := make([]string, 0, len(args))
	var hoisted []string

	for i := 0; i < len(args); {
		if args[i] == "--" {
			positionArgs = append(positionArgs, args[i:]...)
			break
		}

		if parsed, consumed, isGlobal, ok := parseLevelFlagArg(args, i, flagSpecs, globalSpecs); ok {
			if isGlobal {
				hoisted = append(hoisted, parsed...)
			} else {
				flagArgs = append(flagArgs, parsed...)
			}
			i += consumed
			continue
		}

		positionArgs = append(positionArgs, args[i])
		i++
	}

	normalized := make([]string, 0, len(args))
	normalized = append(normalized, flagArgs...)
	normalized = append(normalized, positionArgs...)
	return normalized, hoisted
}

// splitLeadingFlags splits args into the leading run of known flags and the
// remainder, which starts at the first positional (the command name)
func splitLeadingFlags(args []string, flagSpecs map[string]cliFlagSpec) ([]string, []string) {
	i := 0
	for i < len(args) {
		_, consumed, ok := parseKnownFlagArg(args, i, flagSpecs)
		if !ok {
			break
		}
		i += consumed
	}
	return args[:i], args[i:]
}

// parseLevelFlagArg parses a flag known to the current command level, or
// failing that a global flag. A command flag shadows a global flag with the
// same name, so "-c" on "service create" stays a command flag.
func parseLevelFlagArg(args []string, index int, flagSpecs, globalSpecs map[string]cliFlagSpec) ([]string, int, bool, bool) {
	if parsed, consumed, ok := parseKnownFlagArg(args, index, flagSpecs); ok {
		return parsed, consumed, false, true
	}
	if parsed, consumed, ok := parseKnownFlagArg(args, index, globalSpecs); ok {
		return parsed, consumed, true, true
	}
	return nil, 0, false, false
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

// buildGlobalFlagSpecs records the app level flags which can be hoisted from
// a command position to the root. This includes the client version flag, which
// prints the client version and then runs the command. A command level flag
// with the same name (like "provider install --version") takes precedence.
func buildGlobalFlagSpecs(flags []cli.Flag) map[string]cliFlagSpec {
	specs := map[string]cliFlagSpec{}
	for _, flag := range flags {
		addFlagSpec(specs, flag)
	}
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
