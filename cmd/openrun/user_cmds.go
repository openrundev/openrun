// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

const (
	USER_VALUE_FLAG  = "value"
	USER_RANDOM_FLAG = "random"
	USER_PROMPT_FLAG = "prompt"
	USER_GROUPS_FLAG = "groups"
)

func initUserCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "user",
		Usage: "Manage builtin auth users, for apps using the \"builtin\" auth type",
		Subcommands: []*cli.Command{
			userUpdateCommand(commonFlags, clientConfig, false),
			userUpdateCommand(commonFlags, clientConfig, true),
			userDeleteCommand(commonFlags, clientConfig),
			userListCommand(commonFlags, clientConfig),
		},
	}
}

func userPasswordFlags(commonFlags []cli.Flag, update bool) []cli.Flag {
	passwordUsage := "The password value. A random password is generated when no password flag is set"
	if update {
		passwordUsage = "The new password value. The current password is kept when no password flag is set"
	}
	flags := make([]cli.Flag, 0, len(commonFlags)+4)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag(USER_VALUE_FLAG, "v", passwordUsage, ""))
	flags = append(flags, newBoolFlag(USER_RANDOM_FLAG, "r", "Generate a random password (printed to stderr)", false))
	flags = append(flags, newBoolFlag(USER_PROMPT_FLAG, "p", "Prompt for the password", false))
	flags = append(flags, newStringFlag(USER_GROUPS_FLAG, "g",
		"Comma separated groups for the user, used for RBAC group: matching", ""))
	return flags
}

// userPassword resolves the password flags to the plaintext password. For an
// update, no password flag set means keep the current password (returns "")
func userPassword(cCtx *cli.Context, update bool) (string, error) {
	setFlags := 0
	for _, flag := range []string{USER_VALUE_FLAG, USER_RANDOM_FLAG, USER_PROMPT_FLAG} {
		if cCtx.IsSet(flag) {
			setFlags++
		}
	}
	if setFlags > 1 {
		return "", fmt.Errorf("only one of --%s, --%s and --%s can be set", USER_VALUE_FLAG, USER_RANDOM_FLAG, USER_PROMPT_FLAG)
	}

	switch {
	case cCtx.IsSet(USER_VALUE_FLAG):
		return cCtx.String(USER_VALUE_FLAG), nil
	case cCtx.Bool(USER_PROMPT_FLAG):
		return promptPassword("Enter password: ")
	case cCtx.Bool(USER_RANDOM_FLAG) || !update:
		// add generates a password by default; update keeps the current one
		password, err := passwd.GeneratePassword()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "Generated password is: %s\n\n", password)
		return password, nil
	}
	return "", nil
}

func userUpdateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig, update bool) *cli.Command {
	name, usage := "add", "Add a builtin auth user (dynamic config entry, takes effect immediately)"
	usageText := `args: <username>

Examples:
  Add a user with a generated password:  openrun user add alice --groups dev,qa
  Add a user with a password value:      openrun user add alice --value mypassword
  Add a user, prompting for password:    openrun user add alice --prompt`
	if update {
		name, usage = "update", "Update a builtin auth user's password and/or groups"
		usageText = `args: <username>

Examples:
  Change the groups, keep the password:  openrun user update alice --groups dev,ops
  Change the password:                   openrun user update alice --value newpassword
  Generate a new random password:        openrun user update alice --random`
	}

	return &cli.Command{
		Name:      name,
		Usage:     usage,
		Flags:     userPasswordFlags(commonFlags, update),
		ArgsUsage: "<username>",
		UsageText: usageText,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <username>")
			}
			username := cCtx.Args().Get(0)

			password, err := userPassword(cCtx, update)
			if err != nil {
				return err
			}

			updateRequest := types.UserUpdateRequest{}
			if password != "" {
				// The password is hashed client side, only the bcrypt hash is sent
				hash, err := bcrypt.GenerateFromPassword([]byte(password), passwd.BCRYPT_COST)
				if err != nil {
					return err
				}
				updateRequest.Password = string(hash)
			}
			if cCtx.IsSet(USER_GROUPS_FLAG) {
				updateRequest.Groups = parseGroups(cCtx.String(USER_GROUPS_FLAG))
			}

			values := url.Values{}
			values.Add("username", username)
			values.Add("update", strconv.FormatBool(update))

			client := newHttpClient(clientConfig)
			var response types.UserUpdateResponse
			if err := client.Post("/_openrun/user", values, &updateRequest, &response); err != nil {
				return err
			}

			operation := "added"
			if response.Updated {
				operation = "updated"
			}
			printStdout(cCtx, "User %s: %s\n", operation, response.Username)
			return nil
		},
	}
}

// parseGroups splits a comma separated groups value, dropping empty entries
// so --groups "" clears the groups list
func parseGroups(groupsArg string) []string {
	groups := []string{}
	for group := range strings.SplitSeq(groupsArg, ",") {
		if group = strings.TrimSpace(group); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

func userDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete a builtin auth user (dynamic entries only, static openrun.toml entries cannot be deleted)",
		Flags:     commonFlags,
		ArgsUsage: "<username>",
		UsageText: `Examples:
  Delete a user: openrun user delete alice`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <username>")
			}

			values := url.Values{}
			values.Add("username", cCtx.Args().Get(0))

			client := newHttpClient(clientConfig)
			var response types.UserDeleteResponse
			if err := client.Delete("/_openrun/user", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "User deleted: %s\n", response.Username)
			return nil
		},
	}
}

func userListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:  "list",
		Usage: "List builtin auth users (passwords are not shown)",
		Flags: flags,
		UsageText: `Examples:
  List users: openrun user list`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}

			client := newHttpClient(clientConfig)
			var response types.UserListResponse
			if err := client.Get("/_openrun/users", nil, &response); err != nil {
				return err
			}

			printUserList(cCtx, response.Users, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printUserList(cCtx *cli.Context, users []types.BuiltinUserInfo, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(users) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, u := range users {
			enc.Encode(u) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, u := range users {
			enc.Encode(u) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-30s %-40s\n"
		printStdout(cCtx, formatStr, "Username", "Groups")
		for _, u := range users {
			printStdout(cCtx, formatStr, u.Username, strings.Join(u.Groups, ","))
		}
	case FORMAT_TABLE, "":
		formatStr := "%-30s %-10s %-12s %-40s\n"
		printStdout(cCtx, formatStr, "Username", "Source", "Overridden", "Groups")
		for _, u := range users {
			overridden := ""
			if u.Overridden {
				overridden = "true"
			}
			printStdout(cCtx, formatStr, u.Username, u.Source, overridden, strings.Join(u.Groups, ","))
		}
	case FORMAT_CSV:
		for _, u := range users {
			printStdout(cCtx, "%s,%s,%t,%s\n", u.Username, u.Source, u.Overridden, strings.Join(u.Groups, " "))
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}
