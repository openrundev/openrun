// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/openrundev/openrun/internal/passwd"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func getPasswordCommands(clientConfig *types.ClientConfig) ([]*cli.Command, error) {
	flags := []cli.Flag{
		newBoolFlag("random", "r", "Generate a random password", false),
		newBoolFlag("prompt", "p", "Prompt for password", false),
		newStringFlag("value", "v", "Set the password value", ""),
	}

	return []*cli.Command{
		{
			Name:  "password",
			Usage: "Generate a password bcrypt config entry",
			Flags: flags,
			Action: func(cCtx *cli.Context) error {
				return generatePassword(cCtx)
			},
		},
	}, nil
}

func generatePassword(cCtx *cli.Context) error {
	if cCtx.Bool("random") && cCtx.Bool("prompt") {
		return cli.Exit("cannot specify both --random and --prompt", 1)
	}
	if cCtx.Bool("random") && cCtx.IsSet("value") {
		return cli.Exit("cannot specify both --random and --value", 1)
	}
	if cCtx.Bool("prompt") && cCtx.IsSet("value") {
		return cli.Exit("cannot specify both --prompt and --value", 1)
	}

	var err error
	password := cCtx.String("value")

	if cCtx.Bool("prompt") {
		password, err = promptPassword("Enter password: ")
		if err != nil {
			return cli.Exit(err, 1)
		}
	} else if cCtx.Bool("random") || !cCtx.IsSet("value") {
		password, err = passwd.GeneratePassword()
		if err != nil {
			return cli.Exit(err, 1)
		}
		fmt.Fprintf(os.Stderr, "Generated password is: %s\n\n", password)
	}
	if password == "" {
		return cli.Exit("must specify a password value", 1)
	}

	bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(password), passwd.BCRYPT_COST)
	if err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Printf("# Auto generated password hash, add to openrun.toml\n")
	fmt.Printf("[security]\n")
	fmt.Printf("admin_password_bcrypt = \"%s\"\n", bcryptPassword)
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Print("\nConfirm password: ")
	confirmPassword, err := readPassword()
	if err != nil {
		return "", err
	}
	if password != confirmPassword {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}

func readPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(password), nil
}

func getVersionCommands(clientConfig *types.ClientConfig) ([]*cli.Command, error) {
	return []*cli.Command{
		{
			Action: func(cCtx *cli.Context) error {
				return printVersion(cCtx)
			},
		},
	}, nil
}

func printVersion(cCtx *cli.Context) error {
	version := gitVersion
	if gitVersion == "" {
		version = "dev"
	}
	fmt.Printf("OpenRun version %s build %s\n", version, gitCommit)
	return nil
}
