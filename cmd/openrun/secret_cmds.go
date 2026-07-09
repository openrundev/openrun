// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

const (
	SECRET_NAME_FLAG        = "name"
	SECRET_VALUE_FLAG       = "value"
	SECRET_FILE_FLAG        = "file"
	SECRET_DESCRIPTION_FLAG = "description"
	SECRET_PROVIDER_FLAG    = "provider"
	SECRET_UPDATE_FLAG      = "update"
	SECRET_REVEAL_FLAG      = "reveal"
)

func initSecretCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "Manage secrets in the embedded secrets store",
		Subcommands: []*cli.Command{
			secretCreateCommand(commonFlags, clientConfig),
			secretListCommand(commonFlags, clientConfig),
			secretShowCommand(commonFlags, clientConfig),
			secretDeleteCommand(commonFlags, clientConfig),
			secretRekeyCommand(commonFlags, clientConfig),
		},
	}
}

func secretProviderFlag() *cli.StringFlag {
	return newStringFlag(SECRET_PROVIDER_FLAG, "p", "The secret provider to use, default \"db\"", "")
}

func secretCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+6)
	flags = append(flags, commonFlags...)
	flags = append(flags, newStringFlag(SECRET_NAME_FLAG, "n", "Explicit secret name (instead of a generated name with the prefix arg)", ""))
	flags = append(flags, newStringFlag(SECRET_VALUE_FLAG, "v", "The secret value. Prefer stdin or --file to keep the value out of the shell history", ""))
	flags = append(flags, newStringFlag(SECRET_FILE_FLAG, "f", "Read the secret value from a file (binary files are supported)", ""))
	flags = append(flags, newStringFlag(SECRET_DESCRIPTION_FLAG, "d", "Description for the secret", ""))
	flags = append(flags, secretProviderFlag())
	flags = append(flags, newBoolFlag(SECRET_UPDATE_FLAG, "u", "Update the value if the (named) secret already exists", false))

	return &cli.Command{
		Name:      "create",
		Usage:     "Store a secret value, printing the {{secret}} reference to use",
		Flags:     flags,
		ArgsUsage: "[<prefix>]",
		UsageText: `args: [<prefix>]

<prefix> is used to generate a unique secret name. Use --name for an explicit name instead.
The value is read from stdin when neither --value nor --file is set.

Examples:
  Store a value (from stdin):    echo -n "s3cret" | openrun secret create myapp_dbpass
  Store a file:                  openrun secret create myapp_ca --file ./ca.pem
  Explicit name:                 openrun secret create --name myapp_token --value abc123
  Update an existing secret:     openrun secret create --name myapp_token --update --value xyz456
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one arg: <prefix>")
			}
			prefix := cCtx.Args().Get(0)
			name := cCtx.String(SECRET_NAME_FLAG)
			if prefix == "" && name == "" {
				return fmt.Errorf("a <prefix> arg or --name is required")
			}

			value, encoding, sourceFile, err := readSecretValue(cCtx)
			if err != nil {
				return err
			}

			createRequest := types.CreateSecretRequest{
				Name:        name,
				Prefix:      prefix,
				Value:       value,
				Encoding:    encoding,
				Description: cCtx.String(SECRET_DESCRIPTION_FLAG),
				Provider:    cCtx.String(SECRET_PROVIDER_FLAG),
				SourceFile:  sourceFile,
			}

			values := url.Values{}
			values.Add(SECRET_UPDATE_FLAG, strconv.FormatBool(cCtx.Bool(SECRET_UPDATE_FLAG)))

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.SecretCreateResponse
			if err := client.Post("/_openrun/secret", values, &createRequest, &response); err != nil {
				return err
			}

			operation := "created"
			if response.Updated {
				operation = "updated"
			}
			printStdout(cCtx, "Secret %s: %s\n", operation, response.Name)
			printStdout(cCtx, "Use in app params/config as: %s\n", response.SecretRef)
			return nil
		},
	}
}

// readSecretValue returns the secret value from --value, --file or stdin.
// Values which are not valid UTF-8 (from any of the three sources) are base64
// encoded with encoding set to "base64", since JSON strings cannot carry
// arbitrary bytes without mangling them
func readSecretValue(cCtx *cli.Context) (value, encoding, sourceFile string, err error) {
	valueFlag := cCtx.String(SECRET_VALUE_FLAG)
	fileFlag := cCtx.String(SECRET_FILE_FLAG)
	if valueFlag != "" && fileFlag != "" {
		return "", "", "", fmt.Errorf("--value and --file cannot both be set")
	}

	var data []byte
	switch {
	case valueFlag != "":
		data = []byte(valueFlag)
	case fileFlag != "":
		data, err = os.ReadFile(fileFlag)
		if err != nil {
			return "", "", "", fmt.Errorf("error reading file %s: %w", fileFlag, err)
		}
		sourceFile = filepath.Base(fileFlag)
	default:
		fmt.Fprintln(os.Stderr, "Reading secret value from stdin...")
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", "", "", fmt.Errorf("error reading value from stdin: %w", err)
		}
		// Trim the trailing newline added by echo/heredocs, but only for text
		// input: binary data legitimately ending in 0x0a/0x0d must stay intact
		if utf8.Valid(data) {
			data = []byte(strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"))
		}
	}

	if len(data) == 0 {
		return "", "", "", fmt.Errorf("secret value is empty")
	}
	if !utf8.Valid(data) {
		return base64.StdEncoding.EncodeToString(data), "base64", sourceFile, nil
	}
	return string(data), "", sourceFile, nil
}

func secretListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, secretProviderFlag())
	flags = append(flags, newStringFlag("format", "f", "The display format. Valid options are table, basic, csv, json, jsonl and jsonl_pretty", ""))

	return &cli.Command{
		Name:      "list",
		Usage:     "List stored secrets (values are not shown)",
		Flags:     flags,
		ArgsUsage: "[<glob>]",
		UsageText: `Examples:
  List all secrets:              openrun secret list
  List secrets with a prefix:    openrun secret list "myapp_*"
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() > 1 {
				return fmt.Errorf("expected at most one arg: <glob>")
			}

			values := url.Values{}
			if glob := cCtx.Args().Get(0); glob != "" {
				values.Add("glob", glob)
			}
			if provider := cCtx.String(SECRET_PROVIDER_FLAG); provider != "" {
				values.Add(SECRET_PROVIDER_FLAG, provider)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.SecretListResponse
			if err := client.Get("/_openrun/secrets", values, &response); err != nil {
				return err
			}

			printSecretList(cCtx, response.Secrets, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func secretShowCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, secretProviderFlag())
	flags = append(flags, newBoolFlag(SECRET_REVEAL_FLAG, "r", "Print the secret value (requires the secret:reveal permission)", false))

	return &cli.Command{
		Name:      "show",
		Usage:     "Show info about a stored secret",
		Flags:     flags,
		ArgsUsage: "<name>",
		UsageText: `Examples:
  Show secret info:     openrun secret show myapp_dbpass_x7f2ka9c
  Reveal the value:     openrun secret show --reveal myapp_dbpass_x7f2ka9c
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <name>")
			}
			reveal := cCtx.Bool(SECRET_REVEAL_FLAG)

			values := url.Values{}
			values.Add("name", cCtx.Args().Get(0))
			values.Add(SECRET_REVEAL_FLAG, strconv.FormatBool(reveal))
			if provider := cCtx.String(SECRET_PROVIDER_FLAG); provider != "" {
				values.Add(SECRET_PROVIDER_FLAG, provider)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.SecretGetResponse
			if err := client.Get("/_openrun/secret", values, &response); err != nil {
				return err
			}

			if reveal {
				// Write only the exact value bytes, with no trailing newline,
				// so piped/redirected output restores the stored value (a
				// no-newline PEM or token) byte for byte
				data := []byte(response.Value)
				if response.Encoding == "base64" {
					var err error
					if data, err = base64.StdEncoding.DecodeString(response.Value); err != nil {
						return fmt.Errorf("error decoding value: %w", err)
					}
				}
				if _, err := cCtx.App.Writer.Write(data); err != nil {
					return err
				}
				return nil
			}

			enc := json.NewEncoder(cCtx.App.Writer)
			enc.SetIndent("", "  ")
			enc.Encode(response.SecretInfo) //nolint:errcheck
			return nil
		},
	}
}

func secretDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, secretProviderFlag())

	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete a stored secret",
		Flags:     flags,
		ArgsUsage: "<name>",
		UsageText: `Examples:
  Delete a secret: openrun secret delete myapp_dbpass_x7f2ka9c
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <name>")
			}

			values := url.Values{}
			values.Add("name", cCtx.Args().Get(0))
			if provider := cCtx.String(SECRET_PROVIDER_FLAG); provider != "" {
				values.Add(SECRET_PROVIDER_FLAG, provider)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.SecretDeleteResponse
			if err := client.Delete("/_openrun/secret", values, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Secret deleted: %s\n", response.Name)
			return nil
		},
	}
}

func secretRekeyCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+1)
	flags = append(flags, commonFlags...)
	flags = append(flags, secretProviderFlag())

	return &cli.Command{
		Name:  "rekey",
		Usage: "Re-encrypt stored secrets with the active master key",
		Flags: flags,
		UsageText: `Re-encrypts all stored secrets with the active (first) key in the key material.
Used after adding a new master key, before removing the old key.

Examples:
  Rekey the store: openrun secret rekey
`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}

			values := url.Values{}
			if provider := cCtx.String(SECRET_PROVIDER_FLAG); provider != "" {
				values.Add(SECRET_PROVIDER_FLAG, provider)
			}

			client := system.NewHttpClient(clientConfig.ServerUri, clientConfig.AdminUser, clientConfig.Client.AdminPassword, clientConfig.Client.SkipCertCheck)
			var response types.SecretRekeyResponse
			if err := client.Post("/_openrun/secret/rekey", values, nil, &response); err != nil {
				return err
			}

			printStdout(cCtx, "Secrets re-encrypted: %d rekeyed, %d skipped\n", response.Rekeyed, response.Skipped)
			return nil
		},
	}
}

func printSecretList(cCtx *cli.Context, secrets []types.SecretInfo, format string) {
	switch format {
	case FORMAT_JSON:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		enc.Encode(secrets) //nolint:errcheck
	case FORMAT_JSONL:
		enc := json.NewEncoder(cCtx.App.Writer)
		for _, s := range secrets {
			enc.Encode(s) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := json.NewEncoder(cCtx.App.Writer)
		enc.SetIndent("", "  ")
		for _, s := range secrets {
			enc.Encode(s) //nolint:errcheck
		}
	case FORMAT_BASIC:
		formatStr := "%-40s %-40s\n"
		printStdout(cCtx, formatStr, "Name", "Description")
		for _, s := range secrets {
			printStdout(cCtx, formatStr, s.Name, s.Description)
		}
	case FORMAT_TABLE, "":
		formatStr := "%-40s %-12s %-20s %-25s %-40s\n"
		printStdout(cCtx, formatStr, "Name", "KeyId", "CreatedBy", "UpdateTime", "Description")
		for _, s := range secrets {
			printStdout(cCtx, formatStr, s.Name, s.KeyId, s.CreatedBy,
				s.UpdateTime.Format("2006-01-02 15:04:05"), s.Description)
		}
	case FORMAT_CSV:
		for _, s := range secrets {
			printStdout(cCtx, "%s,%s,%s,%s,%s,%s\n", s.Name, s.KeyId, s.CreatedBy,
				s.CreateTime.Format("2006-01-02 15:04:05"), s.UpdateTime.Format("2006-01-02 15:04:05"), s.Description)
		}
	default:
		panic(fmt.Errorf("unknown format %s", format))
	}
}
