// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openrundev/openrun/internal/types"
	"github.com/urfave/cli/v2"
)

// openrun apikey: API key (PAT) management for the remote management API
// surfaces (remote CLI over TCP and MCP). Keys are per-user, RBAC governs
// what each key's identity can do; --scopes adds a further ceiling.

func initApiKeyCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:  "apikey",
		Usage: "Manage API keys for remote CLI and MCP access",
		Subcommands: []*cli.Command{
			apiKeyCreateCommand(commonFlags, clientConfig),
			apiKeyListCommand(commonFlags, clientConfig),
			apiKeyDeleteCommand(commonFlags, clientConfig),
		},
	}
}

func apiKeyCreateCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+5)
	flags = append(flags, commonFlags...)
	flags = append(flags,
		newStringFlag("user", "u", "The key's user identity (provider:username, like builtin:alice)."+
			" Default is the caller; another user requires admin and is prominently audited", ""),
		newStringFlag("expires", "e", "Key lifetime: a Go duration, <N>d for days, or \"never\"."+
			" Default is the server's pat_default_ttl (90 days)", ""),
		newStringFlag("scopes", "s", "Comma separated permission globs limiting the key (like app:*,sync:read)."+
			" RBAC still applies; scopes are a ceiling. Default: unscoped", ""),
		newStringFlag("resource", "r", "API surface the key is valid for: rest, mcp or all", "rest"),
		newStringFlag("desc", "d", "Description for the key", ""),
	)

	return &cli.Command{
		Name:  "create",
		Usage: "Create an API key. The key value is shown once and never stored",
		Flags: flags,
		UsageText: `Examples:
  Key for oneself (remote CLI):     openrun apikey create --desc "laptop"
  Key for an MCP client:            openrun apikey create --resource mcp
  Key for another user (admin):     openrun apikey create --user builtin:alice
  Non-expiring key (explicit):      openrun apikey create --expires never
  Read-only scoped key:             openrun apikey create --scopes "*:read"`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}
			resources, err := parseApiKeyResource(cCtx.String("resource"))
			if err != nil {
				return err
			}
			req := types.ApiKeyCreateRequest{
				User:        cCtx.String("user"),
				ExpiresIn:   cCtx.String("expires"),
				Resources:   resources,
				Description: cCtx.String("desc"),
			}
			if scopes := cCtx.String("scopes"); scopes != "" {
				for scope := range strings.SplitSeq(scopes, ",") {
					if scope = strings.TrimSpace(scope); scope != "" {
						req.Scopes = append(req.Scopes, scope)
					}
				}
			}

			client := newHttpClient(clientConfig)
			var response types.ApiKeyCreateResponse
			if err := client.Post("/_openrun/apikey", nil, &req, &response); err != nil {
				return err
			}

			printStdout(cCtx, "API key created for %s (id %s)\n", response.User, response.Id)
			if response.ExpiresAt != nil {
				printStdout(cCtx, "Expires: %s\n", response.ExpiresAt.Format(time.RFC3339))
			} else {
				printStdout(cCtx, "Expires: never\n")
			}
			printStdout(cCtx, "\n%s\n\nStore this key securely, it is not shown again.\n", response.Key)
			printStdout(cCtx, "Use it with OPENRUN_API_KEY or client.api_key in the client config.\n")
			return nil
		},
	}
}

// parseApiKeyResource maps the --resource flag to the request resource list
func parseApiKeyResource(resource string) ([]string, error) {
	switch resource {
	case "rest", "":
		return []string{"rest"}, nil
	case "mcp":
		return []string{"mcp"}, nil
	case "all":
		return []string{"rest", "mcp"}, nil
	default:
		return nil, fmt.Errorf("invalid resource %q: valid values are rest, mcp and all", resource)
	}
}

func apiKeyListCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	flags := make([]cli.Flag, 0, len(commonFlags)+2)
	flags = append(flags, commonFlags...)
	flags = append(flags, newBoolFlag("all", "a", "List every user's keys (requires admin)", false))
	flags = append(flags, newFormatFlag())

	return &cli.Command{
		Name:  "list",
		Usage: "List API keys (metadata only, never key values)",
		Flags: flags,
		UsageText: `Examples:
  List one's own keys: openrun apikey list
  List all keys:       openrun apikey list --all`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 0 {
				return fmt.Errorf("expected no args")
			}
			values := url.Values{}
			values.Add("all", strconv.FormatBool(cCtx.Bool("all")))

			client := newHttpClient(clientConfig)
			var response types.ApiKeyListResponse
			if err := client.Get("/_openrun/apikey", values, &response); err != nil {
				return err
			}
			printApiKeyList(cCtx, response.Keys, cmp.Or(cCtx.String("format"), clientConfig.Client.DefaultFormat))
			return nil
		},
	}
}

func printApiKeyList(cCtx *cli.Context, keys []types.ApiKeyInfo, format string) {
	switch format {
	case FORMAT_JSON:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		json.MarshalEncode(enc, keys, deterministicJSON) //nolint:errcheck
	case FORMAT_JSONL:
		enc := newJSONEncoder(cCtx.App.Writer, false)
		for _, k := range keys {
			json.MarshalEncode(enc, k, deterministicJSON) //nolint:errcheck
		}
	case FORMAT_JSONL_PRETTY:
		enc := newJSONEncoder(cCtx.App.Writer, true)
		for _, k := range keys {
			json.MarshalEncode(enc, k, deterministicJSON) //nolint:errcheck
		}
	default:
		formatStr := "%-18s %-24s %-14s %-12s %-20s %-20s %-24s %s\n"
		printStdout(cCtx, formatStr, "Id", "User", "Type", "Resources", "Expires", "Last Used", "Scopes", "Description")
		for _, k := range keys {
			expires := "never"
			if k.ExpiresAt != nil {
				expires = k.ExpiresAt.Format("2006-01-02 15:04")
			}
			lastUsed := "-"
			if k.LastUsedAt != nil {
				lastUsed = k.LastUsedAt.Format("2006-01-02 15:04")
			}
			scopes := strings.Join(k.Scopes, ",")
			if scopes == "" {
				scopes = "-"
			}
			printStdout(cCtx, formatStr, k.Id, k.User, k.Type, strings.Join(k.Resources, ","), expires, lastUsed, scopes, k.Description)
		}
	}
}

func apiKeyDeleteCommand(commonFlags []cli.Flag, clientConfig *types.ClientConfig) *cli.Command {
	return &cli.Command{
		Name:      "delete",
		Usage:     "Delete an API key by id (own key, or any key with admin)",
		Flags:     commonFlags,
		ArgsUsage: "<id>",
		UsageText: `Examples:
  Delete a key: openrun apikey delete 1a2b3c4d5e6f7a8b`,
		Action: func(cCtx *cli.Context) error {
			if cCtx.NArg() != 1 {
				return fmt.Errorf("expected one arg: <id>")
			}
			values := url.Values{}
			values.Add("id", cCtx.Args().Get(0))

			client := newHttpClient(clientConfig)
			var response types.ApiKeyDeleteResponse
			if err := client.Delete("/_openrun/apikey", values, &response); err != nil {
				return err
			}
			printStdout(cCtx, "API key deleted: %s (user %s)\n", response.Id, response.User)
			return nil
		},
	}
}
