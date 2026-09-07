---
title: "App Webhooks"
weight: 350
summary: "Trigger app reloads and promotions from CI or signed GitHub push events"
---

App webhooks let CI or a GitHub push trigger an operation on one existing app. Each app and operation has its own token. Webhooks are independent of the remote REST and MCP settings, and remain disabled for an app until a token is created.

| Type | Operation |
| --- | --- |
| `reload` | Load the latest app source into staging. |
| `reload_promote` | Reload the source and promote the staged version to production. |
| `promote` | Promote the current staged version without fetching source. |

For a GitOps workflow that creates apps and changes their declarations, use [scheduled sync]({{< ref "overview/#automated-sync" >}}). App webhooks operate on an already-created app.

## Create a Webhook

```sh
openrun app-webhook create reload example.com:/myapp
openrun app-webhook list example.com:/myapp
```

Creating and deleting webhook tokens requires `app:token_manage` on the app; listing them requires `app:token_read`, which reveals the tokens. Creation prints a token and URL. Use the URL on your externally reachable HTTPS origin, for example `https://openrun.example.com/_openrun_webhook/reload?appPath=example.com%3A%2Fmyapp`. The `appPath` query parameter identifies the app and must be URL-encoded.

The token authorizes its configured operation on that app without a separate user login or user RBAC check. Keep it in your CI secret store. Creating the same webhook type again replaces its token immediately; deleting it disables the endpoint for that app:

```sh
openrun app-webhook delete reload example.com:/myapp
```

## Call from CI

Set `OPENRUN_WEBHOOK_TOKEN` and `OPENRUN_WEBHOOK_URL` in the CI environment, then send a POST:

```sh
curl --fail-with-body --request POST "$OPENRUN_WEBHOOK_URL" \
  --header "Authorization: Bearer $OPENRUN_WEBHOOK_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"ref":"refs/heads/main"}'
```

For reload operations on Git-backed apps, the JSON body must contain `ref` in the form `refs/heads/<branch>`, matching the app's configured branch. Missing or mismatched branches fail the request. OpenRun reloads from the configured source; it does not deploy an arbitrary commit supplied in the payload. Local-source reloads and `promote` do not require branch information.

Webhooks do not approve new plugin permissions. If a code update requires additional permissions, review and approve them through the CLI or console. A promotion includes all currently staged changes for the app. Successful operations and authenticated failures are recorded in the [audit log]({{< ref "audit" >}}).

## Signed GitHub Push Events

In the repository's webhook settings, use the generated URL as the payload URL, select `application/json`, set the webhook token as the secret, and subscribe to push events. OpenRun verifies the `X-Hub-Signature-256` HMAC against the request body when no `Authorization` header is present.

Only pushes to the branch configured on the app are accepted by a reload webhook. A GitHub ping has no branch `ref`, so it does not exercise the reload successfully; test with a push to the configured branch. Use `reload` to keep manual promotion, or `reload_promote` to deploy accepted pushes to production.
