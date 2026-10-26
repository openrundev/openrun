---
title: "Secrets Management"
weight: 600
summary: "Details about working with secret managers"
---

OpenRun supports secret management when working with apps. Secrets can be passed to containerized apps through the environment params. Secrets can also be passed to any plugin as argument. For OAuth config, the client secrets can be configured as secret in the config file.

## Supported Providers

OpenRun currently supports AWS Secrets Manager (ASM), AWS Systems Manager (SSM), HashiCorp Vault and Kubernetes Secrets as providers for secrets management. Secrets can also be read from the environment of the OpenRun server, which can be used in development and testing. Secrets can also be read from a local properties file. In addition, OpenRun has an embedded secrets store (the `db` provider) which encrypts secret values and saves them in the metadata database, with no external service required.

### AWS Secrets Manager

To enable ASM, add one or more entries in the `openrun.toml` config. The config name should be `asm` or should start with `asm_`. For example

```toml {filename="openrun.toml"}
[secret.asm]

[secret.asm_prod]
profile = "myaccount"

```

creates two ASM configs. `asm` uses the default profile and `asm_prod` uses the `myaccount` profile. The default config is read from the home directory ~/.aws/config and ~/.aws/credentials as documented in [AWS docs](https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html). The user id under which the OpenRun server was started is looked up for the aws config file.

To access a secret in app parameters from `asm_prod` config, use `--param MYPARAM='{{secret_from "asm_prod" "MY_SECRET_KEY"}}'` as the param value. Use `--param MYPARAM='{{secret "MY_SECRET_KEY"}}'` to read from the default provider.

### AWS Systems Manager (SSM)

To enable SSM, add one or more entries in the `openrun.toml` config. The config name should be `ssm` or should start with `ssm_`. For example

```toml {filename="openrun.toml"}
[secret.ssm]

[secret.ssm_prod]
profile = "myaccount"

```

creates two SSM configs. `ssm` uses the default profile and `ssm_prod` uses the `myaccount` profile. The default config is read from the home directory ~/.aws/config and ~/.aws/credentials as documented in [AWS docs](https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html). The user id under which the OpenRun server was started is looked up for the aws config file.

To access a secret in app parameters from `ssm_prod` config, use `--param MYPARAM='{{secret_from "ssm_prod" "MY_SECRET_KEY"}}'` as the param value. Use `--param MYPARAM='{{secret "MY_SECRET_KEY"}}'` to read from the default provider.

### HashiCorp Vault

To enable Vault secret provider, add one or more entries in the `openrun.toml` config. The config name should be `vault` or should start with `vault_`. For example

```toml {filename="openrun.toml"}
[secret.vault_local]
address = "http://127.0.0.1:8200"
token = "abc"

[secret.vault_prod]
address = "http://myvault.example.com:8200"
token = "def"
```

creates two Vault configs. The `address` and `token` properties are required.

### Environment Secrets

Adding a secret provider with the name `env` or starting with `env_`, like

```toml {filename="openrun.toml"}
[secret.env]
```

enables looking up the OpenRun server environment for secrets. This can be accessed like `--param MYPARAM='{{secret_from "env" "MY_SECRET_KEY"}}'`. No properties are required in the env provider config. The value of MY_SECRET_KEY in the OpenRun server env will be passed as the param.

### Properties Secrets

Secrets can be read from a properties file. The config name should be `prop` or should start with `prop_`. To use this, add

```toml {filename="openrun.toml"}
[secret.prop_test1]
file_name = "/etc/props.properties"
```

`file_name` is a required property.

### Kubernetes Secrets

Add a provider named `kubernetes` (or beginning with `kubernetes_`) to read native Kubernetes Secrets. In a cluster, OpenRun uses its pod service account and the namespace from `[kubernetes]`; `namespace` can be set on the provider to override it. Outside a cluster, `kubeconfig` can be set to the path of a kubeconfig file (the default kubeconfig loading rules apply otherwise).

```toml {filename="openrun.toml"}
[secret.kubernetes]
```

Pass the Secret name and data key as separate arguments. They are joined with `/`, so these forms are equivalent:

```gotemplate
{{ secret_from "kubernetes" "my-secret" "password" }}
{{ secret_from "kubernetes" "my-secret/password" }}
```

If the Secret contains exactly one data item, the data-key argument can be omitted. The OpenRun service account needs `get` access to Secrets in the selected namespace.

### Embedded Secrets Store (db)

The `db` provider stores secrets in the OpenRun metadata database. Values are encrypted with AES-256-GCM before being saved; the master encryption key lives outside the database, so a database backup alone does not expose secrets. The provider is enabled by default with

```toml {filename="openrun.toml"}
[secret.db]
key = "auto"
```

With `key = "auto"` (the default), a master key is generated on first use and saved in `$OPENRUN_HOME/config/secret.key` (file mode 0600). The file normally contains one or more `<key_id>:<base64 encoded 32 byte key>` entries, separated by newlines or commas. A bare base64 key is also accepted and uses the key ID `default`; blank lines and lines beginning with `#` are ignored. The first key is used to encrypt new values and all listed keys can decrypt.

Instead of containing key material directly, `secret.key` can contain a `{{secret ...}}` or `{{secret_from ...}}` reference. OpenRun resolves the file through another configured provider before parsing the returned key material. For example, a Kubernetes Secret named `openrun-metadata-key` with a `key` data item can be referenced with:

```gotemplate {filename="$OPENRUN_HOME/config/secret.key"}
{{ secret_from "kubernetes" "openrun-metadata-key" "key" }}
```

The Kubernetes provider joins the last two arguments as `openrun-metadata-key/key`. The referenced value must use the same key-material format described above. The `db` provider cannot reference itself because its master key is required before database secrets can be read.

Back up the key material separately from the database: if it is lost, the stored secrets cannot be recovered. If the key does not match the stored secrets, the server still starts (apps that do not use stored secrets are unaffected) but logs an error and the `db` provider is disabled until the key is restored. At most one `db` provider can be configured.

The key can instead be resolved through another configured secret provider, which is the recommended setup for Kubernetes and multi-node deployments (all nodes share the metadata database and must use the same key):

```toml {filename="openrun.toml"}
[secret.env]

[secret.db]
key = '{{secret_from "env" "OPENRUN_SECRET_KEY"}}'
```

On Kubernetes, mount the env value from a native Kubernetes Secret. Any provider other than `db` itself can be referenced. To rotate the master key, prepend a new entry, restart the server, run `openrun secret rekey` to re-encrypt all values with the new key, then remove the old entry.

Secrets are stored with the `openrun secret` commands:

```sh
# Store a value with a generated unique name (value read from stdin)
$ echo -n "s3cret" | openrun secret create myapp_dbpass
Secret created: myapp_dbpass_x7f2ka9c
Use in app params/config as: {{secret_from "db" "myapp_dbpass_x7f2ka9c"}}

# Store a file (binary files are supported)
$ openrun secret create myapp_ca --file ./ca.pem

# Explicit name, and updating an existing secret (--update requires --name)
$ openrun secret create --name myapp_token --value abc123
$ openrun secret create --name myapp_token --update --value xyz456

$ openrun secret list "myapp_*"
$ openrun secret show myapp_token            # metadata only
$ openrun secret show --reveal myapp_token   # print the value
$ openrun secret delete myapp_token
```

The printed reference is used like any other secret, for example `--param MYPARAM='{{secret_from "db" "myapp_dbpass_x7f2ka9c"}}'`. `--description` adds a description shown in `secret list`/`secret show`, and `--provider` (default `db`) names the secret provider to use. The same operations are available through the `openrun_admin` plugin (`create_secret`, `get_secret`, `list_secrets`, `delete_secret`, `rekey_secrets`).

With [RBAC]({{< ref "/docs/configuration/rbac" >}}) enforced (the default), the operations are gated by the `secret:create`, `secret:read`, `secret:delete` and `secret:reveal` permissions. Create, update and rekey are all gated by `secret:create`. `secret:reveal` (reading back a stored value) is separate from `secret:read` (listing and metadata), so day to day operators can store and manage secrets without being able to read values back. No [built-in role]({{< ref "/docs/configuration/rbac/#built-in-roles" >}}) other than `openrun-admin` includes `secret:reveal` — it must be granted explicitly.

## Secrets Usage

Secrets can be accessed using the syntax `{{secret_from "PROVIDER_NAME" "KEY_NAME"}}`. To read from the default provider, use `{{secret "KEY_NAME"}}`. The contexts in which secrets can be accessed are:

- **App Params**: Param values in `params.star` or in the [app metadata definition]({{< ref "/docs/container/overview/#app-environment-params" >}}) can access the secrets. For containerized apps the param is resolved when it is passed to the container. In Starlark code, a param value containing `{{` is a template value, resolved when passed to a plugin, see [below](#secrets-in-plugin-arguments).
- **Plugin arguments**: Template values are resolved when passed as arguments to a [plugin function]({{< ref "plugins" >}}): param values as above, and strings wrapped in `ace.eval(...)`. Plain strings are never evaluated.
- **HTML templates**: An app can reveal a secret into its handler response with `openrun_admin.secret_reveal`, see [below](#revealing-secrets-to-html-templates).
- **Config file**: Secrets are supported in `openrun.toml` config for:
  - For client key and secret in [auth config]({{< ref "/docs/configuration/authentication/#oauth-authentication" >}})
  - For password in [git_auth config]({{< ref "/docs/configuration/security/#private-repository-access" >}})
  - For string values in [plugin config]({{< ref "/docs/plugins/overview/#account-linking" >}})
  - For OTLP exporter headers in [telemetry config]({{< ref "/docs/configuration/telemetry/#collector-headers-and-secrets" >}})
  - For the `db_connection` and `audit_db_connection` values in the `[metadata]` section
  - For string values in the `[node_config]` section
  - For the credentials (`access_key_id`, `secret_access_key`) in [litestream config]({{< ref "/docs/applications/litestream" >}})

Secrets are always resolved late. Starlark code does not get access to the plain text secrets, except through an explicitly approved `secret_reveal` permission as described below. The secret lookup happens when the call to the plugin API is done. In case of params, the lookup happens when the param is passed to the container.

### Secrets in Plugin Arguments

Only template values are evaluated when they reach a plugin call, at any depth inside list, tuple and dict arguments. A plain Starlark string is passed to the plugin as is, even if it contains `{{secret ...}}`, so text taken from a request (query params, form fields, action arguments, uploaded or stored data) can never resolve the app's secrets. A value is a template when:

- It is an app level param value containing `{{`: the default in `params.star`, or the value set with `--param API_KEY='{{secret "API_KEY"}}'`. These are static and set by the developer or operator, so `param.API_KEY` is wrapped automatically and `headers={"X-Key": param.API_KEY}` resolves with no code change. A param value which contains `{{` without being a template referencing a secret passes through literally.
- It was wrapped with `ace.eval("...")` in app code, for a template the app builds itself: `ace.eval('Bearer {{secret "API_TOKEN"}}')`. This is explicit, so it is the only way request data could be evaluated: never wrap request data. `ace.eval` on a value which is already a template returns it unchanged, so `ace.eval(param.API_KEY)` is always safe. A wrapped template must parse, a template error fails the plugin call. Besides `secret` and `secret_from`, the [template functions]({{< ref "/docs/app/templates" >}}) are available.

A template value is not a string. It supports `+` with strings and other templates: the strings are kept literally and never evaluated, so `"Bearer " + param.API_KEY` works and user text joined to a param cannot introduce a template. `str(param.API_KEY)` and `%` formatting give the unevaluated reference text as a plain string, which is not resolved. Other string methods are type errors.

In an action handler, `args.NAME` is the value the caller submitted, a plain string, or the app level template when the caller did not supply the param. Use `param.NAME` when the configured secret is always the one to resolve.

```python {filename="app.star"}
load("http.in", "http")

def handler(req):
    resp = http.get("https://api.example.com/search",
                    headers={"Authorization": ace.eval('Bearer {{secret "API_TOKEN"}}'),
                             "X-Tenant": param.tenant_key},
                    params={"q": req.Query["q"][0]})  # request data, never evaluated
    return resp.value.json()

app = ace.app("search", routes=[ace.api("/", handler)],
              permissions=[ace.permission("http.in", "get", secrets=[["API_TOKEN"], ["TENANT_KEY"]])])
```

```python {filename="params.star"}
param("tenant_key", default='{{secret "TENANT_KEY"}}')
```

The plugin call must be approved for the secrets it resolves, see [Plugin Access to Secrets](#plugin-access-to-secrets).

For OAuth configuration, an example secret reference is

```toml {filename="openrun.toml"}
[auth.google_prod]
key = "mykey.apps.googleusercontent.com"
secret = '{{secret_from "PROVIDER_NAME" "GOOGLE_OAuth_SECRET"}}'
hosted_domain = "example.com"
```

## Plugin Access to Secrets

For secrets which are passed to plugins, through params or `ace.eval` arguments, the plugin needs to be authorized to access the secret. The default server permission for `container.config(...)` does not allow any secrets, so containerized apps that use secrets in params, build args need an explicitly approved `container.config` permission with a `secrets=[...]` allowlist.

The permissions for each plugin are defined in the app definition. For example:

```python {filename="app.star"}
app = ace.app("test",
              routes = [ace.api("/", type="TEXT")],
              permissions = [
                ace.permission("exec.in", "run", ["ls"], secrets=[["c1", "c2"], ["TESTENV"]]),
              ]
             )
```

The secrets accessible are specified as a list of list of strings. In this case, the `{{secret "c1" "c2"}}` and `{{secret "TESTENV"}}` calls are allowed. Additional keys are also permitted.

If the key is specified as a string starting with `regex:`, then the subsequent part is a regex which is matched against the specified value. For example, `ace.permission("exec.in", "run", ["ls"], secrets=[["regex:TEST_.*"]])` allows accessing any secret starting with `TEST_`.

For a containerized app, the permission usually looks like:

```python {filename="app.star"}
ace.permission("container.in", "config", [container.AUTO], secrets=[["DB_PASSWORD"]])
```

The app must then be approved with that permission before `{{secret "DB_PASSWORD"}}` can be resolved for the container. Since the default server config allows the `container.config` call (without secrets), the app deploys without approval even with this permission declared; `openrun app create`, `app reload` and `param update` print a warning that the declared secret access is not approved, and the container fails to start with the same guidance until `openrun app approve <path>` (or `--approve`) records it. With the built-in specs, the permission's allowlist is the `secrets` param, empty by default: set it to declare the access, e.g. `--param secrets='[["DB_PASSWORD"]]'`.

## Revealing Secrets to HTML Templates

Apps that serve HTML sometimes need to materialize a secret into a served page, for example an API key for a third party browser widget, so that the value lives only in the secret store and never in the app source files or git history. The `openrun_admin.secret_reveal` function returns the clear text value of a secret reference, for the handler to pass into a Go HTML template explicitly:

```python {filename="app.star"}
load("openrun_admin.in", "openrun_admin")

def handler(req):
    return {"key": openrun_admin.secret_reveal(param.key).value}

app = ace.app("myapp",
              routes=[ace.html("/mypath", full="index.go.html")],
              permissions=[
                  ace.permission("openrun_admin.in", "secret_reveal", secrets=[["myapp_api_key"]])
              ])
```

```python {filename="params.star"}
param("key", description="The secret reference for the page API key")
```

with `index.go.html` referencing `{{ .Data.key }}`, and the app created with

```shell
openrun app create --approve --auth system --param key='{{secret_from "db" "myapp_api_key"}}' ./mysite /mysite
```

This is disabled by default and is gated like any other plugin secret access:

- The `ace.permission("openrun_admin.in", "secret_reveal", secrets=[[...]])` entry must be declared in the app definition and approved (`openrun app approve`). The audit output shows the exact secret patterns being exposed. Without a matching approved pattern, the request fails and the reference is not resolved.
- `openrun_admin` is a privileged system plugin, so the page request must come from an authenticated user: an anonymous viewer can never trigger the reveal (unless `security.unsafe_allow_system_plugins_anon` is set).
- When RBAC is enabled, the request user must also hold the global `secret:reveal` permission. App approval controls which secrets the app code may request; RBAC independently controls which viewers may receive their values.
- The call can be blocked for all apps with a server config [permissions.disallow]({{< ref "/docs/configuration/security" >}}) entry for `openrun_admin.in` / `secret_reveal`.
- The `permit=` field of `ace.permission` optionally restricts the reveal to request users holding a specific RBAC permission.

Like `openrun_admin.get_secret(name, reveal=True)`, `secret_reveal` enforces the `secret:reveal` RBAC permission against the request caller whenever RBAC is enabled. The value is part of the served response, so use this only where authorized viewers are trusted with the value, and consider setting `Cache-Control: no-store` on the page response.

## Multiple Keys

If the `KEY_NAME` is a single string, it is passed as is to the provider. If multiple keys are specified, they are concatenated and passed to the provider. For example, `{{secret_from "env" "ABC" "DEF"}}` will get converted to a env lookup for `ABC_DEF`. The delimiter used depends on the provider. The defaults are:

- ASM, SSM, Vault, Kubernetes and db : `/`
- Env : `_`
- Properties: `.`

The formatter used to concatenate the keys can be customized by setting the `keys_printf` property. For example,

```toml {filename="openrun.toml"}
[secret.prop]
file_name = "/etc/mykeys.properties"
keys_printf = "%s-%s.%s"
```

combines `{{secret_from "prop" "ABC" "DEF" "XYZ"}}` as `ABC-DEF.XYZ`. This allows the app to work with multiple secret providers without requiring code changes in the app.

## Default Provider

If the provider name is passed as `default` or set to empty, a default provider is used. The default provider can be configured in the `openrun.toml` as

```toml {filename="openrun.toml"}
[app_config]
security.default_secrets_provider = "env"
```

The `env` provider is used by default if it is enabled in the config. The default can be changed per app by setting

```sh
openrun app update conf --promote 'security.default_secrets_provider="prop_myfile"' /myapp
```
