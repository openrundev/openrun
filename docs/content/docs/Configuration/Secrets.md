---
title: "Secrets Management"
weight: 600
summary: "Details about working with secret managers"
---

OpenRun supports secret management when working with apps. Secrets can be passed to containerized apps through the environment params. Secrets can also be passed to any plugin as argument. For OAuth config, the client secrets can be configured as secret in the config file.

## Supported Providers

OpenRun currently supports AWS Secrets Manager (ASM), AWS Systems Manager (SSM) and HashiCorp Vault as providers for secrets management. Secrets can also be read from the environment of the OpenRun server, which can be used in development and testing. Secrets can also be read from a local properties file.

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

## Secrets Usage

Secrets can be accessed using the syntax `{{secret_from "PROVIDER_NAME" "KEY_NAME"}}`. To read from the default provider, use `{{secret "KEY_NAME"}}`. The three contexts in which secrets can be accessed are:

- **App Params**: Param values in `params.star` or in the [app metadata definition]({{< ref "/docs/container/overview/#app-environment-params" >}}) can access the secrets.
- **Plugin arguments**: Secrets can be passed as string arguments in calls to [plugin functions]({{< ref "plugins" >}}).
- **Config file**: Secrets are supported in `openrun.toml` config for:
  - For client key and secret in [auth config]({{< ref "/docs/configuration/authentication/#oauth-authentication" >}})
  - For password in [git_auth config]({{< ref "/docs/configuration/security/#private-repository-access" >}})
  - For string values in [plugin config]({{< ref "/docs/plugins/overview/#account-linking" >}})

Secrets are always resolved late. The Starlark code does not get access to the plain text secrets. The secret lookup happens when the call to the plugin API is done. In case of params, the lookup happens when the param is passed to the container.

For git_auth config, an example secret usage is

```toml {filename="openrun.toml"}
[auth.google_prod]
key = "mykey.apps.googleusercontent.com"
secret = '{{secret_from "PROVIDER_NAME" "GOOGLE_OAuth_SECRET"}}'
hosted_domain = "example.com"
```

## Plugin Access to Secrets

For secrets which are passed to plugins, through app params or plugin arguments, the plugin needs to be authorized to access the secret. The permissions for each plugin are defined in the app definition. For example:

```python {filename="app.star"}
app = ace.app("test",
              routes = [ace.api("/", type="TEXT")],
              permissions = [
                ace.permission("exec.in", "run", ["ls"], secrets=[["c1", "c2"], ["TESTENV"]]),
              ]
             )
```

The secrets accessible are specified as a list of list of strings. In this case, the `{{secret "c1" "c2"}}` and `{{secret "TESTENV"}}` calls are allowed. Additional keys are also permitted.

If the key is specified as a string starting with `regex:`, then the subsequent part is a regex which is matched against the specified value. For example, `ace.permission("exec.in", "run", ["ls"], secrets=[["regex:TEST_.*"]),` allows accessing any secret starting with `TEST_`.

## Multiple Keys

If the `KEY_NAME` is a single string, it is passed as is to the provider. If multiple keys are specified, they are concatenated and passed to the provider. For example, `{{secret_from "env" "ABC" "DEF"}}` will get converted to a env lookup for `ABC_DEF`. The delimiter used depends on the provider. The defaults are:

- ASM and Vault : `/`
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
