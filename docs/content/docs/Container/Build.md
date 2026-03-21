---
title: "Container Builds"
weight: 400
summary: "Container builds on single node install and on Kubernetes"
---

OpenRun checks out the source code and builds the app container images. On single node install, builds are done locally and images are maintained on the machine. For Kubernetes installation, builds are done on the Kubernetes cluster using Kaniko, a shared registry is required. For both single-node and Kubernetes installations, delegated builds are supported where the container build is delegated to a dedicated build machine running OpenRun in a builder mode.

## Builder and Registry Config

The configuration for the container builder is

```toml {filename="openrun.toml"}
[builder]
mode = "auto"                        # "auto" or "kaniko" or "command" or "delegate:<url>"
kaniko_image = "ghcr.io/kaniko-build/dist/chainguard-dev-kaniko/executor:v1.25.3-slim"
```

By default, `auto` mode is used, which implies local build for single node and kaniko build for Kubernetes.

A shared container registry is required for Kubernetes install and delegated builds. The registry config is empty by default. The possible settings are

```toml {filename="openrun.toml"}
[registry]
url = "myregistry.example.com:5000" # registry location, without the protocol prefix
project = ""                        # project within the registry
insecure = false                    # use true if using http:// instead of https://
```

Other options supported for the registry are `username`, `password`, `password_file`, `type` which can be `ecr` or empty, `ca_file`, `client_cert_file`, `client_key_file` and `aws_region`.

## Single-Node Installations

For single node installation, OpenRun checks if the required container image is available locally. If not, the source code is checked out and the container manager command CLI is used to build the image.

## Kubernetes Installation

For Kubernetes installation, a container registry is required. OpenRun checks if the required container image is available in the registry. If not, the source code is checked out and shipped to a Kaniko based container which does the image build and pushes the image to the registry.

## Delegated Build Mode

For single-node install, doing the image build can cause heavy load on the system (CPU and disk). This can impact the performance for API calls to other apps. For Kubernetes based install, doing the Kaniko based install can be slow, since the build runs on a fresh machine which does not have any images cached.

For both single-node and Kubernetes installation, delegated builds are supported. One or more machines need to be dedicated for doing the container builds. The main OpenRun installation should use the delegated build option.

To set up delegated builds, on the builder machine(s) (for example, mybuilder.example.com), enable the builder by installing OpenRun and setting the minimal config to

```toml {filename="openrun.toml"}
[http]
host = "0.0.0.0"          # bind to all interfaces
redirect_to_https = false

[system]
container_command = "docker"

[security]
admin_over_tcp = true
```

Starting the OpenRun server enables the HTTP port (default 25222) to receive delegated build requests. The container manager (Docker/Podman) should be running on the builder machine.

On the actual OpenRun installation, add in the config:

```toml {filename="openrun.toml"}
[builder]
mode = "delegate:http://mybuilder.example.com:25222"
```

Config like registry settings, git credentials etc are not required in the builder machine. Those are passed from the main install to the builder. The main OpenRun install and the builder nodes do not have to point to the same metadata database. The metadata on the builder machines is not used, so it can default to the local SQLite based metadata, even if multiple builder nodes are used.

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <img alt="Delegated Build" src="/d2/delegated_build.svg">
</picture>

{{<callout type="warning" >}}
The builder machine should not be exposed over the public internet. It should be accessible from the main OpenRun node/cluster only. Multiple builder nodes can also be provisioned. In that case, a load-balancer would have to be set up and the delegate URL should use the load-balancer URL.
{{</callout>}}
