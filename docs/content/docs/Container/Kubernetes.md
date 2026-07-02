---
title: "Kubernetes"
weight: 300
summary: "Overview of OpenRun deployment on Kubernetes"
---

## Installation

OpenRun can be installed on a Kubernetes cluster using the Helm chart.

```sh
helm repo add openrun https://openrundev.github.io/openrun-helm-charts/

# Install a registry for use with OpenRun (for testing)
helm install openrun1 openrun/openrun \
  --namespace openrun --create-namespace --set registry.enabled=true

# Install with a external registry (recommended)
helm install openrun1 openrun/openrun \
  --namespace openrun --create-namespace --set config.registry.url=<registry_url>
```

Running the Helm chart creates:

- An service which run the OpenRun API server
- Optionally, a Postgres database for metadata. An external Postgres database can be used instead.
- Optionally, a container registry is installed. An external registry can be used instead.

SQLite based metadata is not supported when using Kubernetes. The Postgres metadata needs to be managed properly, with backups and scheduled upgrades. An externally managed Postgres installation is recommended for production Kubernetes OpenRun installations.

A container registry is required for Kubernetes based OpenRun install. The registry can be installed through the Helm chart or an external registry can be used. An installation with external Postgres and Registry is shown below.

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
<img alt="Kubernetes Deployment" src="/d2/k8s.svg">
</picture>

## Registry Config

OpenRun on Kubernetes requires a registry to which Kaniko built images can be pushed and from which pods can pull. Image pulls by default require an HTTPS-protected registry; self-signed certificates are not valid. Creating a signed certificate is not trivial on dev installations. The workaround for dev installs is to enable HTTP endpoints for pod creation. Details depend on the Kubernetes installation being used. For K3S, install the `registry:2` images as a service. If registry is started at `registry.svc.cluster.local:5000`, edit `/etc/rancher/k3s/registries.yaml` to add:

```{filename="/etc/rancher/k3s/registries.yaml"}
mirrors:
  "registry.svc.cluster.local:5000":
    endpoint:
      - "http://registry.svc.cluster.local:5000"
```

The registry IP might have to added to `/etc/hosts` depending on how it is accessed.

If using OrbStack, run the `registry:2` service and run `orb config docker` and add

```
{
  "insecure-registries": ["registry.orb.local:5000"]
}
```

Restart Kubernetes using `orb restart k8s`.

To install OpenRun, run

```
helm --kube-context orbstack upgrade --install openrun openrun/openrun --namespace openrun --create-namespace --wait --timeout 3m --set config.registry.url=registry.orb.local:5000
```

The Helm chart sets `insecure = true` by default. Change that to `insecure = false` if using a HTTPS registry.

## Install using Terraform

To install a production-ready OpenRun installation on AWS, with EKS cluster, ECR registry and RDS Postgres for metadata, do the following:

- Check out the terraform config `git clone git@github.com:openrundev/openrun.git`
- Switch to the config directory `cd openrun/deploy/terraform`
- Create a copy of sample config `cp tfvars.sample terraform.tfvars`
- Update `terraform.tfvars`, set the values as appropriate.
- Ensure that AWS CLI is installed and credentials are configured. Also, ensure that Helm CLI is installed and the OpenRun repo is updated: `helm repo add openrun https://openrundev.github.io/openrun-helm-charts/; helm repo update`
- Terraform state is by default saved on local disk. If required, update to use S3
- Run `terraform init`. Add `-backend-config` if using remote state.
- Run `terraform plan --var-file terraform.tfvars`, verify the plan.
- Run `terraform apply --var-file terraform.tfvars`, or apply the plan created earlier.

Save the password for the admin user using `terraform output openrun_admin_password`. Add the DNS entries as output under `openrun_dns_records`. The `root_a` and `wildcard_a` DNS entries enable installing apps at the domain level. Wait for the DNS entries to propagate before attempting to access the url (to allow TLS cert creation to work).

After install is done, SSH to the OpenRun instance and run the `sync schedule` to set up the sync. All subsequent operations are done by checking in config updates to the app config in Git.

To destroy the resource created,

- Ensure that kubectl config is set, like `aws eks update-kubeconfig --region us-west-2 --name openrun-eks --profile openrun`. Update the region, the name format is `<prefix>-eks`, default `openrun-eks`.
- Run `terraform destroy --var-file terraform.tfvars`. Run it a second time in case there is a timeout. All resource should be deleted.

## Configuration

```toml {filename="openrun.toml"}
[system]
container_command = "kubernetes"
```

is the main config which enables Kubernetes mode. By default. Kaniko based builds are used. Delegated builds can be configured instead, see [delegated builds]({{< ref "/docs/container/build/#delegated-build-mode" >}}). See [registry]({{< ref "/docs/container/build/#config" >}}) for registry config.

OpenRun service and Kaniko jobs run in the main namespace (default `openrun`). Applications are started in the `<main_ns>-apps` namespace (default `openrun-apps`), which is automatically created by the Helm chart. To clear all apps (including any volume data), run `kubectl delete namespace openrun-apps; kubectl create namespace openrun-apps`.

## Architecture

OpenRun is installed as a Kubernetes Deployment, with a Service for routing API calls. For each containerized app installed on OpenRun, a ClusterIP Service is created for app traffic. API calls to the OpenRun API Server are routed to the app-specific Service using its cluster IP.

All Kubernetes resources are created lazily, on the first API call to the app (or when create/reload is done with the verify option). If an app is running version 1, and a code/config change updates it to version 2, the deployment update happens on the next API call to the app. That API call is blocked while the container image is rebuilt if required and the Kubernetes resources are updated using Server Side Apply API calls.

OpenRun waits until Kubernetes reports the expected new version rollout is complete before processing further API calls. It watches Deployment rollout status so readiness and Kubernetes-declared rollout failures are detected without waiting for the next polling interval, while still honoring the `container.deploy_health_attempts` deployment wait budget.

For stateless apps, OpenRun deploys each new version as a separate Deployment and promotes it by switching the app Service selector after the new Deployment is ready. This keeps the previous version serving traffic until the replacement is healthy. After promotion, OpenRun waits briefly for the Service's EndpointSlices to route only to ready pods from the new version, then removes inactive Deployments for the app and their owned HPA, Secret, and ConfigMap objects. The EndpointSlice wait is best-effort; if the cluster API or OpenRun's Kubernetes RBAC permissions do not allow listing EndpointSlices, OpenRun skips that wait instead of delaying the deployment.

Apps with OpenRun-managed persistent volumes use a stable Deployment name with a single replica and a Recreate update strategy, because a ReadWriteOnce PVC cannot be mounted by two running pods at the same time. PVCs are preserved when an app moves from a persistent-volume configuration to a stateless configuration. If the app later adds the same volume again, the existing PVC is reused and its previous data is still present.

For image-spec apps, OpenRun resolves the supplied image reference directly. Public images such as `nginx` are pulled from their normal registry instead of being rewritten to the OpenRun build registry. When the registry returns a digest, OpenRun pins the pod image to that digest. If a later refresh has a transient registry failure, OpenRun keeps using the last known digest; missing images, invalid references, and registry authorization errors fail the deployment instead of falling back to a floating tag.

Secrets and ConfigMaps generated for mounted app config are named from the workload name and a short hash suffix so that Kubernetes object names stay within the 63-character DNS label limit.
