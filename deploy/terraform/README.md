# OpenRun on AWS (Terraform)

This Terraform configuration provisions a production-ready AWS footprint for OpenRun:

- 2-AZ VPC with public + private subnets and NAT
- Private EKS nodes with a public (restricted) API endpoint
- RDS Postgres (encrypted, Multi-AZ, backups)
- ECR repository for OpenRun images
- OpenRun installed via Helm with external RDS + ECR config

## Prerequisites

- Terraform >= 1.14.3 (latest stable CLI: 1.17.1)
- AWS credentials in your environment (e.g. `aws configure`)
- Network access to the EKS public endpoint from the machine running Terraform

## Quick start

1. Create a `terraform.tfvars` with your values:

```hcl
aws_region                 = "us-east-1"
name_prefix                = "openrun"
openrun_default_domain     = "apps.example.com"
openrun_lets_encrypt_email = "admin@example.com"
openrun_enable_nlb_eips    = true
eks_version                = "1.37"
rds_engine_version         = "18.6"

# Required: allow your IP(s) to reach the EKS API endpoint
# Example: ["203.0.113.10/32"]
eks_public_access_cidrs = ["REPLACE_WITH_YOUR_PUBLIC_IP/32"]
```

2. Initialize and apply:

```bash
terraform init
terraform apply
```

## Dependency versions

Defaults verified against the official registries and AWS `us-west-2` APIs on November 3, 2026:

| Component | Version |
| --- | --- |
| EKS Kubernetes | 1.37 |
| RDS PostgreSQL | 18.6 |
| EKS Terraform module | 21.29.0 |
| VPC Terraform module | 6.7.3 |
| AWS provider | 6.71.0 |
| Kubernetes / Helm providers | 3.4.0 / 3.3.0 |
| Random / TLS / Null providers | 3.9.1 / 4.4.2 / 3.3.2 |
| Cloud-init / Time providers | 2.4.1 / 0.14.2 |
| AWS Load Balancer Controller chart / controller | 3.6.2 / v3.6.2 |
| OpenRun chart / application | 0.20.10 |

EBS CSI, VPC CNI, CoreDNS, and kube-proxy use `aws_eks_addon_version` to select the latest release compatible with `eks_version` in the deployment region at plan time. Review add-on version changes in each plan. Modules and charts are pinned; provider constraints allow patch updates, with exact packages recorded in `.terraform.lock.hcl`.

The controller IAM policy is vendored from [the v3.6.2 release](https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/v3.6.2/docs/install/iam_policy.json). Update it alongside the controller chart. When upgrading an existing controller from before v3.6.0, follow the [upstream CRD upgrade instructions](https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/tag/v3.6.0); Helm upgrades do not automatically update CRDs.

After pulling these changes, run `terraform init -upgrade` and generate a new plan. Existing `terraform.tfvars` values override these defaults. For an existing EKS cluster, upgrade one Kubernetes minor version at a time using `eks_version`; the 1.37 default is suitable for a fresh cluster. For an existing PostgreSQL database, review the major-version upgrade path and set `rds_allow_major_version_upgrade = true` explicitly before applying a major upgrade. The parameter group is created before the previous group is removed. PostgreSQL 18.6 was verified as orderable with `db.m6g.large` and Multi-AZ in `us-west-2`; verify availability when deploying in another region.

## Layout and components

Each major component is a single `.tf` file. If you need to exclude a component, remove its file and any dependents.

Required baseline:

- `vpc.tf` (VPC, subnets, NAT, endpoints)
- `eks.tf` (EKS cluster + node group)

OpenRun stack (depends on the above):

- `ecr.tf` (ECR repository)
- `rds.tf` (Postgres + Secrets Manager)
- `irsa.tf` (OpenRun IRSA role)
- `addons.tf` (AWS LB controller + EBS CSI driver)
- `openrun.tf` (namespaces, service account, Helm release, outputs)

Shared config:

- `versions.tf`, `providers.tf`, `variables.tf`, `locals.tf`, `data.tf`

## Load balancer configuration

By default, Terraform creates an AWS NLB (Network Load Balancer) for external access to OpenRun.

### Disabling the managed NLB

If you prefer to use your own ingress controller, API gateway, or load balancer, set:

```hcl
openrun_enable_nlb = false
```

When disabled:

- No NLB or EIPs are created
- The OpenRun Helm chart deploys with `ClusterIP` service type
- You must configure external access separately (e.g., via an ingress controller, AWS ALB, or service mesh)
- NLB-related outputs (`openrun_load_balancer_hostname`, `openrun_load_balancer_ips`, `openrun_dns_records`) will be empty

### DNS configuration

After apply, Terraform outputs the OpenRun load balancer hostname and (by default) static Elastic IPs.

If you use Route 53, you can create **Alias A** records pointing to the load balancer hostname.
If you need standard **A records**, use the EIP outputs:

- `*.apps.example.com` -> `<EIP1, EIP2, ...>`
- `apps.example.com` -> `<EIP1, EIP2, ...>`
  Note: Elastic IPs incur AWS charges while allocated.

To disable EIP allocation and use CNAMEs instead, set `openrun_enable_nlb_eips = false` and use:

- `*.apps.example.com` -> `<load balancer hostname>`
- `apps.example.com` -> `<load balancer hostname>`

Wait for DNS to propagate before completing TLS issuance.

## TLS notes

- Start with `openrun_lets_encrypt_use_staging = true` for a dry run.
- Switch to production by setting `openrun_lets_encrypt_use_staging = false` and re-applying.

## Authentication (optional)

Set `openrun_auth_mode` to `oidc` or `saml` and provide the matching variables. Outputs include the callback/ACS URLs.

## Binding providers (optional)

Out-of-process [binding providers](https://github.com/openrundev/bindings) (sqlserver, oracle, mongodb, snowflake, clickhouse, databricks) can be installed declaratively:

```hcl
openrun_binding_providers = {
  mongodb   = "v0.1.0"
  sqlserver = "v0.1.0"
}
```

Every OpenRun replica downloads, verifies and registers the declared providers at startup; their service types become available for `openrun service create`. Upgrading a provider is a version change followed by `terraform apply` (which rolls out the deployment). Append `@sha256:<hex>` to a version to pin the binary digest. Set `openrun_bindings_release_url_template` to download from an internal mirror when the cluster restricts egress.

## Security summary

- EKS worker nodes are private and egress via NAT.
- EKS API endpoint is public but locked to `eks_public_access_cidrs`.
- RDS Postgres is private and only reachable from EKS nodes.
- OpenRun uses IRSA to access ECR (no static AWS keys).
- Terraform state will include the generated database password. Store state securely.
- Terraform outputs the OpenRun admin password; treat it as sensitive.

## Troubleshooting

- **EKS API not reachable**: update `eks_public_access_cidrs` with your current public IP.
- **TLS issuance fails**: ensure DNS is correct and has propagated; use staging first.
- **ECR auth issues**: verify OpenRun service account has the IRSA role annotation.

## Notes on ECR repository layout

This configuration uses a single ECR repository for all OpenRun app images. If you need one repository per app, update:

- `config.registry.project` to match each repository name, or
- adjust OpenRun settings to include the full repo path per app.

## Files

- Root component files: `vpc.tf`, `eks.tf`, `ecr.tf`, `rds.tf`, `irsa.tf`, `addons.tf`, `openrun.tf`
- Shared config: `versions.tf`, `providers.tf`, `variables.tf`, `locals.tf`, `data.tf`
