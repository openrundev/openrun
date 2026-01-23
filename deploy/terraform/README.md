# OpenRun on AWS (Terraform)

This Terraform configuration provisions a production-ready AWS footprint for OpenRun:
- 2-AZ VPC with public + private subnets and NAT
- Private EKS nodes with a public (restricted) API endpoint
- RDS Postgres (encrypted, Multi-AZ, backups)
- ECR repository for OpenRun images
- OpenRun installed via Helm with external RDS + ECR config

## Prerequisites
- Terraform >= 1.5
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
rds_engine_version         = "17.6"

# Required: allow your IP(s) to reach the EKS API endpoint
# Example: ["203.0.113.10/32"]
eks_public_access_cidrs = ["REPLACE_WITH_YOUR_PUBLIC_IP/32"]
```

2. Initialize and apply:

```bash
terraform init
terraform apply
```

## DNS configuration
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
- Root configuration: `main.tf`, `variables.tf`, `providers.tf`, `outputs.tf`
- Modules under `modules/`
