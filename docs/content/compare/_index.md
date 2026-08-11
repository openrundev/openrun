---
title: "Compare"
description: "Compare OpenRun with Coolify, CapRover, Kamal, Dokku, Google Cloud Run, AWS App Runner and DIY Kubernetes platforms for deploying web apps and internal tools."
summary: "How OpenRun compares with other deployment platforms."
---

OpenRun is an open-source, self-hosted GitOps platform for deploying web apps to Docker, Podman or Kubernetes. These pages compare OpenRun with other approaches to deploying web apps and internal tools.

The short version: OpenRun differs from most alternatives in providing **true GitOps** (apps are created and configured through Git, not just updated when code changes), **SSO and RBAC for every deployed app**, **scale-to-zero** for idle apps and a **single declarative config** that works on a single server with Docker or Podman and on Kubernetes. OpenRun does not deploy Docker Compose stacks; apps connect to externally managed databases through service bindings.

{{< cards >}}
{{< card link="coolify-caprover-kamal" title="vs Coolify, CapRover, Kamal" subtitle="OpenRun compared with self-hosted PaaS platforms like Coolify, CapRover, Kamal and Dokku" icon="scale" >}}
{{< card link="cloud-run-app-runner" title="vs Cloud Run, App Runner" subtitle="OpenRun compared with managed serverless container platforms from Google and AWS" icon="cloud" >}}
{{< card link="diy-kubernetes" title="vs DIY Kubernetes" subtitle="OpenRun compared with building your own platform from Jenkins, ArgoCD, Knative and an IDP" icon="cog" >}}
{{< /cards >}}
