---
title: "Console Tour"
summary: "A visual tour of the OpenRun management console"
---

A visual tour of the OpenRun management console: creating a database
service with its connection url stored as a secret, binding an app to it,
deploying a containerized app from a git repo, and the operational pages.
The screenshots follow the site theme - toggle light/dark to see the
console in the other theme.

## Create a service

Services are named backing resources (Postgres, MySQL) that apps connect
to through bindings. The lock button encrypts the connection url into the
secrets store; the service config keeps only the secret reference, so
credentials never appear in config listings.

{{< theme-image light="/images/console/01-service-form-light.png" dark="/images/console/01-service-form-dark.png" alt="New service form with the connection url stored as a secret" >}}

The created service shows on the bindings page with its config keys - the
values stay server-side.

{{< theme-image light="/images/console/02-bindings-service-light.png" dark="/images/console/02-bindings-service-dark.png" alt="Bindings page listing the postgres service" >}}

## Create a binding

A binding gives apps access to a service. Creating it provisions a
dedicated account (role and schema) on the database, so each binding is
isolated.

{{< theme-image light="/images/console/03-binding-form-light.png" dark="/images/console/03-binding-form-dark.png" alt="New binding form sourced from the postgres service" >}}

{{< theme-image light="/images/console/04-bindings-populated-light.png" dark="/images/console/04-bindings-populated-dark.png" alt="Bindings page with the service and the base binding" >}}

## Deploy an app

Apps deploy straight from a git repo (or a server directory). The spec
dropdown picks the app type for sources without an app.star, parameters
are passed as key/value pairs (lockable into the secrets store), and the
service bindings dropdown attaches the binding - the app's container gets
the database credentials as environment variables.

{{< theme-image light="/images/console/05-app-create-form-light.png" dark="/images/console/05-app-create-form-dark.png" alt="New app form with spec, params and the binding selected" >}}

Validate does a dry run: the source is fetched and checked, and the
permissions the app will request are listed for review before anything is
created.

{{< theme-image light="/images/console/06-app-validated-light.png" dark="/images/console/06-app-validated-dark.png" alt="App create form after a successful validate dry run" >}}

After create, the app is live with a staging environment alongside prod.

{{< theme-image light="/images/console/07-apps-list-light.png" dark="/images/console/07-apps-list-dark.png" alt="Apps page with the deployed app" >}}

The app detail page shows versions for prod and staging, the approved
permissions, and links to open the running app.

{{< theme-image light="/images/console/08-app-detail-light.png" dark="/images/console/08-app-detail-dark.png" alt="App detail page with versions and permissions" >}}

## Operate

Containers for the deployed apps, with lifecycle actions, stats and logs:

{{< theme-image light="/images/console/09-containers-light.png" dark="/images/console/09-containers-dark.png" alt="Containers page with the app's prod and staging containers" >}}

Every operation is audit logged, filterable by app, operation and status:

{{< theme-image light="/images/console/10-audit-light.png" dark="/images/console/10-audit-dark.png" alt="Audit page with the operations from this flow" >}}

Declarative GitOps sources keep apps synced from a repo on a schedule:

{{< theme-image light="/images/console/11-syncs-light.png" dark="/images/console/11-syncs-dark.png" alt="Syncs page with declarative sources" >}}

The AI app builder creates apps from a prompt in an agent session:

{{< theme-image light="/images/console/12-builder-light.png" dark="/images/console/12-builder-dark.png" alt="App builder page" >}}

Server configuration - auth, git, secrets, RBAC and system settings - is
editable from the console, with staged versions and history:

{{< theme-image light="/images/console/13-config-light.png" dark="/images/console/13-config-dark.png" alt="Configuration page" >}}
