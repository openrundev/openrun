---
title: "Console Tour"
summary: "A visual tour of the OpenRun management console"
---

A visual tour of the OpenRun management console, in two parts. First the
deploy flow: creating a database service with its connection url stored as
a secret, binding an app to it, deploying a containerized app from a git
repo, and the operational pages. Then the RBAC flow: enabling role based
access control from the console and working with team-scoped grants.
The screenshots follow the site theme - toggle light/dark to see the
console in the other theme. A live [demo](https://utils.demo.clace.io/console/)
of the console is available. See
[console install]({{< ref "docs/installation/#install-the-console-app" >}})
for installing the console on your own server.

## Overview

The console home page shows the system at a glance: apps, syncs,
containers, services and recent activity. Every tile links into its area
page.

{{< theme-image light="/images/console/01-overview-light.png" dark="/images/console/01-overview-dark.png" alt="Overview home page before the flow" >}}

## Create a service

Services are named backing resources (Postgres, MySQL) that apps connect
to through bindings. The lock button encrypts the connection url into the
secrets store; the service config keeps only the secret reference, so
credentials never appear in config listings.

{{< theme-image light="/images/console/02-service-form-light.png" dark="/images/console/02-service-form-dark.png" alt="New service form with the connection url stored as a secret" >}}

The created service shows on the bindings page with its config keys - the
values stay server-side.

{{< theme-image light="/images/console/03-bindings-service-light.png" dark="/images/console/03-bindings-service-dark.png" alt="Bindings page listing the postgres service" >}}

## Create a binding

A binding gives apps access to a service. Creating it provisions a
dedicated account (role and schema) on the database, so each binding is
isolated.

{{< theme-image light="/images/console/04-binding-form-light.png" dark="/images/console/04-binding-form-dark.png" alt="New binding form sourced from the postgres service" >}}

{{< theme-image light="/images/console/05-bindings-populated-light.png" dark="/images/console/05-bindings-populated-dark.png" alt="Bindings page with the service and the base binding" >}}

## Deploy an app

Apps deploy straight from a git repo (or a server directory). The spec
dropdown picks the app type for sources without an app.star, parameters
are passed as key/value pairs (lockable into the secrets store), and the
service bindings dropdown attaches the binding - the app's container gets
the database credentials as environment variables.

{{< theme-image light="/images/console/06-app-create-form-light.png" dark="/images/console/06-app-create-form-dark.png" alt="New app form with spec, params and the binding selected" >}}

Validate does a dry run: the source is fetched and checked, and the
permissions the app will request are listed for review before anything is
created.

{{< theme-image light="/images/console/07-app-validated-light.png" dark="/images/console/07-app-validated-dark.png" alt="App create form after a successful validate dry run" >}}

After create, the app is live with a staging environment alongside prod.

{{< theme-image light="/images/console/08-apps-list-light.png" dark="/images/console/08-apps-list-dark.png" alt="Apps page with the deployed app" >}}

The app detail page shows versions for prod and staging, the approved
permissions, and links to open the running app.

{{< theme-image light="/images/console/09-app-detail-light.png" dark="/images/console/09-app-detail-dark.png" alt="App detail page with versions and permissions" >}}

## Operate

Containers for the deployed apps, with lifecycle actions, stats and logs:

{{< theme-image light="/images/console/10-containers-light.png" dark="/images/console/10-containers-dark.png" alt="Containers page with the app's prod and staging containers" >}}

Every operation is audit logged, filterable by app, operation and status:

{{< theme-image light="/images/console/11-audit-light.png" dark="/images/console/11-audit-dark.png" alt="Audit page with the operations from this flow" >}}

Declarative GitOps sources keep apps synced from a repo on a schedule:

{{< theme-image light="/images/console/12-syncs-light.png" dark="/images/console/12-syncs-dark.png" alt="Syncs page with declarative sources" >}}

The AI app builder creates apps from a prompt in an agent session:

{{< theme-image light="/images/console/13-builder-light.png" dark="/images/console/13-builder-dark.png" alt="App builder page" >}}

Server configuration - auth, git, secrets, RBAC and system settings - is
editable from the console, with staged versions and history:

{{< theme-image light="/images/console/14-config-light.png" dark="/images/console/14-config-dark.png" alt="Configuration page" >}}

Back on the overview, the deployed app shows in the apps tile and its
running container is counted in the containers tile:

{{< theme-image light="/images/console/15-overview-final-light.png" dark="/images/console/15-overview-final-dark.png" alt="Overview home page after the flow" >}}

## Role based access control

The second flow enables RBAC from the console and walks a multi-team
setup: eng and finance teams with builtin-auth users, developers scoped
to their team's paths, read-only users, and an operations group covering
everything. Everything below is driven through the console UI.

### Configure and publish

Without RBAC configured, every management call is admin-only:

{{< theme-image light="/images/console_rbac/01-admin-rbac-initial-light.png" dark="/images/console_rbac/01-admin-rbac-initial-dark.png" alt="RBAC configuration page before any groups, roles or grants" >}}

Groups, grants and the enable flag are staged as a draft: team developers
get the openrun-developer role scoped to their team paths, domains,
services and binding namespace; read-only users get openrun-user on the
team apps; the ops group gets openrun-operator on all targets.

{{< theme-image light="/images/console_rbac/02-admin-rbac-staged-light.png" dark="/images/console_rbac/02-admin-rbac-staged-dark.png" alt="RBAC configuration with all grants staged as a draft" >}}

Publishing makes the draft live server-wide, effective immediately - no
restarts:

{{< theme-image light="/images/console_rbac/03-admin-rbac-published-light.png" dark="/images/console_rbac/03-admin-rbac-published-dark.png" alt="Published RBAC configuration with the grants live" >}}

### Team setup

The operator creates the database services - a shared one plus one per
team, each on its own database. The all-target grant shows every service:

{{< theme-image light="/images/console_rbac/04-ops-service-shared-light.png" dark="/images/console_rbac/04-ops-service-shared-dark.png" alt="Operator creating the shared postgres service" >}}

{{< theme-image light="/images/console_rbac/05-ops-services-all-light.png" dark="/images/console_rbac/05-ops-services-all-dark.png" alt="All services visible to the operator" >}}

### Scoped development

Grants are enforced per resource at action time. A developer can reach
the create form (they hold app:create somewhere), but creating an app
outside the team scope is denied:

{{< theme-image light="/images/console_rbac/06-engdev1-create-denied-light.png" dark="/images/console_rbac/06-engdev1-create-denied-dark.png" alt="App create denied for a path outside the team scope" >}}

Inside the scope, the developer creates the team's todo app bound to the
team service - binding attach is authorized by service:bind on that
service:

{{< theme-image light="/images/console_rbac/07-engdev1-apps-light.png" dark="/images/console_rbac/07-engdev1-apps-dark.png" alt="Apps page after the eng developer created the team todo app" >}}

Developers can derive restricted bindings from a base binding - here a
read-only view with per-table grants - and build apps on them. The
binding dropdown lists only services and bindings the caller can read;
other teams' entries never appear:

{{< theme-image light="/images/console_rbac/08-engdev1-derive-binding-light.png" dark="/images/console_rbac/08-engdev1-derive-binding-dark.png" alt="Deriving a read-only binding from the team base binding" >}}

{{< theme-image light="/images/console_rbac/09-engdev1-view-app-light.png" dark="/images/console_rbac/09-engdev1-view-app-dark.png" alt="Creating an app on the derived read-only binding" >}}

Domain glob targets authorize apps on team subdomains too:

{{< theme-image light="/images/console_rbac/10-engdev2-apps-light.png" dark="/images/console_rbac/10-engdev2-apps-dark.png" alt="Domain app created through the team domain glob target" >}}

The other team works the same way in its own scope:

{{< theme-image light="/images/console_rbac/11-financedev1-view-app-light.png" dark="/images/console_rbac/11-financedev1-view-app-dark.png" alt="Finance developer creating an app on their derived binding" >}}

Every list is filtered server-side to what the caller can read - a
developer's bindings page shows the team and shared entries only:

{{< theme-image light="/images/console_rbac/12-engdev1-bindings-light.png" dark="/images/console_rbac/12-engdev1-bindings-dark.png" alt="Bindings page filtered to the eng team's entries" >}}

### Read-only users and operators

A read-only user sees the team apps, with every write control disabled
and labeled with the missing permission; nav areas without a read
permission are disabled too:

{{< theme-image light="/images/console_rbac/13-enguser3-apps-light.png" dark="/images/console_rbac/13-enguser3-apps-dark.png" alt="Read-only user with disabled write controls and nav items" >}}

The operator's all-target grant sees everything, plus approve/promote and
the configuration pages:

{{< theme-image light="/images/console_rbac/14-operator-bindings-light.png" dark="/images/console_rbac/14-operator-bindings-dark.png" alt="Operator view with every app, service and binding visible" >}}

### Per-resource denials and staged updates

Write attempts outside the granted targets - a service outside the team's
namespace, a binding outside the team prefix, a binding sourced from
another team's service - are each denied per resource, with the form
re-rendered in place:

{{< theme-image light="/images/console_rbac/15-engdev1-binding-denied-light.png" dark="/images/console_rbac/15-engdev1-binding-denied-dark.png" alt="Scoped write denial re-rendered inline on the binding form" >}}

Updates always apply to staging first; promoting to prod is a separate
permission. The read-only user sees the pending promotion but a disabled
Promote action:

{{< theme-image light="/images/console_rbac/16-engdev1-promoted-light.png" dark="/images/console_rbac/16-engdev1-promoted-dark.png" alt="Staged param update promoted to prod by the developer" >}}

### Dynamic grant changes

Grant changes publish without restarts. The operator loans the eng
developer to finance - the finance apps, service and bindings appear on
their next request:

{{< theme-image light="/images/console_rbac/17-operator-loan-published-light.png" dark="/images/console_rbac/17-operator-loan-published-dark.png" alt="Loan grant published by the operator" >}}

{{< theme-image light="/images/console_rbac/18-engdev1-loaned-light.png" dark="/images/console_rbac/18-engdev1-loaned-dark.png" alt="Eng developer seeing the finance resources during the loan" >}}

Deleting the loan grant reverts the access just as immediately - the
finance apps drop out of the lists and their URLs 403 again:

{{< theme-image light="/images/console_rbac/19-engdev1-revoked-light.png" dark="/images/console_rbac/19-engdev1-revoked-dark.png" alt="Access back to the team baseline after the loan grant is deleted" >}}
