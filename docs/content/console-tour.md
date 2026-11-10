---
title: "OpenRun Console Tour: Deploy Apps and Manage RBAC"
linkTitle: "Console Tour"
description: "Interactive tour of the OpenRun web console: create a database service, bind and deploy an app from Git, monitor containers and manage RBAC grants."
summary: "An interactive tour of the OpenRun management console"
layout: hextra-home
---

{{< console-title title="Console Tour" >}}
Step through the OpenRun management console, in two parts. **Deploy an app** creates a database service with its connection url stored as a secret, binds an app to it, deploys a containerized app from a git repo and visits the operational pages. **Role based access control** configures RBAC from the console and works with team-scoped grants. Every screen is a real screenshot in the light and dark themes.
{{< /console-title >}}

{{< console-tour >}}

{{< tour-step flow="Deploy an app" chapter="Overview" title="System at a glance" img="/images/console/01-overview" >}}
The console home page shows the system at a glance: apps, syncs, containers, services and recent activity. Every tile links into its area page.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Create a service" title="Add a database service" img="/images/console/02-service-form" >}}
Services are named backing resources (Postgres, MySQL, Redis) that apps connect to through bindings. The lock button encrypts the connection url into the secrets store. The service config keeps only the secret reference, so credentials never appear in config listings.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Create a service" title="The service is listed" img="/images/console/03-bindings-service" >}}
The created service shows on the bindings page with its config keys. The values stay on the server.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Create a binding" title="Bind to the service" img="/images/console/04-binding-form" >}}
A binding gives apps access to a service. Creating it provisions a dedicated account (role and schema) on the database, so each binding is isolated.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Create a binding" title="Service and binding together" img="/images/console/05-bindings-populated" >}}
The bindings page now lists the service and the base binding created from it.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Deploy from Git" title="Fill in the app form" img="/images/console/06-app-create-form" >}}
Apps deploy straight from a git repo (or a server directory). The spec dropdown picks the app type for sources without an app.star, and parameters are passed as key/value pairs that can be locked into the secrets store. The service bindings dropdown attaches the binding, and the app's container gets the database credentials as environment variables.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Deploy from Git" title="Validate before creating" img="/images/console/07-app-validated" >}}
Validate does a dry run: the source is fetched and checked, and the permissions the app will request are listed for review before anything is created.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Deploy from Git" title="The app is live" img="/images/console/08-apps-list" >}}
After create, the app is live with a staging environment alongside prod.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Deploy from Git" title="App details" img="/images/console/09-app-detail" >}}
The app detail page shows versions for prod and staging, the approved permissions, and links to open the running app.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="Containers" img="/images/console/10-containers" >}}
Containers for the deployed apps, with lifecycle actions, stats and logs.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="Audit log" img="/images/console/11-audit" >}}
Every operation is audit logged, filterable by app, operation and status.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="GitOps syncs" img="/images/console/12-syncs" >}}
Declarative GitOps sources keep apps synced from a repo on a schedule.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="AI app builder" img="/images/console/13-builder" >}}
The [AI app builder]({{< relref "docs/appbuilder" >}}) creates apps from a prompt in an agent session.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="Server configuration" img="/images/console/14-config" >}}
Server configuration (auth, git, secrets, RBAC and system settings) is editable from the console, with staged versions and history.
{{< /tour-step >}}

{{< tour-step flow="Deploy an app" chapter="Operate" title="Back on the overview" img="/images/console/15-overview-final" >}}
Back on the overview, the deployed app shows in the apps tile and its running container is counted in the containers tile.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Configure and publish" title="The default grant" img="/images/console_rbac/01-admin-rbac-initial" user="admin" role="admin" >}}
This flow walks a multi-team setup: eng and finance teams with builtin-auth users, developers scoped to their team's paths, read-only users, and an operations group covering everything. RBAC is always on. A fresh install has a single default grant giving every authenticated principal access to all apps, and every management call is admin-only.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Configure and publish" title="Stage the team grants" img="/images/console_rbac/02-admin-rbac-staged" user="admin" role="admin" >}}
The default grant is removed and the team grants are staged as a draft. Team developers get the openrun-developer role scoped to their team paths, domains, services and binding namespace. Read-only users get openrun-user on the team apps, and the ops group gets openrun-operator on all targets.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Configure and publish" title="Publish" img="/images/console_rbac/03-admin-rbac-published" user="admin" role="admin" >}}
Publishing makes the draft live across the server. It takes effect immediately, with no restarts.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Team setup" title="Operator creates services" img="/images/console_rbac/04-ops-service-shared" user="operatoruser1" role="operator" >}}
The operator creates the database services: a shared one plus one per team, each on its own database.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Team setup" title="Every service is visible" img="/images/console_rbac/05-ops-services-all" user="operatoruser1" role="operator" >}}
The operator's all-target grant shows every service.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Create denied outside the scope" img="/images/console_rbac/06-engdev1-create-denied" user="engdev1" role="developer" >}}
Grants are enforced per resource at action time. A developer can reach the create form (they hold app:create somewhere), but creating an app outside the team scope is denied.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Create inside the scope" img="/images/console_rbac/07-engdev1-apps" user="engdev1" role="developer" >}}
Inside the scope, the developer creates the team's todo app bound to the team service. Attaching the binding is authorized by service:bind on that service.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Derive a read-only binding" img="/images/console_rbac/08-engdev1-derive-binding" user="engdev1" role="developer" >}}
Developers can derive restricted bindings from a base binding, here a read-only view with per-table grants.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Build on the derived binding" img="/images/console_rbac/09-engdev1-view-app" user="engdev1" role="developer" >}}
The binding dropdown lists only the services and bindings the caller can read. Other teams' entries never appear.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Team subdomains" img="/images/console_rbac/10-engdev2-apps" user="engdev2" role="developer" >}}
Domain glob targets authorize apps on team subdomains too.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="The other team" img="/images/console_rbac/11-financedev1-view-app" user="financedev1" role="developer" >}}
The finance team works the same way in its own scope.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Scoped development" title="Lists are filtered" img="/images/console_rbac/12-engdev1-bindings" user="engdev1" role="developer" >}}
Every list is filtered on the server to what the caller can read. A developer's bindings page shows the team and shared entries only.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Read-only users and operators" title="Read-only apps page" img="/images/console_rbac/13-enguser3-apps" user="enguser3" role="read-only" >}}
A read-only user sees the team apps, with every write control disabled and labeled with the missing permission. Nav areas without a read permission are disabled too.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Read-only users and operators" title="Read-only app details" img="/images/console_rbac/14-enguser3-app-detail" user="enguser3" role="read-only" >}}
The same user's app detail page shows only the basic app info. The Config, Compare and Files tabs, the source and the per-environment panel need `app:read_detail`, which the user role does not hold.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Read-only users and operators" title="The operator sees everything" img="/images/console_rbac/15-operator-bindings" user="operatoruser1" role="operator" >}}
The operator's all-target grant sees everything, plus approve/promote and the configuration pages.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Per-resource denials and staged updates" title="Denied in place" img="/images/console_rbac/16-engdev1-binding-denied" user="engdev1" role="developer" >}}
Write attempts outside the granted targets are each denied per resource, with the form re-rendered in place: a service outside the team's namespace, a binding outside the team prefix, a binding sourced from another team's service.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Per-resource denials and staged updates" title="Stage, then promote" img="/images/console_rbac/17-engdev1-promoted" user="engdev1" role="developer" >}}
Updates always apply to staging first, and promoting to prod is a separate permission. The read-only user sees the pending promotion but a disabled Promote action.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Dynamic grant changes" title="Loan a developer" img="/images/console_rbac/18-operator-loan-published" user="operatoruser1" role="operator" >}}
Grant changes publish without restarts. The operator loans the eng developer to finance.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Dynamic grant changes" title="Access appears" img="/images/console_rbac/19-engdev1-loaned" user="engdev1" role="developer" >}}
The finance apps, service and bindings appear on the developer's next request.
{{< /tour-step >}}

{{< tour-step flow="Role based access control" chapter="Dynamic grant changes" title="Access reverts" img="/images/console_rbac/20-engdev1-revoked" user="engdev1" role="developer" >}}
Deleting the loan grant reverts the access just as immediately. The finance apps drop out of the lists and their URLs return 403 again.
{{< /tour-step >}}

{{< /console-tour >}}

<p class="console-skin console-note">A live <a href="https://utils.demo.clace.io/console/">demo</a> of the console is available. See <a href="{{< relref "docs/installation/#install-the-console-app" >}}">console install</a> for installing the console on your own server, or the <a href="{{< relref "walkthrough" >}}">walkthrough</a> for a recorded run of a full demo workload.</p>
