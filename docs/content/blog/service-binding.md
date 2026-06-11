---
title: "Service Bindings: Automated Database Access for Apps"
summary: "Service Bindings make it easy to provide isolated databases for each app without manual provisioning."
date: 2026-06-10
---

{{< openrun-intro  >}}

## Background

Most applications require a database for data persistence. Deployment platforms assume that a new database is provisioned with each app being installed. This is the usual Docker Compose or Helm chart for each app. This ignores the complexity involved in making sure that databases are properly managed: backups, monitoring, capacity planning, etc.

The alternative, in larger companies, is you work with your database team (the "DBAs") and request new database accounts to use with your app. After you provide the reasoning and the performance requirements and other details, you may or may not hear back in a few weeks with the credentials to use.

## Service Bindings

There is no single standard definition of Service Binding. Generally, it is a specification to indicate that your application needs to use a particular service. The credentials for using the service are provided by the service provider through an API.

[Cloud Foundry](https://docs.cloudfoundry.org/services/managing-service-brokers.html) uses the Service Binding terminology for service instances to provision and deliver credentials to apps. Kubernetes has a [Service Binding](https://servicebinding.io/) specification. Red Hat’s Service Binding Operator for Kubernetes was [deprecated](https://redhat-developer.github.io/service-binding-operator/userguide/intro.html) in 2024.

## How it Works

OpenRun implements a [Service Binding]({{< ref "/docs/applications/servicebindings/" >}}) feature. The way this works is:

- You create a service in OpenRun, and specify the admin credentials for the service. The service installation and management is outside the scope of OpenRun. It could be a managed RDS database, an instance managed by your database team, etc.
- Each app can request a service binding. If requested, during app installation, OpenRun connects to the service using the admin credentials and creates the app-specific account. This would be a schema and role for Postgres, database and user for MySQL, etc. For derived bindings, database/schema is shared but role/user is unique.
- The app-specific credentials are injected into the app ENV when the app is started. The app code reads the ENV and connects to the database as usual.

There is a one-time cost of initially setting up the service. After that, each new app with a base binding automatically gets an isolated database environment, without any manual configuration being required. The database/schema and user credentials are isolated. The service itself is shared, so there is no isolation in terms of performance and capacity. The monitoring and capacity planning required for the database instance remains the same, but instead of being done for each app, it is done once for the service.

See the [example](https://github.com/openrundev/openrun/blob/main/examples/todo.star) for a sample declaration where two apps are created, each gets its own unique database/schema.

## Staging Environment

OpenRun apps come with a [staging app]({{< ref "docs/applications/lifecycle/#staging-apps" >}}). Since the database credentials are managed by OpenRun, OpenRun automatically ensures that the staging apps get a separate database/schema. No additional work is required for this. By default, the staging environment is on the same database instance as production. At the service level, it is possible to set up a [staging service]({{< ref "/docs/applications/servicebindings/#staging-services" >}}). If this is done, staging environments for that service are on a separate database instance, ensuring that there is performance isolation between staging and production.

## Sharing Access Across Apps

A more interesting use case of this approach is when multiple apps can access the same database/schema, but with different credentials. This allows scenarios like:

- App 1 has full access to a database/schema. App 2 is a different app that has read-only access to the same set of tables.
- App 1 and App 2 are two installations of the same app source code, but with different app-level authentication configured. At the database level, grants can be configured to ensure each installation is given least privilege. For example, an end user logged in through SSO has more privileges than an anonymous user.

[Derived bindings]({{< ref "/docs/applications/servicebindings/#create-derived-bindings" >}}) are used in OpenRun to implement shared access. Derived bindings are created from a base binding. Grants on the derived binding control what that account can do.

Authorization functionality is generally some of the more difficult code to implement and verify. Enforcing privileges at the database layer has the advantage that you get a second level of correctness checks.

See the [example](https://github.com/openrundev/openrun/blob/main/examples/todo_derived.star) for a sample declaration where three apps are created. The admin app has full access to a schema. The todo app has full access to one table and read access to another. A third view app, which shares the source code with the todo app, has read-only access to both tables.

## Row-Level Security

With Postgres, Row-Level Security (RLS) is used as a way to get user/tenant isolation inside one shared database. While RLS has some benefits, it requires careful role/session context setup and can constrain app design. RLS can also have some performance impact at scale.

The service binding approach allows you to build your app any way you want. It is more broadly applicable and can be implemented for most services, even for non-database services like message queues.
