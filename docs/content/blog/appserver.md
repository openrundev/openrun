---
title: "Missed Connections: AppServers in the Containerized Landscape"
summary: "Application Servers can make deployments easier, but they have not kept up with the times."
date: 2024-11-07
---

{{< openrun-intro >}}

Application Servers can make application deployment easy. AppServers do not support all the features of a PaaS solution, but that comes with the benefit of zero-config deployments. Especially for internal tools, AppServers are a great alternative to building a deployment solution on top of Kubernetes. OpenRun is the first AppServer built for use with containers.

## What is an Application Server

An [Application Server](https://en.wikipedia.org/wiki/Application_server) is a service that makes it easy to deploy applications and provides common features required by most apps. This includes implementing connection handling (HTTP request routing), deployment and versioning, logging, monitoring and authentication features.

Many application servers are programming language [specific](https://en.wikipedia.org/wiki/List_of_application_servers). In the Java and .NET ecosystems, class loader level isolation is used to implement app servers. The request processing model of PHP also makes app servers suitable for serving PHP apps. For interpreted languages like Python and Ruby, there are some app servers which provide cross-language support. App server support is limited for compiled languages. This article will focus on app servers which support multiple languages, since those are more widely usable.

## Multi-Language AppServers

Some of the prominent multi-language app servers are:

- [NGINX Unit](https://unit.nginx.org/): Nginx Unit is a different application from the regular Nginx web server. Unit is configured through [JSON based APIs](https://unit.nginx.org/controlapi/). Packaging apps to work with Unit is not straightforward. For example, see [Unit Java sample](https://unit.nginx.org/howto/samples/#sample-java).
- [uWSGI](https://uwsgi-docs.readthedocs.io/): uWSGI is a "full stack for building hosting services". It supports many powerful features for process management. Combining all its features and configuring them correctly is non-trivial. Many languages are supported but outside of interpreted languages, it is not easy to configure. For example, see [uWSGI Java config](https://uwsgi-docs.readthedocs.io/en/latest/JVM.html). The uWSGI project is currently in maintenance mode.
- [Phusion Passenger](https://www.phusionpassenger.com/): Phusion Passenger primarily supports Ruby, Python and JavaScript. Passenger 6 added support for [generic apps](https://www.phusionpassenger.com/docs/advanced_guides/gls/). This requires changing the app to pass the port to use on its command line. For example, [Passenger Java](https://www.phusionpassenger.com/docs/advanced_guides/gls/java.html).

These projects either run the app in-process or use a process model to run each application separately. The in-process model has issues with ensuring stability of apps when another app misbehaves. Even with the multi-process model, complete isolation across apps is not supported.

## AppServers Miss the Cloud-Native Train

Since the initial release of Docker in 2013, containers have become very popular for application deployment. Containers have the advantage of encapsulating the application runtime and dependencies in an easily deployable image. Being able to set resource limits on CPU/memory/disk usage enables isolation across applications.

No application server currently supports running apps within containers. App servers are missing from the crowded cloud native [landscape](https://landscape.cncf.io/) (possibly the only infrastructure software component missing there).

## PaaS vs AppServers

Most of the recent innovation in the container orchestration space has focused on providing support for hosting the complete software stack. This includes deploying stateless applications, stateful databases, object stores and any other type of application. The goal has been to build Platform-As-A-Service solutions (PaaS). Kubernetes is built as a [platform for building platforms](https://www.opensourcerers.org/2021/12/06/kubernetes-is-a-platform-for-building-platforms/). Even beyond Kubernetes, most container deployment platforms focus on trying to provide a complete PaaS solution. Since the scope of applicable use cases is large, even the simplest use case requires complex configuration with a PaaS solution.

AppServers by definition are simpler. They support deploying stateless applications. Given the source code for a service, an AppServer can run the service and give an HTTP endpoint to access the service. An AppServer can provide a standardized deployment approach, irrespective of the language/framework. AppServers do not support deploying databases or queues or object stores.

Many teams choose managed services (like AWS RDS or MSK) for data persistence. If the stateful applications are externally managed, then AppServers can be used for deploying the stateless applications. This avoids the complexity of having to maintain PaaS configurations.

## Cloud-Native AppServer Features

A cloud-native application server would include the following features:

- **Container-Based**: Uses containers for application deployment, with isolation across apps.
- **Easy Config**: Provide a zero-config or simple config approach
- **GitOps**: App deployment driven by source code changes.
- **Elastic Scalability**: Scale down to zero, scale up as required based on load.
- **Declarative Configuration**: All configuration is applied declaratively as opposed to being imperative.

The AppServer is not replacing the language-specific services. For example, with Python, Gunicorn/Uvicorn would provide the WSGI/ASGI functionality within the container.

## AppServer Features of OpenRun

OpenRun is built as a platform for teams to deploy internal tools. As part of that, OpenRun implements an AppServer to deploy containerized apps. The goal is to make it easy for teams to deploy and manage Streamlit/Gradio type apps for internal users. OpenRun provides blue-green staged deployment, GitOps, OAuth access control, secrets management etc. for the apps.

With OpenRun, any Containerized app (having a `Dockerfile`) can be installed using a command like

```sh
openrun app create --spec container --approve github.com/<USERID>/<REPO> /myapp
```

The app will be available at the /myapp URL. For many [frameworks](https://github.com/openrundev/appspecs), zero-config is required. Not even a `Dockerfile` is required. For example

```sh
openrun app create --spec python-streamlit --branch master --approve github.com/streamlit/streamlit-example /streamlit_app
```

deploys a [Streamlit](https://streamlit.io/) based app.

Each app has a dedicated URL, domain-based or path-based. OpenRun ensures that no other app can conflict with that path. OpenRun can currently scale between zero and one instance of the container. More than one is not supported since OpenRun runs on a single machine (multi-node support is planned). OpenRun currently has a CLI interface; a [declarative interface](https://github.com/openrundev/openrun/issues/34) based on the CLI is planned.

<picture  class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <source media="(prefers-color-scheme: dark)" srcset="/AppServerDark.png">
  <source media="(prefers-color-scheme: light)" srcset="/AppServerLight.png">
  <img alt="OpenRun AppServer" src="/AppServerLight.png">
</picture>

For use cases where teams are deploying internal tools, OpenRun can provide a much simpler solution as against using a general purpose PaaS solution.

{{<callout >}}
Update (Jan 2025): OpenRun is now listed in the [CNCF Landscape](https://landscape.cncf.io/?item=app-definition-and-development--application-definition-image-build--openrun).
{{</callout>}}
