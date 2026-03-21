---
title: "Introducing OpenRun"
summary: "OpenRun: Platform for managing internal tools"
date: 2023-11-01
---

{{< openrun-intro  >}}

# OpenRun: Platform for Managing Internal Tools

OpenRun is an [open-source](https://github.com/openrundev/openrun) platform to enable easy development and deployment of web applications for internal tools. The goals for the OpenRun project are:

- Enable development and deployment of secure internal web applications.
- Simplify ongoing maintenance of such apps by removing build and dependency related issues. Updating an app after six months or six years should just work.
- Provide portable and flexible deployment options, easy to use on developer machines and also on a shared server across teams.

## Use-cases

OpenRun is built to solve two different types of use-cases:

- Custom applications: With fully customizable UI, this would be similar to solutions like [Retool](https://retool.com/). A low-code approach is used, with a focus on [Hypermedia driven applications](https://hypermedia.systems/hypermedia-reintroduction/).
- Actions: This would be similar to solutions like [Rundeck](https://www.rundeck.com/). A way to automate internal applications, with a form based interface, with support for triggered and scheduled execution.

One of the aims of OpenRun is to make it possible for everyone, especially backend engineers, to develop and use simple web interfaces. For use-cases where a CLI was developed previously, an OpenRun-based UI could be built. The backend service could invoke the CLI command or directly call the internal API that needs to be exposed. Development and use of simple web interfaces for all types of use-cases should be made easier with OpenRun.

## How does it work?

OpenRun applications are configured in [Starlark](https://github.com/google/starlark-go), which uses a subset of Python syntax. The API routes are defined to be Hypermedia first, using HTML templates to drive the UI interactions. Templates are written using Go HTML templates. [HTMX](https://htmx.org/) is used for server interactions. The backend code runs in a security sandbox and every access to plugins needs to be explicitly permitted. Application updates can be done with no build step required. OpenRun integrates with TailwindCSS/DaisyUI for styling and has [esbuild](https://esbuild.github.io) built-in for [ESM](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules) support.

## Security

The Starlark backend code for OpenRun runs in a sandbox, all external interactions need to go through plugins. The OpenRun platform implements a security sandbox at the plugin boundary. Applications define what operations they need to be able to perform. The platform enforces these permissions at runtime.

This [security model]({{< ref "appsecurity" >}}) enables the following:

- Users can download applications and run on their machine, without worrying about what operations the app can do on their system outside the audited permissions.
- Operations teams can install and approve applications. Further application updates can be handled by the development team, without requiring the operational admins to verify the updated code. As long as the application works within the originally defined permission boundary, application updates will continue to work.
- Application developers can use LLM powered automated code generation tools without worrying about the side-effects of the code. If the generated code tries to perform any operation not previously approved, it will fail.

The sandbox will ensure that the apps can do only authorized operations. This makes OpenRun an ideal target for LLM (like GPT) generated applications. The OpenRun platform will add the authentication/authorization, GitOps-based deployment and operational monitoring features on top of the generated app.

## Current Status

OpenRun is in a beta state currently. Custom application support is functional. Support for loading plugins dynamically is in progress. You can try out OpenRun (on OSX, Linux or Windows with WSL) by doing:

```shell
curl -sSL https://openrun.dev/install.sh | sh
```

Start a new terminal (to get the updated env) and run `openrun server start` to start the OpenRun service.

To install apps declaratively, run

```
openrun apply --approve github.com/openrundev/openrun/examples/utils.star all
```

Open https://localhost:25223/ to see app listing. See [installation]({{< ref "installation" >}}) for details.

## Follow Along

You can keep in touch by these means:

- Star the repo at [github.com/openrundev/openrun](https://github.com/openrundev/openrun)
- Follow on [Twitter](https://twitter.com/ajay_kidave)
- Subscribe to the blog [RSS feed](https://openrun.dev/blog/index.xml)
- Follow OpenRun on [LinkedIn](https://www.linkedin.com/company/openrundev)
- Connect on [Discord](https://discord.gg/t2P8pJFsd7)
- #openrun channel in the [CNCF Slack](https://cloud-native.slack.com/)
- Schedule a [Meeting](https://calendar.app.google/wacEeZ9agtHHZTkMA)

Use [discussions](https://github.com/openrundev/openrun/discussions) feature in GitHub or raise [issues](https://github.com/openrundev/openrun/issues) to provide feedback.
