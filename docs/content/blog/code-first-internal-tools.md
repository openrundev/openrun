---
title: "Code-First Internal Tools vs Low-Code in the Age of AI"
description: "Why code-first internal tools beat low-code now that AI writes the code: as fast to build, easier to maintain, no lock-in. What they still need is a platform."
summary: "Low-code tools were faster than writing code. With AI coding tools that is no longer true, and code-first internal tools make more sense."
date: 2026-10-28
---

{{< openrun-intro >}}

## Background

Every company has a long tail of internal tools: admin panels, approval forms, dashboards over a database, a page to rerun a failed job. Each one is small, used by a few people, and nobody wants to spend a week building it. Low-code platforms grew to fill that gap. Drag a table onto a canvas, connect it to a query, add a button and the tool is done in an hour. This post looks at why, with AI coding tools, code-first internal tools are now the better option for most teams.

Low-code platforms offered two things:

- **Fast UI building**: a visual editor with prebuilt components, so there is no need to write HTML, CSS or frontend code
- **A platform around the apps**: hosting, login, permissions, audit logs and connections to databases and APIs

For a long time, the first one was the main reason to use them. Writing even a simple CRUD app by hand meant picking a framework, wiring up forms and queries, and handling all the small details. It was slower, and for a tool used by five people, slower was not worth it.

## What Changed With AI

AI coding tools like Claude Code, Cursor, Codex and GitHub Copilot can now generate a complete small app from a prompt like:

```text
Build a Streamlit app that lists refund requests from the refunds table in
Postgres. Add filters for status and date, and an Approve button which sets
the status to 'approved' and records the approver.
```

The result is a few hundred lines of regular Python, in a framework which AI models have seen a lot of. It takes minutes, not days. The same applies to FastAPI, Flask, Go, Node.js or whatever language and framework the team already uses.

That removes most of the speed advantage of the visual editor over code-first internal tools. Assembling the app on a canvas and asking an AI tool to write it take about the same time. The difference is in what you end up with.

## The Costs of Low-Code Remain

The downsides of low-code tools have not changed:

- **Proprietary app format**: the app is defined in the vendor's format and runs only on the vendor's runtime. Moving off the platform means rewriting every app.
- **The editor is the only real way to change the app**: some platforms support Git, but what gets saved is serialized editor state. The diffs are hard to review and the files are not meant to be edited by hand.
- **Testing and refactoring are limited**: there is no easy way to write unit tests, share code across apps as a library or run linters and type checkers.
- **Pricing grows with users**: most commercial platforms price per user, sometimes separately for builders and viewers. Every new team using a tool adds to the bill.
- **Security features are often in higher tiers**: SSO with SAML or OIDC, fine-grained permissions and audit logs are usually what the security team asks for first, and they are often in the enterprise plans.

When building with code was slow, these were acceptable trade-offs. When code is fast to generate, they become hard to justify.

## Code-First Internal Tools Work Better With AI

The low-code platforms are adding AI features, which generate apps from prompts within their editors. These are useful, but the output is still an app inside that platform. The AI tool is the one the vendor chose, and the result can only be edited and run on that platform.

Code-first apps work better with AI over the life of the tool, not just for the first version:

- **Changes are pull requests**: an AI tool makes the change, and a person reviews a readable diff before it is deployed
- **Maintenance is easier**: adding a column, changing a business rule or upgrading a framework version are changes AI tools handle well, across many apps
- **Tests are possible**: AI tools can write tests for the app logic, which makes later changes safer
- **No lock-in to a tool or model**: any editor, AI assistant or model works, and that can change as better tools come along

Most of the cost of an internal tool is in the years of small changes after it is built. That is where having regular code in Git helps the most.

## Hypermedia First for Internal Tools

Code-first does not have to mean a single page app with a React frontend, a JSON API and a large JavaScript build. Most internal tools are tables, forms and buttons. For these, a [hypermedia driven](https://hypermedia.systems/) approach works better: the server renders HTML, and a small library like [HTMX](https://htmx.org/) handles partial page updates. FastHTML, Flask, FastAPI or Django with templates and Go's `html/template` all work well this way.

For internal tools, this has some clear advantages:

- **Fewer dependencies**: there is no npm build and no `node_modules` folder with hundreds of transitive packages. Each dependency is a possible supply chain risk and has to be kept updated. Internal tools often go unchanged for months, and a short dependency list means much less to patch when they are revisited.
- **More secure by default**: data and business logic stay on the server. There is no separate JSON API which can return more data than the UI shows, and authorization checks happen in one place. Template engines like Go's `html/template` escape output by default, which protects against XSS.
- **Less code**: one codebase in one language, instead of a frontend and a backend which must be kept in sync. There is less code for an AI tool to generate and less for a person to review.
- **Simpler to deploy**: there are no separate frontend build artifacts; the app is one server process.

Rich client-side interactivity is still possible where it is needed, by adding a JavaScript library to one page, but most internal tools do not need it.

OpenRun supports this approach directly. Apart from containerized apps in any framework, OpenRun runs [hypermedia apps]({{< ref "docs/app/overview/" >}}) written in Starlark (a Python dialect) with Go HTML templates and HTMX, with no container and no npm build step. These apps run in a [sandbox]({{< ref "docs/applications/appsecurity/" >}}): calls to HTTP APIs, commands and other plugins need permissions which are approved when the app is installed. For the simplest tools, [actions]({{< ref "docs/actions/" >}}) generate the form UI from a function's parameter list, with no UI code at all.

## What Code-First Internal Tools Still Need

Generating the app is the easy part. The second thing low-code platforms provided, the platform around the apps, is still needed. An internal tool which handles refunds needs:

- Hosting, with TLS and a stable URL
- Login through the company's identity provider
- Access control, so that only the finance team can approve refunds
- Audit logs of who did what
- Database credentials with limited access, and secrets which are not in the code
- A deployment process, ideally with review and staging before changes go live

Without these, AI-generated apps end up running on someone's laptop or on a VM with no authentication, which is worse than the low-code tool they replaced. Building this for every app is real work. A reverse proxy, an OAuth proxy, a CI pipeline and a secrets setup can be put together, but that becomes a platform project of its own.

This is the gap [OpenRun](https://github.com/openrundev/openrun) is built for. Apps are regular code in Git, deployed declaratively, with SSO, RBAC, audit logs and database bindings provided by the platform for every app. The app code does not need to implement any of it. See [OpenRun vs Retool, Appsmith and Budibase]({{< ref "compare/retool-appsmith-budibase" >}}) for a detailed comparison with low-code platforms.

## When Low-Code Still Makes Sense

Low-code tools are still a good fit in some cases:

- The people building the tools do not work with code at all, and are not going to review AI-generated code
- The app needs many prebuilt connectors to SaaS APIs, which the platform already provides
- The team does not want to run any infrastructure and prefers a vendor-hosted service

For teams where developers build the internal tools, or where people build them with the help of AI coding tools, the balance has shifted toward code-first internal tools. Writing the app as code is now about as fast as assembling it in an editor, and the result is easier to maintain, test and move. The part which still needs a solution is the platform to run those apps securely.

To try running a code-first internal tool, see the [Quick Start]({{< ref "docs/quickstart" >}}).
