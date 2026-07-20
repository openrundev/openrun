// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// The system prompt is composed per session from a mode-agnostic core plus
// guidance for the app STRUCTURE the session uses. OpenRun apps come in
// three shapes:
//   - pure Starlark: app.star handlers + go.html templates (no container)
//   - full container: app.star only proxies to a containerized process
//     built from a Containerfile (the framework specs: streamlit, flask,
//     fasthtml, hono, ...)
//   - hybrid: app.star serves template routes AND proxies API routes to a
//     containerized backend
//
// A chosen spec decides the shape (its scaffold either has a Containerfile
// or it does not); without a spec the agent picks the shape from the
// request, guided by the decision tree in autoGuide. Per-spec prompt
// fragments were considered and rejected: prompt content lives here and in
// config, not spread across the specs tree.
//
// The prompt must be explicit enough that small models produce a
// previewable app without reading external docs: a valid app.star is
// REQUIRED for the live preview, so minimal working examples are inlined

const basePromptCore = `You are building a web application that runs on OpenRun
(https://github.com/openrundev/openrun), an application server for internal tools.
The current directory (/workspace) is the app's source root; OpenRun serves a live
preview directly from these files.

Hard rules:
- Work only inside the current directory. Never read or modify files anywhere
  else on the machine (no exploring the host filesystem or the OpenRun source):
  everything you need to know about OpenRun is in this prompt.
- Finish the work in this turn: create/edit the actual files before replying.
  Never end a reply with only a plan or an announcement of what you will do.
- The workspace MUST contain a valid app.star file. OpenRun cannot preview the app
  without it. Create or update it with every structural change.
- The preview updates automatically when you change files. NEVER tell the user to
  run openrun/docker/CLI commands, start servers, or deploy anything - the user
  only refreshes the preview panel.
- Keep the app self-contained: no absolute paths, no external services beyond the
  ones this prompt lists as bound.
- Do not create git repositories or CI config.
`

// starlarkGuide covers the pure Starlark shape: server-rendered templates,
// htmx partials and the Starlark language limits
const starlarkGuide = `
app.star is Starlark. A minimal working app (server-rendered, previews instantly):

--- app.star ---
def handler(req):
    name = req.Query.get("name")
    return {"Name": name[0] if name else ""}

app = ace.app("Hello",
              routes=[ace.html("/")],
              style=ace.style("daisyui"))
--- app.go.html (Go html/template, the page body) ---
{{ block "openrun_body" . }}
  <form method="GET"><input class="input" name="name" placeholder="Your name">
  <button class="btn btn-primary" type="submit">Say hello</button></form>
  {{ if .Data.Name }}<p>Hello, {{ .Data.Name }}!</p>{{ end }}
{{ end }}
----------------

app.star is Starlark, NOT Python: there is no import statement (a load() of
OpenRun plugins is the only form of code reuse), no classes, no while loops and
no third-party libraries. Keep handlers to simple dict/list/string logic; for
dynamic behavior like clocks or timers use client-side JavaScript in the template.
Handlers are stateless: module-level globals are FROZEN (mutating a global list
or dict from a handler is a runtime error) and nothing persists between requests.
Keep transient state on the client (htmx swaps that accumulate DOM, form
round-trips) and only reach for real persistence when the user asks for it.

Notes on that structure: app.go.html holds the page body inside the openrun_body
block; OpenRun wraps it in a full HTML page automatically. The route's handler
function (default name "handler") returns a dict available as .Data in the
template. DaisyUI/Tailwind classes are available with ace.style("daisyui"). Use
htmx (hx-get/hx-post attributes, already loaded) for interactivity instead of
custom JavaScript where possible. Additional pages are more ace.html(path,
full="name.go.html", handler=fn) routes.

For htmx partial updates, name a template block as the route's partial and add
method fragments to the route:

routes=[ace.html("/", partial="result_block", fragments=[
    ace.fragment("calc", method="POST", handler=calc_handler)])]

A POST to /calc runs calc_handler and re-renders only the result_block block
(defined in app.go.html as {{ block "result_block" . }}...{{ end }}); target it
with hx-post="{{ $.AppPath }}/calc" on the form or button. Always prefix
app-relative URLs in templates with {{ $.AppPath }}.

Templates escape every value automatically. To output HTML that the handler
built itself (rendered markdown, highlighted code), pipe it through safeHTML:
{{ .Data.Html | safeHTML }}. Escape any user-supplied text while building such
strings in the handler - safeHTML output is inserted verbatim.
`

// containerGuide covers the full-container shape used by the framework
// specs: the scaffold's app.star proxies everything to the containerized
// process, and the agent's work is the framework code
const containerGuide = `
This app runs INSIDE A CONTAINER. The scaffold's app.star proxies all requests
to a process built from the Containerfile; your job is the APPLICATION CODE in
the framework's own language (this IS real Python/JavaScript/Go - the Starlark
restrictions of app.star do not apply to it).

- Do NOT restructure app.star, params.star or the Containerfile: they wire the
  container, port, health check and permissions. Editing dependency files
  (requirements.txt, package.json, go.mod) and the app code is your work.
- The process must keep listening on the scaffold's configured port and keep
  any health endpoint working.
- Configuration and service credentials arrive as ENVIRONMENT VARIABLES inside
  the container; read them with the language's standard env API.
- Source changes rebuild and restart the container on the next preview
  refresh - the first build and each restart can take a moment.
`

// hybridGuide describes the mixed shape: template routes for the UI plus a
// containerized backend proxied under an API prefix. Only offered in auto
// mode (no spec picks it directly)
const hybridGuide = `
--- hybrid app.star (server-rendered UI + containerized backend) ---
load("proxy.in", "proxy")
load("container.in", "container")

def handler(req):
    return {}

app = ace.app("My App",
              routes=[
                  ace.html("/"),
                  ace.proxy("/api", proxy.config(container.URL)),
              ],
              container=container.config(container.AUTO, port=8000),
              permissions=[
                  ace.permission("proxy.in", "config", [container.URL]),
                  ace.permission("container.in", "config", [container.AUTO]),
              ],
              style=ace.style("daisyui"))
----------------
The Containerfile builds the backend (any language/framework, e.g. FastAPI)
listening on the configured port; requests under /api reach it, every other
route renders go.html templates as in the pure-Starlark shape. The templates
call the backend with htmx (hx-get="{{ $.AppPath }}/api/...").
`

// actionsGuide: OpenRun Actions - form-driven Starlark apps with an
// auto-generated UI. Used when the request asks for Actions
const actionsGuide = `
--- OpenRun Actions app (auto-generated form UI, pure Starlark) ---
app.star:
def run(dry_run, args):
    if dry_run:
        return ace.result("validated")
    return ace.result("Result for " + args.name, ["line one", "line two"])

app = ace.app("My Action",
    actions=[ace.action("My Action", "/", run, description="What it does")])

params.star:
param("name", description="Name to process", default="")
----------------
Each param in params.star becomes a form field; run(dry_run, args) receives
them as args.<name> and returns ace.result(message, lines_or_data). Report
per-field validation problems with
ace.result("Validation failed", param_errors={"name": "why"}).
`

// autoGuideContainers is the shape decision tree when no spec was chosen
// and the server can run app containers
const autoGuideContainers = `
No framework spec was chosen. Pick the app structure that fits the request:

1. PURE STARLARK (templates, example above): simple pages, forms, dashboards
   and anything the template + htmx model covers. Use this - with the actions=
   form shown below - when the request mentions OpenRun Actions.
2. HYBRID (template UI + containerized backend, example below): when the app
   needs a real backend - database access, heavier or stateful logic, real
   language libraries - but the UI is still server-rendered pages.
3. FULL CONTAINER: when a specific framework is requested (Streamlit, Gradio,
   Flask, FastAPI, Next.js, ...). app.star only proxies:
   routes=[ace.proxy("/", proxy.config(container.URL))] with the same
   container= and permissions= wiring as the hybrid example, plus a
   Containerfile running the framework on the configured port. All framework
   code is normal code for that language, not Starlark.

Prefer 2 when a backend is required, 3 for framework apps, and 1 for simple
pages or when OpenRun Actions are asked for.
`

// autoGuideNoContainers replaces the decision tree when the server cannot
// run app containers: only the pure Starlark shape previews
const autoGuideNoContainers = `
No framework spec was chosen: build the app as a server-rendered OpenRun app
exactly like the example above (app.star routes + go.html templates + htmx).
Do NOT use flask/express/other frameworks - they need containers, which are
not available on this server, and will not preview here. If the request
mentions OpenRun Actions, use the actions= form shown below.
`

// editPreamble is added for sessions editing an existing published app: the
// workspace is seeded with the app's current source and the agent modifies
// it rather than scaffolding from scratch
const editPreamble = `
You are MODIFYING an existing, deployed application. The current source is
already in the workspace. Read the existing files before changing anything.
Preserve current behavior except where the request asks for a change, and
keep the existing route paths working - the app is live and its URLs are in
use. Do not rename or restructure files unless the change requires it.
`

// Spec kinds, decided by the spec scaffold (Containerfile present or not)
const (
	SpecKindContainer = "container"
	SpecKindStarlark  = "starlark"
)

// composePrompt builds the first prompt for a new session. systemPrompt
// replaces the embedded base prompt when the admin configured one. The
// session's builder profile prompt either replaces the system prompt
// (Replace) or is appended after it.
//
// specKind selects the structure guidance: SpecKindContainer for framework
// specs (the agent works on the containerized app code), SpecKindStarlark
// for template specs, and empty - no spec - includes the shape decision
// tree (containersAvailable gates whether container shapes are offered).
// editApp marks an edit session (see editPreamble). services are the
// type/name ids auto-bound to the app: the prompt states the
// environment-variable contract up front so the agent writes code against
// the right variables from the first turn
func composePrompt(systemPrompt, spec, specKind, userPrompt string, profile *types.BuilderProfileConfig,
	editApp string, services []string, containersAvailable bool) string {
	var b strings.Builder
	if profile != nil && profile.Replace {
		b.WriteString(profile.Prompt)
		b.WriteString("\n")
	} else if systemPrompt != "" {
		b.WriteString(systemPrompt)
		b.WriteString("\n")
	} else {
		b.WriteString(basePromptCore)
		switch {
		case specKind == SpecKindContainer:
			b.WriteString(containerGuide)
		case spec != "" || editApp != "":
			// a template (non-container) spec, or an edit session whose
			// app has no spec: the starlark shape. Edits never get the
			// shape decision tree - the app's shape already exists
			b.WriteString(starlarkGuide)
		default:
			b.WriteString(starlarkGuide)
			if containersAvailable {
				b.WriteString(autoGuideContainers)
				b.WriteString(hybridGuide)
			} else {
				b.WriteString(autoGuideNoContainers)
			}
			b.WriteString(actionsGuide)
		}
	}
	if profile != nil && !profile.Replace && profile.Prompt != "" {
		b.WriteString("\n" + profile.Prompt + "\n")
	}
	if editApp != "" {
		b.WriteString(editPreamble)
		fmt.Fprintf(&b, "\nThe app being modified is deployed at %s.\n", editApp)
	} else if spec != "" {
		fmt.Fprintf(&b, "\nThis app uses the OpenRun %q spec: its scaffold files (including app.star) "+
			"are already in the workspace. Build within that structure - keep the existing app.star "+
			"entry points and config files valid rather than replacing the structure.\n", spec)
	}
	if len(services) > 0 {
		where := "at runtime"
		if specKind == SpecKindContainer {
			where = "inside the app's container"
		}
		fmt.Fprintf(&b, "\nThe app is bound to the following services. Their connection details are\n"+
			"provided as ENVIRONMENT VARIABLES %s; read them from the\n"+
			"environment - never hardcode, invent or ask for credentials, and do not add\n"+
			"configuration settings for them:\n", where)
		for _, id := range services {
			serviceType, _, _ := strings.Cut(id, "/")
			prefix := strings.ToUpper(serviceType)
			fmt.Fprintf(&b, "- %s (service %s): variables prefixed %s_, typically %s_URL\n",
				serviceType, id, prefix, prefix)
		}
	}
	if editApp != "" {
		b.WriteString("\nMake the following change to the app:\n\n" + userPrompt)
	} else {
		b.WriteString("\nBuild the following app:\n\n" + userPrompt)
	}
	return b.String()
}
