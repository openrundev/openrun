// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

// basePrompt is the embedded system prompt sent (with the spec name, admin
// prompt_extra and the user's description) as the first message of every
// builder session. Per-spec prompt fragments were considered and rejected:
// prompt content lives here and in config, not spread across the specs tree.
//
// The prompt must be explicit enough that small models produce a previewable
// app without reading external docs: a valid app.star is REQUIRED for the
// live preview, so a minimal working example is inlined
const basePrompt = `You are building a web application that runs on OpenRun
(https://github.com/openrundev/openrun), an application server for internal tools.
The current directory (/workspace) is the app's source root; OpenRun serves a live
preview directly from these files.

Hard rules:
- Work only inside the current directory.
- Finish the work in this turn: create/edit the actual files before replying.
  Never end a reply with only a plan or an announcement of what you will do.
- The workspace MUST contain a valid app.star file. OpenRun cannot preview the app
  without it. Create or update it with every structural change.
- The preview updates automatically when you change files. NEVER tell the user to
  run openrun/docker/CLI commands, start servers, or deploy anything - the user
  only refreshes the preview panel.
- Keep the app self-contained: no absolute paths, no external services unless asked.
- Do not create git repositories, CI config or Dockerfiles unless asked.

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

Notes on that structure: app.go.html holds the page body inside the openrun_body
block; OpenRun wraps it in a full HTML page automatically. The route's handler
function (default name "handler") returns a dict available as .Data in the
template. DaisyUI/Tailwind classes are available with ace.style("daisyui"). Use
htmx (hx-get/hx-post attributes, already loaded) for interactivity instead of
custom JavaScript where possible. Additional pages are more ace.html(path,
full="name.go.html", handler=fn) routes.
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

// composePrompt builds the first prompt for a new session. systemPrompt
// replaces the embedded base prompt when the admin configured one. A chosen
// [builder_prompt.*] preset either replaces the system prompt (Replace) or
// is appended after it. editApp marks an edit session (see editPreamble)
func composePrompt(systemPrompt, spec, promptExtra, userPrompt string, preset *types.BuilderPromptConfig, editApp string) string {
	var b strings.Builder
	if preset != nil && preset.Replace {
		b.WriteString(preset.Prompt)
		b.WriteString("\n")
	} else if systemPrompt != "" {
		b.WriteString(systemPrompt)
		b.WriteString("\n")
	} else {
		b.WriteString(basePrompt)
	}
	if preset != nil && !preset.Replace {
		b.WriteString("\n" + preset.Prompt + "\n")
	}
	if editApp != "" {
		b.WriteString(editPreamble)
		fmt.Fprintf(&b, "\nThe app being modified is deployed at %s.\n", editApp)
	} else if spec != "" {
		fmt.Fprintf(&b, "\nThis app uses the OpenRun %q spec: its scaffold files (including app.star) "+
			"are already in the workspace. Build within that structure - keep the existing app.star "+
			"entry points and config files valid rather than replacing the structure.\n", spec)
	} else {
		b.WriteString("\nNo framework spec was chosen: build the app as a server-rendered OpenRun app " +
			"exactly like the example above (app.star routes + go.html templates + htmx). Do NOT use " +
			"flask/express/other frameworks - they need containers and will not preview here.\n")
	}
	if promptExtra != "" {
		b.WriteString("\n" + promptExtra + "\n")
	}
	if editApp != "" {
		b.WriteString("\nMake the following change to the app:\n\n" + userPrompt)
	} else {
		b.WriteString("\nBuild the following app:\n\n" + userPrompt)
	}
	return b.String()
}
