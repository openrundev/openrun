// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"strings"
	"testing"
)

func TestComposePromptEditMode(t *testing.T) {
	prompt := composePrompt("", "", "", "add a footer", nil, "/pets", nil, true)
	for _, want := range []string{"MODIFYING an existing", "deployed at /pets",
		"Make the following change", "add a footer"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("edit prompt missing %q", want)
		}
	}
	// The create-mode framing and shape decision tree must not appear
	for _, reject := range []string{"Build the following app", "No framework spec was chosen"} {
		if strings.Contains(prompt, reject) {
			t.Errorf("edit prompt contains create-mode text %q", reject)
		}
	}

	create := composePrompt("", "", "", "make an app", nil, "", nil, true)
	if strings.Contains(create, "MODIFYING an existing") {
		t.Error("create prompt contains the edit preamble")
	}
	if !strings.Contains(create, "Build the following app") {
		t.Error("create prompt missing the build framing")
	}
}

// TestComposePromptShapes: the structure guidance follows the spec kind -
// container specs get the container guide (and no starlark example),
// template specs the starlark guide, and no spec the decision tree with
// hybrid + actions examples (container shapes only when the server can run
// app containers)
func TestComposePromptShapes(t *testing.T) {
	container := composePrompt("", "python-streamlit", SpecKindContainer, "build a dashboard", nil, "", nil, true)
	for _, want := range []string{"runs INSIDE A CONTAINER", "Containerfile",
		`the OpenRun "python-streamlit" spec`} {
		if !strings.Contains(container, want) {
			t.Errorf("container prompt missing %q", want)
		}
	}
	if strings.Contains(container, "minimal working app (server-rendered") {
		t.Error("container prompt carries the starlark example")
	}
	if strings.Contains(container, "No framework spec was chosen") {
		t.Error("container prompt carries the decision tree")
	}

	starlark := composePrompt("", "static", SpecKindStarlark, "build a page", nil, "", nil, true)
	if !strings.Contains(starlark, "minimal working app (server-rendered") {
		t.Error("template-spec prompt missing the starlark guide")
	}
	if strings.Contains(starlark, "runs INSIDE A CONTAINER") {
		t.Error("template-spec prompt carries the container guide")
	}

	auto := composePrompt("", "", "", "build something", nil, "", nil, true)
	for _, want := range []string{"Pick the app structure", "PURE STARLARK", "HYBRID",
		"FULL CONTAINER", "hybrid app.star", "OpenRun Actions app", "ace.action("} {
		if !strings.Contains(auto, want) {
			t.Errorf("auto prompt missing %q", want)
		}
	}

	noContainers := composePrompt("", "", "", "build something", nil, "", nil, false)
	for _, want := range []string{"No framework spec was chosen", "not available on this server", "ace.action("} {
		if !strings.Contains(noContainers, want) {
			t.Errorf("no-container prompt missing %q", want)
		}
	}
	for _, reject := range []string{"HYBRID", "hybrid app.star"} {
		if strings.Contains(noContainers, reject) {
			t.Errorf("no-container prompt offers container shapes: %q", reject)
		}
	}
}

func TestComposePromptServices(t *testing.T) {
	prompt := composePrompt("", "", "", "make a todo app", nil, "", []string{"postgres/main", "redis/cache"}, true)
	for _, want := range []string{"bound to the following services",
		"postgres (service postgres/main)", "prefixed POSTGRES_", "POSTGRES_URL",
		"redis (service redis/cache)", "REDIS_URL",
		"never hardcode"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("services prompt missing %q", want)
		}
	}
	// Container-spec sessions state the env arrives inside the container
	container := composePrompt("", "python-streamlit", SpecKindContainer, "dashboard", nil, "",
		[]string{"postgres/p2"}, true)
	for _, want := range []string{"inside the app's container", "POSTGRES_URL"} {
		if !strings.Contains(container, want) {
			t.Errorf("container services prompt missing %q", want)
		}
	}
	// No services: no env-contract section
	plain := composePrompt("", "", "", "make an app", nil, "", nil, true)
	if strings.Contains(plain, "bound to the following services") {
		t.Error("service section rendered with no services")
	}
}
