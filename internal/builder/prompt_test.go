// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"strings"
	"testing"
)

func TestComposePromptEditMode(t *testing.T) {
	prompt := composePrompt("", "", "", "add a footer", nil, "/pets")
	for _, want := range []string{"MODIFYING an existing", "deployed at /pets",
		"Make the following change", "add a footer"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("edit prompt missing %q", want)
		}
	}
	// The create-mode framing and spec/no-spec guidance must not appear
	for _, reject := range []string{"Build the following app", "No framework spec was chosen"} {
		if strings.Contains(prompt, reject) {
			t.Errorf("edit prompt contains create-mode text %q", reject)
		}
	}

	create := composePrompt("", "", "", "make an app", nil, "")
	if strings.Contains(create, "MODIFYING an existing") {
		t.Error("create prompt contains the edit preamble")
	}
	if !strings.Contains(create, "Build the following app") {
		t.Error("create prompt missing the build framing")
	}
}
