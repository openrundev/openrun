// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

func TestValidateBindingCreatePathRejectsAutoPrefix(t *testing.T) {
	tests := []string{
		"/auto",
		"/auto/app",
	}

	for _, bindingPath := range tests {
		t.Run(bindingPath, func(t *testing.T) {
			err := validateBindingCreatePath(bindingPath, false)
			if err == nil {
				t.Fatalf("validateBindingCreatePath(%q) should fail", bindingPath)
			}
			if !strings.Contains(err.Error(), "/auto is reserved for autobindings") {
				t.Fatalf("error = %q, want reserved autobindings message", err.Error())
			}
		})
	}
}

func TestValidateBindingCreatePathAllowsNonAutoPath(t *testing.T) {
	tests := []string{
		"/apps/b1",
		"/autobind",
		"/automation",
	}

	for _, bindingPath := range tests {
		t.Run(bindingPath, func(t *testing.T) {
			if err := validateBindingCreatePath(bindingPath, false); err != nil {
				t.Fatalf("validateBindingCreatePath returned error: %v", err)
			}
		})
	}
}

func TestValidateBindingCreatePathAllowsInternalAutoPath(t *testing.T) {
	if err := validateBindingCreatePath("/auto/app", true); err != nil {
		t.Fatalf("validateBindingCreatePath returned error: %v", err)
	}
}
