// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"strings"
	"testing"
)

func TestValidateDevSettings(t *testing.T) {
	t.Parallel()

	settings := map[string]any{}
	for _, key := range []string{"target", "command", "dir", "reload", "env_files", "additional_mounts", "port"} {
		settings[key] = nil
	}
	if err := validateDevSettings(settings); err != nil {
		t.Fatalf("validateDevSettings returned error: %v", err)
	}
}

func TestValidateDevSettingsRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	unknown := map[string]any{"envFiles": nil}
	if err := validateDevSettings(unknown); err == nil || !strings.Contains(err.Error(), "invalid dev_settings key") {
		t.Fatalf("unknown key error = %v", err)
	}
}
