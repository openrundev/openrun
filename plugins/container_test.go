// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"strings"
	"testing"
)

func TestValidateDevSettingsRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	unknown := map[string]any{"envFiles": nil}
	if err := validateDevSettings(unknown); err == nil || !strings.Contains(err.Error(), "invalid dev_settings key") {
		t.Fatalf("unknown key error = %v", err)
	}
}
