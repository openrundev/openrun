// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestValidateDevSettings(t *testing.T) {
	t.Parallel()

	dict := starlark.NewDict(7)
	for _, key := range []string{"target", "command", "dir", "reload", "env_files", "additional_mounts", "port"} {
		if err := dict.SetKey(starlark.String(key), starlark.None); err != nil {
			t.Fatalf("SetKey(%q): %v", key, err)
		}
	}
	if err := validateDevSettings(dict); err != nil {
		t.Fatalf("validateDevSettings returned error: %v", err)
	}
}

func TestValidateDevSettingsRejectsUnknownAndNonStringKeys(t *testing.T) {
	t.Parallel()

	unknown := starlark.NewDict(1)
	if err := unknown.SetKey(starlark.String("envFiles"), starlark.None); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if err := validateDevSettings(unknown); err == nil || !strings.Contains(err.Error(), "invalid dev_settings key") {
		t.Fatalf("unknown key error = %v", err)
	}

	nonString := starlark.NewDict(1)
	if err := nonString.SetKey(starlark.MakeInt(1), starlark.None); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if err := validateDevSettings(nonString); err == nil || !strings.Contains(err.Error(), "keys must be strings") {
		t.Fatalf("non-string key error = %v", err)
	}
}
