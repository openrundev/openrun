// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestAppConfigSettingsStaticFromDiskMismatch(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")],
              settings={"app_config": {"static_from_disk": True}})

def handler(req):
	return {"key": "myvalue"}`,
	}

	// Prod mode test apps are not served from a disk directory, so declaring
	// static_from_disk in the app settings must fail the app load
	_, _, err := CreateTestApp(logger, fileData)
	if err == nil {
		t.Fatal("expected static_from_disk mismatch error")
	}
	if !strings.Contains(err.Error(), "static_from_disk") {
		t.Fatalf("error = %q, want static_from_disk mismatch", err.Error())
	}
}
