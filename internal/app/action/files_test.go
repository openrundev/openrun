// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestResolveResultURL(t *testing.T) {
	for _, tc := range []struct {
		appPath, actionPath, url string
		local                    string
		external                 bool
	}{
		// Relative to the action page, as a browser resolves it
		{"/app", "/image", "static/logo.png", "/app/static/logo.png", false},
		{"/app", "/", "static/logo.png", "/app/static/logo.png", false},
		{"/app", "/reports/daily", "out.csv", "/app/reports/out.csv", false},
		{"/app", "/image", "/app/_openrun/file/usr_file_1?x=1", "/app/_openrun/file/usr_file_1?x=1", false},
		{"/", "/image", "static/logo.png", "/static/logo.png", false},
		{"/", "/", "/anything", "/anything", false},
		// Outside the app: another app, a parent path, another host
		{"/app", "/image", "/other/static/logo.png", "", true},
		{"/app", "/image", "../../etc/passwd", "", true},
		{"/app", "/image", "/app/../other/x", "", true},
		{"/app", "/image", "/apple/x", "", true},
		{"/app", "/image", "https://example.com/x.png", "", true},
		{"/app", "/image", "//example.com/x.png", "", true},
	} {
		act := &Action{appPath: tc.appPath, actionPath: tc.actionPath}
		local, external, err := act.ResolveResultURL(tc.url)
		testutil.AssertNoError(t, err)
		testutil.AssertEqualsBool(t, tc.url+" external", tc.external, external)
		testutil.AssertEqualsString(t, tc.url+" local", tc.local, local)
	}

	_, _, err := (&Action{appPath: "/app", actionPath: "/"}).ResolveResultURL("")
	testutil.AssertErrorContains(t, err, "invalid result url")
}

func TestResultFiles(t *testing.T) {
	files := ResultFiles([]map[string]any{
		{"name": "a.txt", "url": "/app/_openrun/file/1"},
		{"name": "no url"},
		{"url": "static/b.png"},
	})
	testutil.AssertEqualsInt(t, "files", 2, len(files))
	testutil.AssertEqualsString(t, "name", "a.txt", files[0].Name)
	testutil.AssertEqualsString(t, "url", "static/b.png", files[1].URL)
}
