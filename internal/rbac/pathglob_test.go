// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestParseAppPathGlob(t *testing.T) {
	tests := map[string]struct {
		spec      string
		apps      []types.AppPathDomain
		want      []types.AppPathDomain
		wantError error
	}{
		"Match *": {
			spec:      "*", // defaults to no domain :*
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app"}, {Domain: "mydomain", Path: "/app"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app"}},
			wantError: nil,
		},
		"Match :*": {
			spec:      ":*", // same as *
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app"}, {Domain: "mydomain", Path: "/app"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app"}},
			wantError: nil,
		},
		"Match * none": {
			spec:      "*",
			apps:      []types.AppPathDomain{{Domain: "mydomain", Path: "/app"}},
			want:      []types.AppPathDomain{},
			wantError: nil,
		},
		"Match /abc": {
			spec:      "/abc",
			apps:      []types.AppPathDomain{{Domain: "mydomain", Path: "/abc"}, {Domain: "", Path: "/abc"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/abc"}},
			wantError: nil,
		},
		"Match /abc*": {
			spec:      "/abc*",
			apps:      []types.AppPathDomain{{Domain: "mydomain", Path: "/abc"}, {Domain: "", Path: "/abc"}, {Domain: "", Path: "/abc2"}, {Domain: "", Path: "/abc/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/abc"}, {Domain: "", Path: "/abc2"}},
			wantError: nil,
		},
		"Match /abc/*": {
			spec:      "/abc/*",
			apps:      []types.AppPathDomain{{Domain: "mydomain", Path: "/abc"}, {Domain: "", Path: "/abc"}, {Domain: "", Path: "/abc2"}, {Domain: "", Path: "/abc/def"}, {Domain: "", Path: "/abc/def/xyz"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/abc/def"}},
			wantError: nil,
		},
		"Match /abc/**": {
			spec:      "/abc/**",
			apps:      []types.AppPathDomain{{Domain: "mydomain", Path: "/abc"}, {Domain: "", Path: "/abc"}, {Domain: "", Path: "/abc2"}, {Domain: "", Path: "/abc/def"}, {Domain: "", Path: "/abc/def/xyz"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/abc"}, {Domain: "", Path: "/abc/def"}, {Domain: "", Path: "/abc/def/xyz"}},
			wantError: nil,
		},
		"Match *:*": {
			spec:      "*:*",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app1"}},
			wantError: nil,
		},
		"Match *:": {
			spec:      "*:",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/"}},
			wantError: nil,
		},
		"Match *:**": {
			spec:      "*:**",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			wantError: nil,
		},
		"Match all": {
			spec:      "all",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			wantError: nil,
		},
		"Match empty": {
			spec:      "",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			wantError: nil,
		},
		"Match **:**": {
			spec:      "**:**",
			apps:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "", Path: "/app1"}, {Domain: "mydomain", Path: "/app2/def"}},
			wantError: nil,
		},
		"Match mydomain*:**": {
			spec:      "mydomain*:**",
			apps:      []types.AppPathDomain{{Domain: "testdomain", Path: "/app1"}, {Domain: "mydomain", Path: "/app/def"}, {Domain: "mydomain.test", Path: "/app2/def"}},
			want:      []types.AppPathDomain{{Domain: "mydomain", Path: "/app/def"}, {Domain: "mydomain.test", Path: "/app2/def"}},
			wantError: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotApps, gotError := ParseGlob(tc.spec, tc.apps)
			testutil.AssertEqualsError(t, "error", gotError, tc.wantError)
			result := slices.Equal(gotApps, tc.want)
			if !result {
				t.Errorf("response got: %v, want: %v", gotApps, tc.want)
			}
		})
	}
}

func TestParseAppPathGlobErrors(t *testing.T) {
	tests := map[string]struct {
		spec      string
		wantError error
	}{
		"Match a:b:c": {
			spec:      "a:b:c",
			wantError: fmt.Errorf("path glob has to be in the format of domain:path"),
		},
		"Match invalid path": {
			spec:      ":[]",
			wantError: fmt.Errorf("syntax error in pattern"),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, gotError := ParseGlob(tc.spec, []types.AppPathDomain{{Domain: "", Path: "/app1"}})
			testutil.AssertErrorContains(t, gotError, tc.wantError.Error())
		})
	}
}
