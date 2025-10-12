// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestGetSourceUrl(t *testing.T) {
	tests := []struct {
		url    string
		branch string
		want   string
	}{
		{
			url:    "github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "main",
			want:   "https://github.com/openrundev/openrun/tree/main/myapp/",
		},
		{
			url:    "/openrundev/openrun/myapp",
			branch: "main",
			want:   "",
		},
		{
			url:    "git@github.com/openrundev/openrun.git/myapp/t1/t2",
			branch: "develop",
			want:   "",
		},
		{
			url:    "git@github.com:openrundev/openrun.git/myapp/t1/t2",
			branch: "develop",
			want:   "",
		},
		{
			url:    "github.com/openrundev",
			branch: "main",
			want:   "",
		},
		{
			url:    "https://github.com/openrundev/openrun/myapp",
			branch: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		testutil.AssertEqualsString(t, tt.url, tt.want, getSourceUrl(tt.url, tt.branch))
	}
}
