// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
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

func TestListAllAppsBreadcrumbGlobsCoverDisplayedBreadcrumbs(t *testing.T) {
	now := time.Now()
	apps := []types.AppInfo{
		{
			AppPathDomain: types.AppPathDomain{Domain: "counter.utils.demo.clace.io", Path: "/"},
			Name:          "Counter",
			Id:            types.ID_PREFIX_APP_PROD + "counter",
			Auth:          types.AppAuthnDefault,
			UpdateTime:    now,
		},
		{
			AppPathDomain: types.AppPathDomain{Domain: "counter.utils.demo.clace.io", Path: "/" + types.STAGE_SUFFIX},
			Name:          "Counter stage",
			Id:            types.ID_PREFIX_APP_STAGE + "counter",
			MainApp:       types.ID_PREFIX_APP_PROD + "counter",
			LinkedAppPath: "counter.utils.demo.clace.io:/",
			Auth:          types.AppAuthnDefault,
			UpdateTime:    now,
		},
	}
	server := &Server{
		apps: &AppStore{allApps: apps},
		staticConfig: &types.ServerConfig{
			System: types.SystemConfig{DefaultDomain: "utils.demo.clace.io"},
			Http:   types.HttpConfig{Port: 80},
		},
	}

	got, err := (&openrunPlugin{server: server}).ListAllApps(
		&starlark.Thread{Name: "test"},
		nil,
		starlark.Tuple{starlark.String(""), starlark.String(""), starlark.Bool(true)},
		nil,
	)
	if err != nil {
		t.Fatalf("list all apps: %v", err)
	}

	list, ok := got.(*starlark.List)
	if !ok {
		t.Fatalf("result type = %T, want *starlark.List", got)
	}
	var foundStage bool
	for i := 0; i < list.Len(); i++ {
		app, ok := list.Index(i).(*starlark.Dict)
		if !ok {
			t.Fatalf("app %d type = %T, want *starlark.Dict", i, list.Index(i))
		}
		pathSplit := dictList(t, app, "path_split")
		pathSplitGlob := dictList(t, app, "path_split_glob")
		if pathSplitGlob.Len() < pathSplit.Len() {
			t.Fatalf("app %d path_split_glob length = %d, want at least path_split length %d", i, pathSplitGlob.Len(), pathSplit.Len())
		}

		idValue, _, err := app.Get(starlark.String("id"))
		if err != nil {
			t.Fatalf("get app id: %v", err)
		}
		if string(idValue.(starlark.String)) != types.ID_PREFIX_APP_STAGE+"counter" {
			continue
		}
		foundStage = true
		testutil.AssertEqualsInt(t, "stage path_split length", 2, pathSplit.Len())
		testutil.AssertEqualsString(t, "stage path_split domain", "counter.utils.demo.clace.io", string(pathSplit.Index(0).(starlark.String)))
		testutil.AssertEqualsString(t, "stage path_split path", "/"+types.STAGE_SUFFIX, string(pathSplit.Index(1).(starlark.String)))
		testutil.AssertEqualsString(t, "stage domain glob", "counter.utils.demo.clace.io:**", string(pathSplitGlob.Index(0).(starlark.String)))
		testutil.AssertEqualsString(t, "stage path glob", "counter.utils.demo.clace.io:/", string(pathSplitGlob.Index(1).(starlark.String)))
	}
	if !foundStage {
		t.Fatal("stage app not returned")
	}
}

func dictList(t *testing.T, dict *starlark.Dict, key string) *starlark.List {
	t.Helper()
	value, ok, err := dict.Get(starlark.String(key))
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	if !ok {
		t.Fatalf("missing %s", key)
	}
	list, ok := value.(*starlark.List)
	if !ok {
		t.Fatalf("%s type = %T, want *starlark.List", key, value)
	}
	return list
}
