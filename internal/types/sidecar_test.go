// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"testing"
)

func TestParseSidecarSpec(t *testing.T) {
	spec, err := ParseSidecarSpec(`{"name":"cache","image":"image:memcached:1.6-alpine","port":11211,"args":["-m","64"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "cache" || spec.ImageRef() != "memcached:1.6-alpine" || spec.Port != 11211 || len(spec.Args) != 2 {
		t.Fatalf("unexpected spec %+v", spec)
	}
	if spec.IsAppImage() || spec.InheritsEnv() || spec.IsAlwaysOn() {
		t.Fatalf("foreign port'd sidecar defaults wrong: inherit=%v alwaysOn=%v", spec.InheritsEnv(), spec.IsAlwaysOn())
	}

	worker, err := ParseSidecarSpec(`{"name":"job-runner","command":["python","worker.py"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !worker.IsAppImage() || !worker.InheritsEnv() || !worker.IsAlwaysOn() {
		t.Fatalf("app image worker defaults wrong: inherit=%v alwaysOn=%v", worker.InheritsEnv(), worker.IsAlwaysOn())
	}
	if got := SidecarAddrEnvName(worker.Name); got != "CL_SIDECAR_JOB_RUNNER_ADDR" {
		t.Fatalf("env name %s", got)
	}

	// Explicit overrides of the conditional defaults survive the canonical round trip
	explicit, err := ParseSidecarSpec(`{"name":"w","command":["x"],"inherit_env":false,"always_on":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.InheritsEnv() || explicit.IsAlwaysOn() {
		t.Fatalf("explicit false overrides lost")
	}
	again, err := ParseSidecarSpec(explicit.String())
	if err != nil {
		t.Fatal(err)
	}
	if again.InheritsEnv() || again.IsAlwaysOn() {
		t.Fatalf("explicit false overrides lost after round trip: %s", explicit.String())
	}
	if !strings.Contains(explicit.String(), `"inherit_env":false`) {
		t.Fatalf("canonical form dropped explicit false: %s", explicit.String())
	}
}

func TestParseSidecarSpecErrors(t *testing.T) {
	cases := map[string]string{
		`{"name":"x","command":["a"],"bogus":1}`:                "unknown",
		`{"name":"Bad_Name","command":["a"]}`:                   "invalid sidecar name",
		`{"name":"w"}`:                                          "must set command",
		`{"name":"c","image":"memcached"}`:                      "image must be",
		`{"name":"c","image":"image:"}`:                         "image reference is empty",
		`{"name":"c","image":"image:m","health":"http:/x"}`:     "health requires port",
		`{"name":"c","image":"image:m","port":1,"health":"/x"}`: "health must be",
		`{"name":"c","image":"image:m","port":70000}`:           "invalid port",
		`{"name":"c","image":"image:m","env":{"A B":"v"}}`:      "invalid env name",
	}
	for input, want := range cases {
		_, err := ParseSidecarSpec(input)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", input, err, want)
		}
	}
	if _, err := ParseSidecarSpecs([]string{`{"name":"a","command":["x"]}`, `{"name":"a","command":["y"]}`}); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate names: %v", err)
	}
}

func TestMergeSidecarSpecs(t *testing.T) {
	fromApp := []SidecarSpec{
		{Name: "cache", Image: "image:memcached:1.6", Port: 11211},
		{Name: "worker", Command: []string{"python", "w.py"}, Env: map[string]string{"A": "1"}},
	}
	fromMetadata := []SidecarSpec{
		{Name: "worker", Command: []string{"python", "w2.py"}},
		{Name: "extra", Command: []string{"x"}},
	}
	merged, err := MergeSidecarSpecs(fromApp, fromMetadata, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].Name != "cache" || merged[1].Name != "worker" || merged[2].Name != "extra" {
		t.Fatalf("merge order wrong: %+v", merged)
	}
	// Metadata replaces the whole declaration, no field merge
	if merged[1].Command[1] != "w2.py" || merged[1].Env != nil {
		t.Fatalf("metadata sidecar did not replace: %+v", merged[1])
	}

	if _, err := MergeSidecarSpecs(fromApp, nil, 11211); err == nil || !strings.Contains(err.Error(), "conflicts with the app port") {
		t.Errorf("app port conflict: %v", err)
	}
	dup := []SidecarSpec{{Name: "a", Image: "image:m", Port: 1}, {Name: "b", Image: "image:m", Port: 1}}
	if _, err := MergeSidecarSpecs(dup, nil, 0); err == nil || !strings.Contains(err.Error(), "both use port") {
		t.Errorf("sidecar port conflict: %v", err)
	}
}

func TestSidecarImageAllowed(t *testing.T) {
	if ok, _ := SidecarImageAllowed(nil, "anything"); !ok {
		t.Error("empty list must allow")
	}
	ok, err := SidecarImageAllowed([]string{"memcached:1.6-alpine", "regex:^redis:.*"}, "redis:7")
	if err != nil || !ok {
		t.Errorf("regex entry: %v %v", ok, err)
	}
	if ok, _ := SidecarImageAllowed([]string{"memcached:1.6-alpine"}, "memcached:1.5"); ok {
		t.Error("non matching image allowed")
	}
}
