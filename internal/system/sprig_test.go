// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	htmltemplate "html/template"
	"strings"
	"testing"
)

// TestAppEvalTemplatePassthrough guards the plugin-argument path: arbitrary
// user text with {{ }} braces (chat messages, params holding template or
// code snippets) must pass through literally; only templates actually
// calling secret/secret_from are executed. A crash here surfaced as a hard
// handler error on any console form whose value contained braces
func TestAppEvalTemplatePassthrough(t *testing.T) {
	s := &SecretManager{funcMap: GetFuncMap()}
	s.funcMap["secret"] = s.templateSecretFunc
	s.funcMap["secret_from"] = s.templateSecretFromFunc

	for _, input := range []string{
		"use {{ .Data.Html | safeHTML }} in the template", // parses, no secrets
		"try {{ x }} something",                           // does not parse (unknown func)
		"{{ unclosed",                                     // not a template at all
		"upper {{ upper \"a\" }}",                         // sprig-only action, no secrets
		"plain text",                                      // no braces fast path
	} {
		got, err := s.AppEvalTemplate(nil, "", input)
		if err != nil {
			t.Fatalf("input %q: unexpected error %v", input, err)
		}
		if got != input {
			t.Fatalf("input %q: changed to %q, must pass through literally", input, got)
		}
	}

	// A real secret reference still evaluates (and errors: no provider
	// configured) - references must not silently become literal text
	if _, err := s.AppEvalTemplate(nil, "prop", `{{secret "k"}}`); err == nil {
		t.Fatal("a real secret reference must still be evaluated")
	}
}

func TestSafeHTMLFunc(t *testing.T) {
	tmpl, err := htmltemplate.New("t").Funcs(GetFuncMap()).
		Parse(`{{ .Escaped }}|{{ .Raw | safeHTML }}`)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	err = tmpl.Execute(&b, map[string]string{
		"Escaped": "<b>x</b>",
		"Raw":     "<b>x</b>",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if got != "&lt;b&gt;x&lt;/b&gt;|<b>x</b>" {
		t.Fatalf("safeHTML did not bypass escaping (default escaping must stay): %q", got)
	}
}
