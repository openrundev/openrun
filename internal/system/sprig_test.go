// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	htmltemplate "html/template"
	"math"
	"strings"
	"testing"
)

// TestAppEvalTemplatePassthrough guards the lenient path (container env and
// build args): arbitrary operator strings with {{ }} braces must pass
// through literally; only templates actually calling secret/secret_from are
// executed. Plugin arguments use the strict path (ace.eval values only)
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
		got, err := s.AppEvalTemplate(nil, "", input, false)
		if err != nil {
			t.Fatalf("input %q: unexpected error %v", input, err)
		}
		if got != input {
			t.Fatalf("input %q: changed to %q, must pass through literally", input, got)
		}
	}

	// A real secret reference still evaluates (and errors: no provider
	// configured) - references must not silently become literal text
	if _, err := s.AppEvalTemplate(nil, "prop", `{{secret "k"}}`, false); err == nil {
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

// The allocating sprig functions are capped: a count from a request value
// cannot make a template allocate without bound
func TestSprigFuncCaps(t *testing.T) {
	funcMap := GetFuncMap()
	render := func(src string, data any) (string, error) {
		tmpl, err := htmltemplate.New("t").Funcs(funcMap).Parse(src)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		var out strings.Builder
		err = tmpl.Execute(&out, data)
		return out.String(), err
	}
	ok := map[string]string{
		`{{ len (until 5) }}`:           "5",
		`{{ len (until -3) }}`:          "3",
		`{{ len (untilStep 10 0 -2) }}`: "5",
		`{{ seq 3 }}`:                   "1 2 3",
		`{{ seq 5 1 }}`:                 "5 4 3 2 1",
		`{{ seq 1 2 7 }}`:               "1 3 5 7",
		`{{ repeat 3 "ab" }}`:           "ababab",
		`{{ indent 2 "a\nb" }}`:         "  a\n  b",
		`{{ nindent 1 "a" }}`:           "\n a",
		`{{ len (randAlpha 8) }}`:       "8",
		`{{ len (randAlphaNum 8) }}`:    "8",
		`{{ len (randAscii 8) }}`:       "8",
		`{{ len (randNumeric 8) }}`:     "8",
		`{{ len (until .n) }}`:          "1000000",
		`{{ len (repeat .n "x") }}`:     "1000000",
	}
	for src, want := range ok {
		got, err := render(src, map[string]any{"n": MaxTemplateItems})
		if err != nil {
			t.Errorf("%s: %v", src, err)
		} else if got != want {
			t.Errorf("%s: got %q want %q", src, got, want)
		}
	}
	itemsOver := []string{
		`{{ until .n }}`, `{{ until -1000001 }}`, `{{ untilStep 0 .n 1 }}`, `{{ untilStep .n 0 -1 }}`,
		`{{ seq .n }}`, `{{ seq 1 .n }}`, `{{ seq 1 1 .n }}`, `{{ seq .n 1 }}`,
	}
	for _, src := range itemsOver {
		if _, err := render(src, map[string]any{"n": MaxTemplateItems + 1}); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
			t.Errorf("%s: expected the cap error, got %v", src, err)
		}
	}
	bytesOver := []string{
		`{{ repeat .n "x" }}`, `{{ repeat 2 .s }}`, `{{ indent .n "a\nb" }}`, `{{ nindent .n "a" }}`,
		`{{ randAlpha .n }}`, `{{ randAlphaNum .n }}`, `{{ randAscii .n }}`, `{{ randNumeric .n }}`, `{{ randBytes .n }}`,
	}
	for _, src := range bytesOver {
		data := map[string]any{"n": MaxTemplateBytes + 1, "s": strings.Repeat("x", MaxTemplateBytes/2+1)}
		if _, err := render(src, data); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
			t.Errorf("%s: expected the cap error, got %v", src, err)
		}
	}
	// seq with a huge count never materializes the sequence
	if _, err := render(`{{ seq 1000000000000 }}`, nil); err == nil {
		t.Error("seq of 10^12 items not refused")
	}
	// A count whose product with the unit size wraps the int64 range must
	// fail, not pass as a small size; a negative count would make sprig
	// panic in strings.Repeat and is refused too
	for _, src := range []string{
		`{{ indent .huge "a\nb\nc\nd" }}`, `{{ nindent .huge "a\nb\nc\nd" }}`, `{{ repeat .huge "abcd" }}`,
		`{{ indent .max "a" }}`, `{{ repeat .max "x" }}`, `{{ indent -1 "a" }}`, `{{ nindent -1 "a" }}`,
		`{{ repeat -1 "a" }}`, `{{ randAlpha -1 }}`, `{{ randAlphaNum -1 }}`, `{{ randAscii -1 }}`,
		`{{ randNumeric -1 }}`, `{{ randBytes -1 }}`,
	} {
		if _, err := render(src, map[string]any{"huge": 1 << 62, "max": math.MaxInt}); err == nil {
			t.Errorf("%s: overflowing or negative count not refused", src)
		}
	}
	// A zero count and an empty string are fine
	for src, want := range map[string]string{`{{ indent 0 "a" }}`: "a", `{{ repeat 0 "a" }}`: "", `{{ repeat .max "" }}`: ""} {
		if got, err := render(src, map[string]any{"max": math.MaxInt}); err != nil || got != want {
			t.Errorf("%s: got %q want %q, %v", src, got, want, err)
		}
	}
	// Counts near the int boundary: the count computation must not overflow
	// (a negative count would pass the cap), and a range whose loop counter
	// would wrap past the boundary (sprig's loop never terminates) is refused
	// even when its element count is small
	boundary := map[string]any{"max": math.MaxInt, "min": math.MinInt, "nearMax": math.MaxInt - 5, "nearMin": math.MinInt + 5,
		"maxLess1": math.MaxInt - 1, "minPlus1": math.MinInt + 1}
	for _, src := range []string{
		`{{ untilStep 0 .max 2 }}`, `{{ untilStep .min .max 1 }}`, `{{ untilStep .max .min -1 }}`,
		`{{ until .max }}`, `{{ until .min }}`, `{{ seq .min 1 .nearMax }}`, `{{ seq .nearMax -1 .minPlus1 }}`,
		`{{ untilStep .nearMax .max 2 }}`, `{{ untilStep .nearMin .min -2 }}`,
		`{{ seq .nearMax 2 .maxLess1 }}`, `{{ seq .nearMin -2 .minPlus1 }}`,
	} {
		if _, err := render(src, boundary); err == nil {
			t.Errorf("%s: range at the int boundary not refused", src)
		}
	}
	// Ranges ending exactly on the boundary terminate and are small
	for src, want := range map[string]string{
		`{{ len (untilStep .nearMax .max 5) }}`: "1", `{{ len (untilStep .max .nearMax -2) }}`: "3",
		`{{ len (untilStep .nearMin .min -5) }}`: "1",
	} {
		if got, err := render(src, boundary); err != nil || got != want {
			t.Errorf("%s: got %q want %q, %v", src, got, want, err)
		}
	}
	// seq up to the max int: sprig's own stop computation wraps and sprig
	// renders an empty sequence; the check mirrors that and lets it through
	for _, src := range []string{`{{ seq .max }}`, `{{ seq 1 .max }}`, `{{ seq .min .max }}`, `{{ seq .nearMax 2 .max }}`, `{{ seq .nearMax -1 .min }}`} {
		if got, err := render(src, boundary); err != nil || got != "" {
			t.Errorf("%s: got %q, %v", src, got, err)
		}
	}
}

func TestRangeItems(t *testing.T) {
	cases := []struct {
		start, stop, step int
		items             int64
		wraps             bool
	}{
		{0, 10, 3, 4, false}, {0, 10, 1, 10, false}, {10, 0, -3, 4, false}, {-10, -5, 1, 5, false},
		{0, 10, -1, 0, false}, {10, 0, 1, 0, false}, {0, 0, 1, 0, false}, {0, 10, 0, 0, false},
		{math.MaxInt - 4, math.MaxInt, 2, 2, false}, {math.MinInt + 4, math.MinInt, -2, 2, false},
		{math.MinInt, math.MaxInt, 1, math.MaxInt64, false},
		{0, math.MaxInt, math.MaxInt, 1, false}, {0, math.MaxInt, 2, 0, true}, {math.MaxInt - 5, math.MaxInt, 2, 0, true},
		{math.MinInt, math.MaxInt, 2, 0, true}, {math.MaxInt, math.MinInt, -2, 0, true}, {0, math.MinInt, math.MinInt, 0, true},
	}
	for _, c := range cases {
		items, err := rangeItems(c.start, c.stop, c.step)
		if (err != nil) != c.wraps || items != c.items {
			t.Errorf("rangeItems(%d, %d, %d) = %d, %v; want %d, wraps %v", c.start, c.stop, c.step, items, err, c.items, c.wraps)
		}
	}
}
