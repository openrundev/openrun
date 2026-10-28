// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
	htmltemplate "html/template"
	"math"
	"math/big"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/openrundev/openrun/internal/webstatic"
)

// The sprig functions which allocate in proportion to an integer argument
// are capped: a template commonly passes a request value to them
// ({{ range until .n }}, {{ repeat .n "-" }}), template rendering has no
// cancellation, and nothing else bounds the allocation
const (
	// MaxTemplateItems caps the element count of the sequence functions
	// until, untilStep and seq
	MaxTemplateItems = 1_000_000
	// MaxTemplateBytes caps the output of the string generating functions
	// repeat, indent, nindent and rand*
	MaxTemplateBytes = 16 << 20
)

// rangeItems is the element count of sprig's untilStep(start, stop, step)
// loop, computed without signed overflow. The loop increments its counter
// past the last element before the exit test, so a range whose final
// counter value is outside the int range never terminates (the counter
// wraps around and stays below stop); such a range is an error
func rangeItems(start, stop, step int) (int64, error) {
	if step == 0 || stop == start || (stop > start) != (step > 0) {
		return 0, nil
	}
	bigStart, bigStep := big.NewInt(int64(start)), big.NewInt(int64(step))
	span := new(big.Int).Sub(big.NewInt(int64(stop)), bigStart)
	// span and step have the same sign: items = ceil(span / step)
	items := new(big.Int).Sub(span, big.NewInt(int64(step/abs(step))))
	items.Quo(items, bigStep).Add(items, big.NewInt(1))
	final := new(big.Int).Add(bigStart, new(big.Int).Mul(items, bigStep))
	if !final.IsInt64() {
		return 0, fmt.Errorf("range from %d to %d by %d ends outside the integer range", start, stop, step)
	}
	if !items.IsInt64() {
		return math.MaxInt64, nil
	}
	return items.Int64(), nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// checkRange rejects a sprig untilStep range over MaxTemplateItems elements
// or one whose loop would not terminate, see rangeItems
func checkRange(name string, start, stop, step int) error {
	items, err := rangeItems(start, stop, step)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return checkTemplateItems(name, items)
}

func checkTemplateItems(name string, items int64) error {
	if items > MaxTemplateItems {
		return fmt.Errorf("%s: %d items exceeds the limit of %d", name, items, MaxTemplateItems)
	}
	return nil
}

func checkTemplateBytes(name string, size int64) error {
	if size > MaxTemplateBytes {
		return fmt.Errorf("%s: %d bytes exceeds the limit of %d", name, size, MaxTemplateBytes)
	}
	return nil
}

// checkTemplateProduct applies checkTemplateBytes to count*size+extra
// without overflowing: a request-derived count large enough to wrap the
// product must fail, not pass as a small size. A negative count is refused
// as well: the sprig functions pass it to strings.Repeat, which panics
func checkTemplateProduct(name string, count, size, extra int64) error {
	if count < 0 {
		return fmt.Errorf("%s: negative count %d", name, count)
	}
	if size > 0 && count > MaxTemplateBytes/size {
		return fmt.Errorf("%s: %d bytes exceeds the limit of %d", name, MaxTemplateBytes+1, MaxTemplateBytes)
	}
	// count*size is at most MaxTemplateBytes here, so the sum cannot overflow
	return checkTemplateBytes(name, count*size+extra)
}

// checkSeq applies checkRange to the untilStep call sprig's seq(params...)
// makes. The stop computations wrap exactly as in sprig (Go int addition),
// so the checked range is the one sprig iterates
func checkSeq(params []int) error {
	switch len(params) {
	case 1:
		start, end, increment := 1, params[0], 1
		if end < start {
			increment = -1
		}
		return checkRange("seq", start, end+increment, increment)
	case 2:
		start, end, step := params[0], params[1], 1
		if end < start {
			step = -1
		}
		return checkRange("seq", start, end+step, step)
	case 3:
		start, step, end, increment := params[0], params[1], params[2], 1
		if end < start {
			increment = -1
			if step > 0 {
				return nil
			}
		}
		return checkRange("seq", start, end+increment, step)
	}
	return nil
}

// sprigFunc returns the sprig function of the name with its expected
// signature; a signature change in sprig is a startup failure, not a
// silently dropped cap
func sprigFunc[F any](funcMap template.FuncMap, name string) F {
	fn, ok := funcMap[name].(F)
	if !ok {
		panic(fmt.Sprintf("sprig function %s has an unexpected signature %T", name, funcMap[name]))
	}
	return fn
}

// capSprigFuncs replaces the allocating sprig functions with capped versions
func capSprigFuncs(funcMap template.FuncMap) {
	until := sprigFunc[func(int) []int](funcMap, "until")
	funcMap["until"] = func(count int) ([]int, error) {
		step := 1
		if count < 0 {
			step = -1
		}
		if err := checkRange("until", 0, count, step); err != nil {
			return nil, err
		}
		return until(count), nil
	}
	untilStep := sprigFunc[func(int, int, int) []int](funcMap, "untilStep")
	funcMap["untilStep"] = func(start, stop, step int) ([]int, error) {
		if err := checkRange("untilStep", start, stop, step); err != nil {
			return nil, err
		}
		return untilStep(start, stop, step), nil
	}
	seq := sprigFunc[func(...int) string](funcMap, "seq")
	funcMap["seq"] = func(params ...int) (string, error) {
		if err := checkSeq(params); err != nil {
			return "", err
		}
		return seq(params...), nil
	}
	repeat := sprigFunc[func(int, string) string](funcMap, "repeat")
	funcMap["repeat"] = func(count int, str string) (string, error) {
		if err := checkTemplateProduct("repeat", int64(count), int64(len(str)), 0); err != nil {
			return "", err
		}
		return repeat(count, str), nil
	}
	for _, name := range []string{"indent", "nindent"} {
		indent := sprigFunc[func(int, string) string](funcMap, name)
		funcMap[name] = func(spaces int, v string) (string, error) {
			lines := int64(strings.Count(v, "\n") + 1)
			if err := checkTemplateProduct(name, int64(spaces), lines, int64(len(v))); err != nil {
				return "", err
			}
			return indent(spaces, v), nil
		}
	}
	for _, name := range []string{"randAlphaNum", "randAlpha", "randAscii", "randNumeric"} {
		random := sprigFunc[func(int) string](funcMap, name)
		funcMap[name] = func(count int) (string, error) {
			if err := checkTemplateProduct(name, int64(count), 1, 0); err != nil {
				return "", err
			}
			return random(count), nil
		}
	}
	randBytes := sprigFunc[func(int) (string, error)](funcMap, "randBytes")
	funcMap["randBytes"] = func(count int) (string, error) {
		if err := checkTemplateProduct("randBytes", int64(count), 1, 0); err != nil {
			return "", err
		}
		return randBytes(count)
	}
}

// GetFuncMap returns a template.FuncMap that includes all the sprig functions except for env and expandenv.
func GetFuncMap() template.FuncMap {
	funcMap := sprig.FuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")
	capSprigFuncs(funcMap)
	funcMap["pathEscape"] = url.PathEscape
	funcMap["pathUnescape"] = url.PathUnescape
	funcMap["queryEscape"] = url.QueryEscape
	funcMap["queryUnescape"] = url.QueryUnescape
	// safeHTML marks a handler-built string as pre-escaped markup, opting it
	// out of html/template's contextual escaping (sprig has no equivalent).
	// Apps that render server-side HTML (markdown previews, rich text) need
	// it; any user input must be escaped while building the string
	funcMap["safeHTML"] = func(s string) htmltemplate.HTML { return htmltemplate.HTML(s) }
	// relTime renders a timestamp as a relative age via HumanDuration,
	// defaulting to a single unit - "1 day ago", "3 hours ago", "recently" -
	// so hours never accumulate past a day ("1540 hours" renders as days).
	// An optional resolution argument widens it: {{ relTime .t 2 }} gives
	// "1 day 3 hours ago". Accepts time.Time or an RFC3339 string
	// (fractional seconds and offsets tolerated); zero times and
	// unparseable values render as "-"
	funcMap["relTime"] = relTime
	// openrun_static resolves a browser asset shared by every app and served
	// by the server binary (htmx, the <log-tail> viewer, action css, brand
	// fonts) to its content-hashed /_openrun/static url, see
	// internal/webstatic
	funcMap["openrun_static"] = webstatic.URL
	return funcMap
}

func relTime(value any, resolution ...int) string {
	var t time.Time
	switch v := value.(type) {
	case time.Time:
		t = v
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
		if err != nil {
			return "-"
		}
		t = parsed
	default:
		return "-"
	}
	if t.IsZero() {
		return "-"
	}
	units := 1
	if len(resolution) > 0 && resolution[0] > 0 {
		units = resolution[0]
	}
	return HumanDuration(time.Since(t), units)
}
