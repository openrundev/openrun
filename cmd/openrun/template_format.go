// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"math"
	"strings"
	"text/template"

	"github.com/openrundev/openrun/internal/system"
	"github.com/urfave/cli/v2"
)

// isTemplateFormat reports whether a --format value is a Go template rather
// than one of the fixed format names. Like docker --format, any value which
// contains a template action is a template; a value without one has to be a
// known name, so a typo like "jsno" is still an error
func isTemplateFormat(format string) bool {
	return strings.Contains(format, "{{")
}

// templateFuncMap is the function set available to --format templates:
// text/template builtins plus sprig (minus env/expandenv) and the openrun
// additions like relTime. The HTML-only helpers of the app template func map
// are dropped, and json renders a value as compact JSON
func templateFuncMap() template.FuncMap {
	funcMap := system.GetFuncMap()
	delete(funcMap, "safeHTML")
	delete(funcMap, "openrun_static")
	funcMap["json"] = func(v any) (string, error) {
		data, err := json.Marshal(v, deterministicJSON)
		return string(data), err
	}
	return funcMap
}

// parseFormatTemplate compiles a --format template
func parseFormatTemplate(format string) (*template.Template, error) {
	tmpl, err := template.New("format").Funcs(templateFuncMap()).Parse(format)
	if err != nil {
		return nil, fmt.Errorf("invalid format template: %w", err)
	}
	return tmpl, nil
}

// printTemplate renders a --format template once per item of a list, one
// line per item. Each item is rendered through its JSON form, so the field
// names are the ones shown by --format json ({{.metadata.name}}), whatever
// the Go struct calls them
func printTemplate(cCtx *cli.Context, format string, items any) error {
	tmpl, err := parseFormatTemplate(format)
	if err != nil {
		return err
	}
	rows, err := templateRows(items)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, row := range rows {
		buf.Reset()
		if err := tmpl.Execute(&buf, row); err != nil {
			return fmt.Errorf("error rendering format template: %w", err)
		}
		buf.WriteByte('\n')
		if _, err := cCtx.App.Writer.Write(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// templateRows converts a list of API values to their JSON form, as the data
// a template renders. Integral numbers are kept as int64 so a version or a
// file size prints as 3 and 1048576 rather than 3 and 1.048576e+06
func templateRows(items any) ([]any, error) {
	data, err := json.Marshal(items, deterministicJSON)
	if err != nil {
		return nil, fmt.Errorf("error converting rows for format template: %w", err)
	}
	var rows []any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("error converting rows for format template: %w", err)
	}
	for i, row := range rows {
		rows[i] = normalizeNumbers(row)
	}
	return rows, nil
}

func normalizeNumbers(v any) any {
	switch value := v.(type) {
	case float64:
		if value == math.Trunc(value) && math.Abs(value) < 1<<53 {
			return int64(value)
		}
		return value
	case map[string]any:
		for k, item := range value {
			value[k] = normalizeNumbers(item)
		}
		return value
	case []any:
		for i, item := range value {
			value[i] = normalizeNumbers(item)
		}
		return value
	default:
		return v
	}
}
