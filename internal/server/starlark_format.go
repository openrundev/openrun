// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openrundev/openrun/internal/types"
)

// formatLineWidth is the width above which a dict value is wrapped to one
// entry per line
const formatLineWidth = 100

// formatConfig renders binding() and app() definitions as a declarative config
// file: path and source on their own lines, one kwarg per line, one blank line
// between definitions and two blank lines between the bindings and apps
// sections. The output is deterministic (sorted dict keys, no timestamps) so
// exports of unchanged state are byte identical
func formatConfig(bindings []*types.CreateBindingRequest, apps []*types.CreateAppRequest) (string, []string) {
	warnings := []string{}
	bindingBlocks := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		bindingBlocks = append(bindingBlocks, formatBinding(binding))
	}
	appBlocks := make([]string, 0, len(apps))
	for _, app := range apps {
		call, callWarnings := formatApp(app)
		warnings = append(warnings, callWarnings...)
		appBlocks = append(appBlocks, call)
	}

	var sb strings.Builder
	sb.WriteString(strings.Join(bindingBlocks, "\n\n"))
	if len(bindingBlocks) > 0 && len(appBlocks) > 0 {
		sb.WriteString("\n\n\n")
	}
	sb.WriteString(strings.Join(appBlocks, "\n\n"))
	if len(bindingBlocks) > 0 || len(appBlocks) > 0 {
		sb.WriteString("\n")
	}
	return sb.String(), warnings
}

// callArg is one argument of a rendered call. Dict- and list-valued kwargs
// carry their entries so wrapCall can expand them to one entry per line when
// too long
type callArg struct {
	text        string   // inline form, including the key= prefix for kwargs
	prefix      string   // key= prefix, set only for expandable kwargs
	entries     []string // entries for the expanded form
	open, close string   // expanded form brackets: {} for dicts, [] for lists
}

func strArg(text string) callArg {
	return callArg{text: text}
}

func formatBinding(req *types.CreateBindingRequest) string {
	args := []callArg{strArg("path=" + quoteStarlark(req.Path)), strArg("source=" + quoteStarlark(req.Source))}
	if len(req.Grants) > 0 {
		args = append(args, strArg("grants="+formatStringList(req.Grants)))
	}
	if len(req.Config) > 0 {
		args = append(args, dictArg("config", stringDictEntries(req.Config)))
	}
	return wrapCall(BINDING, args)
}

// formatApp renders one app() call. kwargs follow the app() builtin's
// declaration order and default values are omitted
func formatApp(req *types.CreateAppRequest) (string, []string) {
	warnings := []string{}
	args := []callArg{strArg("path=" + quoteStarlark(req.Path)), strArg("source=" + quoteStarlark(req.SourceUrl))}
	addStr := func(key, value string) {
		if value != "" {
			args = append(args, strArg(key+"="+quoteStarlark(value)))
		}
	}

	if req.IsDev {
		args = append(args, strArg("dev=True"))
	}
	if req.AppAuthn != types.AppAuthnDefault {
		addStr("auth", string(req.AppAuthn))
	}
	addStr("git_auth", req.GitAuthName)
	addStr("git_branch", req.GitBranch)
	addStr("git_commit", req.GitCommit)
	if len(req.ParamValues) > 0 {
		args = append(args, dictArg("params", stringDictEntries(req.ParamValues)))
	}
	addStr("spec", string(req.Spec))
	addStr("stage_at", req.StageAt)
	if len(req.AppConfig) > 0 {
		entries, entryWarnings := appConfigEntries(req.AppConfig, req.Path)
		warnings = append(warnings, entryWarnings...)
		args = append(args, dictArg("app_config", entries))
	}
	if len(req.ContainerOptions) > 0 {
		args = append(args, dictArg("container_opts", stringDictEntries(req.ContainerOptions)))
	}
	if len(req.ContainerArgs) > 0 {
		args = append(args, dictArg("container_args", stringDictEntries(req.ContainerArgs)))
	}
	if len(req.ContainerVolumes) > 0 {
		args = append(args, strArg("container_vols="+formatStringList(req.ContainerVolumes)))
	}
	if len(req.Sidecars) > 0 {
		// Stored as canonical JSON docs, exported as sidecar(...) calls
		args = append(args, listArg("sidecars", sidecarLiterals(req.Sidecars)))
	}
	if len(req.Jobs) > 0 {
		// Stored as canonical JSON docs, exported as job(...) calls
		args = append(args, listArg("jobs", jobLiterals(req.Jobs)))
	}
	if len(req.Bindings) > 0 {
		args = append(args, strArg("bindings="+formatStringList(req.Bindings)))
	}
	if req.Verify {
		args = append(args, strArg("verify=True"))
	}
	return wrapCall(APP, args), warnings
}

// wrapCall renders a call with path= on the opening line, then source= and
// each kwarg on their own lines. Over-long dict kwargs are further expanded
// to one entry per line; lists always stay on one line
func wrapCall(name string, args []callArg) string {
	var sb strings.Builder
	sb.WriteString(name + "(" + args[0].text + ",\n")
	for i := 1; i < len(args); i++ {
		suffix := ","
		if i == len(args)-1 {
			suffix = ")"
		}
		arg := args[i]
		if arg.entries != nil && len("    "+arg.text)+len(suffix) > formatLineWidth {
			sb.WriteString("    " + arg.prefix + arg.open + "\n")
			for _, entry := range arg.entries {
				sb.WriteString("        " + entry + ",\n")
			}
			sb.WriteString("    " + arg.close + suffix + "\n")
		} else {
			sb.WriteString("    " + arg.text + suffix + "\n")
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

func dictArg(key string, entries []string) callArg {
	return callArg{
		text:    key + "={" + strings.Join(entries, ", ") + "}",
		prefix:  key + "=",
		entries: entries,
		open:    "{", close: "}",
	}
}

// listArg is an expandable list kwarg: one entry per line when too long
func listArg(key string, entries []string) callArg {
	return callArg{
		text:    key + "=[" + strings.Join(entries, ", ") + "]",
		prefix:  key + "=",
		entries: entries,
		open:    "[", close: "]",
	}
}

// sidecarLiterals renders the stored sidecar JSON documents as
// sidecar(...) calls, kwargs in the SidecarSpec declaration order
// with defaults omitted - the same starlark surface app.star uses in
// container.config(sidecars=)
func sidecarLiterals(docs []string) []string {
	literals := make([]string, 0, len(docs))
	for _, doc := range docs {
		literals = append(literals, sidecarLiteral(doc))
	}
	return literals
}

func sidecarLiteral(doc string) string {
	spec, err := types.ParseSidecarSpec(doc)
	if err != nil {
		// Not expected for stored metadata; keep the raw JSON string
		return quoteStarlark(doc)
	}
	args := []string{quoteStarlark(spec.Name)}
	add := func(key, literal string) {
		args = append(args, key+"="+literal)
	}
	boolLit := func(b bool) string {
		if b {
			return "True"
		}
		return "False"
	}
	if spec.Image != "" {
		add("image", quoteStarlark(spec.Image))
	}
	if len(spec.Command) > 0 {
		add("command", formatStringList(spec.Command))
	}
	if len(spec.Args) > 0 {
		add("args", formatStringList(spec.Args))
	}
	if len(spec.Env) > 0 {
		add("env", "{"+strings.Join(stringDictEntries(spec.Env), ", ")+"}")
	}
	if spec.InheritEnv != nil {
		add("inherit_env", boolLit(*spec.InheritEnv))
	}
	if spec.Port != 0 {
		add("port", strconv.Itoa(int(spec.Port)))
	}
	if spec.Health != "" {
		add("health", quoteStarlark(spec.Health))
	}
	if len(spec.Volumes) > 0 {
		add("volumes", formatStringList(spec.Volumes))
	}
	if spec.AlwaysOn != nil {
		add("always_on", boolLit(*spec.AlwaysOn))
	}
	if len(spec.Options) > 0 {
		add("options", "{"+strings.Join(stringDictEntries(spec.Options), ", ")+"}")
	}
	return "sidecar(" + strings.Join(args, ", ") + ")"
}

// jobLiterals renders the stored job JSON documents as job(...) calls
func jobLiterals(docs []string) []string {
	literals := make([]string, 0, len(docs))
	for _, doc := range docs {
		literals = append(literals, jobLiteral(doc))
	}
	return literals
}

func jobLiteral(doc string) string {
	spec, err := types.ParseJobSpec(doc)
	if err != nil {
		return quoteStarlark(doc)
	}
	args := []string{quoteStarlark(spec.Name)}
	add := func(key, literal string) {
		args = append(args, key+"="+literal)
	}
	boolLit := func(b bool) string {
		if b {
			return "True"
		}
		return "False"
	}
	if len(spec.Command) > 0 {
		add("command", formatStringList(spec.Command))
	}
	if len(spec.Args) > 0 {
		add("args", formatStringList(spec.Args))
	}
	if spec.Shell {
		add("shell", "True")
	}
	if spec.Image != "" {
		add("image", quoteStarlark(spec.Image))
	}
	if len(spec.Env) > 0 {
		add("env", "{"+strings.Join(stringDictEntries(spec.Env), ", ")+"}")
	}
	if spec.InheritEnv != nil {
		add("inherit_env", boolLit(*spec.InheritEnv))
	}
	if len(spec.Volumes) > 0 {
		add("volumes", formatStringList(spec.Volumes))
	}
	if len(spec.Options) > 0 {
		add("options", "{"+strings.Join(stringDictEntries(spec.Options), ", ")+"}")
	}
	switch spec.TriggerType() {
	case types.JobTriggerCron:
		cronArgs := []string{quoteStarlark(spec.Trigger.Schedule)}
		if spec.Trigger.Timezone != "" {
			cronArgs = append(cronArgs, "timezone="+quoteStarlark(spec.Trigger.Timezone))
		}
		add("trigger", "cron("+strings.Join(cronArgs, ", ")+")")
	case types.JobTriggerBeforeDeploy:
		add("trigger", "before_deploy()")
	}
	if spec.Timeout != "" {
		add("timeout", quoteStarlark(spec.Timeout))
	}
	if spec.Enabled != nil {
		add("enabled", boolLit(*spec.Enabled))
	}
	if len(spec.Params) > 0 {
		add("params", formatStringList(spec.Params))
	}
	if spec.Description != "" {
		add("description", quoteStarlark(spec.Description))
	}
	return "job(" + strings.Join(args, ", ") + ")"
}

// stringDictEntries renders a string valued map as sorted dict entries
func stringDictEntries(m map[string]string) []string {
	entries := make([]string, 0, len(m))
	for _, key := range sortedMapKeys(m) {
		entries = append(entries, quoteStarlark(key)+": "+quoteStarlark(m[key]))
	}
	return entries
}

// appConfigEntries renders app_config values, which are stored TOML encoded
// (strings quoted, other types TOML marshalled), back as starlark literals so
// re-applying the output reproduces the stored values exactly
func appConfigEntries(m map[string]string, appPath string) ([]string, []string) {
	entries := make([]string, 0, len(m))
	warnings := []string{}
	for _, key := range sortedMapKeys(m) {
		literal, ok := decodeAppConfigValue(m[key])
		if !ok {
			warnings = append(warnings, fmt.Sprintf("app %s app_config %s value %q is not valid TOML; exported as a string, which will TOML-quote it on apply",
				appPath, key, m[key]))
			literal = quoteStarlark(m[key])
		}
		entries = append(entries, quoteStarlark(key)+": "+literal)
	}
	return entries, warnings
}

// decodeAppConfigValue converts one stored app_config value to a starlark
// literal. Strings are stored wrapped in quotes (without escaping), other
// types are stored TOML marshalled
func decodeAppConfigValue(value string) (string, bool) {
	if len(value) >= 2 && strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		// Exact inverse of the quote wrapping done on apply
		return quoteStarlark(value[1 : len(value)-1]), true
	}
	var wrapped map[string]any
	if err := toml.Unmarshal([]byte("v = "+value), &wrapped); err == nil {
		if literal, err := starlarkLiteral(wrapped["v"]); err == nil {
			return literal, true
		}
	}
	// Dict values are TOML marshalled to table form ("k = 1\n" lines)
	var table map[string]any
	if err := toml.Unmarshal([]byte(value), &table); err == nil && len(table) > 0 {
		if literal, err := starlarkLiteral(table); err == nil {
			return literal, true
		}
	}
	return "", false
}

// starlarkLiteral renders a decoded TOML value as a starlark literal
func starlarkLiteral(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return quoteStarlark(v), nil
	case bool:
		if v {
			return "True", nil
		}
		return "False", nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case int:
		return strconv.Itoa(v), nil
	case float64:
		formatted := strconv.FormatFloat(v, 'g', -1, 64)
		if !strings.ContainsAny(formatted, ".eE") {
			formatted += ".0" // keep it a float literal so the type round-trips
		}
		return formatted, nil
	case []any:
		items := make([]string, 0, len(v))
		for _, item := range v {
			literal, err := starlarkLiteral(item)
			if err != nil {
				return "", err
			}
			items = append(items, literal)
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		entries := make([]string, 0, len(v))
		for _, key := range keys {
			literal, err := starlarkLiteral(v[key])
			if err != nil {
				return "", err
			}
			entries = append(entries, quoteStarlark(key)+": "+literal)
		}
		return "{" + strings.Join(entries, ", ") + "}", nil
	default:
		return "", fmt.Errorf("unsupported value type %T", value)
	}
}

func formatStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = quoteStarlark(value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// quoteStarlark quotes a string as a starlark string literal. Go escaping is
// compatible with starlark's double quoted strings
func quoteStarlark(s string) string {
	return strconv.Quote(s)
}
