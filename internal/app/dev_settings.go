// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/openrundev/openrun/internal/types"
)

// defaultDevStage is the Containerfile stage name looked up by convention for
// the fast dev reload flow when dev_settings dev_stage is not set.
const defaultDevStage = "dev"

// cfEntry is a CMD or ENTRYPOINT instruction. Exec form keeps the parsed
// tokens; shell form is a single raw string value.
type cfEntry struct {
	execForm bool
	values   []string
}

// cfKV is an ENV or ARG name/value pair. noDefault marks an ARG declared
// without a default (ARG NAME), which inherits a global default if one exists.
type cfKV struct {
	key, val  string
	noDefault bool
}

// cfInstr is one Containerfile instruction relevant to dev settings
// resolution, in stage order.
type cfInstr struct {
	kind    string // workdir | cmd | entrypoint | env | arg | run | copy
	value   string // workdir value
	entry   *cfEntry
	kv      []cfKV   // env or arg name/value pairs
	tokens  []string // copy sources and destination
	flags   []string // run/copy instruction flags (--from, --mount, ...)
	heredoc bool     // run instruction with heredoc content, cannot be replayed
}

type cfStage struct {
	name   string // stage name as written, "" if unnamed
	parent int    // index of the in-file stage this stage builds FROM, -1 for an external base
	instrs []cfInstr
}

// containerfileInfo is the stage level view of a parsed Containerfile used to
// infer dev settings.
type containerfileInfo struct {
	stages     []cfStage
	globalArgs []cfKV // ARGs declared before the first FROM
}

// collectContainerfileInfo extracts the per stage instructions needed for dev
// settings resolution from a parsed Containerfile. buildArgs (cargs) override
// global ARG defaults when expanding FROM values.
func collectContainerfileInfo(result *parser.Result, buildArgs map[string]string) *containerfileInfo {
	cf := &containerfileInfo{}
	cur := -1
	fromVars := map[string]string{} // global ARGs, usable in FROM values
	for _, child := range result.AST.Children {
		kind := strings.ToLower(child.Value)
		if kind == "from" {
			stage := cfStage{parent: -1}
			if img := child.Next; img != nil {
				// A FROM value can reference an earlier stage by name, and
				// global ARGs expand in FROM before that resolution
				stage.parent = cf.stageIndex(expandVars(img.Value, fromVars))
				if img.Next != nil && strings.EqualFold(img.Next.Value, "AS") && img.Next.Next != nil {
					stage.name = img.Next.Next.Value
				}
			}
			cf.stages = append(cf.stages, stage)
			cur = len(cf.stages) - 1
			continue
		}
		if kind == "arg" && cur < 0 {
			pairs := argPairs(child)
			cf.globalArgs = append(cf.globalArgs, pairs...)
			applyArgs(fromVars, cf.globalArgs, pairs, buildArgs)
			continue
		}
		if cur < 0 {
			continue
		}
		switch kind {
		case "workdir":
			if child.Next != nil {
				cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, value: child.Next.Value})
			}
		case "cmd", "entrypoint":
			entry := &cfEntry{execForm: child.Attributes["json"]}
			for n := child.Next; n != nil; n = n.Next {
				entry.values = append(entry.values, n.Value)
			}
			if !entry.execForm && len(entry.values) > 1 {
				// Shell form is parsed as a single node, join defensively
				entry.values = []string{strings.Join(entry.values, " ")}
			}
			if len(entry.values) == 0 {
				entry = nil // e.g. ENTRYPOINT [] resets the instruction
			}
			cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, entry: entry})
		case "env":
			// ENV parses to key, value, separator node triples
			var kvs []cfKV
			for n := child.Next; n != nil && n.Next != nil; {
				kvs = append(kvs, cfKV{key: n.Value, val: unquote(n.Next.Value)})
				n = n.Next.Next // skip the separator node
				if n != nil {
					n = n.Next
				}
			}
			if len(kvs) > 0 {
				cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, kv: kvs})
			}
		case "arg":
			if kvs := argPairs(child); len(kvs) > 0 {
				cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, kv: kvs})
			}
		case "run":
			entry := &cfEntry{execForm: child.Attributes["json"]}
			for n := child.Next; n != nil; n = n.Next {
				entry.values = append(entry.values, n.Value)
			}
			if !entry.execForm && len(entry.values) > 1 {
				entry.values = []string{strings.Join(entry.values, " ")}
			}
			if len(entry.values) == 0 {
				continue
			}
			cf.stages[cur].instrs = append(cf.stages[cur].instrs,
				cfInstr{kind: kind, entry: entry, flags: child.Flags, heredoc: len(child.Heredocs) > 0})
		case "copy":
			var tokens []string
			for n := child.Next; n != nil; n = n.Next {
				tokens = append(tokens, n.Value)
			}
			if len(tokens) < 2 {
				continue
			}
			cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, tokens: tokens, flags: child.Flags})
		case "shell":
			var tokens []string
			for n := child.Next; n != nil; n = n.Next {
				tokens = append(tokens, n.Value)
			}
			if len(tokens) > 0 {
				cf.stages[cur].instrs = append(cf.stages[cur].instrs, cfInstr{kind: kind, tokens: tokens})
			}
		}
	}
	return cf
}

// copyFromRef returns the value of a COPY instruction's --from flag, "" when
// the copy is from the build context (a source copy).
func copyFromRef(flags []string) string {
	for _, flag := range flags {
		if val, ok := strings.CutPrefix(flag, "--from="); ok {
			return val
		}
	}
	return ""
}

// argPairs parses ARG instruction nodes ("name" or "name=default").
func argPairs(child *parser.Node) []cfKV {
	var kvs []cfKV
	for n := child.Next; n != nil; n = n.Next {
		k, v, found := strings.Cut(n.Value, "=")
		kvs = append(kvs, cfKV{key: k, val: unquote(v), noDefault: !found})
	}
	return kvs
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// stageIndex returns the index of the named stage, matching case
// insensitively as the container build does, or -1.
func (cf *containerfileInfo) stageIndex(name string) int {
	if name == "" {
		return -1
	}
	for i, stage := range cf.stages {
		if stage.name != "" && strings.EqualFold(stage.name, name) {
			return i
		}
	}
	return -1
}

// chain returns the in-file stage indexes from the root base stage down to
// idx, in build order.
func (cf *containerfileInfo) chain(idx int) []int {
	var order []int
	for i := idx; i >= 0; i = cf.stages[i].parent {
		order = append(order, i)
	}
	slices.Reverse(order)
	return order
}

// cfResolved is the effective state of a stage after applying its in-file
// inheritance chain. Values inherited from external base images are unknown
// and left unset.
type cfResolved struct {
	workDir    string // absolute effective WORKDIR, "" if unknown
	cmd        *cfEntry
	entrypoint *cfEntry
	shell      []string          // effective SHELL instruction tokens, nil for the default
	vars       map[string]string // ARG defaults (with cargs overrides) and ENV values, for substitution
}

// resolveStage computes the effective WORKDIR, CMD and ENTRYPOINT of a stage
// by walking its in-file inheritance chain, substituting ARG and ENV values.
func (cf *containerfileInfo) resolveStage(idx int, cargs map[string]string) cfResolved {
	res := cfResolved{vars: map[string]string{}}
	cmdStagePos := -1
	for pos, stageIdx := range cf.chain(idx) {
		for _, instr := range cf.stages[stageIdx].instrs {
			switch instr.kind {
			case "arg":
				applyArgs(res.vars, cf.globalArgs, instr.kv, cargs)
			case "env":
				// All assignments of one ENV instruction expand against the
				// environment from before the instruction
				snap := maps.Clone(res.vars)
				for _, kv := range instr.kv {
					res.vars[kv.key] = expandVars(kv.val, snap)
				}
			case "shell":
				res.shell = instr.tokens
			case "workdir":
				v := expandVars(instr.value, res.vars)
				if path.IsAbs(v) {
					res.workDir = path.Clean(v)
				} else if res.workDir != "" {
					res.workDir = path.Join(res.workDir, v)
				}
				// A relative WORKDIR on an external base stays unknown
			case "cmd":
				res.cmd = instr.entry
				cmdStagePos = pos
			case "entrypoint":
				res.entrypoint = instr.entry
				if cmdStagePos < pos {
					// Setting ENTRYPOINT resets a CMD inherited from a base stage
					res.cmd = nil
				}
			}
		}
	}
	return res
}

// stageEnvOutside collects the resolved ENV values declared on stages of the
// final stage's chain that are not part of the excluded (build target) chain.
// These are the runtime environment values the built dev image lacks.
//
// pathUnsafe reports that a final-only PATH cannot be reproduced in the dev
// container. Docker does not expand references in runtime environment
// overrides, and replacing the build image's PATH with a literal value such as
// "/app/.venv/bin:$PATH" would both leave $PATH unresolved and commonly point
// into content hidden by the source bind mount.
func (cf *containerfileInfo) stageEnvOutside(finalIdx int, exclude map[int]bool,
	cargs map[string]string) (out map[string]string, pathUnsafe bool) {
	vars := map[string]string{}
	out = map[string]string{}
	for _, stageIdx := range cf.chain(finalIdx) {
		for _, instr := range cf.stages[stageIdx].instrs {
			switch instr.kind {
			case "arg":
				applyArgs(vars, cf.globalArgs, instr.kv, cargs)
			case "env":
				// Expand against the pre-instruction environment, matching
				// the image build semantics
				snap := maps.Clone(vars)
				for _, kv := range instr.kv {
					val := expandVars(kv.val, snap)
					vars[kv.key] = val
					if exclude[stageIdx] {
						continue
					}
					// PATH is never propagated: values like
					// PATH="/app/.venv/bin:$PATH" resolve against the final
					// base image's PATH, which is unknown here, and passing
					// them as container env would replace the dev image's
					// PATH (docker env values are literal, $refs do not
					// expand). The same applies to any value that still has
					// unresolved references after expansion
					if kv.key == "PATH" {
						pathUnsafe = true
						delete(out, kv.key)
						continue
					}
					if strings.ContainsRune(val, '$') {
						delete(out, kv.key)
						continue
					}
					out[kv.key] = val
				}
			}
		}
	}
	return out, pathUnsafe
}

// mergeMounts appends the extra volume mounts whose target path is not
// already mounted.
func mergeMounts(mounts, extra []string) []string {
	targets := map[string]bool{}
	for _, m := range mounts {
		if _, target, ok := strings.Cut(m, ":"); ok {
			targets[path.Clean(target)] = true
		}
	}
	for _, m := range extra {
		if _, target, ok := strings.Cut(m, ":"); ok && !targets[path.Clean(target)] {
			targets[path.Clean(target)] = true
			mounts = append(mounts, m)
		}
	}
	return mounts
}

// applyArgs makes the ARG declarations kvs visible in vars. Build args
// (cargs) win; an ARG declared without a default inherits the global default
// declared before the first FROM, if any, else resolves to empty.
func applyArgs(vars map[string]string, globalArgs, kvs []cfKV, cargs map[string]string) {
	for _, kv := range kvs {
		if override, ok := cargs[kv.key]; ok {
			vars[kv.key] = override
			continue
		}
		val := kv.val
		if kv.noDefault {
			for _, global := range globalArgs {
				if global.key == kv.key {
					val = global.val
					break
				}
			}
		}
		vars[kv.key] = val
	}
}

var varNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*`)

// expandVars substitutes $NAME and ${NAME} references from vars, leaving
// unknown references and unsupported forms (e.g. ${NAME:-default}) untouched
// for the runtime shell to expand.
func expandVars(s string, vars map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		rest := s[i+1:]
		if rest[0] == '{' {
			if end := strings.IndexByte(rest, '}'); end > 1 {
				name := rest[1:end]
				if val, ok := vars[name]; ok && varNameRe.FindString(name) == name {
					b.WriteString(val)
					i += end + 2
					continue
				}
			}
		} else if name := varNameRe.FindString(rest); name != "" {
			if val, ok := vars[name]; ok {
				b.WriteString(val)
				i += len(name) + 1
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

var shellSafeRe = regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`)

func shellQuote(s string) string {
	if s != "" && shellSafeRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(tokens []string) string {
	quoted := make([]string, 0, len(tokens))
	for _, t := range tokens {
		quoted = append(quoted, shellQuote(t))
	}
	return strings.Join(quoted, " ")
}

// entryTokens returns a stage's ENTRYPOINT/CMD as a token list, following the
// image build semantics for combining them. shellForm reports that the tokens
// came from whitespace-splitting a shell form instruction (raw holds the
// original string) and should be rejoined with spaces (preserving shell
// syntax) rather than quoted.
func entryTokens(entrypoint, cmd *cfEntry) (tokens []string, shellForm bool, raw string, ok bool) {
	if entrypoint != nil {
		if !entrypoint.execForm {
			// Shell form ENTRYPOINT ignores CMD
			return strings.Fields(entrypoint.values[0]), true, entrypoint.values[0], true
		}
		tokens = slices.Clone(entrypoint.values)
		if cmd != nil {
			if cmd.execForm {
				tokens = append(tokens, cmd.values...)
			} else {
				tokens = append(tokens, "/bin/sh", "-c", cmd.values[0])
			}
		}
		return tokens, false, "", true
	}
	if cmd != nil {
		if !cmd.execForm {
			return strings.Fields(cmd.values[0]), true, cmd.values[0], true
		}
		return slices.Clone(cmd.values), false, "", true
	}
	return nil, false, "", false
}

func joinEntryTokens(tokens []string, shellForm bool) string {
	if shellForm {
		return strings.Join(tokens, " ")
	}
	return shellJoin(tokens)
}

// cfCopyEntry describes content the final image receives via COPY that the
// built dev stage image does not have: a build artifact (COPY --from of the
// build target's chain) or a build context file copied by a final stage. src
// is where the same content is reachable in the dev container: the build
// stage path for artifacts (recreated by build replay), the path under the
// source mount for context files. src is "" when not traceable (wildcards,
// foreign stages, files missing from the source).
type cfCopyEntry struct {
	src        string
	dest       string // resolved absolute destination (file target, or directory root the contents land in)
	destIsDir  bool   // dest is a directory: COPY places base(src) (files) or src's contents (dirs) inside it
	srcIsFile  bool   // src basename has an extension: it cannot provide paths nested under dest
	isArtifact bool   // copied out of the build stage, referencing it requires build replay
}

// collectCopyEntries gathers the COPY instructions on the final stage's chain
// (excluding the build target's own chain) that describe content the dev
// stage image lacks.
func (cf *containerfileInfo) collectCopyEntries(finalIdx int, targetChain map[int]bool,
	vars map[string]string, finalWorkDir, mountDir string, sourceExists func(string) bool) []cfCopyEntry {
	var entries []cfCopyEntry
	for _, stageIdx := range cf.chain(finalIdx) {
		if targetChain[stageIdx] {
			continue
		}
		for _, instr := range cf.stages[stageIdx].instrs {
			if instr.kind != "copy" {
				continue
			}
			from := copyFromRef(instr.flags)
			fromIdx := cf.stageIndex(from)
			if from != "" && fromIdx < 0 {
				// Stages can also be referenced by index
				if n, err := strconv.Atoi(from); err == nil && n >= 0 && n < len(cf.stages) {
					fromIdx = n
				}
			}
			srcs, destRaw := instr.tokens[:len(instr.tokens)-1], instr.tokens[len(instr.tokens)-1]
			dest := expandVars(destRaw, vars)
			if !path.IsAbs(dest) {
				if finalWorkDir == "" {
					continue // cannot resolve the destination, unmatchable
				}
				dest = path.Join(finalWorkDir, dest)
			}
			dest = path.Clean(dest)
			destIsDir := strings.HasSuffix(destRaw, "/") || destRaw == "." || len(srcs) > 1
			for _, srcRaw := range srcs {
				src := expandVars(srcRaw, vars)
				wildcard := strings.ContainsAny(src, "*?[")
				entry := cfCopyEntry{dest: dest, destIsDir: destIsDir}
				if from != "" {
					entry.isArtifact = true
					if fromIdx >= 0 && targetChain[fromIdx] && !wildcard {
						if !path.IsAbs(src) {
							// COPY --from source paths resolve from the stage's root
							src = "/" + src
						}
						entry.src = path.Clean(src)
					}
				} else if !wildcard {
					// Context copy: the file is part of the app source, which
					// is bind mounted in the dev container
					rel := path.Clean(strings.TrimPrefix(src, "./"))
					if !path.IsAbs(rel) && sourceExists != nil && sourceExists(rel) {
						entry.src = path.Join(mountDir, rel)
					}
				}
				if entry.src != "" {
					base := path.Base(entry.src)
					entry.srcIsFile = path.Ext(base) != "" && !strings.HasPrefix(base, ".")
				}
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

// fileTarget returns the path the copied entry occupies when its source is a
// single file, "" when unknown.
func (e *cfCopyEntry) fileTarget() string {
	if e.src == "" {
		return ""
	}
	if e.destIsDir {
		return path.Join(e.dest, path.Base(e.src))
	}
	return e.dest
}

// subtreeMatch maps cand to the copy's source location when cand lies inside
// the copied tree (the source being a directory whose contents land at dest).
// unsure is set when cand is inside an untraceable copy or the source cannot
// contain nested paths.
func (e *cfCopyEntry) subtreeMatch(cand string) (mapped string, matched, unsure bool) {
	rest, found := strings.CutPrefix(cand, e.dest+"/")
	if !found {
		return "", false, false
	}
	if e.src == "" {
		return "", true, true // wildcard or foreign copy, exact source unknown
	}
	if e.srcIsFile {
		return "", false, false // a file source cannot provide nested paths
	}
	return path.Join(e.src, rest), true, false
}

// replayRunMounts converts a replayed RUN instruction's flags into named
// volume mounts. Only --mount=type=cache is reproducible at dev run time;
// any other flag (secret/ssh/bind mounts, --network, ...) makes the replay
// unsafe and returns ok false.
func replayRunMounts(flags []string) (mounts []string, ok bool) {
	for _, flag := range flags {
		spec, found := strings.CutPrefix(flag, "--mount=")
		if !found {
			return nil, false
		}
		mountType := "bind" // the default when type is omitted
		target := ""
		for part := range strings.SplitSeq(spec, ",") {
			k, v, _ := strings.Cut(part, "=")
			switch k {
			case "type":
				mountType = v
			case "target", "dst", "destination":
				target = v
			}
		}
		if mountType != "cache" || !path.IsAbs(target) {
			return nil, false
		}
		name := "openrun-cache" + strings.TrimRight(cacheNameRe.ReplaceAllString(strings.ToLower(target), "-"), "-")
		mounts = append(mounts, name+":"+path.Clean(target))
	}
	return mounts, true
}

var cacheNameRe = regexp.MustCompile(`[^a-z0-9]+`)

// nonDefaultShell reports whether a SHELL instruction deviates from the
// default /bin/sh -c that the dev command wrapper uses.
func nonDefaultShell(shell []string) bool {
	if len(shell) == 0 {
		return false
	}
	return len(shell) != 2 || (shell[0] != "/bin/sh" && shell[0] != "sh") || shell[1] != "-c"
}

var shellWrappers = map[string]bool{
	"sh": true, "/bin/sh": true, "/usr/bin/sh": true,
	"bash": true, "/bin/bash": true, "/usr/bin/bash": true,
}

// inferEntryCommand computes the auto-inferred dev command for running the
// final stage's entry in the build target stage. Every path-like word of the
// entry is resolved against the COPY instructions the dev image misses:
// words naming build artifacts trigger a build replay (the target chain's
// RUN steps after the last source COPY, then exec the entry), words naming
// final stage context copies are rewritten to their location under the
// source mount, and words that resolve under the mount must exist in the app
// source. Words are rewritten to the location the content has in the dev
// container only when that differs from how the word resolves at runtime.
//
// A non-empty reason means inference is not safe: something the entry needs
// cannot be provided or verified (per the rule that auto-inference is only
// used when it is expected to work), and the caller must not use the entry.
func (cf *containerfileInfo) inferEntryCommand(targetIdx, finalIdx int, targetRes, finalRes cfResolved,
	mountDir string, sourceExists func(string) bool) (cmd string, cacheMounts []string, reason string) {

	tokens, shellForm, raw, hasEntry := entryTokens(finalRes.entrypoint, finalRes.cmd)
	if !hasEntry {
		return "", nil, "no CMD or ENTRYPOINT found to run in dev mode"
	}
	if shellForm && nonDefaultShell(finalRes.shell) {
		return "", nil, "the entry command uses a custom SHELL, it cannot be run with the sh based dev command"
	}
	targetChain := map[int]bool{}
	for _, i := range cf.chain(targetIdx) {
		targetChain[i] = true
	}
	entries := cf.collectCopyEntries(finalIdx, targetChain, finalRes.vars, finalRes.workDir, mountDir, sourceExists)

	needsReplay := false
	rewrote := false
	// checkWord resolves one word of the entry command; it returns the word
	// to use (possibly rewritten) and a non-empty reason when unsafe.
	// shellCtx marks words from a shell command string, where assignments
	// (JAR=/app/app.jar), quoting and trailing separators can wrap the path
	checkWord := func(word string, shellCtx, executable bool) (string, string) {
		exp := expandVars(word, finalRes.vars)
		// An assignment or option value (JAR=/app/x, -Dcfg=/app/x) carries
		// the path in its value part; check and rewrite that part
		prefix, core := "", exp
		if eq := strings.IndexByte(exp, '='); eq >= 0 {
			prefix, core = exp[:eq+1], exp[eq+1:]
		} else if strings.HasPrefix(exp, "-") {
			return word, "" // plain flag
		}
		suffix := ""
		if shellCtx {
			// Trailing command separators glue to the word (path.jar;)
			if trimmed := strings.TrimRight(core, ";"); trimmed != core {
				suffix, core = core[len(trimmed):], trimmed
			}
			core = unquote(core)
		}
		if core == "" || strings.ContainsRune(core, '$') {
			// Unresolved references expand at runtime (propagated env)
			return word, ""
		}
		if strings.ContainsRune(core, ':') {
			// URLs, scheme prefixes (classpath:...), host:port, path lists
			return word, ""
		}
		if !strings.Contains(core, "/") && path.Ext(core) == "" {
			// Bare words: command names resolved via PATH, subcommands
			return word, ""
		}
		cand := core
		if !path.IsAbs(cand) {
			if finalRes.workDir == "" {
				return word, ""
			}
			cand = path.Join(finalRes.workDir, core)
		}
		cand = path.Clean(cand)
		// runtime is where the word points in the dev container, which runs
		// in the mount dir
		runtime := core
		if !path.IsAbs(runtime) {
			runtime = path.Join(mountDir, core)
		}
		runtime = path.Clean(runtime)
		rewriteTo := func(mapped string) string {
			if runtime == mapped {
				return word // already resolves to the right place
			}
			rewrote = true
			return prefix + mapped + suffix
		}

		// 1. An exact match on a copied file is the strongest evidence
		for _, e := range entries {
			if target := e.fileTarget(); target != "" && cand == target {
				if e.isArtifact {
					needsReplay = true
				}
				return rewriteTo(e.src), ""
			}
		}
		// 2. Words that point into the mounted app source are valid as is
		underMount := runtime == mountDir || strings.HasPrefix(runtime, mountDir+"/")
		if underMount && runtime != mountDir && sourceExists != nil {
			rel := strings.TrimPrefix(runtime, mountDir+"/")
			first, _, _ := strings.Cut(rel, "/")
			if sourceExists(first) {
				return word, ""
			}
		}
		// 3. Words inside a copied directory tree map to the tree's source
		mapped, matchedArtifact := "", false
		for _, e := range entries {
			m, matched, unsure := e.subtreeMatch(cand)
			if unsure {
				return word, fmt.Sprintf("the entry command references %s from a copy whose source cannot be determined", core)
			}
			if matched && m != mapped {
				if mapped != "" {
					return word, fmt.Sprintf("the entry command reference %s matches multiple copied paths", core)
				}
				mapped = m
				matchedArtifact = e.isArtifact
			}
		}
		if mapped != "" {
			if matchedArtifact {
				needsReplay = true
			}
			return rewriteTo(mapped), ""
		}
		// 4. A path under the mount that is neither in the app source nor
		// provided by a copy would not exist in the dev container
		if underMount {
			return word, fmt.Sprintf("the entry command references %s, which is not in the app source and is not a copied build output", core)
		}
		// An absolute entry executable outside the mount may have been
		// installed only in the final image. Unless a traceable COPY above
		// supplied it, the build target cannot be assumed to contain it.
		if executable && path.IsAbs(core) {
			return word, fmt.Sprintf("the entry executable %s is outside the source mount and cannot be verified in the build stage", core)
		}
		// Other paths outside the mount may be provided by the build image
		return word, ""
	}
	// Command substitution can conceal copied paths from the word scan; when
	// there is copied content to reference, refuse rather than guess
	concealRisk := func(s string) bool {
		return strings.Contains(s, "$(") || strings.ContainsRune(s, '`')
	}

	// A shell wrapper entry (sh -c "...") holds the real command inside one
	// token; scan and rewrite its words individually
	payloadIdx := -1
	if !shellForm && len(tokens) >= 3 && shellWrappers[tokens[0]] && tokens[1] == "-c" {
		payloadIdx = 2
	}
	if len(entries) > 0 && (concealRisk(raw) || (payloadIdx >= 0 && concealRisk(tokens[payloadIdx]))) {
		return "", nil, "the entry shell command uses command substitution, its references to copied files cannot be verified"
	}
	for i, tok := range tokens {
		if i == payloadIdx {
			words := strings.Fields(tok)
			payloadRewrote := false
			for w, word := range words {
				before := rewrote
				rewrote = false
				newWord, wordReason := checkWord(word, true, w == 0 && !shellWrappers[word])
				payloadRewrote = payloadRewrote || rewrote
				rewrote = before || rewrote
				if wordReason != "" {
					return "", nil, wordReason
				}
				words[w] = newWord
			}
			if payloadRewrote {
				if strings.ContainsAny(tok, `'"`+"`") {
					return "", nil, "the entry shell command needs a path rewrite but uses shell quoting that cannot be rewritten safely"
				}
				tokens[i] = strings.Join(words, " ")
			}
			continue
		}
		newTok, tokReason := checkWord(tok, shellForm, i == 0 && !shellWrappers[tok])
		if tokReason != "" {
			return "", nil, tokReason
		}
		tokens[i] = newTok
	}
	if shellForm && rewrote && strings.ContainsAny(raw, `'"`+"`") {
		return "", nil, "the entry shell command needs a path rewrite but uses shell quoting that cannot be rewritten safely"
	}

	entryStr := joinEntryTokens(tokens, shellForm)
	if !needsReplay {
		return entryStr, nil, ""
	}

	// Build replay: collect the target chain's RUN instructions after the
	// last source COPY (earlier steps like dependency downloads are baked
	// into the dev image and their outputs live outside the mount)
	var steps []cfInstr
	shell := []string(nil)
	var stepShells [][]string
	for _, stageIdx := range cf.chain(targetIdx) {
		for _, instr := range cf.stages[stageIdx].instrs {
			switch instr.kind {
			case "shell":
				shell = instr.tokens
			case "copy":
				if copyFromRef(instr.flags) == "" {
					steps, stepShells = steps[:0], stepShells[:0] // source copy, later RUNs rebuild from source
				}
			case "run":
				steps = append(steps, instr)
				stepShells = append(stepShells, shell)
			}
		}
	}
	if len(steps) == 0 {
		return "", nil, "the entry command runs a build artifact but the build stage has no RUN steps after the source COPY to replay"
	}
	parts := make([]string, 0, len(steps)+1)
	for i, step := range steps {
		if step.heredoc {
			return "", nil, "the build steps use heredoc RUN instructions which cannot be replayed"
		}
		mounts, mountsOk := replayRunMounts(step.flags)
		if !mountsOk {
			return "", nil, "the build steps use RUN flags (secret/ssh/bind mounts or options) which cannot be replayed"
		}
		var runStr string
		if step.entry.execForm {
			expanded := make([]string, 0, len(step.entry.values))
			for _, v := range step.entry.values {
				expanded = append(expanded, expandVars(v, targetRes.vars))
			}
			runStr = shellJoin(expanded)
		} else {
			if nonDefaultShell(stepShells[i]) {
				return "", nil, "the build steps use a custom SHELL, they cannot be replayed with the sh based dev command"
			}
			runStr = expandVars(step.entry.values[0], targetRes.vars)
		}
		parts = append(parts, runStr)
		cacheMounts = append(cacheMounts, mounts...)
	}
	parts = append(parts, "exec "+entryStr)
	return strings.Join(parts, " && "), cacheMounts, ""
}

// resolveDevSettings fills in unset dev_settings values from the parsed
// Containerfile: the build target from the dev stage convention (a stage
// named dev_stage, default "dev") or the penultimate stage, the command from
// the dev stage's CMD or the final stage's entry command, and dir from the
// effective WORKDIR of the stage being run.
//
// When no settings were configured (implicit), any inference gap returns nil
// settings so the app stays on the legacy dev flow. When settings were
// explicitly configured, inference gaps for target/command are skipped (the
// full image is built and its own entry runs, the pre-inference behavior);
// only an unresolvable dir fails, along with genuine config errors (a
// configured dev_stage that does not exist, a dev stage with no CMD).
//
// The returned env map holds final stage ENV values the built dev image
// lacks, to be added to the dev container environment.
func resolveDevSettings(logger *types.Logger, ds *types.DevSettings, devStageName string, devStageExplicit bool,
	cf *containerfileInfo, cargs map[string]string, containerFile string,
	sourceExists func(string) bool) (*types.DevSettings, map[string]string, error) {

	implicit := ds == nil
	if implicit {
		ds = &types.DevSettings{}
	}
	fallback := func(format string, args ...any) bool {
		if implicit {
			logger.Debug().Msgf("Fast dev reload not inferred for "+containerFile+": "+format, args...)
			return true
		}
		return false
	}

	numStages := len(cf.stages)
	if numStages == 0 {
		if fallback("no stages found") {
			return nil, nil, nil
		}
		if ds.Dir == "" {
			return nil, nil, fmt.Errorf("dev_settings dir must be set, no stages found in %s to infer it from", containerFile)
		}
		return ds, nil, nil
	}
	finalIdx := numStages - 1

	// Resolve the build target: explicit target, dev stage convention, or
	// the penultimate (builder) stage
	usingDevStage := false
	runIdx := finalIdx // the stage whose image runs in dev mode
	if ds.Target != "" {
		if idx := cf.stageIndex(ds.Target); idx >= 0 {
			runIdx = idx
		} else {
			// The app can supply its own Containerfile, overriding the spec's;
			// build the full image instead of failing with an unknown stage
			logger.Warn().Msgf("Container file %s has no stage %q, building the full image for dev mode", containerFile, ds.Target)
			ds.Target = ""
		}
	} else if idx := cf.stageIndex(devStageName); idx >= 0 {
		usingDevStage = true
		runIdx = idx
		ds.Target = cf.stages[idx].name
		if idx == finalIdx {
			logger.Warn().Msgf("Stage %q is the last stage in %s: production image builds will build the dev stage. "+
				"Move the %q stage above the runtime stage", devStageName, containerFile, devStageName)
		}
	} else if devStageExplicit {
		return nil, nil, fmt.Errorf("dev_settings dev_stage %q not found in %s", devStageName, containerFile)
	} else if numStages > 1 {
		if pen := &cf.stages[numStages-2]; pen.name != "" {
			ds.Target = pen.name
			runIdx = numStages - 2
		} else if fallback("the build stage (stage %d) is not named, cannot build it for dev mode", numStages-1) {
			return nil, nil, nil
		}
		// Explicit settings with an unnamed build stage: full image build
	}
	// With a single stage the target stays empty and the full image is built;
	// it typically contains the toolchain, and its own entry command runs

	res := cf.resolveStage(runIdx, cargs)
	if ds.Dir == "" {
		if res.workDir == "" {
			if fallback("could not determine the WORKDIR of the dev stage") {
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("dev_settings dir must be set, could not determine the WORKDIR of the dev stage in %s", containerFile)
		}
		ds.Dir = res.workDir
	}

	var inferredEnv map[string]string
	if ds.Command == "" {
		if usingDevStage && res.entrypoint == nil && res.cmd == nil {
			return nil, nil, fmt.Errorf("stage %q in %s must define the CMD used to run the app in dev mode "+
				"(or set dev_settings command)", devStageName, containerFile)
		}
		if runIdx != finalIdx && res.entrypoint == nil && res.cmd == nil {
			// The build stage has no entry of its own: run the final stage's
			// entry command in it, with the final stage's ENV values
			finalRes := cf.resolveStage(finalIdx, cargs)
			if _, _, _, hasEntry := entryTokens(finalRes.entrypoint, finalRes.cmd); !hasEntry {
				if fallback("no CMD or ENTRYPOINT found to run in dev mode") {
					return nil, nil, nil
				}
				// Explicit settings: the built stage image's own entry runs
			} else {
				targetChain := map[int]bool{}
				for _, i := range cf.chain(runIdx) {
					targetChain[i] = true
				}
				finalEnv, pathUnsafe := cf.stageEnvOutside(finalIdx, targetChain, cargs)
				if pathUnsafe {
					reason := "the final stage changes PATH, which cannot be reproduced safely in the build-stage dev image"
					if fallback("%s", reason) {
						return nil, nil, nil
					}
					return nil, nil, fmt.Errorf("dev_settings: %s in %s; add a 'dev' stage with the dev run command "+
						"or set dev_settings command", reason, containerFile)
				}
				cmdStr, cacheMounts, reason := cf.inferEntryCommand(runIdx, finalIdx, res, finalRes, ds.Dir, sourceExists)
				if reason != "" {
					// Inference is only used when it is expected to work; do
					// not ship a command known or suspected to be broken
					if fallback("%s", reason) {
						return nil, nil, nil
					}
					return nil, nil, fmt.Errorf("dev_settings: %s in %s; add a 'dev' stage with the dev run command "+
						"or set dev_settings command", reason, containerFile)
				}
				ds.Command = cmdStr
				ds.Inferred = true
				ds.AdditionalMounts = mergeMounts(ds.AdditionalMounts, cacheMounts)
				inferredEnv = finalEnv
			}
		}
		// Otherwise the built image's own CMD/ENTRYPOINT runs unmodified
	}

	if ds.Reload == "" {
		ds.Reload = types.DEV_RELOAD_RESTART
	}
	return ds, inferredEnv, nil
}

// checkProdDevStage fails Containerfile based prod apps whose last stage is
// the dev stage: the production image build runs with no --target and builds
// the last stage, which would silently ship the dev image.
func checkProdDevStage(cf *containerfileInfo, devStageName, containerFile string) error {
	if len(cf.stages) == 0 {
		return nil
	}
	last := cf.stages[len(cf.stages)-1]
	if last.name != "" && strings.EqualFold(last.name, devStageName) {
		return fmt.Errorf("stage %q is the last stage in %s: the production image build would build the dev stage. "+
			"Move the %q stage above the runtime stage", last.name, containerFile, last.name)
	}
	return nil
}
