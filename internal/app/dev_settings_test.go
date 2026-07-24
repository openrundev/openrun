// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/openrundev/openrun/internal/types"
)

func parseCFInfo(t *testing.T, data string) *containerfileInfo {
	t.Helper()
	result, err := parser.Parse(bytes.NewReader([]byte(data)))
	if err != nil {
		t.Fatalf("error parsing container file: %v", err)
	}
	return collectContainerfileInfo(result, nil)
}

// resolveForTest resolves dev settings for a Containerfile; files lists the
// paths that exist in the (simulated) app source tree.
func resolveForTest(t *testing.T, data string, ds *types.DevSettings, devStageName string, devStageExplicit bool,
	cargs map[string]string, files ...string) (*types.DevSettings, map[string]string, error) {
	t.Helper()
	if devStageName == "" {
		devStageName = defaultDevStage
	}
	exists := map[string]bool{}
	for _, f := range files {
		exists[f] = true
	}
	logger := types.NewLogger(&types.LogConfig{Level: "WARN"})
	return resolveDevSettings(logger, ds, devStageName, devStageExplicit, parseCFInfo(t, data), cargs, "Containerfile",
		func(rel string) bool { return exists[rel] })
}

const cowbullContainerfile = `
ARG GO_VERSION=1.24
ARG APP_NAME=cowbull

FROM golang:${GO_VERSION} AS builder
ARG APP_NAME
ENV CGO_ENABLED=0
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o ${APP_NAME} ./cmd/cowbull

FROM alpine:latest
ARG APP_NAME
ENV APP_NAME=${APP_NAME}
WORKDIR /app
COPY --from=builder /app/${APP_NAME} .
VOLUME /app/data
ENTRYPOINT /app/${APP_NAME} -f /app/data/db.sqlite ${APP_ARGS}
`

func TestResolveDevStageConvention(t *testing.T) {
	t.Parallel()

	data := `
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM builder AS dev
CMD go run .

FROM alpine
COPY --from=builder /app/app /app/app
ENTRYPOINT ["/app/app"]
`
	ds, env, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil {
		t.Fatal("expected settings, got nil")
	}
	if ds.Target != "dev" {
		t.Fatalf("target = %q, want dev", ds.Target)
	}
	if ds.Command != "" {
		t.Fatalf("command = %q, want empty (dev stage CMD runs)", ds.Command)
	}
	if ds.Dir != "/app" {
		t.Fatalf("dir = %q, want /app (inherited WORKDIR)", ds.Dir)
	}
	if ds.Reload != types.DEV_RELOAD_RESTART {
		t.Fatalf("reload = %q, want restart", ds.Reload)
	}
	if len(env) != 0 {
		t.Fatalf("inferred env = %v, want empty for dev stage mode", env)
	}
}

func TestResolveDevStageWithoutCommandFails(t *testing.T) {
	t.Parallel()

	data := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM builder AS dev

FROM alpine
ENTRYPOINT ["/app/app"]
`
	_, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err == nil || !strings.Contains(err.Error(), "must define the CMD") {
		t.Fatalf("expected missing CMD error, got %v", err)
	}
	// An explicit command makes the same layout valid
	ds, _, err := resolveForTest(t, data, &types.DevSettings{Command: "go run ."}, "", false, nil)
	if err != nil || ds == nil || ds.Target != "dev" || ds.Command != "go run ." {
		t.Fatalf("explicit command resolution = %+v, %v", ds, err)
	}
}

func TestResolveCustomDevStageName(t *testing.T) {
	t.Parallel()

	data := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM builder AS fastdev
CMD go run .

FROM alpine
ENTRYPOINT ["/app/app"]
`
	ds, _, err := resolveForTest(t, data, &types.DevSettings{DevStage: "fastdev"}, "fastdev", true, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds.Target != "fastdev" || ds.Dir != "/app" {
		t.Fatalf("resolved = %+v, want target fastdev dir /app", ds)
	}

	// An explicitly configured dev_stage that does not exist fails
	_, _, err = resolveForTest(t, data, &types.DevSettings{DevStage: "missing"}, "missing", true, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing dev_stage error, got %v", err)
	}
}

func TestResolveAutoInferenceReplaysBuildForCompiledApp(t *testing.T) {
	t.Parallel()

	// The data dir exists in the app source (mounted), so /app/data/... args
	// are left alone; the binary path is recognized as the build artifact
	ds, env, err := resolveForTest(t, cowbullContainerfile, nil, "", false, nil, "data")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil {
		t.Fatal("expected settings, got nil")
	}
	if ds.Target != "builder" {
		t.Fatalf("target = %q, want builder (penultimate stage)", ds.Target)
	}
	// The entry runs a build artifact (COPY --from=builder): the dev command
	// replays the build RUN steps after the source COPY, then execs the entry.
	// The artifact path is identical in the build stage, so the token is kept
	// as is (${APP_NAME} expands at runtime from the propagated env); the RUN
	// step's ARG reference is expanded statically
	want := "go build -o cowbull ./cmd/cowbull && exec /app/${APP_NAME} -f /app/data/db.sqlite ${APP_ARGS}"
	if ds.Command != want {
		t.Fatalf("command = %q, want %q", ds.Command, want)
	}
	if !ds.Inferred {
		t.Fatal("Inferred flag not set for auto-inferred command")
	}
	if ds.Dir != "/app" {
		t.Fatalf("dir = %q, want /app", ds.Dir)
	}
	// APP_NAME is set only in the final stage, with its ARG default expanded;
	// CGO_ENABLED belongs to the builder stage chain and is not propagated
	if env["APP_NAME"] != "cowbull" {
		t.Fatalf("inferred env = %v, want APP_NAME=cowbull", env)
	}
	if _, ok := env["CGO_ENABLED"]; ok {
		t.Fatalf("inferred env = %v, builder stage env should not be propagated", env)
	}
}

func TestResolveReplayArtifactRename(t *testing.T) {
	t.Parallel()

	// Java style layout: the jar is renamed by the COPY --from, the replayed
	// entry must reference the build stage path
	data := `
FROM maven:3-eclipse-temurin-21 AS builder
WORKDIR /build
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /build/target/app-1.0.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil {
		t.Fatal("expected settings, got nil")
	}
	want := "mvn -q package -DskipTests && exec java -jar /build/target/app-1.0.jar"
	if ds.Command != want {
		t.Fatalf("command = %q, want %q", ds.Command, want)
	}
	if ds.Dir != "/build" {
		t.Fatalf("dir = %q, want /build", ds.Dir)
	}
	// The replayed RUN's cache mount becomes a named volume; the pre source
	// COPY dependency step is not replayed
	if strings.Join(ds.AdditionalMounts, ",") != "openrun-cache-root-m2:/root/.m2" {
		t.Fatalf("additional mounts = %v", ds.AdditionalMounts)
	}
}

func TestResolveReplayArtifactDirectory(t *testing.T) {
	t.Parallel()

	// A directory artifact: tokens inside the copied dir map to the build
	// stage paths
	data := `
FROM node:22 AS builder
WORKDIR /src
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM node:22-slim
WORKDIR /srv
COPY --from=builder /src/dist ./dist
ENTRYPOINT ["node", "dist/server.js"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	// dist/server.js resolves to the same path in the builder WORKDIR, so the
	// token is not rewritten; npm run build recreates dist under the mount
	want := "npm run build && exec node dist/server.js"
	if ds == nil || ds.Command != want {
		t.Fatalf("command = %+v, want %q", ds, want)
	}
}

func TestResolveReplayUnreplayableFallsBack(t *testing.T) {
	t.Parallel()

	// The entry references an artifact but the build stage has no RUN after
	// the source COPY to replay: implicit settings fall back to legacy
	noBuildRun := `
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .

FROM alpine
WORKDIR /app
COPY --from=builder /app/prebuilt .
ENTRYPOINT ["/app/prebuilt"]
`
	ds, _, err := resolveForTest(t, noBuildRun, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds != nil {
		t.Fatalf("resolved = %+v, want nil (unreplayable artifact)", ds)
	}
	// Explicit settings fail instead of shipping a missing binary
	_, _, err = resolveForTest(t, noBuildRun, &types.DevSettings{Reload: types.DEV_RELOAD_RESTART}, "", false, nil)
	if err == nil || !strings.Contains(err.Error(), "build artifact") {
		t.Fatalf("expected build artifact error, got %v", err)
	}

	// A wildcard COPY --from hides the artifact source: also unreplayable
	wildcard := strings.Replace(noBuildRun, "COPY --from=builder /app/prebuilt .", "COPY --from=builder /app/* .", 1)
	ds, _, err = resolveForTest(t, wildcard, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("wildcard resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveAutoInferenceCargsOverrideArgs(t *testing.T) {
	t.Parallel()

	_, env, err := resolveForTest(t, cowbullContainerfile, nil, "", false, map[string]string{"APP_NAME": "custom"}, "data")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if env["APP_NAME"] != "custom" {
		t.Fatalf("inferred env = %v, want APP_NAME=custom (cargs override)", env)
	}
}

func TestResolveAutoInferenceExecFormEntry(t *testing.T) {
	t.Parallel()

	data := `
FROM node:22 AS builder
WORKDIR /src
COPY . .
RUN npm install

FROM node:22-slim
WORKDIR /srv
COPY --from=builder /src /srv
ENTRYPOINT ["node", "server.js"]
CMD ["--port", "8080", "a b"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	// The whole builder tree is copied to the final stage, so the entry
	// tokens stay valid in the builder WORKDIR; npm install re-runs since the
	// source mount shadows the baked node_modules
	if ds.Command != "npm install && exec node server.js --port 8080 'a b'" {
		t.Fatalf("command = %q", ds.Command)
	}
	if ds.Dir != "/src" {
		t.Fatalf("dir = %q, want the builder stage WORKDIR /src", ds.Dir)
	}
}

func TestResolveBuilderStageWithOwnEntryIsKept(t *testing.T) {
	t.Parallel()

	data := `
FROM python:3.12 AS builder
WORKDIR /app
COPY . .
CMD ["python", "app.py"]

FROM python:3.12-slim
WORKDIR /app
ENTRYPOINT ["python", "optimized.py"]
`
	ds, env, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	// The build stage defines its own CMD, which runs as is
	if ds.Command != "" || ds.Target != "builder" {
		t.Fatalf("resolved = %+v, want empty command with target builder", ds)
	}
	if len(env) != 0 {
		t.Fatalf("inferred env = %v, want empty", env)
	}
}

func TestResolveSingleStage(t *testing.T) {
	t.Parallel()

	data := `
FROM python:3.12
WORKDIR /code
COPY . .
CMD ["python", "app.py"]
`
	ds, env, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil {
		t.Fatal("expected settings, got nil")
	}
	// Full image build, its own CMD runs, source mounted at the WORKDIR
	if ds.Target != "" || ds.Command != "" || ds.Dir != "/code" {
		t.Fatalf("resolved = %+v", ds)
	}
	if len(env) != 0 {
		t.Fatalf("inferred env = %v, want empty", env)
	}
}

func TestResolveImplicitFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "no workdir", data: "FROM python:3.12\nCMD [\"python\", \"app.py\"]\n"},
		{name: "unnamed build stage", data: "FROM golang:1.24\nWORKDIR /app\n\nFROM alpine\nWORKDIR /app\nENTRYPOINT [\"/app/app\"]\n"},
		{name: "no entry command", data: "FROM golang:1.24 AS builder\nWORKDIR /app\n\nFROM alpine\nWORKDIR /app\n"},
		{name: "relative workdir on external base", data: "FROM python:3.12\nWORKDIR code\nCMD [\"python\", \"app.py\"]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, _, err := resolveForTest(t, tt.data, nil, "", false, nil)
			if err != nil {
				t.Fatalf("resolveDevSettings returned error: %v", err)
			}
			if ds != nil {
				t.Fatalf("resolved = %+v, want nil (legacy flow fallback)", ds)
			}
		})
	}
}

func TestResolveExplicitSettingsSoftSkipInference(t *testing.T) {
	t.Parallel()

	// Unnamed build stage: target/command inference is skipped, the full
	// image is built (pre-inference behavior), dir comes from the final stage
	data := "FROM golang:1.24\nWORKDIR /build\n\nFROM alpine\nWORKDIR /app\nENTRYPOINT [\"/app/app\"]\n"
	ds, _, err := resolveForTest(t, data, &types.DevSettings{Reload: types.DEV_RELOAD_RESTART}, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil || ds.Target != "" || ds.Command != "" || ds.Dir != "/app" {
		t.Fatalf("resolved = %+v, want full image build with dir /app", ds)
	}

	// Explicit settings with no resolvable dir fail
	noWorkdir := "FROM python:3.12\nCMD [\"python\", \"app.py\"]\n"
	_, _, err = resolveForTest(t, noWorkdir, &types.DevSettings{Reload: types.DEV_RELOAD_RESTART}, "", false, nil)
	if err == nil || !strings.Contains(err.Error(), "dir must be set") {
		t.Fatalf("expected dir error, got %v", err)
	}
}

func TestResolveExplicitTargetMissingStageFallsBackToFullBuild(t *testing.T) {
	t.Parallel()

	// Preserves the pre-existing devBuildTarget behavior: a configured target
	// stage missing from an app supplied Containerfile builds the full image
	data := "FROM alpine\nWORKDIR /app\nCMD [\"/app/run\"]\n"
	ds, _, err := resolveForTest(t, data, &types.DevSettings{Target: "builder", Dir: "/app"}, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds.Target != "" {
		t.Fatalf("target = %q, want empty (full image build)", ds.Target)
	}

	// Matching stage is kept, case-insensitively
	ds, _, err = resolveForTest(t, "FROM alpine AS BUILDER\nWORKDIR /app\nCMD [\"/app/run\"]\n",
		&types.DevSettings{Target: "builder", Dir: "/app"}, "", false, nil)
	if err != nil || ds.Target != "builder" {
		t.Fatalf("target = %q err %v, want builder", ds.Target, err)
	}
}

func TestResolveDisableAndProdGuard(t *testing.T) {
	t.Parallel()

	devLast := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM builder AS dev
CMD go run .
`
	cf := parseCFInfo(t, devLast)
	if err := checkProdDevStage(cf, "dev", "Containerfile"); err == nil {
		t.Fatal("expected prod guard error for dev stage as last stage")
	}
	ok := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM builder AS dev
CMD go run .

FROM alpine
ENTRYPOINT ["/app/app"]
`
	if err := checkProdDevStage(parseCFInfo(t, ok), "dev", "Containerfile"); err != nil {
		t.Fatalf("prod guard returned error for valid layout: %v", err)
	}
}

func TestResolveWorkdirInheritanceAndSubstitution(t *testing.T) {
	t.Parallel()

	data := `
ARG BASE_DIR=/srv
FROM golang:1.24 AS builder
ARG BASE_DIR
WORKDIR ${BASE_DIR}/app
WORKDIR sub

FROM builder AS dev
CMD go run .

FROM alpine
ENTRYPOINT ["/app/app"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds.Dir != "/srv/app/sub" {
		t.Fatalf("dir = %q, want /srv/app/sub", ds.Dir)
	}
}

func TestResolveReplayDirContentsCopy(t *testing.T) {
	t.Parallel()

	// COPY of a directory places its contents at the destination root:
	// /app/server.js comes from /app/.next/standalone/server.js
	data := `
FROM node:22 AS builder
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM node:22-slim
WORKDIR /app
COPY --from=builder /app/.next/standalone ./
CMD ["node", "server.js"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil, "package.json")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	want := "npm run build && exec node /app/.next/standalone/server.js"
	if ds == nil || ds.Command != want {
		t.Fatalf("command = %+v, want %q", ds, want)
	}
}

func TestResolveReplayShellWrapperPayload(t *testing.T) {
	t.Parallel()

	// The artifact reference is inside a sh -c payload token
	base := `
FROM maven:3-eclipse-temurin-21 AS builder
WORKDIR /build
COPY . .
RUN mvn -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /build/target/app-1.0.jar app.jar
CMD ["sh", "-c", "java -jar app.jar"]
`
	ds, _, err := resolveForTest(t, base, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	want := "mvn -q package -DskipTests && exec sh -c 'java -jar /build/target/app-1.0.jar'"
	if ds == nil || ds.Command != want {
		t.Fatalf("command = %+v, want %q", ds, want)
	}

	// A payload that needs a rewrite but uses shell quoting cannot be
	// rewritten safely: fall back
	quoted := strings.Replace(base, `"java -jar app.jar"`, `"java $JAVA_OPTS -jar 'app.jar'"`, 1)
	ds, _, err = resolveForTest(t, quoted, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("quoted payload resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveReplayPayloadAssignment(t *testing.T) {
	t.Parallel()

	// The artifact path is hidden inside a shell variable assignment; the
	// assignment value is checked and rewritten. classpath: style values and
	// $VAR references are left for the runtime shell
	data := `
FROM maven:3-eclipse-temurin-21 AS builder
WORKDIR /build
COPY . .
RUN mvn -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /build/target/app-1.0.jar /app/app.jar
CMD ["sh", "-c", "JAR=/app/app.jar; exec java -Dcfg=classpath:app.yml -jar $JAR"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	want := "mvn -q package -DskipTests && exec sh -c " +
		"'JAR=/build/target/app-1.0.jar; exec java -Dcfg=classpath:app.yml -jar $JAR'"
	if ds == nil || ds.Command != want {
		t.Fatalf("command = %+v, want %q", ds, want)
	}
}

func TestResolveCommandSubstitutionFallsBack(t *testing.T) {
	t.Parallel()

	// Command substitution can conceal references to copied files; with
	// copied content present the entry cannot be verified
	data := `
FROM maven:3-eclipse-temurin-21 AS builder
WORKDIR /build
COPY . .
RUN mvn -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /build/target/app-1.0.jar /app/app.jar
CMD ["sh", "-c", "exec java -jar $(ls /app/*.jar)"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveContextCopyRewrite(t *testing.T) {
	t.Parallel()

	// The final stage copies an entrypoint script from the build context to a
	// path the build stage image lacks; the script is in the mounted source
	data := `
FROM python:3.12 AS builder
WORKDIR /app
COPY . .

FROM python:3.12-slim
WORKDIR /app
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "serve"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil, "docker-entrypoint.sh")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	want := "/app/docker-entrypoint.sh serve"
	if ds == nil || ds.Command != want {
		t.Fatalf("command = %+v, want %q", ds, want)
	}

	// Without the script in the app source the copy is untraceable: fall back
	ds, _, err = resolveForTest(t, data, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("missing context file resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveCustomShellFallsBack(t *testing.T) {
	t.Parallel()

	// A custom SHELL on a replayed shell form RUN cannot be reproduced with
	// the sh based dev command
	buildShell := `
FROM golang:1.24 AS builder
SHELL ["/bin/bash", "-c"]
WORKDIR /app
COPY . .
RUN go build -o app . && [[ -f app ]]

FROM alpine
WORKDIR /app
COPY --from=builder /app/app .
ENTRYPOINT ["/app/app"]
`
	ds, _, err := resolveForTest(t, buildShell, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("custom build SHELL resolve = (%+v, %v), want nil fallback", ds, err)
	}

	// A custom SHELL with a shell form entry command changes its semantics
	entryShell := `
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM alpine
SHELL ["/bin/bash", "-c"]
WORKDIR /app
COPY --from=builder /app/app .
ENTRYPOINT /app/app serve
`
	ds, _, err = resolveForTest(t, entryShell, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("custom entry SHELL resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveReplayRejectsUnreproducibleRunFlags(t *testing.T) {
	t.Parallel()

	data := `
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN --mount=type=secret,id=token go build -o app .

FROM alpine
WORKDIR /app
COPY --from=builder /app/app .
ENTRYPOINT ["/app/app"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("secret mount resolve = (%+v, %v), want nil fallback", ds, err)
	}
	// Explicit settings error instead of silently using the legacy flow
	_, _, err = resolveForTest(t, data, &types.DevSettings{Reload: types.DEV_RELOAD_RESTART}, "", false, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be replayed") {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestResolveEnvSnapshotSemantics(t *testing.T) {
	t.Parallel()

	// ENV assignments expand against the environment from before their own
	// instruction: B gets the old value of A
	data := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM alpine
ENV A=old
ENV A=new B=$A
ENTRYPOINT ["/app/app"]
`
	_, env, err := resolveForTest(t, data, nil, "", false, nil, "app")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if env["A"] != "new" || env["B"] != "old" {
		t.Fatalf("inferred env = %v, want A=new B=old", env)
	}
}

func TestResolveArgExpandedFrom(t *testing.T) {
	t.Parallel()

	// Global ARGs expand in FROM before stage references are resolved: the
	// dev stage inherits builder's WORKDIR through FROM ${DEV_BASE}
	data := `
ARG DEV_BASE=builder
FROM golang:1.24 AS builder
WORKDIR /app

FROM ${DEV_BASE} AS dev
CMD go run .

FROM alpine
ENTRYPOINT ["/app/app"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	if ds == nil || ds.Target != "dev" || ds.Dir != "/app" {
		t.Fatalf("resolved = %+v, want target dev dir /app", ds)
	}
}

func TestResolveGeneratedFileWithoutProviderFallsBack(t *testing.T) {
	t.Parallel()

	// The entry references a path under the mount that is neither in the app
	// source nor provided by any COPY: it would not exist in the dev container
	data := `
FROM node:22 AS builder
WORKDIR /app
COPY . .
RUN npm run build

FROM node:22-slim
WORKDIR /app
COPY --from=builder /app/gen.js .
CMD ["node", "other.js"]
`
	ds, _, err := resolveForTest(t, data, nil, "", false, nil)
	if err != nil || ds != nil {
		t.Fatalf("resolve = (%+v, %v), want nil fallback", ds, err)
	}
}

func TestResolveEnvPropagationSkipsUnresolvable(t *testing.T) {
	t.Parallel()

	// PATH resolves against the final base image's PATH which is unknown, and
	// docker env values are literal; propagating either would break the dev
	// container (a PATH without /bin makes the sh entrypoint fail to start)
	data := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM alpine
ENV PATH="/app/.venv/bin:$PATH"
ENV UNRESOLVED=${SOME_BASE_VAR}/data
ENV OK=plain
ENTRYPOINT ["/app/app"]
`
	_, env, err := resolveForTest(t, data, nil, "", false, nil, "app")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	want := map[string]string{"OK": "plain"}
	if !maps.Equal(env, want) {
		t.Fatalf("inferred env = %v, want %v", env, want)
	}
}

func TestCollectContainerfileInfoEnvForms(t *testing.T) {
	t.Parallel()

	data := `
FROM golang:1.24 AS builder
WORKDIR /app

FROM alpine
ENV LEGACY value with spaces
ENV A=1 B="two words" C=$A
ENTRYPOINT ["/app/app"]
`
	_, env, err := resolveForTest(t, data, nil, "", false, nil, "app")
	if err != nil {
		t.Fatalf("resolveDevSettings returned error: %v", err)
	}
	// C=$A expands against the environment from before its own ENV
	// instruction (image build semantics), where A is unset; the unresolved
	// value is then dropped from propagation
	want := map[string]string{"LEGACY": "value with spaces", "A": "1", "B": "two words"}
	if !maps.Equal(env, want) {
		t.Fatalf("inferred env = %v, want %v", env, want)
	}
}
