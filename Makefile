# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
OPENRUN_HOME := `pwd`
INPUT := $(word 2,$(MAKECMDGOALS))
INPUT2 := $(word 3,$(MAKECMDGOALS))
# GOWORK=off: package lists are computed in module mode so a local go.work
# (used for pkg/binding development) does not change what gets built/linted.
# In workspace mode `go list -m` returns every workspace module and
# `go list ./...` crosses into the nested pkg/binding module.
GO_PACKAGES = $$(GOWORK=off go list ./... | grep -v '/ui/')
GO_COVER_PACKAGES = $$(GOWORK=off go list ./... | grep -v '/ui/' | paste -sd, -)
GO_LINT_PACKAGES = $$(module=$$(GOWORK=off go list -m); GOWORK=off go list ./... | grep -v '/ui/' | awk -v module="$$module" '{ sub("^" module, "."); print }')

# tests/run_cli_tests.sh flags, settable from the make command line, e.g.
# `make int CONTAINER_COMMANDS=docker POSTGRES=1`. RUN_CLI_TEST_ARGS is an
# escape hatch for anything not covered by a dedicated variable.
CONTAINER_COMMANDS ?=
CONTAINER_TOOL ?=
POSTGRES ?=
POSTGRES_URL ?=
MYSQL ?=
MYSQL_URL ?=
KUBE_REGISTRY ?=
KUBE_NAMESPACE ?=
SKIP_BUILD ?=
RUN_CLI_TEST_ARGS ?=
RUN_CLI_TESTS_FLAGS = --home $(OPENRUN_HOME) \
  $(if $(CONTAINER_COMMANDS),--container-commands "$(CONTAINER_COMMANDS)") \
  $(if $(CONTAINER_TOOL),--container-tool $(CONTAINER_TOOL)) \
  $(if $(POSTGRES),--postgres) \
  $(if $(POSTGRES_URL),--postgres-url $(POSTGRES_URL)) \
  $(if $(MYSQL),--mysql) \
  $(if $(MYSQL_URL),--mysql-url $(MYSQL_URL)) \
  $(if $(KUBE_REGISTRY),--kube-registry $(KUBE_REGISTRY)) \
  $(if $(KUBE_NAMESPACE),--kube-namespace $(KUBE_NAMESPACE)) \
  $(if $(SKIP_BUILD),--skip-build) \
  $(RUN_CLI_TEST_ARGS)

ARCH        := $(shell uname -m)
TARGET_DIR  := dist/linux/$(ARCH)
BINARY      := openrun
IMAGE_TAG   := openrun:latest

.DEFAULT_GOAL := help
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >
TAG := 

.PHONY: help test unit int testui covtest covunit covint release fullrelease int_single lint verify build-linux image tags docs-screenshots

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: unit int ## Run all tests
verify: lint test ## Run lint and all tests

build-linux: ## Build linux binary into dist/
> mkdir -p $(TARGET_DIR)
> CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o $(TARGET_DIR)/$(BINARY) ./cmd/openrun

image: build-linux ## Build docker image
> docker build -f deploy/Dockerfile -t $(IMAGE_TAG) dist

covtest: covunit covint ## Run all tests with coverage
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/unit,$(OPENRUN_HOME)/coverage/int
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/unit,$(OPENRUN_HOME)/coverage/int -o $(OPENRUN_HOME)/coverage.txt
> go tool cover -func coverage/profile

unit: ## Run unit tests
> packages="$(GO_PACKAGES)"
> go test $$packages
> cd pkg/binding && GOWORK=off go test ./...

lint: ## Run lint
> packages="$(GO_LINT_PACKAGES)"
> golangci-lint run $$packages
> cd pkg/binding && GOWORK=off golangci-lint run ./...

covunit: ## Run unit tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/unit && mkdir -p $(OPENRUN_HOME)/coverage/unit
> packages="$(GO_PACKAGES)"
> cover_packages="$(GO_COVER_PACKAGES)"
> go test -coverpkg "$$cover_packages" $$packages -args -test.gocoverdir="$(OPENRUN_HOME)/coverage/unit"
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/unit
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/unit -o $(OPENRUN_HOME)/coverage/profile
> go tool cover -func coverage/profile

int: ## Run integration tests
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS)

testui: ## Run the console app integration tests (ui/console_tests, own module)
> cd ui/console_tests && go test -count=1 ./...

docs-screenshots: ## Copy the console walkthrough screenshots (light/dark pairs) into the public docs; generate first with: cd ui/console_tests && make todoflow
> @if ! ls ui/console_tests/browser/walkthrough/*.png > /dev/null 2>&1; then \
>    echo "Error: no screenshots found, generate them with: cd ui/console_tests && make todoflow"; \
>    exit 1; \
> fi
> mkdir -p docs/static/images/console
> rm -f docs/static/images/console/*.png
> cp ui/console_tests/browser/walkthrough/*.png docs/static/images/console/
> @echo "Copied `ls docs/static/images/console/*.png | wc -l | tr -d ' '` screenshots to docs/static/images/console/"

int_single: ## Run one integration test; args: <test-file.yaml>
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS) ${INPUT}

covint: ## Run integration tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/int && mkdir -p $(OPENRUN_HOME)/coverage/int
> rm -rf $(OPENRUN_HOME)/coverage/client && mkdir -p $(OPENRUN_HOME)/coverage/client
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS) --coverdir $(OPENRUN_HOME)/coverage/int
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/int
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/int -o $(OPENRUN_HOME)/coverage/profile
> go tool cover -func coverage/profile

tags: ## Show current release version tags
> @echo "OpenRun   : " `git tag -l --sort=-creatordate | head -n 1`
> @cd ../openrun-helm-charts/
> @git pull > /dev/null
> @echo "Helm Chart: " `git tag -l --sort=-creatordate | head -n 1`
> @cd - > /dev/null

release: ## Tag and push a release; args: <app_version> <helm_version>
> @if [[ -z "$(INPUT)" || "$(INPUT)" == v* ]]; then \
>    echo "Error: OpenRun version has to be set, without the v prefix"; \
>    exit 1; \
> fi
> @if [[ -z "$(INPUT2)" || "$(INPUT2)" == openrun* ]]; then \
>    echo "Error: Helm version has to be set, without the openrun prefix"; \
>    exit 1; \
> fi
> git tag -a v$(INPUT) -m "Release v$(INPUT)"; git push origin v$(INPUT)
> @cd ../openrun-helm-charts/
> sed -i.bak -E "s/^([[:space:]]*version:[[:space:]]*)[^#[:space:]]+/\1${INPUT2}/" charts/openrun/Chart.yaml
> mv charts/openrun/Chart.yaml.bak /tmp/chart.bak1
> sed -i.bak -E "s/^([[:space:]]*appVersion:[[:space:]]*)[^#[:space:]]+/\1${INPUT}/" charts/openrun/Chart.yaml
> mv charts/openrun/Chart.yaml.bak /tmp/chart.bak2
> git add charts/openrun/Chart.yaml
> git commit -m "Updated Helm chart to $(INPUT2), app version to $(INPUT)"
> echo "************************************************** "
> echo "   cd ../openrun-helm-charts/ && git push"
> echo "************************************************** "
> echo "Run above command to push the Helm chart after the OpenRun release job is done"
> @cd - > /dev/null

fullrelease: ## Tag+push openrun, pkg/binding and all bindings under one version; stage (not push) the Helm chart; args: <version>
> @version="$(INPUT)"
> version="$${version#v}"
> if [[ -z "$$version" ]]; then
>   echo "Usage: make fullrelease <version>, e.g. make fullrelease 0.19.0"
>   exit 1
> fi
> if ! [[ "$$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$$ ]]; then
>   echo "Error: version '$$version' does not look like a semver version"
>   exit 1
> fi
> # Everything is tagged from the current checkouts: all three repos must be
> # clean, and nothing may be tagged/pushed if any tag already exists
> for repo in . ../bindings ../openrun-helm-charts; do
>   if [[ -n "$$(git -C $$repo status --porcelain)" ]]; then
>     echo "Error: working tree $$repo is not clean, commit or stash changes first"
>     exit 1
>   fi
> done
> for tag in "v$$version" "pkg/binding/v$$version"; do
>   if git rev-parse -q --verify "refs/tags/$$tag" > /dev/null; then
>     echo "Error: tag $$tag already exists"
>     exit 1
>   fi
> done
> if [[ -n "$$(git -C ../bindings tag -l "*/v$$version")" ]]; then
>   echo "Error: bindings tags for v$$version already exist:" $$(git -C ../bindings tag -l "*/v$$version")
>   exit 1
> fi
> # openrun server + pkg/binding SDK: tag and push. The SDK tag must be on the
> # remote before the bindings release, whose go mod tidy resolves it.
> git tag -a "v$$version" -m "Release v$$version"
> git tag -a "pkg/binding/v$$version" -m "Release pkg/binding/v$$version"
> git push origin "v$$version" "pkg/binding/v$$version"
> # Bindings: update every provider module to the new SDK version, tag each
> # module and push; the bindings release workflow builds and publishes each
> # provider (binaries + OCI image) from its pushed tag
> $(MAKE) -C ../bindings release INPUT="v$$version" INPUT2="v$$version" PUSH=1
> # Helm chart: stage the release commit only. It is pushed manually after the
> # OpenRun release job has published the v$$version images, since the chart's
> # appVersion is the server image tag.
> cd ../openrun-helm-charts/
> sed -i.bak -E "s/^([[:space:]]*version:[[:space:]]*)[^#[:space:]]+/\1$$version/" charts/openrun/Chart.yaml
> rm -f charts/openrun/Chart.yaml.bak
> sed -i.bak -E "s/^([[:space:]]*appVersion:[[:space:]]*)[^#[:space:]]+/\1$$version/" charts/openrun/Chart.yaml
> rm -f charts/openrun/Chart.yaml.bak
> git add charts/openrun/Chart.yaml
> git commit -m "Updated Helm chart to $$version, app version to $$version"
> cd - > /dev/null
> echo "**************************************************"
> echo " Tagged and pushed: v$$version, pkg/binding/v$$version, bindings */v$$version"
> echo " Helm chart commit staged in ../openrun-helm-charts (not pushed)"
> echo " After the OpenRun release job for v$$version is done, run:"
> echo "   cd ../openrun-helm-charts/ && git push"
> echo "**************************************************"

# Swallow extra command-line words (e.g. `make int_single test_reload.yaml`)
# so make doesn't also try to build them as targets; $(INPUT)/$(INPUT2) above
# already pick them up positionally.
%:
> @:
