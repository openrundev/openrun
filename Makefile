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
GOLANGCI_LINT_VERSION := v2.13.1
GOLANGCI_LINT = GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# tests/run_cli_tests.sh flags, settable from the make command line, e.g.
# `make int CONTAINER_COMMANDS=docker POSTGRES=1`. RUN_CLI_TEST_ARGS is an
# escape hatch for anything not covered by a dedicated variable.
CONTAINER_COMMANDS ?=
CONTAINER_TOOL ?=
POSTGRES ?=
POSTGRES_URL ?=
MYSQL ?=
MYSQL_URL ?=
REDIS ?=
REDIS_URL ?=
SEAWEEDFS ?=
S3_URL ?=
KUBE_REGISTRY ?=
KUBE_NAMESPACE ?=
DR ?=
SKIP_BUILD ?=
RUN_CLI_TEST_ARGS ?=
RUN_CLI_TESTS_FLAGS = --home $(OPENRUN_HOME) \
  $(if $(CONTAINER_COMMANDS),--container-commands "$(CONTAINER_COMMANDS)") \
  $(if $(CONTAINER_TOOL),--container-tool $(CONTAINER_TOOL)) \
  $(if $(POSTGRES),--postgres) \
  $(if $(POSTGRES_URL),--postgres-url $(POSTGRES_URL)) \
  $(if $(MYSQL),--mysql) \
  $(if $(MYSQL_URL),--mysql-url $(MYSQL_URL)) \
  $(if $(REDIS),--redis) \
  $(if $(REDIS_URL),--redis-url $(REDIS_URL)) \
  $(if $(SEAWEEDFS),--seaweedfs) \
  $(if $(S3_URL),--s3-url $(S3_URL)) \
  $(if $(KUBE_REGISTRY),--kube-registry $(KUBE_REGISTRY)) \
  $(if $(KUBE_NAMESPACE),--kube-namespace $(KUBE_NAMESPACE)) \
  $(if $(DR),--dr) \
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

.PHONY: help test unit int testui covtest covunit covint release fullrelease update-dep update-go int_single lint verify build-linux image tags docs-screenshots

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
> go tool cover -func coverage.txt | grep '^total:'

unit: ## Run unit tests
> packages="$(GO_PACKAGES)"
> go test $$packages
> cd pkg/binding && GOWORK=off go test -race ./...

lint: ## Run lint
> packages="$(GO_LINT_PACKAGES)"
> $(GOLANGCI_LINT) run $$packages
> cd pkg/binding && $(GOLANGCI_LINT) run ./...

covunit: ## Run unit tests with coverage and the race detector
> rm -rf $(OPENRUN_HOME)/coverage/unit && mkdir -p $(OPENRUN_HOME)/coverage/unit
> packages="$(GO_PACKAGES)"
> cover_packages="$(GO_COVER_PACKAGES)"
> go test -race -covermode=atomic -coverpkg "$$cover_packages" $$packages -args -test.gocoverdir="$(OPENRUN_HOME)/coverage/unit"

int: ## Run integration tests
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS)

testui: ## Run the console app integration tests (ui/console_tests, own module)
> cd ui/console_tests && go test -count=1 ./...

docs-screenshots: ## Copy the console walkthrough screenshots (light/dark pairs) and walkthrough.html pages into the public docs; generate first with: cd ui/console_tests && make todoflow rbacflow
> @if ! ls ui/console_tests/browser/walkthrough/*.png > /dev/null 2>&1; then \
>    echo "Error: no todo flow screenshots found, generate them with: cd ui/console_tests && make todoflow"; \
>    exit 1; \
> fi
> @if ! ls ui/console_tests/browser/rbac_walkthrough/*.png > /dev/null 2>&1; then \
>    echo "Error: no rbac flow screenshots found, generate them with: cd ui/console_tests && make rbacflow"; \
>    exit 1; \
> fi
> mkdir -p docs/static/images/console docs/static/images/console_rbac
> rm -f docs/static/images/console/*.png docs/static/images/console/walkthrough.html
> rm -f docs/static/images/console_rbac/*.png docs/static/images/console_rbac/walkthrough.html
> cp ui/console_tests/browser/walkthrough/*.png ui/console_tests/browser/walkthrough/walkthrough.html docs/static/images/console/
> cp ui/console_tests/browser/rbac_walkthrough/*.png ui/console_tests/browser/rbac_walkthrough/walkthrough.html docs/static/images/console_rbac/
> @echo "Copied `ls docs/static/images/console/*.png | wc -l | tr -d ' '` todo + `ls docs/static/images/console_rbac/*.png | wc -l | tr -d ' '` rbac screenshots and both walkthrough.html pages into docs/static/images/"

int_single: ## Run one integration test; args: <test-file.yaml>
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS) ${INPUT}

covint: ## Run integration tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/int && mkdir -p $(OPENRUN_HOME)/coverage/int
> rm -rf $(OPENRUN_HOME)/coverage/client && mkdir -p $(OPENRUN_HOME)/coverage/client
> ./tests/run_cli_tests.sh $(RUN_CLI_TESTS_FLAGS) --coverdir $(OPENRUN_HOME)/coverage/int

tags: ## Show current release version tags
> @echo "OpenRun SDK releases"
> echo "OpenRun    : $$(git tag -l 'v*' --sort=-version:refname | head -n 1)"
> echo "Binding SDK: $$(git tag -l 'pkg/binding/v*' --sort=-version:refname | head -n 1)"
> echo "Plugin SDK : $$(git tag -l 'pkg/plugin/v*' --sort=-version:refname | head -n 1)"
> echo "Binding providers"
> $(MAKE) --no-print-directory -s -C ../bindings tags
> echo "Helm chart : $$(git -C ../openrun-helm-charts tag -l 'openrun-*' --sort=-version:refname | head -n 1)"

update-dep: ## Update one dependency in all OpenRun and binding-provider modules; args: <module[@version]>
> @dependency="$(INPUT)"
> if [[ -z "$$dependency" ]]; then
>   echo "Usage: make update-dep <module[@version]>, e.g. make update-dep google.golang.org/grpc"
>   exit 1
> fi
> module_dirs=(. internal/bindings/testdata/fixtureprovider pkg/plugin pkg/binding)
> if [[ ! -f ../bindings/Makefile ]]; then
>   echo "Error: ../bindings is required"
>   exit 1
> fi
> binding_modules="$$($(MAKE) --no-print-directory -s -C ../bindings modules)"
> for module in $$binding_modules; do
>   module_dirs+=("../bindings/$$module")
> done
> for module_dir in "$${module_dirs[@]}"; do
>   if [[ ! -f "$$module_dir/go.mod" ]]; then
>     echo "Error: module file not found: $$module_dir/go.mod"
>     exit 1
>   fi
> done
> for module_dir in "$${module_dirs[@]}"; do
>   echo "==> $$module_dir: go get -u $$dependency"
>   (cd "$$module_dir" && GOWORK=off go get -u "$$dependency")
> done

update-go: ## Update the Go version in all modules and Actions workflows; args: <major.minor.patch>
> @version="$(INPUT)"
> version="$${version#go}"
> if [[ ! "$$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$$ ]]; then
>   echo "Usage: make update-go <major.minor.patch>, e.g. make update-go 1.26.6"
>   exit 1
> fi
> module_dirs=(. docs internal/bindings/testdata/fixtureprovider pkg/plugin pkg/binding ui/console_tests)
> if [[ ! -f ../bindings/Makefile ]]; then
>   echo "Error: ../bindings is required"
>   exit 1
> fi
> binding_modules="$$($(MAKE) --no-print-directory -s -C ../bindings modules)"
> for module in $$binding_modules; do
>   module_dirs+=("../bindings/$$module")
> done
> for module_dir in "$${module_dirs[@]}"; do
>   if [[ ! -f "$$module_dir/go.mod" ]]; then
>     echo "Error: module file not found: $$module_dir/go.mod"
>     exit 1
>   fi
> done
> workflow_dirs=(.github/workflows ../bindings/.github/workflows ui/console_tests/.github/workflows)
> for workflow_dir in "$${workflow_dirs[@]}"; do
>   if [[ ! -d "$$workflow_dir" ]]; then
>     echo "Error: workflow directory not found: $$workflow_dir"
>     exit 1
>   fi
> done
> for module_dir in "$${module_dirs[@]}"; do
>   echo "==> $$module_dir/go.mod: go $$version"
>   (cd "$$module_dir" && GOWORK=off go mod edit -go="$$version")
> done
> for workflow_dir in "$${workflow_dirs[@]}"; do
>   while IFS= read -r -d '' workflow; do
>     if ! grep -Eq "^[[:space:]]*go-version:[[:space:]]*(\[?[\"']?)?[0-9]+\.[0-9]+" "$$workflow"; then
>       continue
>     fi
>     sed -E \
>       -e "s/^([[:space:]]*go-version:[[:space:]]*\[?\")[0-9]+\.[0-9]+(\.[0-9]+)?(\"\]?[[:space:]]*)$$/\1$$version\3/" \
>       -e "s/^([[:space:]]*go-version:[[:space:]]*\[?')[0-9]+\.[0-9]+(\.[0-9]+)?('\]?[[:space:]]*)$$/\1$$version\3/" \
>       -e "s/^([[:space:]]*go-version:[[:space:]]*)[0-9]+\.[0-9]+(\.[0-9]+)?([[:space:]]*)$$/\1$$version\3/" \
>       "$$workflow" > "$$workflow.new"
>     mv "$$workflow.new" "$$workflow"
>   done < <(find "$$workflow_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
> done
> echo "Updated Go version to $$version in $${#module_dirs[@]} modules and Actions workflows"

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

fullrelease: ## Tag+push OpenRun, SDKs and all bindings; create (not push) the Helm chart release commit; args: <version>
> @version="$(INPUT)"
> version="$${version#v}"
> if [[ -z "$$version" ]]; then
>   echo "Usage: make fullrelease <version>, e.g. make fullrelease 0.19.0"
>   exit 1
> fi
> semver_re='^(0|[1-9][0-9]*)\.((0|[1-9][0-9]*))\.((0|[1-9][0-9]*))(-((0|[1-9][0-9]*)|([0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(\.((0|[1-9][0-9]*)|([0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?$$'
> if ! [[ "$$version" =~ $$semver_re ]]; then
>   echo "Error: version '$$version' must be SemVer without build metadata (for example 1.2.3 or 1.2.3-rc.1)"
>   exit 1
> fi
> # Everything is tagged from the current checkouts. Require clean main
> # branches synchronized with origin/main, and fetch tags before checking for
> # collisions so a remote-only tag cannot cause a partial release later.
> for repo in . ../bindings ../openrun-helm-charts; do
>   if [[ -n "$$(git -C $$repo status --porcelain)" ]]; then
>     echo "Error: working tree $$repo is not clean, commit or stash changes first"
>     exit 1
>   fi
>   branch="$$(git -C $$repo branch --show-current)"
>   if [[ "$$branch" != "main" ]]; then
>     echo "Error: $$repo must be on main (currently '$$branch')"
>     exit 1
>   fi
>   git -C $$repo fetch --quiet --prune --tags origin
>   if [[ "$$(git -C $$repo rev-parse HEAD)" != "$$(git -C $$repo rev-parse refs/remotes/origin/main)" ]]; then
>     echo "Error: $$repo main is not synchronized with origin/main"
>     exit 1
>   fi
> done
> for tag in "v$$version" "pkg/binding/v$$version" "pkg/plugin/v$$version"; do
>   if git rev-parse -q --verify "refs/tags/$$tag" > /dev/null; then
>     echo "Error: tag $$tag already exists"
>     exit 1
>   fi
> done
> binding_modules="$$($(MAKE) --no-print-directory -s -C ../bindings modules)"
> for module in $$binding_modules; do
>   tag="$$module/v$$version"
>   if git -C ../bindings rev-parse -q --verify "refs/tags/$$tag" > /dev/null; then
>     echo "Error: bindings tag $$tag already exists"
>     exit 1
>   fi
> done
> helm_tag="openrun-$$version"
> if git -C ../openrun-helm-charts rev-parse -q --verify "refs/tags/$$helm_tag" > /dev/null; then
>   echo "Error: Helm chart tag $$helm_tag already exists"
>   exit 1
> fi
> chart_version="$$(awk '$$1 == "version:" { print $$2; exit }' ../openrun-helm-charts/charts/openrun/Chart.yaml)"
> chart_app_version="$$(awk '$$1 == "appVersion:" { print $$2; exit }' ../openrun-helm-charts/charts/openrun/Chart.yaml)"
> if [[ -z "$$chart_version" || -z "$$chart_app_version" ]]; then
>   echo "Error: could not read version and appVersion from the OpenRun Chart.yaml"
>   exit 1
> fi
> if [[ "$$chart_version" == "$$version" && "$$chart_app_version" == "$$version" ]]; then
>   echo "Error: Helm Chart.yaml is already at $$version but tag $$helm_tag does not exist"
>   echo "Repair or rerun the Helm chart release before starting a new full release"
>   exit 1
> fi
> # The main module's SDK requirements must name the versions being released.
> # Local replace directives are not honored by downstream module consumers,
> # so pin both SDKs before the server and nested modules are tagged.
> go mod edit -require=github.com/openrundev/openrun/pkg/binding@v$$version
> go mod edit -require=github.com/openrundev/openrun/pkg/plugin@v$$version
> if ! git diff --quiet go.mod; then
>   git add go.mod
>   git commit -m "Pin SDK modules to v$$version for release"
> fi
> # openrun server + pkg/binding and pkg/plugin SDKs: tag, then push the
> # current branch and all three tags. The binding SDK tag must be on the
> # remote before the bindings release, whose go mod tidy resolves it; the
> # plugin SDK tag makes the release resolvable for plugin provider builds.
> git tag -a "v$$version" -m "Release v$$version"
> git tag -a "pkg/binding/v$$version" -m "Release pkg/binding/v$$version"
> git tag -a "pkg/plugin/v$$version" -m "Release pkg/plugin/v$$version"
> git push --atomic origin HEAD:main "v$$version" "pkg/binding/v$$version" "pkg/plugin/v$$version"
> # Bindings: update every provider module to the new SDK version, tag each
> # module and push; the bindings release workflow builds and publishes each
> # provider (binaries + OCI image) from its pushed tag
> $(MAKE) -C ../bindings release INPUT="v$$version" INPUT2="v$$version" PUSH=1
> # Helm chart: create the release commit only. It is pushed manually after the
> # OpenRun release job has published the v$$version images, since the chart's
> # appVersion is the server image tag.
> cd ../openrun-helm-charts/
> sed -i.bak -E "s/^([[:space:]]*version:[[:space:]]*)[^#[:space:]]+/\1$$version/" charts/openrun/Chart.yaml
> rm -f charts/openrun/Chart.yaml.bak
> sed -i.bak -E "s/^([[:space:]]*appVersion:[[:space:]]*)[^#[:space:]]+/\1$$version/" charts/openrun/Chart.yaml
> rm -f charts/openrun/Chart.yaml.bak
> if ! grep -q "^version: $$version$$" charts/openrun/Chart.yaml || ! grep -q "^appVersion: $$version$$" charts/openrun/Chart.yaml; then
>   echo "Error: failed to update Helm Chart.yaml to $$version"
>   exit 1
> fi
> git add charts/openrun/Chart.yaml
> git commit -m "Updated Helm chart to $$version, app version to $$version"
> cd - > /dev/null
> echo "**************************************************"
> echo " Tagged and pushed: v$$version, pkg/binding/v$$version, pkg/plugin/v$$version, bindings */v$$version"
> echo " Helm chart release commit created in ../openrun-helm-charts (not pushed)"
> echo " After the OpenRun release job for v$$version is done, run:"
> echo "   cd ../openrun-helm-charts/ && git push"
> echo "**************************************************"

# Swallow extra command-line words (e.g. `make int_single test_reload.yaml`)
# so make doesn't also try to build them as targets; $(INPUT)/$(INPUT2) above
# already pick them up positionally.
%:
> @:
