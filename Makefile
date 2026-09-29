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

.PHONY: help test unit int testui covtest covunit covint release-sdk release fullrelease update-dep update-go int_single lint verify build-linux image tags docs-screenshots

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

# ---------------------------------------------------------------------------
# Releases
#
# Versions are given without the v prefix (e.g. 0.20.0); the tags add it:
#   v<version>                              OpenRun server (this repo)
#   pkg/binding/v<version>, pkg/plugin/v<version>  SDK modules (this repo)
#   <provider>/v<version>                   binding providers (../bindings)
#   openrun-<version>                       Helm chart (../openrun-helm-charts)
#
#   make release-sdk <version>              tag + push both SDK modules only
#   make release <version> [<helm_version>] tag + push the server, then create
#                                           the Helm chart release commit
#   make fullrelease <version>              SDKs + server + every binding
#                                           provider + Helm chart commit
#   make -C ../bindings release <sdk_version> <bindings_version> PUSH=1
#                                           binding providers only
#
# Every repo that gets tagged must be on a clean main synchronized with
# origin/main. The Helm chart commit is never pushed automatically: its
# appVersion is the server image tag, so push it after the OpenRun release
# job has published the images.
# ---------------------------------------------------------------------------

# Bash helpers shared by the release targets; expanded as the first recipe line
define RELEASE_SH
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$$'
# version_arg <name> <value>: print the version without a v prefix, or fail
version_arg() {
  local v="$${2#v}"
  if [[ -z "$$v" ]]; then
    echo "Error: $$1 is required, e.g. 0.20.0" >&2
    return 1
  fi
  if ! [[ "$$v" =~ $$semver_re ]]; then
    echo "Error: $$1 '$$2' is not a version like 0.20.0 or 0.20.0-rc.1" >&2
    return 1
  fi
  echo "$$v"
}
# require_release_ready <repo>: clean working tree, on main, synchronized with origin/main
require_release_ready() {
  if [[ -n "$$(git -C "$$1" status --porcelain)" ]]; then
    echo "Error: $$1 has uncommitted changes, commit or stash them first" >&2
    return 1
  fi
  if [[ "$$(git -C "$$1" branch --show-current)" != "main" ]]; then
    echo "Error: $$1 must be on main" >&2
    return 1
  fi
  git -C "$$1" fetch --quiet --prune --tags origin
  if [[ "$$(git -C "$$1" rev-parse HEAD)" != "$$(git -C "$$1" rev-parse origin/main)" ]]; then
    echo "Error: $$1 main is not synchronized with origin/main" >&2
    return 1
  fi
}
# require_no_tag <repo> <tag>: fail if the tag exists (run after fetching tags)
require_no_tag() {
  if git -C "$$1" rev-parse -q --verify "refs/tags/$$2" > /dev/null; then
    echo "Error: tag $$2 already exists in $$1" >&2
    return 1
  fi
}
# helm_chart_commit <chart_version> <app_version>: commit Chart.yaml in ../openrun-helm-charts (not pushed)
helm_chart_commit() {
  local chart=../openrun-helm-charts/charts/openrun/Chart.yaml
  sed -i.bak -E \
    -e "s/^([[:space:]]*version:[[:space:]]*)[^#[:space:]]+/\1$$1/" \
    -e "s/^([[:space:]]*appVersion:[[:space:]]*)[^#[:space:]]+/\1$$2/" "$$chart"
  rm -f "$$chart.bak"
  if ! grep -q "^version: $$1$$" "$$chart" || ! grep -q "^appVersion: $$2$$" "$$chart"; then
    echo "Error: failed to update $$chart to version $$1, appVersion $$2" >&2
    return 1
  fi
  git -C ../openrun-helm-charts add charts/openrun/Chart.yaml
  git -C ../openrun-helm-charts commit -q -m "Updated Helm chart to $$1, app version to $$2"
  echo "**************************************************"
  echo " Helm chart release commit created in ../openrun-helm-charts (not pushed)"
  echo " After the OpenRun release job for v$$2 has published its images, run:"
  echo "   cd ../openrun-helm-charts && git push"
  echo "**************************************************"
}
endef

release-sdk: ## Tag and push the pkg/binding and pkg/plugin SDK modules; args: <version>
> @$(RELEASE_SH)
> version=$$(version_arg version "$(INPUT)")
> require_release_ready .
> for tag in "pkg/binding/v$$version" "pkg/plugin/v$$version"; do require_no_tag . "$$tag"; done
> git tag -a "pkg/binding/v$$version" -m "Release pkg/binding/v$$version"
> git tag -a "pkg/plugin/v$$version" -m "Release pkg/plugin/v$$version"
> git push --atomic origin "pkg/binding/v$$version" "pkg/plugin/v$$version"
> echo "Pushed pkg/binding/v$$version and pkg/plugin/v$$version; consumers can now require them"

release: ## Tag and push the OpenRun server, then create the Helm chart release commit; args: <version> [<helm_version>, default <version>]
> @$(RELEASE_SH)
> version=$$(version_arg version "$(INPUT)")
> helm_version=$$(version_arg helm_version "$(if $(INPUT2),$(INPUT2),$(INPUT))")
> require_release_ready .
> require_release_ready ../openrun-helm-charts
> require_no_tag . "v$$version"
> require_no_tag ../openrun-helm-charts "openrun-$$helm_version"
> git tag -a "v$$version" -m "Release v$$version"
> git push origin "v$$version"
> helm_chart_commit "$$helm_version" "$$version"

fullrelease: ## Release everything at one version: SDKs, server, every binding provider, Helm chart commit; args: <version>
> @$(RELEASE_SH)
> version=$$(version_arg version "$(INPUT)")
> for repo in . ../bindings ../openrun-helm-charts; do require_release_ready "$$repo"; done
> for tag in "v$$version" "pkg/binding/v$$version" "pkg/plugin/v$$version"; do require_no_tag . "$$tag"; done
> for module in $$($(MAKE) --no-print-directory -s -C ../bindings modules); do require_no_tag ../bindings "$$module/v$$version"; done
> require_no_tag ../openrun-helm-charts "openrun-$$version"
> if grep -q "^version: $$version$$" ../openrun-helm-charts/charts/openrun/Chart.yaml; then
>   echo "Error: Chart.yaml is already at $$version but tag openrun-$$version does not exist; finish that chart release first"
>   exit 1
> fi
> # The server tag must require the SDK versions being released: downstream
> # consumers of the server module do not see the local replace directives.
> go mod edit -require=github.com/openrundev/openrun/pkg/binding@v$$version -require=github.com/openrundev/openrun/pkg/plugin@v$$version
> if ! git diff --quiet go.mod; then
>   git add go.mod
>   git commit -q -m "Pin SDK modules to v$$version for release"
> fi
> # Server and SDK tags go out in one push; the bindings release below runs
> # go mod tidy against the published pkg/binding tag.
> for tag in "v$$version" "pkg/binding/v$$version" "pkg/plugin/v$$version"; do git tag -a "$$tag" -m "Release $$tag"; done
> git push --atomic origin HEAD:main "v$$version" "pkg/binding/v$$version" "pkg/plugin/v$$version"
> $(MAKE) -C ../bindings release INPUT="$$version" INPUT2="$$version" PUSH=1
> echo "Tagged and pushed v$$version, pkg/binding/v$$version, pkg/plugin/v$$version and every bindings <provider>/v$$version"
> helm_chart_commit "$$version" "$$version"

# Swallow extra command-line words (e.g. `make int_single test_reload.yaml`)
# so make doesn't also try to build them as targets; $(INPUT)/$(INPUT2) above
# already pick them up positionally.
%:
> @:
