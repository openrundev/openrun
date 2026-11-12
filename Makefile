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
INPUT3 := $(word 4,$(MAKECMDGOALS))
# GOWORK=off: package lists are computed in module mode so a local go.work
# (used for pkg/binding development) does not change what gets built/linted.
# In workspace mode `go list -m` returns every workspace module and
# `go list ./...` crosses into the nested pkg/binding module.
# tests/ui holds the browser-driven suites, run by testui rather than unit (they are linted)
GO_PACKAGES = $$(GOWORK=off go list ./... | grep -v 'openrun/ui/' | grep -v '/tests/ui/')
GO_COVER_PACKAGES = $$(GOWORK=off go list ./... | grep -v 'openrun/ui/' | grep -v '/tests/ui/' | paste -sd, -)
GO_LINT_PACKAGES = $$(module=$$(GOWORK=off go list -m); GOWORK=off go list ./... | grep -v 'openrun/ui/' | awk -v module="$$module" '{ sub("^" module, "."); print }')
GOLANGCI_LINT_VERSION := v2.15.0
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

.PHONY: help test unit int testui testconsole covtest covtest-parallel covbuild covunit covint covui covclient covreport next-version release-sdk release fullrelease update-dep update-go int_single lint verify build-linux image tags docs-screenshots

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: unit int testui ## Run all tests
verify: lint test ## Run lint and all tests

build-linux: ## Build linux binary into dist/
> mkdir -p $(TARGET_DIR)
> CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o $(TARGET_DIR)/$(BINARY) ./cmd/openrun

image: build-linux ## Build docker image
> docker build -f deploy/Dockerfile -t $(IMAGE_TAG) dist

# The CLI build temporarily stages test appspecs in the source tree. Finish
# it before starting unit tests, which embed/read the original appspecs.
# covui runs first on its own: make --jobs never kills in-flight jobs, it only
# stops launching new ones, so a failure in the short browser suite would
# otherwise wait on the long covint run before the target fails.
covtest-parallel: covbuild covclient ## Run unit and integration coverage concurrently (CI)
> $(MAKE) covui SKIP_BUILD=1
> $(MAKE) --jobs=2 covunit covint SKIP_BUILD=1
> $(MAKE) covreport

covbuild: ## Build the coverage-enabled CLI without running integration tests
> ./tests/run_cli_tests.sh --home $(OPENRUN_HOME) --coverdir $(OPENRUN_HOME)/coverage/int --build-only

# covint and covui both write CLI coverage data to coverage/client, so it is
# reset once per run here rather than by either of them
covclient:
> rm -rf $(OPENRUN_HOME)/coverage/client && mkdir -p $(OPENRUN_HOME)/coverage/client

covtest: covclient covunit covint covui ## Run all tests with coverage
> $(MAKE) covreport

covreport: ## Merge and print the coverage collected by covunit, covint and covui
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/unit,$(OPENRUN_HOME)/coverage/int,$(OPENRUN_HOME)/coverage/ui
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/unit,$(OPENRUN_HOME)/coverage/int,$(OPENRUN_HOME)/coverage/ui -o $(OPENRUN_HOME)/coverage.txt
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

# The tests/ui suites drive a real server and the CLI through a headless
# Chromium (go-rod); they skip when no Chromium-based browser is found
# (OPENRUN_TEST_BROWSER names one). They are excluded from unit (GO_PACKAGES)
testui: ## Run the browser-driven integration tests (tests/ui: federated login flows, action pages)
> GOWORK=off go vet ./tests/ui/...
> GOWORK=off go test -count=1 ./tests/ui/...

# The server binary is built coverage-instrumented by the suite, or reused
# from covbuild (./openrun in the repo root, where run_cli_tests.sh builds it)
# when SKIP_BUILD is set, like covint. Server data goes to coverage/ui, CLI
# data to coverage/client
covui: ## Run the browser-driven integration tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/ui && mkdir -p $(OPENRUN_HOME)/coverage/ui $(OPENRUN_HOME)/coverage/client
> GOWORK=off GOCOVERDIR=$(OPENRUN_HOME)/coverage/ui $(if $(SKIP_BUILD),OPENRUN_TEST_BIN=$(OPENRUN_HOME)/openrun) go test -count=1 ./tests/ui/...

testconsole: ## Run the console app integration tests (ui/console_tests, own module)
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
> rm -rf $(OPENRUN_HOME)/coverage/int && mkdir -p $(OPENRUN_HOME)/coverage/int $(OPENRUN_HOME)/coverage/client
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
# The OpenRun server is released on the Tip channel (Apache-2.0, from main)
# with tags of the form vMAJOR.YYMM.PATCH:
#   MAJOR   the number in deploy/TIP_MAJOR, the latest shipped Pro major
#   YYMM    release year and month (UTC)
#   PATCH   DD * 10 + V, DD the day of the month (UTC) and V the zero-based
#           release sequence for that day (0-9)
# e.g. v1.2611.120 is the first release on November 12, 2026 and v1.2611.121
# the second. The version is computed from the UTC date and the existing
# tags. A version passed on the command line is only accepted if it is the
# computed one, so it works as a confirmation. A tag whose release job fails
# is not reused, the retry takes the next sequence number.
#
# The SDK modules, binding providers and Helm chart use conventional SemVer,
# given without the v prefix (e.g. 0.20.0), and are versioned independently
# of the server:
#   pkg/binding/v<version>, pkg/plugin/v<version>  SDK modules (this repo)
#   <provider>/v<version>                   binding providers (../bindings)
#   openrun-<version>                       Helm chart (../openrun-helm-charts)
#
#   make next-version                       print the next server version
#   make release [<version>] [<helm_version>]
#                                           tag + push the server, then create
#                                           the Helm chart release commit; the
#                                           chart version defaults to the
#                                           server version
#   make release-sdk <version>              tag + push both SDK modules only
#   make fullrelease <sdk_version> <bindings_version> [<version>]
#                                           SDKs + server + every binding
#                                           provider + Helm chart commit
#   make -C ../bindings release <sdk_version> <bindings_version> PUSH=1
#                                           binding providers only
#
# Every repo that gets tagged must be on a clean main synchronized with
# origin/main. The Helm chart commit is never pushed automatically: its
# appVersion is the server image tag, so push it after the OpenRun release
# job has published the images.
#
# Pro channel tags (pro/vMAJOR.MINOR.PATCH, from maintenance branches) are not
# handled here yet. The tip_* helpers below only look at v tags, so pro/ tags
# can be added without affecting them.
# ---------------------------------------------------------------------------

# Sub-make for the release recipes. GNU Make runs any recipe that mentions
# MAKE directly even under -n, and with .ONESHELL that is the whole recipe,
# so `make -n fullrelease` would tag and push. Going through this variable
# keeps -n a real dry run that only prints the recipe.
RELEASE_MAKE = $(MAKE)

# Bash helpers shared by the release targets; expanded as the first recipe
# line. Helpers whose output is captured by a command substitution return
# explicitly on errors, since bash does not apply errexit inside one.
define RELEASE_SH
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$$'
tip_re='^(0|[1-9][0-9]*)\.([0-9]{4})\.([1-9][0-9]{1,2})$$'
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
# tip_major: print the Tip major version from deploy/TIP_MAJOR
tip_major() {
  local major
  major="$$(tr -d '[:space:]' < deploy/TIP_MAJOR)" || return 1
  if ! [[ "$$major" =~ ^(0|[1-9][0-9]*)$$ ]]; then
    echo "Error: deploy/TIP_MAJOR must hold a single number, found '$$major'" >&2
    return 1
  fi
  echo "$$major"
}
# require_date <YYMMDD>: fail unless it is a real calendar date (years 2000-2099)
require_date() {
  local yy mm dd days
  if ! [[ "$$1" =~ ^[0-9]{6}$$ ]]; then
    echo "Error: date '$$1' is not in YYMMDD form" >&2
    return 1
  fi
  yy="$$((10#$${1:0:2}))"
  mm="$$((10#$${1:2:2}))"
  dd="$$((10#$${1:4:2}))"
  case "$$mm" in
    1|3|5|7|8|10|12) days=31 ;;
    4|6|9|11) days=30 ;;
    2) if (( yy % 4 == 0 )); then days=29; else days=28; fi ;;
    *) days=0 ;;
  esac
  if (( dd < 1 || dd > days )); then
    echo "Error: '$$1' (YYMMDD) is not a valid calendar date" >&2
    return 1
  fi
}
# latest_server_version: print the highest vX.Y.Z server tag without the v
# prefix, or nothing if there is none (run after fetching tags)
latest_server_version() {
  git tag -l 'v[0-9]*' | { grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' || true; } \
    | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}
# tip_version [<version>] [<YYMMDD>]: print the next Tip version,
# MAJOR.YYMM.PATCH for today's UTC date. A version passed in must be exactly
# that version. The date argument replaces today's date; only next-version
# passes it, the targets that tag and push always use the real date.
tip_version() {
  local v="$${1#v}" today="$${2:-}" major yymm dd latest expected
  local seq=0 lmaj=0 lyymm=0 lpatch=0
  major="$$(tip_major)" || return 1
  if [[ -z "$$today" ]]; then
    today="$$(date -u +%y%m%d)" || return 1
  fi
  require_date "$$today" || return 1
  yymm="$${today:0:4}"
  dd="$$((10#$${today:4:2}))"
  latest="$$(latest_server_version)" || return 1
  if [[ -n "$$latest" ]]; then
    IFS=. read -r lmaj lyymm lpatch <<< "$$latest"
    if (( 10#$$lmaj == 10#$$major && 10#$$lyymm == 10#$$yymm && 10#$$lpatch / 10 == dd )); then
      seq="$$((10#$$lpatch % 10 + 1))"
    fi
  fi
  if (( seq > 9 )); then
    echo "Error: v$$latest is already the tenth Tip release for today (UTC), the daily limit" >&2
    return 1
  fi
  expected="$$major.$$yymm.$$((dd * 10 + seq))"
  if [[ -n "$$latest" ]] && (( 10#$$major < 10#$$lmaj \
      || (10#$$major == 10#$$lmaj && 10#$$yymm < 10#$$lyymm) \
      || (10#$$major == 10#$$lmaj && 10#$$yymm == 10#$$lyymm && dd * 10 + seq <= 10#$$lpatch) )); then
    echo "Error: next Tip version v$$expected is not greater than the latest tag v$$latest;" \
      "check deploy/TIP_MAJOR and the system clock" >&2
    return 1
  fi
  if [[ -n "$$v" ]]; then
    if ! [[ "$$v" =~ $$tip_re ]]; then
      echo "Error: version '$$1' is not a Tip version (MAJOR.YYMM.PATCH), the next one is $$expected" >&2
      return 1
    fi
    if (( 10#$${BASH_REMATCH[1]} != 10#$$major )); then
      echo "Error: version '$$1' must use major $$major from deploy/TIP_MAJOR, the next one is $$expected" >&2
      return 1
    fi
    if [[ "$${BASH_REMATCH[2]}" != "$$yymm" ]] || (( 10#$${BASH_REMATCH[3]} / 10 != dd )); then
      echo "Error: version '$$1' is not dated today (UTC), the next one is $$expected" >&2
      return 1
    fi
    if [[ "$$v" != "$$expected" ]]; then
      echo "Error: version '$$1' has the wrong daily sequence number, the next one is $$expected" >&2
      return 1
    fi
  fi
  echo "$$expected"
}
# require_tip_ancestry: HEAD must contain the commit of the latest server tag
require_tip_ancestry() {
  local latest
  latest="$$(latest_server_version)"
  if [[ -n "$$latest" ]] && ! git merge-base --is-ancestor "v$$latest^{commit}" HEAD; then
    echo "Error: HEAD does not contain the latest release v$$latest" >&2
    return 1
  fi
}
# tip_tag <version>: create the annotated Tip tag for HEAD, the tag message
# records the release metadata
tip_tag() {
  local commit
  commit="$$(git rev-parse HEAD)"
  git tag -a "v$$1" -m "Release v$$1" \
    -m "Channel: tip" -m "Version: $$1" -m "Commit: $$commit" -m "License: Apache-2.0"
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

next-version: ## Print the Tip version the next server release would get, tags nothing; args: [<version> to validate], TIP_TODAY=YYMMDD to preview another date
> @$(RELEASE_SH)
> version=$$(tip_version "$(INPUT)" "$${TIP_TODAY:-}")
> echo "v$$version"

release-sdk: ## Tag and push the pkg/binding and pkg/plugin SDK modules; args: <version>
> @$(RELEASE_SH)
> version=$$(version_arg version "$(INPUT)")
> require_release_ready .
> for tag in "pkg/binding/v$$version" "pkg/plugin/v$$version"; do require_no_tag . "$$tag"; done
> git tag -a "pkg/binding/v$$version" -m "Release pkg/binding/v$$version"
> git tag -a "pkg/plugin/v$$version" -m "Release pkg/plugin/v$$version"
> git push --atomic origin "pkg/binding/v$$version" "pkg/plugin/v$$version"
> echo "Pushed pkg/binding/v$$version and pkg/plugin/v$$version; consumers can now require them"

release: ## Tag and push the OpenRun server (Tip channel), then create the Helm chart release commit; args: [<version>, default computed] [<helm_version>, default <version>]
> @$(RELEASE_SH)
> require_release_ready .
> require_release_ready ../openrun-helm-charts
> version=$$(tip_version "$(INPUT)")
> helm_version=$$(version_arg helm_version "$(if $(INPUT2),$(INPUT2),$$version)")
> require_tip_ancestry
> require_no_tag . "v$$version"
> require_no_tag ../openrun-helm-charts "openrun-$$helm_version"
> tip_tag "$$version"
> git push origin "v$$version"
> echo "Tagged and pushed Tip release v$$version"
> helm_chart_commit "$$helm_version" "$$version"

fullrelease: ## Release everything: SDKs, server (Tip channel), every binding provider, Helm chart commit; args: <sdk_version> <bindings_version> [<version>, default computed]
> @$(RELEASE_SH)
> sdk_version=$$(version_arg sdk_version "$(INPUT)")
> bindings_version=$$(version_arg bindings_version "$(INPUT2)")
> for repo in . ../bindings ../openrun-helm-charts; do require_release_ready "$$repo"; done
> version=$$(tip_version "$(INPUT3)")
> require_tip_ancestry
> for tag in "v$$version" "pkg/binding/v$$sdk_version" "pkg/plugin/v$$sdk_version"; do require_no_tag . "$$tag"; done
> for module in $$($(RELEASE_MAKE) --no-print-directory -s -C ../bindings modules); do require_no_tag ../bindings "$$module/v$$bindings_version"; done
> require_no_tag ../openrun-helm-charts "openrun-$$version"
> if grep -q "^version: $$version$$" ../openrun-helm-charts/charts/openrun/Chart.yaml; then
>   echo "Error: Chart.yaml is already at $$version but tag openrun-$$version does not exist; finish that chart release first"
>   exit 1
> fi
> # The server tag must require the SDK versions being released: downstream
> # consumers of the server module do not see the local replace directives.
> go mod edit -require=github.com/openrundev/openrun/pkg/binding@v$$sdk_version -require=github.com/openrundev/openrun/pkg/plugin@v$$sdk_version
> if ! git diff --quiet go.mod; then
>   git add go.mod
>   git commit -q -m "Pin SDK modules to v$$sdk_version for release"
> fi
> # Server and SDK tags go out in one push; the bindings release below runs
> # go mod tidy against the published pkg/binding tag.
> tip_tag "$$version"
> for tag in "pkg/binding/v$$sdk_version" "pkg/plugin/v$$sdk_version"; do git tag -a "$$tag" -m "Release $$tag"; done
> git push --atomic origin HEAD:main "v$$version" "pkg/binding/v$$sdk_version" "pkg/plugin/v$$sdk_version"
> $(RELEASE_MAKE) -C ../bindings release INPUT="$$sdk_version" INPUT2="$$bindings_version" PUSH=1
> echo "Tagged and pushed v$$version, pkg/binding/v$$sdk_version, pkg/plugin/v$$sdk_version and every bindings <provider>/v$$bindings_version"
> helm_chart_commit "$$version" "$$version"

# Swallow extra command-line words (e.g. `make int_single test_reload.yaml`)
# so make doesn't also try to build them as targets; $(INPUT)/$(INPUT2) above
# already pick them up positionally.
%:
> @:
