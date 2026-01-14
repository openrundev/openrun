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

.PHONY: help test unit int covtest covunit covint release int_single lint verify build-linux image show_tags

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
> go test ./...

lint: ## Run lint
> golangci-lint run

covunit: ## Run unit tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/unit && mkdir -p $(OPENRUN_HOME)/coverage/unit
> go test -coverpkg ./... ./... -args -test.gocoverdir="$(OPENRUN_HOME)/coverage/unit"
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/unit
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/unit -o $(OPENRUN_HOME)/coverage/profile
> go tool cover -func coverage/profile

int: ## Run integration tests
> OPENRUN_HOME=$(OPENRUN_HOME) ./tests/run_cli_tests.sh

int_single: ## Run one integration test
> CL_SINGLE_TEST=${INPUT} OPENRUN_HOME=$(OPENRUN_HOME) ./tests/run_cli_tests.sh

covint: ## Run integration tests with coverage
> rm -rf $(OPENRUN_HOME)/coverage/int && mkdir -p $(OPENRUN_HOME)/coverage/int
> rm -rf $(OPENRUN_HOME)/coverage/client && mkdir -p $(OPENRUN_HOME)/coverage/client
> OPENRUN_HOME=. GOCOVERDIR=$(OPENRUN_HOME)/coverage/int ./tests/run_cli_tests.sh
> go tool covdata percent -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/int
> go tool covdata textfmt -i=$(OPENRUN_HOME)/coverage/client,$(OPENRUN_HOME)/coverage/int -o $(OPENRUN_HOME)/coverage/profile
> go tool cover -func coverage/profile

show_tags: ## Show current release version tags
> @echo "OpenRun   : " `git tag -l --sort=-creatordate | head -n 1`
> @cd ../openrun-helm-charts/
> @echo "Helm Chart: " `git tag -l --sort=-creatordate | head -n 1`
> @cd - > /dev/null

release: ## Tag and push a release, requires app_version and helm_version
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
> git push
> @cd - > /dev/null
