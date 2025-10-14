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

.DEFAULT_GOAL := help
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >
TAG := 

.PHONY: help test unit int covtest covunit covint release int_single lint verify

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: unit int ## Run all tests
verify: lint test ## Run lint and all tests

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

release: ## Tag and push a release
> @if [[ -z "$(INPUT)" || "$(INPUT)" == v* ]]; then \
>    echo "Error: TAG has to be set, without the v prefix"; \
>    exit 1; \
> fi
> echo git tag -a v$(INPUT) -m "Release v$(INPUT)"; git push origin v$(INPUT)
