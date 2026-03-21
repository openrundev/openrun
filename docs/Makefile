.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL := help
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >
TAG := 
.PHONY: help install-d2 update-diagrams

DIAGRAMS := $(wildcard ./static/d2/*.d2)

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install-d2: ## Install d2
> @curl -fsSL https://d2lang.com/install.sh | sh -s --

update-diagrams: ## Update diagrams
> @for d in $(DIAGRAMS); do \
> d2 --layout elk --theme 104 --dark-theme 201 "$$d"; \
> done