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
ARTICLE_HEADER_SIZE := 744x400

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install-d2: ## Install d2
> @curl -fsSL https://d2lang.com/install.sh | sh -s --

update-diagrams: ## Update diagrams. Source files are named <name>.<engine>.d2, engine is dagre, elk or tala
> @for d in $(DIAGRAMS); do \
> base="$${d%.d2}"; engine="$${base##*.}"; name="$${base%.*}"; \
> case "$$engine" in dagre|elk|tala) ;; *) echo "$$d: file name must be <name>.<dagre|elk|tala>.d2"; exit 1;; esac; \
> d2 --layout "$$engine" --theme 104 --dark-theme 201 "$$d" "$$name.svg"; \
> d2 --layout "$$engine" --theme 104 "$$d" "$${name}_light.svg"; \
> d2 --layout "$$engine" --theme 201 "$$d" "$${name}_dark.svg"; \
> d2 --layout "$$engine" --theme 104 "$$d" "$$name.png"; \
> magick "$$name.png" -resize '$(ARTICLE_HEADER_SIZE)' -background white -gravity center -extent '$(ARTICLE_HEADER_SIZE)' -alpha remove -alpha off -strip -define png:compression-level=9 "$${name}_small.png"; \
> done
