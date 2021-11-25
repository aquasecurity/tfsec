pwd = $(shell pwd)

SHELL=/bin/bash

# define standard colors
BLACK     := $(shell tput -Txterm setaf 0)
RED       := $(shell tput -Txterm setaf 1)
GREEN     := $(shell tput -Txterm setaf 2)
YELLOW    := $(shell tput -Txterm setaf 3)
BLUE      := $(shell tput -Txterm setaf 4)
PURPLE    := $(shell tput -Txterm setaf 5)
LIGHTBLUE := $(shell tput -Txterm setaf 6)
WHITE     := $(shell tput -Txterm setaf 7)

RESET := $(shell tput -Txterm sgr0)

.DEFAULT_GOAL := help
.PHONY: build

PROJECTNAME=$(shell basename "$(PWD)")
BRANCHENAME=$(shell git rev-parse --abbrev-ref HEAD)

%::
	make
	@echo "$(RED) > type one of the targets above$(RESET)"
	@echo

colors: ## show all the colors
	@echo "${BLACK}BLACK${RESET}"
	@echo "${RED}RED${RESET}"
	@echo "${GREEN}GREEN${RESET}"
	@echo "${YELLOW}YELLOW${RESET}"
	@echo "${BLUE}DARKBLUE${RESET}"
	@echo "${PURPLE}PURPLE${RESET}"
	@echo "${LIGHTBLUE}LIGHTBLUE${RESET}"
	@echo "${WHITE}WHITE${RESET}"

## up: starts docker
docker-up:
	@echo -en "\033c"
	@echo "$(LIGHTBLUE) > Starting docker $(BLUE)$(PROJECTNAME) $(YELLOW)$(BRANCHENAME)$(RESET)"
	@docker run -it --rm -v "$PWD":/usr/src/app -p "4000:4000" starefossen/github-pages
	@echo "$(GREEN) > ready: $(BLUE)$(PROJECTNAME)$(RESET) $(YELLOW)$(BRANCHENAME)$(RESET)"

makefile: help
help: Makefile
	@echo -en "\033c"
	@echo "$(RED) > Choose a make command from the following:$(RESET)"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo
	@echo "$(GREEN) > ready: $(BLUE)$(PROJECTNAME)$(RESET) $(YELLOW)$(BRANCHENAME)$(RESET)"

.PHONY: typos
typos:
	./scripts/typos.sh

.PHONY: fix-typos
fix-typos:
	./scripts/typos.sh fix

.PHONY: serve
serve:
	bundle exec jekyll serve