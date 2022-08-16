IMAGE := tfsec/tfsec
SHELL := /bin/bash

MKDOCS_IMAGE := aquasec/mkdocs-material:tracee
MKDOCS_PORT := 8000

.PHONY: image
image:
	docker build --build-arg tfsec_version=$(TRAVIS_TAG) -t $(IMAGE) .

.PHONY: test
test:
	which gotestsum || (pushd /tmp && go install gotest.tools/gotestsum@latest && popd)
	gotestsum -- -bench=^$$ -race ./...

.PHONY: build
build:
	./scripts/build.sh
	

.PHONY: generate-docs
generate-docs:
	@go run ./cmd/tfsec-docs

.PHONY: publish-docs
publish-docs: generate-docs
	@python3 ./scripts/build_checks_nav.py

.PHONY: tagger
tagger:
	@git checkout master
	@git fetch --tags
	@echo "the most recent tag was `git describe --tags --abbrev=0`"
	@echo ""
	read -p "Tag number: " TAG; \
	 git tag -a "$${TAG}" -m "$${TAG}"; \
	 git push origin "$${TAG}"

.PHONY: typos
typos:
	which codespell || pip install codespell
	codespell -S _examples,.tfsec,.terraform,.git,go.sum --ignore-words .codespellignore -f

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.46.2
	golangci-lint run

.PHONY: fix-typos
fix-typos:
	which codespell || pip install codespell
	codespell -S .terraform,go.sum --ignore-words .codespellignore -f -w -i1

.PHONY: clone-image-github
clone-image-github:
	./scripts/clone-images.sh ghcr.io/aquasecurity

.PHONY: pr-ready
pr-ready: quality typos

.PHONY: bench
bench:
	go test -run ^$$ -bench . ./...

# Runs MkDocs dev server to preview the docs page before it is published.
.PHONY: mkdocs-serve
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/Dockerfile docs
	docker  run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

.PHONY: update-defsec
update-defsec:
	go get github.com/aquasecurity/defsec@latest
	go mod tidy
