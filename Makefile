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
	gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: build
build:
	./scripts/build.sh

.PHONY: generate-docs
generate-docs:
	@go run ./cmd/tfsec-docs

.PHONY: generate-codes-json
generate-codes-json:
	@go run ./cmd/tfsec-codes

.PHONY: publish-docs
publish-docs:
	./scripts/publish-docs.sh

.PHONY: new-check
new-check:
	@go run ./cmd/tfsec-skeleton

.PHONY: lint-pr-checks
lint-pr-checks:
	@go run ./cmd/tfsec-pr-lint

.PHONY: tagger
tagger:
	@git checkout master
	@git fetch --tags
	@echo "the most recent tag was `git describe --tags --abbrev=0`"
	@echo ""
	read -p "Tag number: " TAG; \
	 git tag -a "$${TAG}" -m "$${TAG}"; \
	 git push origin "$${TAG}"

.PHONY: cyclo
cyclo:
	which gocyclo || go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	gocyclo -over 15 -ignore 'vendor/|funcs|cmd/tfsec-skeleton' .

.PHONY: vet
vet:
	go vet ./...

.PHONY: typos
typos:
	which codespell || pip install codespell
	codespell -S vendor,funcs,.terraform,.git --ignore-words .codespellignore -f

.PHONY: quality
quality: cyclo vet

.PHONY: fix-typos
fix-typos:
	which codespell || pip install codespell
	codespell -S vendor,funcs,.terraform --ignore-words .codespellignore -f -w -i1

.PHONY: clone-image-github
clone-image-github:
	./scripts/clone-images.sh ghcr.io/aquasecurity

.PHONY: clone-image-tfsec
clone-image-tfsec:
	./scripts/clone-images.sh tfsec

.PHONY: sanity
sanity: test
	go run ./cmd/tfsec -s -p --force-all-dirs ./example > /dev/null

.PHONY: pr-lint
pr-lint: 
	go run ./cmd/tfsec-pr-lint

.PHONY: pr-ready
pr-ready: quality sanity pr-lint typos

.PHONY: bench
bench:
	go test -run ^$$ -bench . ./...

# Runs MkDocs dev server to preview the docs page before it is published.
.PHONY: mkdocs-serve
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/Dockerfile docs
	docker  run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)