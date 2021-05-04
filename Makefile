IMAGE := tfsec/tfsec

image:
	docker build --build-arg tfsec_version=$(TRAVIS_TAG) -t $(IMAGE) .

push-image:
	./scripts/publish-image.sh

test:
	go test -v ./...

build:
	./scripts/build.sh

build-doc-gen:
	@go build ./cmd/tfsec-docs

build-skeleton:
	@go build ./cmd/tfsec-skeleton

generate-docs: build-doc-gen
	@./tfsec-docs

generate-wiki: build-doc-gen
	@./tfsec-docs --generate-wiki
	@scripts/update-wiki.sh

publish-docs:
	./scripts/publish-docs.sh

new-check: build-skeleton
	@./tfsec-skeleton

lint-pr-checks:
	@go run ./cmd/tfsec-pr-lint

.PHONY: image push-image test build build-doc-gen build-skeleton generate-docs publish-docs new-check lint-pr-checks

