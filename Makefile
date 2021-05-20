IMAGE := tfsec/tfsec

.PHONY: image
image:
	docker build --build-arg tfsec_version=$(TRAVIS_TAG) -t $(IMAGE) .

.PHONY: test
test:
	go test -mod=vendor -v ./...

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
