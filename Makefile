IMAGE := liamg/tfsec

image:
	docker build --build-arg tfsec_version=$(TRAVIS_TAG) -t $(IMAGE) .

push-image:
	docker tag $(IMAGE) $(IMAGE):$(TRAVIS_TAG)
	docker push $(IMAGE):$(TRAVIS_TAG)
	docker tag $(IMAGE) $(IMAGE):latest
	docker push $(IMAGE):latest

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

.PHONY: image push-image test build build-doc-gen build-skeleton generate-docs publish-docs new-check
