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
generate-docs: build-doc-gen
	@./tfsec-docs

.PHONY: image push-image test build build-doc-gen generate-docs
