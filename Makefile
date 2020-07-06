IMAGE := liamg/tfsec

image:
	docker build --build-arg tfsec_version=$(TRAVIS_TAG) -t $(IMAGE) .
push-image:
	docker push $(IMAGE):$(TRAVIS_TAG)
	docker push $(IMAGE):latest
test:
	go test -v ./...
build:
	./scripts/build.sh

.PHONY: image push-image test build
