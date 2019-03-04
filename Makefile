test:
	go test ./...
build: test
	./scripts/build.sh