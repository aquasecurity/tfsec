#!/bin/bash
BINARY=tfsec
TAG=${TRAVIS_TAG:-development}
mkdir -p bin/darwin-amd64
GOOS=darwin GOARCH=amd64 go build -o bin/darwin-amd64/${BINARY} -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/linux-amd64
GOOS=linux GOARCH=amd64 go build -o bin/linux-amd64/${BINARY} -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/windows-amd64
GOOS=windows GOARCH=amd64 go build -o bin/windows-amd64/${BINARY}.exe -ldflags "-X github.com/liamg/tfsec/version.Version=${TRAVIS_TAG}"
