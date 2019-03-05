#!/bin/bash
BINARY=tfsec
TAG=${TRAVIS_TAG:-development}
mkdir -p bin/darwin
GOOS=darwin GOARCH=amd64 go build -o bin/darwin/${BINARY}-darwin-amd64 -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build -o bin/linux/${BINARY}-linux-amd64 -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows/${BINARY}-windows-amd64.exe -ldflags "-X github.com/liamg/tfsec/version.Version=${TRAVIS_TAG}"
