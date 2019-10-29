#!/bin/bash
BINARY=tfsec
TAG=${TRAVIS_TAG:-development}
GO111MODULE=on
mkdir -p bin/darwin
GOOS=darwin GOARCH=amd64 go build ./cmd/tfsec/ -o bin/darwin/${BINARY}-darwin-amd64 -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build ./cmd/tfsec/ -o bin/linux/${BINARY}-linux-amd64 -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}"
mkdir -p bin/windows
GOOS=windows GOARCH=amd64 go build ./cmd/tfsec/ -o bin/windows/${BINARY}-windows-amd64.exe -ldflags "-X github.com/liamg/tfsec/version.Version=${TRAVIS_TAG}"
