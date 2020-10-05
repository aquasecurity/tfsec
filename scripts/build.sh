#!/bin/bash
BINARY=tfsec
TAG=${TRAVIS_TAG:-development}
GO111MODULE=on
export CGO_ENABLED=0
export GOFLAGS=-mod=vendor
mkdir -p bin/darwin
GOOS=darwin GOARCH=amd64 go build -o bin/darwin/${BINARY}-darwin-amd64 -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec/
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build -o bin/linux/${BINARY}-linux-amd64 -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec/
mkdir -p bin/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows/${BINARY}-windows-amd64.exe -ldflags "-X github.com/tfsec/tfsec/version.Version=${TRAVIS_TAG}" ./cmd/tfsec/
