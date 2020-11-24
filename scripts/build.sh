#!/bin/bash
BINARY=tfsec
CHECK_GEN_BINARY=tfsec-checkgen
TAG=${TRAVIS_TAG:-development}
GO111MODULE=on
export CGO_ENABLED=0
export GOFLAGS=-mod=vendor
args=(-ldflags '-s -w -extldflags "-fno-PIC -static"')

mkdir -p bin/darwin
GOOS=darwin GOARCH=amd64 go build -o bin/darwin/${BINARY}-darwin-amd64 "${args[@]}" -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec/
GOOS=darwin GOARCH=amd64 go build -o bin/darwin/${CHECK_GEN_BINARY}-darwin-amd64 -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec-checkgen/
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build -o bin/linux/${BINARY}-linux-amd64 "${args[@]}" -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec/
GOOS=linux GOARCH=amd64 go build -o bin/linux/${CHECK_GEN_BINARY}-linux-amd64 "${args[@]}" -ldflags "-X github.com/tfsec/tfsec/version.Version=${TAG}" ./cmd/tfsec-checkgen/
mkdir -p bin/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows/${BINARY}-windows-amd64.exe "${args[@]}" -ldflags "-X github.com/tfsec/tfsec/version.Version=${TRAVIS_TAG}" ./cmd/tfsec/
GOOS=windows GOARCH=amd64 go build -o bin/windows/${CHECK_GEN_BINARY}-windows-amd64.exe "${args[@]}" -ldflags "-X github.com/tfsec/tfsec/version.Version=${TRAVIS_TAG}" ./cmd/tfsec-checkgen/
