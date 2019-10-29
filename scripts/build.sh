#!/bin/bash
BINARY=tfsec
TAG=${TRAVIS_TAG:-development}
GO111MODULE=on
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build -o bin/linux/${BINARY}-linux-amd64 -ldflags "-X github.com/liamg/tfsec/version.Version=${TAG}" ./cmd/tfsec/
