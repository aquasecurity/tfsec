#!/bin/bash

set -eux

env GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-X github.com/aquasecurity/tfsec/version.Version=${1}" ./cmd/tfsec
