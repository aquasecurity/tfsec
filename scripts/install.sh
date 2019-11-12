#!/bin/bash

set -eux

env GO111MODULE=on go build -ldflags "-X github.com/liamg/tfsec/version.Version=${1}" ./cmd/tfsec
