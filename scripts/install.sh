#!/bin/bash

set -eux

env GO111MODULE=on go build ./cmd/tfsec -ldflags "-X github.com/liamg/tfsec/version.Version=${1}"
