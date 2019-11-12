#!/bin/bash

set -eux

env GO111MODULE=on go build ./cmd/tfsec
