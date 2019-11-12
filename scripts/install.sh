#!/bin/bash

set -eux

env GO111MODULE=on go install ./cmd/tfsec
