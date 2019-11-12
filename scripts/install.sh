#!/bin/bash

set -eux

export GOPATH="$(pwd)/.tfsec_install"
export GO111MODULE=on
SRCDIR="${GOPATH}/src/github.com/liamg/tfsec"

[ -d ${GOPATH} ] && rm -rf ${GOPATH}
mkdir -p ${GOPATH}/{src,pkg,bin}
mkdir -p ${SRCDIR}
cp -r . ${SRCDIR}
(
    echo ${GOPATH}
    cd ${SRCDIR}
    go install ./cmd/tfsec
)
