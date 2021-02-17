FROM golang:1.16-alpine AS build-env

ARG tfsec_version=0.0.0

COPY ../.. /src
WORKDIR /src
ENV CGO_ENABLED=0
RUN go build \
  -a \
  -ldflags "-X github.com/tfsec/tfsec/version.Version=${tfsec_version} -s -w -extldflags '-static'" \
  -mod=vendor \
  ./cmd/tfsec
