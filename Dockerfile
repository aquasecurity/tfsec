FROM golang:1.15-alpine AS build-env

ARG tfsec_version=0.0.0

COPY . /src
WORKDIR /src
ENV CGO_ENABLED=0
RUN go build \
  -a \
  -ldflags "-X github.com/tfsec/tfsec/version.Version=${tfsec_version} -s -w -extldflags '-static'" \
  -mod=vendor \
  ./cmd/tfsec

###
FROM scratch

# Copy tfsec from build container
COPY --from=build-env /src/tfsec /usr/bin/tfsec

# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "tfsec" ]

# as we specified an entrypoint, this is appended as an argument (i.e., `tfsec --help`)
CMD [ "--help" ]
