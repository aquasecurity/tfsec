FROM golang:1.14-alpine  AS build-env

ARG tfsec_version=0.0.0

COPY . /src
WORKDIR /src
RUN go build -ldflags "-X github.com/tfsec/tfsec/version.Version=${tfsec_version}" -mod=vendor ./cmd/tfsec

FROM alpine

# use a non-privileged user
USER nobody

# work somewhere where we can write
COPY --from=build-env /src/tfsec /usr/bin/tfsec

# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "tfsec" ]

# as we specified an entrytrypoint, this is appended as an argument (i.e., `tfsec --help`)
CMD [ "--help" ]
