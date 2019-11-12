# pinned version of the Alpine-tagged 'go' image
FROM golang:1.13-alpine

# grab tfsec from GitHub (taken from README.md)
RUN env GO111MODULE=on go get -u github.com/liamg/tfsec/cmd/tfsec && mkdir /workdir && chown -R nobody /workdir

# use a non-privileged user
USER nobody

# work somewhere where we can write
WORKDIR /workdir

# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "tfsec" ]

# as we specified an entrytrypoint, this is appended as an argument (i.e., `tfsec --help`)
CMD [ "--help" ]
