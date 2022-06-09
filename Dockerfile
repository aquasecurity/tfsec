FROM alpine:3.16.0

# install git
RUN apk add --no-cache git

# work somewhere where we can write
COPY tfsec /usr/bin/tfsec
RUN chmod a+x /usr/bin/tfsec

# use a non-privileged user
RUN adduser -D tfsec
USER tfsec

# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "tfsec" ]
# as we specified an entrypoint, this is appended as an argument (i.e., `tfsec --help`)
CMD [ "--help" ]
