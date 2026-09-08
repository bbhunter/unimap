# The release workflow stages the binaries under bin/<arch>/ straight from the
# build that produced the release assets, so the image carries exactly the
# version being released and nothing is downloaded at build time.
#
# To build by hand, put a static musl binary at docker/bin/amd64/unimap
# (and docker/bin/arm64/unimap for a multi-arch image) and run:
#
#   docker build -f docker/Dockerfile docker/
#
# docker run --rm edu4rdshl/unimap -t example.com --fast-scan
FROM alpine:3.22
ARG TARGETARCH
LABEL maintainers="edu4rdshl@protonmail.com"
# The SYN scan needs nmap and root, which is what the image runs as.
RUN apk add --no-cache nmap nmap-scripts
WORKDIR /opt/unimap
COPY --chmod=755 bin/${TARGETARCH}/unimap /usr/local/bin/unimap
ENTRYPOINT ["unimap"]
