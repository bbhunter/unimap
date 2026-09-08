FROM rust:1-alpine AS builder
RUN apk add --no-cache build-base

WORKDIR /usr/src/unimap
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/
RUN cargo build --release --locked

FROM alpine:3.22

RUN apk add --no-cache nmap nmap-scripts
COPY --from=builder /usr/src/unimap/target/release/unimap /usr/local/bin/unimap

ENTRYPOINT [ "/usr/local/bin/unimap" ]
