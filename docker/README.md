# Unimap Docker image

The published image is `edu4rdshl/unimap`, built for `linux/amd64` and
`linux/arm64`. Every release pushes it under two tags, `latest` and the
release version, so a deployment can pin one:

```
docker pull edu4rdshl/unimap:latest
docker run --rm edu4rdshl/unimap:latest -t example.com --fast-scan
```

The container runs as root, which the Nmap SYN scan needs. The working
directory inside is `/opt/unimap`. Bind mount a host directory there to keep
the CSV written with `-o` or `-u` and the Nmap XML files after the container
is gone:

```
docker run --rm -v "$(pwd):/opt/unimap" edu4rdshl/unimap:latest \
  -f targets.txt --fast-scan -u results.csv
```

The image carries the same static binaries that the release ships as
`unimap-linux.zip` and `unimap-aarch64-musl.zip`, dropped on top of Alpine
with Nmap installed. Nothing else is downloaded while the image builds, so it
always matches the release it was built with.

## Building it yourself

The Dockerfile expects one static musl binary per architecture under
`bin/<arch>/`, using Docker's architecture names. Stage the ones you need and
build from this directory:

```
mkdir -p bin/amd64 bin/arm64
cp /path/to/x86_64-unknown-linux-musl/release/unimap  bin/amd64/unimap
cp /path/to/aarch64-unknown-linux-musl/release/unimap bin/arm64/unimap
docker build -f Dockerfile -t unimap .
```

For a single architecture, stage only that one and build with `--platform`,
for instance `--platform linux/amd64`. For a multi-arch image use buildx with
`--platform linux/amd64,linux/arm64`; the `apk add` step for the foreign
architecture runs under QEMU.

The binaries must be the musl builds: the glibc ones in `unimap-aarch64.zip`
and `unimap-armv7.zip` do not run on Alpine.

## Rebuilding a published release

The `Build Docker images` workflow, run by hand from the Actions tab, takes a
release tag, fetches its binaries and pushes the image again. It is there for
the day the base image needs refreshing without cutting a new release.
