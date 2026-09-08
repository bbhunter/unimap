#!/usr/bin/env bash
# Builds the Docker image from a local static binary, the way the release
# workflow does, and runs a few short real scans with it.
# Usage: scripts/container-test.sh [image-tag]
set -euo pipefail

IMAGE="${1:-unimap:test}"
# Provided by the Nmap project for scan testing.
TARGET="scanme.nmap.org"
PORTS="22,80"
TIMEOUT="${UNIMAP_TEST_TIMEOUT:-120}"
DOCKER="${DOCKER:-docker}"
MUSL_TARGET="x86_64-unknown-linux-musl"

cd "$(dirname "$0")/.."

echo "==> Building the static binary for $MUSL_TARGET"
cargo build --release --locked --target "$MUSL_TARGET"
install -D -m 755 "target/$MUSL_TARGET/release/unimap" docker/bin/amd64/unimap

echo "==> Building image $IMAGE"
"$DOCKER" build -q --platform linux/amd64 -f docker/Dockerfile -t "$IMAGE" docker/ >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
printf '%s\nwww.%s\nhttp://%s/\nthis is not a host\n' "$TARGET" "$TARGET" "$TARGET" > "$WORK/targets.txt"
chmod 777 "$WORK"

fail() { echo "FAIL: $*" >&2; exit 1; }

run_unimap() {
  timeout "$TIMEOUT" "$DOCKER" run --rm -i -v "$WORK:/opt/unimap" "$IMAGE" "$@"
}

echo "==> 1/4 table output, single target, fast scan"
OUT="$(run_unimap -t "$TARGET" --fast-scan --ports "$PORTS" -k)"
echo "$OUT"
grep -q "$TARGET" <<<"$OUT" || fail "target missing from table output"
grep -Eq "22(;80)?" <<<"$OUT" || fail "expected open port 22 in table output"
grep -q "Job finished" <<<"$OUT" || fail "run did not finish cleanly"

echo "==> 2/4 raw output from a targets file (duplicates + invalid lines) with CSV log"
OUT="$(run_unimap -f targets.txt --fast-scan --ports "$PORTS" -r -u result.csv)"
echo "$OUT"
grep -q "^HOST,IP,PORT,SERVICE" <<<"$OUT" || fail "raw header missing"
grep -Eq "^$TARGET,[0-9.]+,22,ssh" <<<"$OUT" || fail "raw line for port 22 missing"
grep -q "Skipped 1 invalid targets" <<<"$OUT" || fail "invalid target line was not skipped"
[ -f "$WORK/result.csv" ] || fail "CSV output not written"
grep -q "^HOST,IP,OPEN PORTS,SERVICES" "$WORK/result.csv" || fail "CSV header missing"
grep -q "^$TARGET," "$WORK/result.csv" || fail "CSV row missing"
# One XML per unique IP: each IP is scanned only once.
XMLS=$(ls "$WORK"/unimap_logs/*.xml 2>/dev/null | wc -l)
[ "$XMLS" -eq 1 ] || fail "expected exactly one Nmap XML for one unique IP, found $XMLS"

echo "==> 2b/4 appending a second run to the same CSV keeps a single header"
run_unimap -t "$TARGET" --fast-scan --ports "$PORTS" -q -u result.csv
HEADERS=$(grep -c "^HOST,IP,OPEN PORTS,SERVICES" "$WORK/result.csv")
ROWS=$(grep -c "^$TARGET," "$WORK/result.csv")
[ "$HEADERS" -eq 1 ] || fail "expected one CSV header after two runs, found $HEADERS"
[ "$ROWS" -eq 2 ] || fail "expected two CSV rows after two runs, found $ROWS"

echo "==> 3/4 url output, quiet mode, reading targets from stdin"
OUT="$(printf '%s\n' "$TARGET" | run_unimap --stdin --fast-scan --ports "$PORTS" --url-output -q -k 2>&1 || true)"
echo "$OUT"
grep -q "^$TARGET:22$" <<<"$OUT" || fail "url output line missing"
grep -q "INFO" <<<"$OUT" && fail "quiet mode printed informative messages"

echo "==> 4/4 service detection on a single port"
OUT="$(run_unimap -t "$TARGET" --ports 22 -r -q -k)"
echo "$OUT"
grep -Eq "^$TARGET,[0-9.]+,22,ssh,[^,]+,OpenSSH" <<<"$OUT" || fail "service detection did not report OpenSSH"

echo "All container tests passed."
