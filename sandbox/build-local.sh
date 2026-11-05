#!/bin/sh
# Build the sandbox image.
#   Normal (Vultr VM, laptop):   ./build-local.sh
#   Behind a TLS proxy that blocks apt mirrors (dev containers):
#     EXTRA_CA=/path/ca.crt HOST_STRACE=1 ./build-local.sh
#   HOST_STRACE=1 copies this machine's strace + libs into a base layer instead of apt.
set -e
cd "$(dirname "$0")"
ARGS=""
if [ -n "$HOST_STRACE" ]; then
  tmp=$(mktemp -d)
  mkdir -p "$tmp/lib"
  cp "$(command -v strace)" "$tmp/strace"
  ldd "$(command -v strace)" | awk '/=>/{print $3}' | grep -E 'unwind|lzma' | xargs -I{} cp {} "$tmp/lib/"
  cat > "$tmp/Dockerfile" <<'D'
FROM python:3.12-slim
COPY strace /usr/local/bin/strace
COPY lib/ /usr/local/lib/
RUN ldconfig && strace -V | head -1
D
  docker build -q -t tq-sandbox-base:dev "$tmp"
  rm -rf "$tmp"
  ARGS="--build-arg BASE=tq-sandbox-base:dev"
fi
if [ -n "$EXTRA_CA" ]; then
  ARGS="$ARGS --network host --build-arg HTTPS_PROXY --build-arg https_proxy --secret id=extra_ca,src=$EXTRA_CA"
fi
docker build $ARGS -t tq-sandbox:latest .
