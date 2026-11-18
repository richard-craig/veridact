#!/usr/bin/env bash
# Build the authoriser's deployment package into build/ for the python3.13 x86_64 runtime.
# Third-party wheels are fetched for the Lambda platform (cryptography and aries-askar are
# native), and the Veridact packages come from this repository.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
rm -rf build && mkdir build
pip install --quiet --target build \
  --platform manylinux2014_x86_64 --implementation cp --python-version 3.13 --only-binary=:all: \
  cryptography==50.0.2 did-webvh==1.0.1 aiohttp==3.14.5
pip install --quiet --target build --no-deps "$ROOT/verify" "$ROOT/sidecar" . 2>&1 | grep -v "already exists" || true
rm -rf build/bin
# boto3 is in the Lambda runtime.
echo "build/ is ready: $(du -sh build | cut -f1)"
