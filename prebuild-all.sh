#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building prebuilds for {musl, glibc} x {amd64, arm64}..."
echo ""

rm -rf prebuilds out-*

# build <dockerfile> <platform> <out-dir>
build() {
    local dockerfile="$1" platform="$2" out="$3"
    echo "--- Building $platform ($dockerfile) ---"
    docker buildx build \
        --platform "$platform" \
        --output "type=local,dest=./$out" \
        -f "./$dockerfile" \
        .
}

# musl (Alpine) -> libnftnl.so.11
build Dockerfile        linux/amd64 out-musl-amd64
build Dockerfile        linux/arm64 out-musl-arm64

# glibc (Debian trixie) -> libnftnl.so.11
build Dockerfile.debian linux/amd64 out-glibc-amd64
build Dockerfile.debian linux/arm64 out-glibc-arm64

mkdir -p prebuilds
# Each build tags its file by libc family, so the trees merge without clobbering.
cp -r out-musl-amd64/prebuilds/*  prebuilds/
cp -r out-musl-arm64/prebuilds/*  prebuilds/
cp -r out-glibc-amd64/prebuilds/* prebuilds/
cp -r out-glibc-arm64/prebuilds/* prebuilds/

rm -rf out-musl-amd64 out-musl-arm64 out-glibc-amd64 out-glibc-arm64

echo ""
echo "==> Done! Prebuilds:"
find prebuilds -type f
echo ""
echo "Structure should look like:"
echo "  prebuilds/linux-x64/nftables-napi.musl.node    (musl,  libnftnl.so.11)"
echo "  prebuilds/linux-x64/nftables-napi.glibc.node   (glibc, libnftnl.so.11)"
echo "  prebuilds/linux-arm64/nftables-napi.musl.node  (musl,  libnftnl.so.11)"
echo "  prebuilds/linux-arm64/nftables-napi.glibc.node (glibc, libnftnl.so.11)"
