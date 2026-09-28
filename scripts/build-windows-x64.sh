#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST=x86_64-w64-mingw32
JOBS="${JOBS:-$(nproc)}"

cd "$ROOT_DIR"
make -C depends HOST="$HOST" -j"$JOBS"

cmake -S . -B build-windows-x64 \
  --toolchain "depends/$HOST/toolchain.cmake" \
  -DCMAKE_PREFIX_PATH="$ROOT_DIR/depends/$HOST" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDEFAULT_CHAIN_TYPE=tensor \
  -DBUILD_GUI=ON \
  -DENABLE_WALLET=ON \
  -DBUILD_WALLET_TOOL=ON \
  -DBUILD_GUI_TESTS=OFF \
  -DREDUCE_EXPORTS=ON

cmake --build build-windows-x64 --target deploy -j"$JOBS"

DIST="$ROOT_DIR/dist/windows-x64"
rm -rf "$DIST"
mkdir -p "$DIST/cli"
cp build-windows-x64/bitcoin-win64-setup.exe "$DIST/tensorcash-win64-setup.exe"
for binary in bitcoind bitcoin-cli bitcoin-wallet; do
  found="$(find build-windows-x64 -type f -name "${binary}.exe" -print -quit)"
  test -n "$found"
  cp "$found" "$DIST/cli/"
done
cp examples/bitcoin.conf WINDOWS_BUILD_CN.md "$DIST/cli/"
(cd "$DIST/cli" && zip -9 ../tensorcash-cli-windows-x64.zip ./*)
sha256sum "$DIST"/*.exe "$DIST"/*.zip > "$DIST/SHA256SUMS"
