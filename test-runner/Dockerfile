# Stage 1: Build Rust cosign-bridge
# Rust 1.85+ is required because transitive crates (e.g. getrandom 0.4.x)
# use edition2024 in their manifests.
FROM rust:1.87-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY services/core-node/cosign-bridge /workspace/cosign-bridge
RUN cd /workspace/cosign-bridge && cargo build --release

# Stage 2: Build ChiaVDF with assembly optimizations
FROM ubuntu:22.04 AS chiavdf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nasm yasm build-essential cmake git patch pkg-config \
      libtool autoconf automake wget m4 libboost-all-dev libflint-dev \
      libsecp256k1-dev \
      python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Build GMP from source with assembly optimizations
ENV GMP_VERSION=6.3.0
RUN (wget --timeout=30 --tries=2 https://ftp.gnu.org/gnu/gmp/gmp-${GMP_VERSION}.tar.xz || \
     wget --timeout=30 --tries=2 https://mirrors.kernel.org/gnu/gmp/gmp-${GMP_VERSION}.tar.xz || \
     wget --timeout=30 --tries=2 https://mirror.dogado.de/gnu/gmp/gmp-${GMP_VERSION}.tar.xz || \
     wget --timeout=30 --tries=2 https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz) && \
    tar xf gmp-${GMP_VERSION}.tar.xz && \
    cd gmp-${GMP_VERSION} && \
    ./configure --enable-assembly --enable-shared --enable-static --with-pic && \
    make -j$(nproc) && make install && ldconfig && \
    cd .. && rm -rf gmp-${GMP_VERSION}*

# Build ChiaVDF Python wheel
WORKDIR /opt/chiavdf
COPY shared-utils/chiavdf /opt/chiavdf

RUN rm -rf .git && git init && \
    git config user.email "build@docker.com" && \
    git config user.name "Docker Build" && \
    git add . && git commit -m "Initial commit" && \
    git tag -a v1.0.0 -m "Version 1.0.0" && \
    pip3 install --upgrade pip wheel setuptools setuptools_scm pybind11

ENV GMP_USE_ASM=1 \
    FLINT_ENABLE_ASM=1 \
    CHIAVDF_NO_ASM=""

ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    CMAKE_PREFIX_PATH=/usr/local \
    CMAKE_INCLUDE_PATH=/usr/local/include \
    CMAKE_LIBRARY_PATH=/usr/local/lib

ENV BUILD_VDF_CLIENT=N

RUN VERBOSE=1 pip3 wheel . -w /chiavdf-wheels

# Stage 3: Main test runner image
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build

# Install core build tools, libs, Tor, Python, and Qt6 for GUI compilation
# Also install clang/llvm for fuzz support if BUILD_FUZZ arg is set
ARG BUILD_FUZZ=0
RUN apt-get update && \
    apt-get install -y \
      build-essential \
      cmake \
      git \
      pkg-config \
      curl \
      ca-certificates \
      tor \
      libevent-dev \
      libssl-dev \
      libzmq3-dev \
      libsqlite3-dev \
      libgmp-dev \
      libargon2-dev \
      libboost-all-dev \
      libflint-dev \
      autoconf \
      automake \
      libtool \
      libzstd-dev \
      python3 \
      python3-pip \
      supervisor \
      bsdmainutils \
      qt6-base-dev \
      qt6-tools-dev \
      qt6-tools-dev-tools \
      qt6-l10n-tools \
      libqt6core6 \
      libqt6gui6 \
      libqt6widgets6 \
      libqt6network6 \
      libqt6dbus6 \
      libqt6opengl6-dev \
      libgl1-mesa-dev \
      libglu1-mesa-dev \
      libqrencode-dev \
      libdb-dev \
      libdb++-dev && \
    if [ "$BUILD_FUZZ" = "1" ]; then \
      apt-get install -y software-properties-common wget && \
      wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
      add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-16 main" && \
      apt-get update && \
      apt-get install -y clang-16 llvm-16 libfuzzer-16-dev; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# 2) Build & install FlatBuffers v25.2.10 from source (EXACT COPY from tor.Dockerfile)
RUN git clone --depth 1 \
      --branch v25.2.10 \
      https://github.com/google/flatbuffers.git /build/flatbuffers && \
    mkdir -p /build/flatbuffers/build && \
    cd /build/flatbuffers/build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /build/flatbuffers

# 2.5) Build & install blst library with optimizations
RUN git clone --depth 1 \
      --branch v0.3.11 \
      https://github.com/supranational/blst.git /build/blst && \
    cd /build/blst && \
    ./build.sh -O3 && \
    cp libblst.a /usr/local/lib/ && \
    mkdir -p /usr/local/bindings && \
    cp bindings/*.h /usr/local/bindings/ && \
    ldconfig && \
    rm -rf /build/blst

# 2.6) Install Go for building kyc-prover CGO library
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL https://go.dev/dl/go1.21.0.linux-${ARCH}.tar.gz -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"

# 3) Copy Bitcoin Core source (EXACT COPY from tor.Dockerfile)
COPY services/core-node/bcore /build/bcore
# Bring chiavdf into a stable include location for CMake auto-detect
COPY shared-utils/chiavdf /build/bcore/src/external/chiavdf

# Build secp256k1-zkp with adaptor signatures
COPY shared-utils/secp256k1-zkp /build/bcore/src/external/secp256k1-zkp
RUN cd /build/bcore/src/external/secp256k1-zkp && \
    ./autogen.sh && \
    ./configure --disable-shared \
                --enable-experimental \
                --enable-module-ecdh \
                --enable-module-extrakeys \
                --enable-module-schnorrsig \
                --enable-module-musig \
                --enable-module-ellswift \
                --enable-module-ecdsa-adaptor \
                --enable-module-recovery && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig

# Copy KYC prover source and build libzkprover.so
# NOTE: vectors_hd_v1/ contains LFS-tracked PK/VK binaries + golden vectors JSON.
# The CI checkout (lfs: true) fetches real content, so COPY gets actual binaries.
# These are consumed by:
#   - C++ groth16_hdv1_golden_tests (cross-language proof verification)
#   - Functional test generatezkproof RPC (real proof generation)
RUN mkdir -p /build/shared-utils/kyc-prover
COPY shared-utils/kyc-prover /build/shared-utils/kyc-prover
WORKDIR /build/shared-utils/kyc-prover/cgo
RUN go build -buildmode=c-shared -o libzkprover.so . && \
    cp libzkprover.so /usr/local/lib/ && \
    ldconfig

# Verify HDv1 artifacts are present (fail early if LFS checkout was incomplete)
RUN test -f /build/shared-utils/kyc-prover/vectors_hd_v1/proving_key_v1.bin || \
    { echo "ERROR: vectors_hd_v1/proving_key_v1.bin missing — git-lfs checkout incomplete"; exit 1; } && \
    test -f /build/shared-utils/kyc-prover/vectors_hd_v1/golden_vectors_hd_v1.json || \
    { echo "ERROR: vectors_hd_v1/golden_vectors_hd_v1.json missing"; exit 1; } && \
    echo "HDv1 artifacts verified:" && ls -lh /build/shared-utils/kyc-prover/vectors_hd_v1/

# Build liboqs for ML-DSA (FIPS 204) post-quantum verification
# Minimal build: only ML-DSA-44/65/87 for Taproot v2
COPY shared-utils/liboqs /build/bcore/src/external/liboqs
RUN cd /build/bcore/src/external/liboqs && \
    rm -rf build && mkdir -p build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=OFF \
          -DOQS_USE_OPENSSL=OFF \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" \
          -DOQS_ENABLE_TEST_CONSTANT_TIME=ON \
          .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

WORKDIR /build/bcore

# GENERATE FBS SCHEMA FILES (EXACT COPY from tor.Dockerfile)
COPY shared-utils/fb-schemas/proof.fbs /build/bcore/
COPY shared-utils/fb-schemas/blockheader.fbs /build/bcore/
COPY shared-utils/fb-schemas/validation.fbs /build/bcore/
RUN flatc --cpp -o src/rpc proof.fbs blockheader.fbs validation.fbs

# 4) Build WITH TESTS, GUI (Qt6), BENCH, and optionally FUZZ (conditional on BUILD_FUZZ arg)
ARG BUILD_FUZZ=0
RUN rm -rf build build_fuzz && \
    cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCH=ON -DWITH_ZMQ=ON -DENABLE_WALLET=ON -DBUILD_GUI=ON -DDEFAULT_CHAIN_TYPE="" && \
    cmake --build build --target bitcoind bitcoin-cli bitcoin-wallet bitcoin-util bitcoin-qt test_bitcoin test_bitcoin-qt bench_bitcoin -- -j"$(nproc)" && \
    if [ "$BUILD_FUZZ" = "1" ]; then \
      echo "Building fuzz binary..."; \
      CC=clang-16 CXX=clang++-16 cmake -H. -Bbuild_fuzz \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_FUZZ_BINARY=ON \
        -DWITH_ZMQ=ON \
        -DSANITIZERS=fuzzer,address,undefined && \
      cmake --build build_fuzz --target fuzz -- -j"$(nproc)"; \
    fi

# 5) Copy Rust cosign-bridge binary from builder (after build directory exists)
COPY --from=rust-builder /workspace/cosign-bridge/target/release/cosign-bridge /build/bcore/build/bin/cosign-bridge
COPY --from=rust-builder /workspace/cosign-bridge/target/release/cosign-local-relay /build/bcore/build/bin/cosign-local-relay
RUN chmod +x /build/bcore/build/bin/cosign-bridge /build/bcore/build/bin/cosign-local-relay

# 6) Copy GMP libs & headers from builder and install ChiaVDF
COPY --from=chiavdf-builder /usr/local/lib/libgmp* /usr/local/lib/
COPY --from=chiavdf-builder /usr/local/include/gmp* /usr/local/include/
RUN ldconfig

# Install the ChiaVDF wheel for functional tests to generate real VDF proofs
COPY --from=chiavdf-builder /chiavdf-wheels/*.whl /tmp/
RUN pip3 install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl && \
    echo "ChiaVDF installed from built wheel"

# Python flatbuffers runtime: feature_broker_mining_rpc.py's valid-submission
# legs build proof::MiningResponse buffers via test_framework/proof_fb (the
# vendored flatc output). Without this module those legs SKIP and the test
# still reports success — i.e. coverage silently degrades to structural-only.
# The import guard below fails the image build (fail-fast) if either this or
# the chiavdf wheel above is ever dropped, so CI can never quietly lose the
# accepted/rejected submit_mining_response coverage.
# argon2-cffi: feature_v3_acceptance.py scenario 4 (positive v3 admission) grinds
# an admissible Argon2id nonce and rebuilds the transcript with it. Without it
# that scenario SKIPs (the negative admission legs still run), so the same
# fail-fast guard below keeps CI from silently losing positive-admission
# coverage. pow_v3.py is the SINGLE canonical helper (shared-utils/pow-utils);
# it is vendored into the functional dir (cwd on sys.path) rather than copied
# into the repo, so there is exactly one source of truth.
COPY shared-utils/pow-utils/pow_v3.py /build/bcore/test/functional/pow_v3.py
# R=1024 B_cred table (§4) — pow_v3 imports it; vendor it beside pow_v3.py.
COPY shared-utils/pow-utils/bcred_table_r1024.py /build/bcore/test/functional/bcred_table_r1024.py
RUN pip3 install --no-cache-dir flatbuffers argon2-cffi && \
    python3 -c "import flatbuffers, chiavdf, argon2; print('functional-test deps OK: flatbuffers', flatbuffers.__version__)" && \
    ( cd /build/bcore/test/functional && python3 -c "import pow_v3; assert pow_v3.V3_PROOF_VERSION == 3 and pow_v3.BCRED_R == 1024; print('pow_v3 vendored OK')" )

# 7) Copy test runner scripts
COPY services/core-node/bcore/test/run_asset_tests.sh /run_asset_tests.sh
RUN chmod +x /run_asset_tests.sh
COPY services/core-node/bcore/test-runner/run_functional.sh /run_functional.sh
RUN chmod +x /run_functional.sh
COPY services/core-node/bcore/test-runner/run_fuzz.sh /run_fuzz.sh
RUN chmod +x /run_fuzz.sh 2>/dev/null || true

# Create corpus and output directories for fuzzing if BUILD_FUZZ is enabled
ARG BUILD_FUZZ=0
RUN if [ "$BUILD_FUZZ" = "1" ]; then \
      mkdir -p /build/bcore/fuzz_corpora /build/bcore/fuzz_outputs; \
    fi

# 8) Set environment and create wrapper script
ENV BUILD_DIR=/build/bcore/build
ENV UNITTEST_CHAIN=tensor-reg
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo 'echo "=== BUILD STATUS ==="' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/test_bitcoin" ]; then echo "✓ test_bitcoin built"; else echo "✗ test_bitcoin missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/bench_bitcoin" ]; then echo "✓ bench_bitcoin built"; else echo "✗ bench_bitcoin missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/bitcoin-qt" ]; then echo "✓ bitcoin-qt (GUI) built"; else echo "✗ bitcoin-qt missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/src/qt/test/test_bitcoin-qt" ]; then echo "✓ test_bitcoin-qt (Qt tests) built"; else echo "✗ test_bitcoin-qt missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build_fuzz/bin/fuzz" ]; then echo "✓ fuzz binary built"; else echo "(fuzz binary not built in this image)"; fi' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'if [ -n "${TC_FUZZ}" ]; then' >> /entrypoint.sh && \
    echo '  if [ -x "/build/bcore/build_fuzz/bin/fuzz" ]; then' >> /entrypoint.sh && \
    echo '    exec /run_fuzz.sh "$@"' >> /entrypoint.sh && \
    echo '  else' >> /entrypoint.sh && \
    echo '    echo "ERROR: Fuzz binary not available. Rebuild image with BUILD_FUZZ=1"' >> /entrypoint.sh && \
    echo '    exit 1' >> /entrypoint.sh && \
    echo '  fi' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'if [ -n "${TC_FUNCTIONAL}" ]; then exec /run_functional.sh; fi' >> /entrypoint.sh && \
    echo 'exec /run_asset_tests.sh' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Set default command to run the comprehensive test suite
CMD ["/entrypoint.sh"]
