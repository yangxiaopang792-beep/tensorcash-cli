# Stage 1: Build Rust cosign-bridge
# Rust 1.85+ is required because transitive crates use edition2024.
FROM rust:1.87-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY services/core-node/cosign-bridge /workspace/cosign-bridge
RUN cd /workspace/cosign-bridge && cargo build --release --bin cosign-bridge --bin cosign-local-relay

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

RUN git init && \
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

# Stage 3: Main GUI test runner image with VNC
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build

# Add Tor Project apt repo to pull a modern Tor (more compatible with current HSDir protocols)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates gnupg curl && \
    mkdir -p /usr/share/keyrings && \
    if curl -fsSL https://deb.torproject.org/torproject.org/gpgkey | gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg; then \
      echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(. /etc/os-release; echo $VERSION_CODENAME) main" > /etc/apt/sources.list.d/tor.list; \
    else \
      echo "WARN: Tor Project key fetch failed; using distro tor packages"; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Install core build tools, libs, Qt6 for GUI, and VNC/XFCE for remote desktop
RUN apt-get update && \
    apt-get install -y \
      build-essential \
      cmake \
      git \
      pkg-config \
      curl \
      ca-certificates \
      tor \
      tor-geoipdb \
      libevent-dev \
      libssl-dev \
      libzmq3-dev \
      libsqlite3-dev \
      libgmp-dev \
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
      libdb++-dev \
      xfce4 \
      xfce4-terminal \
      openbox \
      tint2 \
      pcmanfm \
      icewm \
      tigervnc-standalone-server \
      tigervnc-common \
      autocutsel \
      x11-apps \
      x11-utils \
      dbus-x11 \
      nano \
      vim \
      jq \
      bc \
      netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Build and install Tor 0.4.8.12 from source (supports FlowCtrl=2 Relay=4 protocols for HSDirs)
ENV TOR_VERSION=0.4.8.12
RUN set -eux; \
    cd /tmp; \
    curl -fsSL "https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz" -o tor.tar.gz; \
    tar xf tor.tar.gz; \
    cd "tor-${TOR_VERSION}"; \
    ./configure --disable-dependency-tracking --disable-systemd; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    cd /tmp; \
    rm -rf "tor-${TOR_VERSION}" tor.tar.gz; \
    tor --version

# Build & install FlatBuffers v25.2.10 from source
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

# Build & install blst library with optimizations
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

# Install Go for building kyc-prover CGO library
RUN apt-get update && \
    apt-get install -y wget && \
    ARCH=$(dpkg --print-architecture) && \
    wget https://go.dev/dl/go1.21.0.linux-${ARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-${ARCH}.tar.gz && \
    rm go1.21.0.linux-${ARCH}.tar.gz && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"

# Copy Bitcoin Core source
COPY services/core-node/bcore /build/bcore
# Bring chiavdf into a stable include location for CMake auto-detect
COPY shared-utils/chiavdf /build/bcore/src/external/chiavdf
COPY shared-utils/secp256k1-zkp /build/bcore/src/external/secp256k1-zkp

# Build liboqs for ML-DSA (FIPS 204) post-quantum verification
# Minimal build: only ML-DSA-44/65/87 for Taproot v2
COPY shared-utils/liboqs /build/bcore/src/external/liboqs
RUN cd /build/bcore/src/external/liboqs && \
    rm -rf build && mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_USE_OPENSSL=OFF \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" \
          -DOQS_ENABLE_TEST_CONSTANT_TIME=ON \
          .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

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
RUN mkdir -p /build/shared-utils/kyc-prover
COPY shared-utils/kyc-prover /build/shared-utils/kyc-prover
WORKDIR /build/shared-utils/kyc-prover/cgo
RUN go build -buildmode=c-shared -o libzkprover.so . && \
    cp libzkprover.so /usr/local/lib/ && \
    ldconfig

WORKDIR /build/bcore

# Generate FBS schema files
COPY shared-utils/fb-schemas/proof.fbs /build/bcore/
COPY shared-utils/fb-schemas/blockheader.fbs /build/bcore/
COPY shared-utils/fb-schemas/validation.fbs /build/bcore/
RUN flatc --cpp -o src/rpc proof.fbs blockheader.fbs validation.fbs

# Build WITH TESTS and GUI (Qt6) and ML-DSA (Post-Quantum) support
RUN rm -rf build && \
    cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTS=ON \
      -DWITH_ZMQ=ON \
      -DENABLE_WALLET=ON \
      -DBUILD_GUI=ON \
      -DWITH_GUI=qt6 \
      -DENABLE_MLDSA=ON && \
    cmake --build build --target bitcoind bitcoin-cli bitcoin-wallet bitcoin-util -- -j"$(nproc)" && \
    echo "=== Core binaries built, now building bitcoin-qt ===" && \
    cmake --build build --target bitcoin-qt -- -j"$(nproc)" && \
    echo "=== bitcoin-qt built successfully ===" && \
    cmake --build build --target test_bitcoin test_bitcoin-qt -- -j"$(nproc)" && \
    echo "=== Build Complete ===" && \
    echo "Checking where binaries actually are:" && \
    find build -name "bitcoind" -type f -executable 2>/dev/null | head -5 && \
    find build -name "bitcoin-cli" -type f -executable 2>/dev/null | head -5 && \
    find build -name "bitcoin-qt" -type f -executable 2>/dev/null | head -5

# Copy Rust cosign-bridge binary from builder (after build directory exists)
COPY --from=rust-builder /workspace/cosign-bridge/target/release/cosign-bridge /build/bcore/build/bin/cosign-bridge
RUN chmod +x /build/bcore/build/bin/cosign-bridge

# Copy cosign-local-relay binary for testing
COPY --from=rust-builder /workspace/cosign-bridge/target/release/cosign-local-relay /build/bcore/build/bin/cosign-local-relay
RUN chmod +x /build/bcore/build/bin/cosign-local-relay

# Copy GMP libs & headers from builder and install ChiaVDF
COPY --from=chiavdf-builder /usr/local/lib/libgmp* /usr/local/lib/
COPY --from=chiavdf-builder /usr/local/include/gmp* /usr/local/include/
RUN ldconfig

# Install the ChiaVDF wheel for functional tests
COPY --from=chiavdf-builder /chiavdf-wheels/*.whl /tmp/
RUN pip3 install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl && \
    echo "ChiaVDF installed from built wheel"

# Copy test runner scripts
COPY services/core-node/bcore/test/run_asset_tests.sh /run_asset_tests.sh
RUN chmod +x /run_asset_tests.sh
COPY services/core-node/bcore/test-runner/run_functional.sh /run_functional.sh
RUN chmod +x /run_functional.sh
COPY services/core-node/bcore/test-runner/setup-assets-functional.sh /setup-assets-functional.sh
RUN chmod +x /setup-assets-functional.sh
COPY services/core-node/bcore/test-runner/setup-assets-direct.sh /setup-assets-direct.sh
RUN chmod +x /setup-assets-direct.sh
COPY services/core-node/bcore/test-runner/gui-test-complete.sh /gui-test-complete.sh
RUN chmod +x /gui-test-complete.sh
COPY services/core-node/bcore/test-runner/gui-assets-test.sh /gui-assets-test.sh
RUN chmod +x /gui-assets-test.sh
COPY services/core-node/bcore/test-runner/gui-assets-shutdown.sh /gui-assets-shutdown.sh
RUN chmod +x /gui-assets-shutdown.sh
COPY services/core-node/bcore/test-runner/gui-assets-simple.py /build/bcore/test-runner/gui-assets-simple.py
RUN chmod +x /build/bcore/test-runner/gui-assets-simple.py
COPY services/core-node/bcore/test-runner/run-gui-assets.sh /run-gui-assets.sh
RUN chmod +x /run-gui-assets.sh
COPY services/core-node/bcore/test-runner/gui-assets-clean.py /build/bcore/test-runner/gui-assets-clean.py
RUN chmod +x /build/bcore/test-runner/gui-assets-clean.py
COPY services/core-node/bcore/test-runner/run-gui-clean.sh /run-gui-clean.sh
RUN chmod +x /run-gui-clean.sh
COPY services/core-node/bcore/test-runner/gui-assets-dual.py /build/bcore/test-runner/gui-assets-dual.py
RUN chmod +x /build/bcore/test-runner/gui-assets-dual.py
COPY services/core-node/bcore/test-runner/run-gui-dual.sh /run-gui-dual.sh
RUN chmod +x /run-gui-dual.sh


# Set up VNC server
RUN mkdir /root/.vnc && \
    echo "password" | vncpasswd -f > /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# Create VNC startup script with IceWM (simplest WM that works in Docker)
RUN echo '#!/bin/bash' > /root/.vnc/xstartup && \
    echo '[ -f $HOME/.Xresources ] && xrdb $HOME/.Xresources' >> /root/.vnc/xstartup && \
    echo 'autocutsel -fork' >> /root/.vnc/xstartup && \
    echo 'autocutsel -selection PRIMARY -fork' >> /root/.vnc/xstartup && \
    echo '' >> /root/.vnc/xstartup && \
    echo '# Set Qt to use software rendering to avoid OpenGL issues in VNC' >> /root/.vnc/xstartup && \
    echo 'export QT_QPA_PLATFORM=xcb' >> /root/.vnc/xstartup && \
    echo 'export QT_X11_NO_MITSHM=1' >> /root/.vnc/xstartup && \
    echo 'export LIBGL_ALWAYS_SOFTWARE=1' >> /root/.vnc/xstartup && \
    echo '' >> /root/.vnc/xstartup && \
    echo '# Use IceWM - simplest window manager, no session manager, works in Docker' >> /root/.vnc/xstartup && \
    echo 'exec icewm' >> /root/.vnc/xstartup && \
    chmod +x /root/.vnc/xstartup

# Pre-configure XFCE to disable compositor (prevents black screens in VNC on x86_64)
RUN mkdir -p /root/.config/xfce4/xfconf/xfce-perchannel-xml && \
    echo '<?xml version="1.0" encoding="UTF-8"?>' > /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '<channel name="xfwm4" version="1.0">' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '  <property name="general" type="empty">' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '    <property name="use_compositing" type="bool" value="false"/>' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '    <property name="vblank_mode" type="string" value="off"/>' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '  </property>' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml && \
    echo '</channel>' >> /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml

# Create test directories and configs for wallet testing
RUN mkdir -p /root/tensorcash-test/node1 /root/tensorcash-test/node2

# Node 1 Config (GUI wallet)
RUN echo '# Global settings' > /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'server=1' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'daemon=0' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'txindex=1' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'rpcuser=test' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'rpcpassword=test123' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'rpcallowip=127.0.0.1' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo '' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo '[regtest]' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'port=18444' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'rpcport=18443' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'listen=1' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'assetsheight=1' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'policymaxassetspertx=100' >> /root/tensorcash-test/node1/bitcoin.conf && \
    echo 'assetminfeerate=1' >> /root/tensorcash-test/node1/bitcoin.conf

# Node 2 Config (Mining node)
RUN echo '# Global settings' > /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'server=1' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'daemon=0' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'txindex=1' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'rpcuser=test' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'rpcpassword=test123' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'rpcallowip=127.0.0.1' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo '' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo '[regtest]' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'port=28444' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'rpcport=28443' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'listen=1' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'connect=127.0.0.1:18444' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'assetsheight=1' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'policymaxassetspertx=100' >> /root/tensorcash-test/node2/bitcoin.conf && \
    echo 'assetminfeerate=1' >> /root/tensorcash-test/node2/bitcoin.conf

# Create helper scripts with TigerVNC and clipboard support
RUN echo '#!/bin/bash' > /start-vnc.sh && \
    echo 'export USER=root' >> /start-vnc.sh && \
    echo 'export HOME=/root' >> /start-vnc.sh && \
    echo 'echo "Starting VNC server on port 5901..."' >> /start-vnc.sh && \
    echo 'echo "Password: password"' >> /start-vnc.sh && \
    echo 'vncserver -kill :1 2>/dev/null || true' >> /start-vnc.sh && \
    echo 'rm -rf /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true' >> /start-vnc.sh && \
    echo 'vncserver :1 -geometry 1280x800 -depth 24 -localhost no -SecurityTypes None' >> /start-vnc.sh && \
    echo 'export DISPLAY=:1' >> /start-vnc.sh && \
    echo 'echo ""' >> /start-vnc.sh && \
    echo 'echo "VNC server started with clipboard support! Connect from your Mac using:"' >> /start-vnc.sh && \
    echo 'echo "  Screen Sharing app: vnc://localhost:5901"' >> /start-vnc.sh && \
    echo 'echo "  Or in Finder: Go → Connect to Server → vnc://localhost:5901"' >> /start-vnc.sh && \
    echo 'echo ""' >> /start-vnc.sh && \
    echo 'echo "Copy/paste should work between your Mac and the VNC session!"' >> /start-vnc.sh && \
    echo 'echo "Once connected, open a terminal in the XFCE desktop to run tests."' >> /start-vnc.sh && \
    echo 'tail -f /dev/null' >> /start-vnc.sh && \
    chmod +x /start-vnc.sh

# Create GUI test script
RUN echo '#!/bin/bash' > /run-gui-test.sh && \
    echo 'export DISPLAY=:1' >> /run-gui-test.sh && \
    echo 'export USER=root' >> /run-gui-test.sh && \
    echo 'export HOME=/root' >> /run-gui-test.sh && \
    echo 'echo "=== TensorCash Wallet GUI Test Script ==="' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Checking if VNC display is available..."' >> /run-gui-test.sh && \
    echo 'if ! xdpyinfo -display :1 >/dev/null 2>&1; then' >> /run-gui-test.sh && \
    echo '  echo "ERROR: VNC display :1 not found. Please run /start-vnc.sh first!"' >> /run-gui-test.sh && \
    echo '  exit 1' >> /run-gui-test.sh && \
    echo 'fi' >> /run-gui-test.sh && \
    echo 'echo "Display :1 is available"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Starting Qt wallet on node1 with ASN and fee settings..."' >> /run-gui-test.sh && \
    echo 'cd /build/bcore' >> /run-gui-test.sh && \
    echo 'DISPLAY=:1 ./build/bin/bitcoin-qt -datadir=/root/tensorcash-test/node1 -regtest -spv-asn-min=1 -fallbackfee=0.00001 &' >> /run-gui-test.sh && \
    echo 'QT_PID=$!' >> /run-gui-test.sh && \
    echo 'echo "Qt wallet started with PID: $QT_PID"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Starting mining node (node2) in background..."' >> /run-gui-test.sh && \
    echo './build/bin/bitcoind -datadir=/root/tensorcash-test/node2 -regtest -spv-asn-min=1 -fallbackfee=0.00001 &' >> /run-gui-test.sh && \
    echo 'BITCOIND_PID=$!' >> /run-gui-test.sh && \
    echo 'echo "Mining node started with PID: $BITCOIND_PID"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Waiting for nodes to start..."' >> /run-gui-test.sh && \
    echo 'sleep 5' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "=== Test Environment Ready ==="' >> /run-gui-test.sh && \
    echo 'echo "You can now interact with:"' >> /run-gui-test.sh && \
    echo 'echo "1. Qt Wallet GUI (visible in VNC)"' >> /run-gui-test.sh && \
    echo 'echo "2. Node 1 CLI: ./build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node1 -regtest -rpcuser=test -rpcpassword=test123"' >> /run-gui-test.sh && \
    echo 'echo "3. Node 2 CLI: ./build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Creating shell script with aliases..."' >> /run-gui-test.sh && \
    echo 'cat > /root/test-env.sh << "EOF"' >> /run-gui-test.sh && \
    echo '#!/bin/bash' >> /run-gui-test.sh && \
    echo 'alias tcli1="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node1 -regtest -rpcuser=test -rpcpassword=test123"' >> /run-gui-test.sh && \
    echo 'alias tcli2="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443"' >> /run-gui-test.sh && \
    echo 'echo "Aliases loaded: tcli1 (node1) and tcli2 (node2)"' >> /run-gui-test.sh && \
    echo 'EOF' >> /run-gui-test.sh && \
    echo 'chmod +x /root/test-env.sh' >> /run-gui-test.sh && \
    echo 'echo "Run: source /root/test-env.sh to load aliases"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'echo "Follow WALLET_GUI_TESTING_GUIDE.md for testing steps"' >> /run-gui-test.sh && \
    echo 'echo ""' >> /run-gui-test.sh && \
    echo 'wait' >> /run-gui-test.sh && \
    chmod +x /run-gui-test.sh

# Create automated asset setup script
RUN echo '#!/bin/bash' > /setup-test-assets.sh && \
    echo 'echo "=== Automated Asset Setup Script ==="' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Define CLI commands' >> /setup-test-assets.sh && \
    echo 'CLI1="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node1 -regtest -rpcuser=test -rpcpassword=test123"' >> /setup-test-assets.sh && \
    echo 'CLI2="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Create wallets' >> /setup-test-assets.sh && \
    echo 'echo "Creating wallets..."' >> /setup-test-assets.sh && \
    echo '$CLI1 createwallet "test_wallet" 2>/dev/null || echo "Wallet already exists"' >> /setup-test-assets.sh && \
    echo '$CLI2 createwallet "miner" 2>/dev/null || echo "Wallet already exists"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Generate initial funds' >> /setup-test-assets.sh && \
    echo 'echo "Generating initial blocks for funding..."' >> /setup-test-assets.sh && \
    echo 'ADDR2=$($CLI2 getnewaddress)' >> /setup-test-assets.sh && \
    echo '$CLI2 generatetoaddress 150 $ADDR2 >/dev/null' >> /setup-test-assets.sh && \
    echo 'echo "Generated 150 blocks"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Send funds to GUI wallet' >> /setup-test-assets.sh && \
    echo 'echo "Sending funds to GUI wallet..."' >> /setup-test-assets.sh && \
    echo 'ADDR1=$($CLI1 getnewaddress)' >> /setup-test-assets.sh && \
    echo '$CLI2 sendtoaddress $ADDR1 10 >/dev/null' >> /setup-test-assets.sh && \
    echo '$CLI2 generatetoaddress 1 $ADDR2 >/dev/null' >> /setup-test-assets.sh && \
    echo 'echo "Sent 10 BTC to wallet"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Register GOLD asset' >> /setup-test-assets.sh && \
    echo 'echo "Registering GOLD asset..."' >> /setup-test-assets.sh && \
    echo 'GOLD_ID="1111111111111111111111111111111111111111111111111111111111111111"' >> /setup-test-assets.sh && \
    echo '$CLI1 registerasset "$GOLD_ID" 3 100000000 1000000 "GOLD" 8 >/dev/null' >> /setup-test-assets.sh && \
    echo '$CLI2 generatetoaddress 1 $ADDR2 >/dev/null' >> /setup-test-assets.sh && \
    echo 'echo "GOLD asset registered"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Register SILVER asset' >> /setup-test-assets.sh && \
    echo 'echo "Registering SILVER asset..."' >> /setup-test-assets.sh && \
    echo 'SILVER_ID="2222222222222222222222222222222222222222222222222222222222222222"' >> /setup-test-assets.sh && \
    echo '$CLI1 registerasset "$SILVER_ID" 3 100000000 1000000 "SILVER" 6 >/dev/null' >> /setup-test-assets.sh && \
    echo '$CLI2 generatetoaddress 1 $ADDR2 >/dev/null' >> /setup-test-assets.sh && \
    echo 'echo "SILVER asset registered"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Mint assets' >> /setup-test-assets.sh && \
    echo 'echo "Minting assets..."' >> /setup-test-assets.sh && \
    echo '$CLI1 mintasset "$GOLD_ID" 100000000 $ADDR1 >/dev/null' >> /setup-test-assets.sh && \
    echo '$CLI1 mintasset "$SILVER_ID" 500000000 $ADDR1 >/dev/null' >> /setup-test-assets.sh && \
    echo '$CLI2 generatetoaddress 2 $ADDR2 >/dev/null' >> /setup-test-assets.sh && \
    echo 'echo "Minted 1 GOLD and 500 SILVER"' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo '# Show asset balance' >> /setup-test-assets.sh && \
    echo 'echo "Asset balances:"' >> /setup-test-assets.sh && \
    echo '$CLI1 getassetbalance' >> /setup-test-assets.sh && \
    echo 'echo ""' >> /setup-test-assets.sh && \
    echo 'echo "=== Setup Complete ==="' >> /setup-test-assets.sh && \
    echo 'echo "Check the GUI Overview tab to see asset balances!"' >> /setup-test-assets.sh && \
    echo 'echo "You can now test transfers, burns, and other operations."' >> /setup-test-assets.sh && \
    chmod +x /setup-test-assets.sh

# Set environment
ENV BUILD_DIR=/build/bcore/build
ENV UNITTEST_CHAIN=tensor-reg
ENV DISPLAY=:1
# Qt rendering environment for VNC compatibility (prevents black screens)
ENV QT_QPA_PLATFORM=xcb
ENV QT_X11_NO_MITSHM=1
ENV LIBGL_ALWAYS_SOFTWARE=1
ENV USER=root
# Cosign relay configuration (local relay for testing)
ENV COSIGN_RELAY_URL=ws://127.0.0.1:9736

# Create entrypoint script
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo 'echo "=== TensorCash GUI Test Container ==="' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo '# Start Tor daemons for GUI instances (instance 0 and 1)' >> /entrypoint.sh && \
    echo 'start_tor_instance() {' >> /entrypoint.sh && \
    echo '  local INSTANCE_ID=$1' >> /entrypoint.sh && \
    echo '  local SOCKS_PORT=$((9150 + INSTANCE_ID * 10))' >> /entrypoint.sh && \
    echo '  local CONTROL_PORT=$((9151 + INSTANCE_ID * 10))' >> /entrypoint.sh && \
    echo '  local BASE_SERVICE_PORT=$((9735 + INSTANCE_ID * 100))' >> /entrypoint.sh && \
    echo '  local TOR_DATA_DIR="/root/tensorcash-test/node$((INSTANCE_ID + 1))/.tor"' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  # Create Tor data directory with restrictive permissions' >> /entrypoint.sh && \
    echo '  mkdir -p "$TOR_DATA_DIR"' >> /entrypoint.sh && \
    echo '  chmod 700 "$TOR_DATA_DIR"' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  # Generate torrc configuration' >> /entrypoint.sh && \
    echo '  cat > "$TOR_DATA_DIR/torrc" << EOF' >> /entrypoint.sh && \
    echo '# TensorCash Tor Configuration (Instance $INSTANCE_ID)' >> /entrypoint.sh && \
    echo '# Auto-generated by Docker entrypoint' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# SOCKS proxy for cosign-bridge' >> /entrypoint.sh && \
    echo 'SocksPort 127.0.0.1:$SOCKS_PORT' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Control port for ephemeral hidden services' >> /entrypoint.sh && \
    echo 'ControlPort 127.0.0.1:$CONTROL_PORT' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Use cookie authentication (no passwords in logs)' >> /entrypoint.sh && \
    echo 'CookieAuthentication 1' >> /entrypoint.sh && \
    echo 'CookieAuthFileGroupReadable 1' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Data directory' >> /entrypoint.sh && \
    echo 'DataDirectory $TOR_DATA_DIR' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Logging' >> /entrypoint.sh && \
    echo 'Log notice file $TOR_DATA_DIR/tor.log' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Connection limits for resource efficiency' >> /entrypoint.sh && \
    echo 'ConnLimit 100' >> /entrypoint.sh && \
    echo 'MaxClientCircuitsPending 32' >> /entrypoint.sh && \
    echo 'EOF' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  chmod 600 "$TOR_DATA_DIR/torrc"' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  # Start Tor daemon' >> /entrypoint.sh && \
    echo '  tor -f "$TOR_DATA_DIR/torrc" > "$TOR_DATA_DIR/tor-startup.log" 2>&1 &' >> /entrypoint.sh && \
    echo '  local TOR_PID=$!' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  # Wait for Tor to be ready (check SOCKS port)' >> /entrypoint.sh && \
    echo '  echo "  Waiting for Tor instance $INSTANCE_ID to be ready..."' >> /entrypoint.sh && \
    echo '  for i in {1..30}; do' >> /entrypoint.sh && \
    echo '    if nc -z 127.0.0.1 $SOCKS_PORT 2>/dev/null; then' >> /entrypoint.sh && \
    echo '      echo "  ✓ Tor instance $INSTANCE_ID ready (SOCKS: 127.0.0.1:$SOCKS_PORT, Control: 127.0.0.1:$CONTROL_PORT, BasePort: $BASE_SERVICE_PORT)"' >> /entrypoint.sh && \
    echo '      return 0' >> /entrypoint.sh && \
    echo '    fi' >> /entrypoint.sh && \
    echo '    sleep 1' >> /entrypoint.sh && \
    echo '  done' >> /entrypoint.sh && \
    echo '  ' >> /entrypoint.sh && \
    echo '  echo "  ✗ Tor instance $INSTANCE_ID failed to start (check $TOR_DATA_DIR/tor.log)"' >> /entrypoint.sh && \
    echo '  return 1' >> /entrypoint.sh && \
    echo '}' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# NOTE: Tor startup removed - GUIs manage their own Tor via TorManager' >> /entrypoint.sh && \
    echo '# Each GUI starts Tor on its own ports based on -guiinstance parameter:' >> /entrypoint.sh && \
    echo '#   GUI instance 0: SOCKS 9150, Control 9151, BasePort 9735' >> /entrypoint.sh && \
    echo '#   GUI instance 1: SOCKS 9160, Control 9161, BasePort 9835' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# NOTE: COSIGN_TOR_* environment variables are set by each GUI via TorManager' >> /entrypoint.sh && \
    echo '# Do not set them globally in the entrypoint' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo '' >> /entrypoint.sh && \
    echo '# Start local cosign relay in background' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/cosign-local-relay" ]; then' >> /entrypoint.sh && \
    echo '  echo "Starting local cosign relay on ws://127.0.0.1:9736..."' >> /entrypoint.sh && \
    echo '  /build/bcore/build/bin/cosign-local-relay --host 127.0.0.1 --port 9736 > /var/log/cosign-relay.log 2>&1 &' >> /entrypoint.sh && \
    echo '  RELAY_PID=$!' >> /entrypoint.sh && \
    echo '  sleep 1' >> /entrypoint.sh && \
    echo '  if ps -p $RELAY_PID > /dev/null; then' >> /entrypoint.sh && \
    echo '    echo "✓ Local cosign relay started (PID: $RELAY_PID)"' >> /entrypoint.sh && \
    echo '  else' >> /entrypoint.sh && \
    echo '    echo "✗ Failed to start relay (check /var/log/cosign-relay.log)"' >> /entrypoint.sh && \
    echo '  fi' >> /entrypoint.sh && \
    echo 'else' >> /entrypoint.sh && \
    echo '  echo "✗ cosign-local-relay binary not found"' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "BUILD STATUS:"' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/bitcoin-qt" ]; then echo "✓ bitcoin-qt (GUI) built"; else echo "✗ bitcoin-qt missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/bitcoind" ]; then echo "✓ bitcoind built"; else echo "✗ bitcoind missing"; fi' >> /entrypoint.sh && \
    echo 'if [ -x "/build/bcore/build/bin/bitcoin-cli" ]; then echo "✓ bitcoin-cli built"; else echo "✗ bitcoin-cli missing"; fi' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "AVAILABLE COMMANDS:"' >> /entrypoint.sh && \
    echo 'echo "  /run-gui-dual.sh         - *** NEW: Dual wallet GUI testing (2 VNC servers)"' >> /entrypoint.sh && \
    echo 'echo "  /run-gui-clean.sh        - Single GUI wallet as separate node"' >> /entrypoint.sh && \
    echo 'echo "  /run-gui-assets.sh       - Pure Python test with GUI swap (may have wallet issues)"' >> /entrypoint.sh && \
    echo 'echo "  /gui-assets-test.sh      - One command to set up everything (directory copy method)"' >> /entrypoint.sh && \
    echo 'echo "  /gui-test-complete.sh    - Complete GUI test setup (VNC + Assets)"' >> /entrypoint.sh && \
    echo 'echo "  /setup-assets-functional.sh - Build asset state via functional test"' >> /entrypoint.sh && \
    echo 'echo "  /gui-assets-shutdown.sh  - Stop GUI/miner and flush data before copying"' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "QUICK START:"' >> /entrypoint.sh && \
    echo 'echo "  Single Wallet: /run-gui-clean.sh"' >> /entrypoint.sh && \
    echo 'echo "  Dual Wallets:  /run-gui-dual.sh  (recommended for wallet-to-wallet testing)"' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "SINGLE WALLET MODE (/run-gui-clean.sh):"' >> /entrypoint.sh && \
    echo 'echo "  1. Start VNC server on port 5901"' >> /entrypoint.sh && \
    echo 'echo "  2. Run 2 bitcoind nodes and create/mint assets"' >> /entrypoint.sh && \
    echo 'echo "  3. Launch GUI as separate 3rd node"' >> /entrypoint.sh && \
    echo 'echo "  4. Send assets to GUI wallet and keep mining"' >> /entrypoint.sh && \
    echo 'echo "  VNC: vnc://localhost:5901 (password: password)"' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "DUAL WALLET MODE (/run-gui-dual.sh):"' >> /entrypoint.sh && \
    echo 'echo "  1. Start VNC servers on ports 5901 and 5902"' >> /entrypoint.sh && \
    echo 'echo "  2. Run 2 bitcoind nodes (miner + asset holder)"' >> /entrypoint.sh && \
    echo 'echo "  3. Launch GUI1 and GUI2 as separate wallet nodes"' >> /entrypoint.sh && \
    echo 'echo "  4. Fund both wallets with BTC and assets"' >> /entrypoint.sh && \
    echo 'echo "  5. Test wallet-to-wallet transactions"' >> /entrypoint.sh && \
    echo 'echo "  GUI1: vnc://localhost:5901 (password: password)"' >> /entrypoint.sh && \
    echo 'echo "  GUI2: vnc://localhost:5902 (password: password)"' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'echo "MANUAL SETUP:"' >> /entrypoint.sh && \
    echo 'echo "1. Run: /start-vnc.sh"' >> /entrypoint.sh && \
    echo 'echo "2. Connect from Mac: vnc://localhost:5901 (password: password)"' >> /entrypoint.sh && \
    echo 'echo "3. Run: /setup-assets-direct.sh"' >> /entrypoint.sh && \
    echo 'echo "4. Launch GUI manually with provided commands"' >> /entrypoint.sh && \
    echo 'echo ""' >> /entrypoint.sh && \
    echo 'exec /bin/bash' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Expose VNC ports (5901 for single wallet, 5902 for dual wallet mode)
EXPOSE 5901 5902

# Default command
CMD ["/entrypoint.sh"]
