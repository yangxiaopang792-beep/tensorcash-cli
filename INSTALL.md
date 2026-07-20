# Building TensorCash bcore

Platform-specific build instructions live under [`doc/`](doc/):

- Unix/Linux — [`doc/build-unix.md`](doc/build-unix.md)
- macOS — [`doc/build-osx.md`](doc/build-osx.md)
- Windows (MinGW cross-build) — [`doc/build-windows.md`](doc/build-windows.md)
- Windows (MSVC) — [`doc/build-windows-msvc.md`](doc/build-windows-msvc.md)
- FreeBSD — [`doc/build-freebsd.md`](doc/build-freebsd.md)
- NetBSD — [`doc/build-netbsd.md`](doc/build-netbsd.md)
- OpenBSD — [`doc/build-openbsd.md`](doc/build-openbsd.md)

`bcore` depends on the TensorCash shared utilities (post-quantum `liboqs`,
`secp256k1-zkp`, and the VDF/PoW helpers). It is consumed as a submodule by the
umbrella [`tensorcash`](https://github.com/tensorcash/tensorcash) repository,
which initialises those dependencies and wires the node together with the miner
and verification services. Most users should build from the umbrella repository
rather than building `bcore` standalone.
