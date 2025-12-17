# qaTox-PQ: Android Client Implementation Plan

**Project**: Hybrid backwards-compatible post-quantum secure Tox client for Android
**Base**: c-toxcore-pq (this repository)
**Target**: Android app with ML-KEM-768 + X25519 hybrid key exchange and security UI

## Overview

This folder contains documentation for building a post-quantum capable Android Tox client (qaTox-PQ) that integrates the c-toxcore-pq library.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         qaTox-PQ (Android)                          │
├─────────────────────────────────────────────────────────────────────┤
│  Kotlin UI Layer          │  Security Status Display                │
│  - Connection indicators  │  - "PQ-Verified" / "PQ" / "Classical"  │
│  - Settings for PQ policy │  - Per-friend identity status           │
├───────────────────────────┴─────────────────────────────────────────┤
│                         tox4j JNI Bridge                            │
│  - Extended API for PQ status queries                               │
│  - Hybrid identity management (46-byte addresses)                   │
├─────────────────────────────────────────────────────────────────────┤
│                    c-toxcore-pq (This Repository)                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  crypto_core_pq  │  │    net_crypto    │  │    Messenger     │  │
│  │  - Hybrid KDF    │  │  - PQ handshake  │  │  - PQ address    │  │
│  │  - ML-KEM wrap   │  │  - In-band nego  │  │  - Identity      │  │
│  │  - Commitment    │  │  - Fallback      │  │    verification  │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                     │                     │             │
│           └─────────────────────┴─────────────────────┘             │
│                                 │                                   │
├─────────────────────────────────┴───────────────────────────────────┤
│                      libsodium (upgraded)                           │
│  - crypto_scalarmult_curve25519 (existing)                          │
│  - crypto_kem_mlkem768_* (new in master)                            │
│  - crypto_kdf_hkdf_sha512_* (key derivation)                        │
└─────────────────────────────────────────────────────────────────────┘
```

## Documentation

- [PHASE-3-INTEGRATION.md](PHASE-3-INTEGRATION.md) - Complete Android integration guide including:
  - Cross-compilation for Android ABIs
  - tox4j JNI bindings
  - Kotlin domain layer updates
  - UI components (security badges, settings)
  - Database schema migrations

## Prerequisites

- Android Studio Arctic Fox or later
- NDK r25 or later
- CMake 3.18+
- c-toxcore-pq built with ML-KEM support
- libsodium master branch (with ML-KEM-768 support)

## Quick Start

```bash
# Clone qaTox-PQ (once created)
git clone --recurse-submodules https://github.com/YOUR_USERNAME/qaTox-PQ.git
cd qaTox-PQ

# Build modified c-toxcore-pq for Android
cd c-toxcore-pq
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
         -DANDROID_ABI=arm64-v8a \
         -DANDROID_PLATFORM=android-26
make -j$(nproc)

# Build tox4j with PQ bindings
cd ../../tox4j
./scripts/build-aarch64-linux-android -j$(nproc) release

# Build qaTox-PQ
cd ..
./gradlew assembleRelease
```

## Security UI

The Android client should display security status for each friend connection:

| Status | Badge | Description |
|--------|-------|-------------|
| `PQ_VERIFIED` | "PQ-Verified" | Full quantum protection (46-byte address used) |
| `PQ_UNVERIFIED` | "PQ" | Quantum-resistant session, unverified identity |
| `CLASSICAL` | "Classical" | Legacy X25519-only connection |

## Files to Modify in tox4j

| File | Changes |
|------|---------|
| `ToxCore.scala` | Add PQ status methods |
| `ToxCoreJni.cpp` | JNI bindings for new functions |

## Contributing

Before implementing the Android client, ensure c-toxcore-pq passes all tests:

```bash
cd c-toxcore-pq/_build
ctest -j$(nproc) --output-on-failure
```

## License

GPL-3.0 (same as c-toxcore)
