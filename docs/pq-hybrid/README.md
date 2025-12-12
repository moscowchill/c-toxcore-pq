# aqTox-PQ: Hybrid Post-Quantum Tox Client Implementation Plan

**Project**: Hybrid backwards-compatible post-quantum secure Tox client for Android  
**Base Fork**: [moscowchill/aqTox](https://github.com/moscowchill/aqTox)  
**Target**: ML-KEM-768 + X25519 hybrid key exchange with graceful legacy fallback

## Executive Summary

This implementation adds post-quantum cryptographic protection to Tox messaging while maintaining full backwards compatibility with existing Tox clients. The approach uses libsodium's native ML-KEM-768 implementation combined with existing X25519 in a hybrid scheme, ensuring security even if one primitive is broken.

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| PQ Algorithm | ML-KEM-768 | NIST FIPS 203 standardized, available in libsodium master |
| Hybrid Mode | X25519 + ML-KEM-768 | Belt-and-suspenders security during transition |
| Compatibility | Option A (Full Interop) | Negotiate PQ with capable peers, fallback to classical |
| Library | libsodium only | No external PQ library needed, simplifies build |
| Negotiation | ToxExt protocol | Existing extension mechanism, no protocol break |

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         aqTox-PQ (Android)                          │
├─────────────────────────────────────────────────────────────────────┤
│  Kotlin UI Layer          │  Security Status Display                │
│  - Connection indicators  │  - "PQ-Hybrid" / "Classical" badges    │
│  - Settings for PQ policy │  - Per-friend security level            │
├───────────────────────────┴─────────────────────────────────────────┤
│                         tox4j JNI Bridge                            │
│  - Extended API for PQ status queries                               │
│  - Hybrid identity management                                       │
├─────────────────────────────────────────────────────────────────────┤
│                    c-toxcore (Modified)                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  crypto_core_pq  │  │   net_crypto_pq  │  │    ToxExt PQ     │  │
│  │  - Hybrid KDF    │  │  - PQ handshake  │  │  - Capability    │  │
│  │  - Key storage   │  │  - Fallback      │  │    negotiation   │  │
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

## Project Structure

```
aqtox-pq-implementation/
├── README.md                          # This file
├── docs/
│   ├── 01-ARCHITECTURE.md             # Detailed technical architecture
│   ├── 02-CRYPTO-DESIGN.md            # Cryptographic protocol specification
│   ├── 03-PROTOCOL-NEGOTIATION.md     # ToxExt capability negotiation
│   └── 04-SECURITY-CONSIDERATIONS.md  # Threat model and security analysis
├── phases/
│   ├── PHASE-1-FOUNDATION.md          # libsodium upgrade, hybrid primitives
│   ├── PHASE-2-HANDSHAKE.md           # Session establishment modifications
│   ├── PHASE-3-INTEGRATION.md         # aTox integration and UI
│   └── PHASE-4-TESTING.md             # Test strategy and validation
├── c-toxcore-patches/
│   ├── crypto_core_pq.h               # New PQ crypto header
│   ├── crypto_core_pq.c               # Hybrid KDF implementation
│   ├── net_crypto_pq.h                # PQ handshake extensions
│   ├── net_crypto_pq.c                # Handshake implementation
│   └── toxext_pq.c                    # ToxExt capability module
├── tox4j-patches/
│   └── pq_bindings.md                 # JNI binding modifications
└── atox-patches/
    └── ui_security_status.md          # Android UI changes
```

## Implementation Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1: Foundation | 4-6 weeks | Hybrid crypto primitives in c-toxcore |
| Phase 2: Handshake | 6-8 weeks | PQ-capable session establishment |
| Phase 3: Integration | 4-6 weeks | Android client with security UI |
| Phase 4: Testing | 2-4 weeks | Interop testing, security review |
| **Total MVP** | **16-24 weeks** | Production-ready hybrid client |

## Quick Start

### Prerequisites

- Android Studio Arctic Fox or later
- NDK r25 or later
- CMake 3.18+
- libsodium master branch (with ML-KEM-768 support)

### Build Steps (when implementation is complete)

```bash
# Clone the fork
git clone --recurse-submodules https://github.com/YOUR_USERNAME/aqTox-PQ.git
cd aqTox-PQ

# Build modified c-toxcore with PQ support
cd c-toxcore
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
         -DANDROID_ABI=arm64-v8a \
         -DANDROID_PLATFORM=android-26
make -j$(nproc)

# Build tox4j with PQ bindings
cd ../../tox4j
./scripts/build-aarch64-linux-android -j$(nproc) release

# Build aqTox-PQ
cd ..
./gradlew assembleRelease
```

## Security Properties

### With PQ-capable peer (hybrid mode)
- **Key exchange**: X25519 + ML-KEM-768 combined via HKDF-SHA512
- **Forward secrecy**: Per-session ephemeral keys for both X25519 and ML-KEM
- **Quantum resistance**: Session keys secure against quantum adversary
- **Classical security**: Maintains X25519 security if ML-KEM has implementation bugs

### With legacy peer (classical fallback)
- **Key exchange**: X25519 only (existing Tox security)
- **User notification**: UI indicates reduced security level
- **No protocol break**: Legacy clients work normally

## Contributing

See individual phase documents for detailed implementation guidance. Key areas needing work:

1. **c-toxcore crypto**: Core hybrid key exchange implementation
2. **Protocol design**: ToxExt message format finalization  
3. **Android UI**: Security indicator design
4. **Testing**: Interoperability test suite

## License

GPL-3.0 (same as c-toxcore and aTox)

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/)
- [libsodium ML-KEM API](https://doc.libsodium.org/)
- [Tox Protocol Specification](https://toktok.ltd/spec.html)
- [ToxExt Protocol](https://github.com/toxext/toxext)
