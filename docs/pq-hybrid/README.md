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
| Negotiation | In-band signaling | PQ marker (0x02) in cookie request, no protocol break |
| Identity | ML-KEM commitment | 46-byte Tox ID with 8-byte ML-KEM commitment for quantum-resistant identity |

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         aqTox-PQ (Android)                          │
├─────────────────────────────────────────────────────────────────────┤
│  Kotlin UI Layer          │  Security Status Display                │
│  - Connection indicators  │  - "PQ-Verified" / "PQ" / "Classical"  │
│  - Settings for PQ policy │  - Per-friend identity status           │
├───────────────────────────┴─────────────────────────────────────────┤
│                         tox4j JNI Bridge                            │
│  - Extended API for PQ status queries                               │
│  - Hybrid identity management (46-byte addresses)                   │
├─────────────────────────────────────────────────────────────────────┤
│                    c-toxcore (Modified)                             │
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

## Project Structure

```
docs/pq-hybrid/
├── README.md                          # This file
├── 01-ARCHITECTURE.md                 # Detailed technical architecture
├── 02-CRYPTO-DESIGN.md                # Cryptographic protocol specification
├── 03-PROTOCOL-NEGOTIATION.md         # In-band capability negotiation
├── 05-IDENTITY-COMMITMENT.md          # Quantum-resistant identity (46-byte address)
├── PHASE-1-FOUNDATION.md              # ML-KEM + X25519 primitives (✅ Complete)
├── PHASE-2-HANDSHAKE.md               # Session establishment (✅ Complete)
├── PHASE-3-INTEGRATION.md             # aTox integration and UI
└── PHASE-4-TESTING.md                 # Test strategy and validation

toxcore/ (modified files)
├── crypto_core_pq.h                   # PQ crypto API: hybrid KDF, ML-KEM wrappers, commitment
├── crypto_core_pq.c                   # Implementation of PQ primitives
├── net_crypto.h/.c                    # Modified for hybrid handshake, in-band PQ negotiation
├── Messenger.h/.c                     # Extended for 46-byte PQ address, identity status
├── tox.h                              # Public API additions (PQ address, identity status)
└── tox_struct.h                       # Identity status callback

auto_tests/
└── crypto_pq_test.c                   # Unit tests for PQ primitives and commitment
```

## Implementation Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1: Foundation | ✅ **Complete** | ML-KEM-768 + X25519 hybrid primitives, HKDF key derivation |
| Phase 2: Handshake | ✅ **Complete** | In-band PQ negotiation, hybrid cookie/handshake packets |
| Phase 2.5: Identity | ✅ **Complete** | 46-byte PQ Tox ID with ML-KEM commitment |
| Phase 3: Integration | 📋 Planned | aTox Android integration, UI security indicators |
| Phase 4: Testing | 📋 Planned | Comprehensive test suite, security audit |

### Phase 1 & 2 Highlights

- **Hybrid KDF**: `HKDF-SHA512(0xFF[32] || X25519_shared || ML-KEM_shared)` - secure if either primitive is secure
- **In-band negotiation**: Version byte 0x02 in cookie request padding signals PQ capability
- **Graceful fallback**: Automatically falls back to X25519-only for classical peers
- **All tests passing**: Unit tests for crypto primitives and integration tests

### Phase 2.5 Identity Highlights

- **46-byte PQ address**: `[X25519:32][ML-KEM_commit:8][nospam:4][checksum:2]`
- **ML-KEM commitment**: `SHA256(ML-KEM_public_key)[0:8]` for quantum-resistant identity
- **Identity verification API**: `tox_friend_get_identity_status()` returns CLASSICAL/PQ_UNVERIFIED/PQ_VERIFIED
- **Backwards compatible**: 38-byte addresses still work, but identity not quantum-verified

## Original Timeline (for reference)

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

### With PQ-capable peer (hybrid mode + PQ identity)
- **Key exchange**: X25519 + ML-KEM-768 combined via HKDF-SHA512
- **Forward secrecy**: Per-session ephemeral keys for both X25519 and ML-KEM
- **Quantum resistance**: Session keys secure against quantum adversary
- **Classical security**: Maintains X25519 security if ML-KEM has implementation bugs
- **Identity verification**: ML-KEM commitment in 46-byte address provides quantum-resistant identity
- **Identity status**: `PQ_VERIFIED` - Full quantum protection for both session and identity

### With PQ-capable peer (hybrid mode, no PQ identity)
- **Key exchange**: Same as above (quantum-resistant session keys)
- **Identity**: X25519 public key only (friend added with 38-byte address)
- **Identity status**: `PQ_UNVERIFIED` - Session quantum-safe, but identity could theoretically be spoofed by quantum attacker
- **User notification**: UI indicates "PQ" badge (vs "PQ-Verified")

### With legacy peer (classical fallback)
- **Key exchange**: X25519 only (existing Tox security)
- **Identity status**: `CLASSICAL` - No quantum protection
- **User notification**: UI indicates "Classical" badge
- **No protocol break**: Legacy clients work normally

## Contributing

See individual phase documents for detailed implementation guidance. Key areas needing work:

1. **Android UI**: Security indicator design (Phase 3)
2. **tox4j bindings**: JNI bridge for PQ address and identity status APIs
3. **Testing**: Interoperability test suite with real devices
4. **Security audit**: Third-party review of cryptographic implementation

## License

GPL-3.0 (same as c-toxcore and aTox)

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) - Future: ML-DSA for identity signatures
- [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/) - Inspiration for hybrid design
- [libsodium ML-KEM API](https://doc.libsodium.org/public-key_cryptography/kem) - Implementation reference
- [Tox Protocol Specification](https://toktok.ltd/spec.html) - Base protocol
