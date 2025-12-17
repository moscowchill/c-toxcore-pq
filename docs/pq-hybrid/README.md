# c-toxcore-pq: Hybrid Post-Quantum Tox Protocol Implementation

**Project**: ML-KEM-768 + X25519 hybrid post-quantum key exchange for c-toxcore
**Base Fork**: [TokTok/c-toxcore](https://github.com/TokTok/c-toxcore)
**Target**: Quantum-resistant encryption with backwards compatibility for legacy Tox clients

## Executive Summary

This implementation adds post-quantum cryptographic protection to the Tox protocol while maintaining full backwards compatibility with existing Tox clients. The approach uses libsodium's native ML-KEM-768 implementation combined with existing X25519 in a hybrid scheme, ensuring security even if one primitive is broken.

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| PQ Algorithm | ML-KEM-768 | NIST FIPS 203 standardized, available in libsodium master |
| Hybrid Mode | X25519 + ML-KEM-768 | Belt-and-suspenders security during transition |
| Compatibility | Full Interop | Negotiate PQ with capable peers, fallback to classical |
| Library | libsodium only | No external PQ library needed, simplifies build |
| Negotiation | In-band signaling | PQ marker (0x02) in cookie request, no protocol break |
| Identity | ML-KEM commitment | 46-byte Tox ID with 8-byte ML-KEM commitment for quantum-resistant identity |

## Project Structure

```
docs/pq-hybrid/
├── README.md                          # This file
├── 01-ARCHITECTURE.md                 # Detailed technical architecture
├── 02-CRYPTO-DESIGN.md                # Cryptographic protocol specification
├── 03-PROTOCOL-NEGOTIATION.md         # In-band capability negotiation
├── 05-IDENTITY-COMMITMENT.md          # Quantum-resistant identity (46-byte address)
├── PHASE-1-FOUNDATION.md              # ML-KEM + X25519 primitives
├── PHASE-2-HANDSHAKE.md               # Session establishment
├── PHASE-4-TESTING.md                 # Test strategy and validation
└── qatox/                             # Android client documentation (separate)
    ├── README.md
    └── PHASE-3-INTEGRATION.md

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
| Phase 1: Foundation | **Complete** | ML-KEM-768 + X25519 hybrid primitives, HKDF key derivation |
| Phase 2: Handshake | **Complete** | In-band PQ negotiation, hybrid cookie/handshake packets |
| Phase 2.5: Identity | **Complete** | 46-byte PQ Tox ID with ML-KEM commitment |
| Phase 4: Testing | **In Progress** | Comprehensive test suite, security validation |

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

## Quick Start

### Prerequisites

- CMake 3.18+
- libsodium master branch (with ML-KEM-768 support)
- GTest (for unit tests)

### Build

```bash
# Initialize submodules (required for cmp library)
git submodule update --init

# Build
mkdir _build && cd _build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DAUTOTEST=ON -DUNITTEST=ON

make -j$(nproc)

# Run all tests
ctest -j$(nproc) --output-on-failure
```

### Build libsodium from Source (if needed)

```bash
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig
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

### With legacy peer (classical fallback)
- **Key exchange**: X25519 only (existing Tox security)
- **Identity status**: `CLASSICAL` - No quantum protection
- **No protocol break**: Legacy clients work normally

## Backwards Compatibility Matrix

| Client A | Client B | Key Exchange | Session Security | Identity Security |
|----------|----------|--------------|------------------|-------------------|
| c-toxcore-pq (46-byte) | c-toxcore-pq | Hybrid | Quantum-resistant | PQ_VERIFIED |
| c-toxcore-pq (38-byte) | c-toxcore-pq | Hybrid | Quantum-resistant | PQ_UNVERIFIED |
| c-toxcore-pq | Legacy Tox | X25519 only | Classical | CLASSICAL |
| Legacy Tox | c-toxcore-pq | X25519 only | Classical | CLASSICAL |
| Legacy Tox | Legacy Tox | X25519 only | Classical | CLASSICAL |

## Public API Additions

### Get PQ Tox Address

```c
// Get 46-byte PQ address with ML-KEM commitment
bool tox_self_get_address_pq(const Tox *tox, uint8_t address[TOX_ADDRESS_SIZE_PQ]);

// Check if PQ identity available
bool tox_self_has_pq_identity(const Tox *tox);
```

### Add Friend with PQ Address

```c
// Add friend with 46-byte PQ address
Tox_Friend_Number tox_friend_add_pq(
    Tox *tox,
    const uint8_t address[TOX_ADDRESS_SIZE_PQ],
    const uint8_t message[],
    size_t length,
    Tox_Err_Friend_Add *error);
```

### Query Identity Status

```c
typedef enum Tox_Connection_Identity {
    TOX_CONNECTION_IDENTITY_UNKNOWN,
    TOX_CONNECTION_IDENTITY_CLASSICAL,
    TOX_CONNECTION_IDENTITY_PQ_UNVERIFIED,
    TOX_CONNECTION_IDENTITY_PQ_VERIFIED,
} Tox_Connection_Identity;

Tox_Connection_Identity tox_friend_get_identity_status(
    const Tox *tox,
    Tox_Friend_Number friend_number,
    Tox_Err_Friend_Query *error);
```

## Contributing

See individual phase documents for detailed implementation guidance. Key areas:

1. **Testing**: Expand test coverage, fuzzing
2. **Security audit**: Third-party review of cryptographic implementation
3. **Client integration**: See [qatox/](qatox/) for Android client documentation

## License

GPL-3.0-or-later (same as c-toxcore)

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) - Future: ML-DSA for identity signatures
- [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/) - Inspiration for hybrid design
- [libsodium ML-KEM API](https://doc.libsodium.org/public-key_cryptography/kem) - Implementation reference
- [Tox Protocol Specification](https://toktok.ltd/spec.html) - Base protocol
