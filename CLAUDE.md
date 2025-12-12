# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a fork of TokTok/c-toxcore implementing **ML-KEM-768 + X25519 hybrid post-quantum key exchange** for the Tox peer-to-peer messenger. The goal is quantum-resistant encryption while maintaining backwards compatibility with legacy Tox clients.

**Implementation specs**: `docs/pq-hybrid/` — start with `PHASE-1-FOUNDATION.md`

## Build Commands

```bash
# Initialize submodules (required for cmp library)
git submodule update --init

# Standard build
mkdir _build && cd _build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# Build with all tests enabled
cmake .. -DAUTOTEST=ON -DUNITTEST=ON -DTEST_TIMEOUT_SECONDS=120

# Run all tests
ctest -j$(nproc) --output-on-failure

# Run a single unit test (GTest-based, in toxcore/)
./unit_crypto_core_test

# Run a single integration test (in auto_tests/)
./auto_crypto_test
```

## Key CMake Options

| Option | Description |
|--------|-------------|
| `AUTOTEST=ON` | Enable integration tests in `auto_tests/` |
| `UNITTEST=ON` | Enable unit tests (requires GTest) |
| `BUILD_TOXAV=ON` | Build audio/video library (requires opus, vpx) |
| `MIN_LOGGER_LEVEL=TRACE` | Set logging verbosity |

## Architecture

### Core Layers
- **toxcore/** — Main protocol implementation (Messenger, DHT, net_crypto)
- **toxav/** — Audio/video streaming
- **toxencryptsave/** — Profile encryption

### Crypto Stack (what you'll modify for PQ)
- `toxcore/crypto_core.h/.c` — Current X25519/XSalsa20/Poly1305 primitives
- `toxcore/net_crypto.h/.c` — Session establishment, handshake protocol
- `toxcore/shared_key_cache.c` — Key caching (may need PQ-aware cache)

### Files to Create for PQ Hybrid
```
toxcore/crypto_core_pq.h    # Hybrid type definitions, API
toxcore/crypto_core_pq.c    # Hybrid KDF, ML-KEM wrappers
auto_tests/crypto_pq_test.c # Unit tests for PQ primitives
```

## Test Structure

- **Unit tests** (`toxcore/*_test.cc`): GTest-based, test individual functions
- **Integration tests** (`auto_tests/*_test.c`): Full protocol tests with networking
- Test naming: `unit_<module>_test` and `auto_<module>_test`

## PQ Implementation Reference

### ML-KEM-768 Sizes (NIST FIPS 203)
| Parameter | Bytes |
|-----------|-------|
| Public key | 1,184 |
| Secret key | 2,400 |
| Ciphertext | 1,088 |
| Shared secret | 32 |

### Hybrid KDF Construction
```
IKM = 0xFF[32] || X25519_shared || ML-KEM_shared
PRK = HKDF-Extract(salt=zeros, IKM)
Key = HKDF-Expand(PRK, "ToxHybridKDF" || version || context, 32)
```

Security holds if EITHER X25519 OR ML-KEM remains secure.

### libsodium APIs (requires master branch)
```c
crypto_kem_mlkem768_keypair(pk, sk)
crypto_kem_mlkem768_enc(ct, ss, pk)      // Encapsulate
crypto_kem_mlkem768_dec(ss, ct, sk)      // Decapsulate
crypto_kdf_hkdf_sha512_extract(prk, salt, salt_len, ikm, ikm_len)
crypto_kdf_hkdf_sha512_expand(out, out_len, info, info_len, prk)
```

## Code Style

- C99/C11 standard
- Use `sodium_memzero()` for clearing sensitive data
- Error return: 0 = success, -1 = failure
- Use existing `ccompat.h` macros for portability
- SPDX license headers on new files: `/* SPDX-License-Identifier: GPL-3.0-or-later */`

## CI/CD

CI runs on pull requests via `.github/workflows/ci.yml`:
- Sanitizers: ASan, TSan, UBSan
- Static analysis: clang-tidy, cppcheck, tokstyle
- Cross-platform: Linux, macOS, Windows, FreeBSD, NetBSD
