# Architecture Deep Dive

## Current Tox Cryptographic Architecture

Understanding the existing crypto flow is essential before modifying it.

### Layer Model

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Messenger (Messenger.c)                                │
│ - Friend management, message routing                            │
│ - Uses net_crypto for all secure communications                 │
│ - Public API: tox.h                                             │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: Net Crypto (net_crypto.c) ← PRIMARY MODIFICATION POINT │
│ - Session key establishment (cookie + handshake)                │
│ - Encrypted packet framing                                      │
│ - Connection state management                                   │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: DHT + Onion (DHT.c, onion*.c)                          │
│ - Peer discovery, NAT traversal                                 │
│ - Onion routing for friend finding                              │
│ - Each layer has own crypto (future scope)                      │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1: Crypto Core (crypto_core.c) ← FOUNDATION MODIFICATIONS │
│ - All cryptographic primitives                                  │
│ - Key generation, encryption, authentication                    │
├─────────────────────────────────────────────────────────────────┤
│ Layer 0: libsodium                                              │
│ - NaCl primitives + ML-KEM-768 (new)                            │
└─────────────────────────────────────────────────────────────────┘
```

### Current Cryptographic Primitives (crypto_core.c)

| Function | Algorithm | Key Size | Purpose |
|----------|-----------|----------|---------|
| `crypto_box_keypair` | X25519 | 32 bytes | Identity/session keys |
| `crypto_box` | XSalsa20-Poly1305 | 32 bytes | Authenticated encryption |
| `crypto_box_beforenm` | X25519 ECDH | 32 bytes | Shared secret derivation |
| `crypto_secretbox` | XSalsa20-Poly1305 | 32 bytes | Symmetric encryption |
| `crypto_hash_sha512` | SHA-512 | 64 bytes | Hashing |
| `random_nonce` | /dev/urandom | 24 bytes | Nonce generation |

### Key Types in Current Tox

```c
// Identity keypair (permanent)
struct Tox_Identity {
    uint8_t public_key[32];    // X25519 public
    uint8_t secret_key[32];    // X25519 secret
};

// Ephemeral session keypair  
struct Session_Keys {
    uint8_t session_public[32];
    uint8_t session_secret[32];
    uint8_t shared_key[32];    // DH result
};

// Tox Address (for friend requests)
// [32-byte public key][4-byte nospam][2-byte checksum] = 38 bytes
```

## Hybrid Architecture Design

### New Key Structures

```c
/* crypto_core_pq.h */

// Protocol version identifiers
#define TOX_CRYPTO_VERSION_CLASSIC  0x01
#define TOX_CRYPTO_VERSION_HYBRID   0x02

// ML-KEM-768 sizes (from libsodium)
#define TOX_MLKEM_PUBLICKEYBYTES    1184
#define TOX_MLKEM_SECRETKEYBYTES    2400  
#define TOX_MLKEM_CIPHERTEXTBYTES   1088
#define TOX_MLKEM_SHAREDSECRETBYTES 32

// Combined hybrid public key
#define TOX_HYBRID_PUBLICKEYBYTES   (1 + 32 + TOX_MLKEM_PUBLICKEYBYTES)  // 1217 bytes

// Hybrid identity structure
typedef struct Tox_Hybrid_Identity {
    uint8_t version;                              // 0x02 for hybrid
    uint8_t x25519_public[32];
    uint8_t x25519_secret[32];
    uint8_t mlkem_public[TOX_MLKEM_PUBLICKEYBYTES];
    uint8_t mlkem_secret[TOX_MLKEM_SECRETKEYBYTES];
} Tox_Hybrid_Identity;

// Hybrid session keys
typedef struct Tox_Hybrid_Session {
    uint8_t x25519_ephemeral_public[32];
    uint8_t x25519_ephemeral_secret[32];
    uint8_t x25519_shared[32];
    
    uint8_t mlkem_ciphertext[TOX_MLKEM_CIPHERTEXTBYTES];
    uint8_t mlkem_shared[32];
    
    uint8_t combined_session_key[32];  // Final hybrid key
    
    bool peer_pq_capable;
} Tox_Hybrid_Session;

// Capability flags for negotiation
typedef struct Tox_PQ_Capabilities {
    uint16_t protocol_version;         // 0x0002 for hybrid
    uint16_t supported_kems;           // Bitmask: bit 0 = ML-KEM-768
    uint16_t supported_sigs;           // Future: ML-DSA support
    uint8_t  capability_hash[32];      // SHA256 of capability string
    uint8_t  signature[64];            // Ed25519 sig for commitment
} Tox_PQ_Capabilities;
```

### Hybrid Key Derivation Function

The core cryptographic construction combining X25519 and ML-KEM:

```c
/* crypto_core_pq.c */

#include <sodium.h>
#include "crypto_core_pq.h"

/**
 * Derive a hybrid session key from X25519 and ML-KEM shared secrets.
 * 
 * Construction follows Signal's PQXDH pattern:
 * - Domain separation prefix prevents cross-protocol attacks
 * - HKDF provides proper key stretching
 * - Security holds if EITHER X25519 OR ML-KEM is secure
 *
 * @param session_key   Output: 32-byte combined session key
 * @param x25519_shared Input: 32-byte X25519 DH result  
 * @param mlkem_shared  Input: 32-byte ML-KEM decapsulation result
 * @param context       Input: Context string (e.g., "ToxSession")
 * @param context_len   Input: Length of context string
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_kdf(
    uint8_t session_key[32],
    const uint8_t x25519_shared[32],
    const uint8_t mlkem_shared[32],
    const uint8_t *context,
    size_t context_len
) {
    // Input validation
    if (session_key == NULL || x25519_shared == NULL || mlkem_shared == NULL) {
        return -1;
    }
    
    // Domain separation: 32 bytes of 0xFF followed by secrets
    // This prevents using classical-only shared secrets in hybrid context
    uint8_t ikm[96];
    memset(ikm, 0xFF, 32);  // Domain separator
    memcpy(ikm + 32, x25519_shared, 32);
    memcpy(ikm + 64, mlkem_shared, 32);
    
    // HKDF-SHA512 extract
    uint8_t prk[64];
    static const uint8_t salt[64] = {0};  // Zero salt per PQXDH spec
    
    if (crypto_kdf_hkdf_sha512_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm)) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        return -1;
    }
    
    // HKDF-SHA512 expand with context
    uint8_t info[256];
    size_t info_len = 0;
    
    // Build info: "ToxHybridKDF" || version || context
    static const char prefix[] = "ToxHybridKDF";
    memcpy(info, prefix, sizeof(prefix) - 1);
    info_len += sizeof(prefix) - 1;
    info[info_len++] = TOX_CRYPTO_VERSION_HYBRID;
    
    if (context != NULL && context_len > 0 && context_len < 200) {
        memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }
    
    if (crypto_kdf_hkdf_sha512_expand(session_key, 32, (const char *)info, info_len, prk) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        sodium_memzero(prk, sizeof(prk));
        return -1;
    }
    
    // Secure cleanup
    sodium_memzero(ikm, sizeof(ikm));
    sodium_memzero(prk, sizeof(prk));
    
    return 0;
}

/**
 * Classical-only KDF for legacy peer fallback.
 * Uses same structure but with zeroed ML-KEM component.
 */
int tox_classical_kdf(
    uint8_t session_key[32],
    const uint8_t x25519_shared[32],
    const uint8_t *context,
    size_t context_len
) {
    // For classical mode, we use zeros for ML-KEM slot
    // This maintains consistent derivation structure
    uint8_t zero_mlkem[32] = {0};
    
    return tox_hybrid_kdf(session_key, x25519_shared, zero_mlkem, context, context_len);
}
```

### Key Generation

```c
/**
 * Generate a new hybrid identity keypair.
 *
 * @param identity Output: Populated hybrid identity structure
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_identity_generate(Tox_Hybrid_Identity *identity) {
    if (identity == NULL) {
        return -1;
    }
    
    identity->version = TOX_CRYPTO_VERSION_HYBRID;
    
    // Generate X25519 keypair
    if (crypto_box_keypair(identity->x25519_public, identity->x25519_secret) != 0) {
        return -1;
    }
    
    // Generate ML-KEM-768 keypair
    if (crypto_kem_mlkem768_keypair(identity->mlkem_public, identity->mlkem_secret) != 0) {
        sodium_memzero(identity->x25519_secret, 32);
        return -1;
    }
    
    return 0;
}

/**
 * Derive hybrid identity from seed (deterministic).
 * Used when loading from saved profile.
 */
int tox_hybrid_identity_from_seed(
    Tox_Hybrid_Identity *identity,
    const uint8_t seed[32]
) {
    if (identity == NULL || seed == NULL) {
        return -1;
    }
    
    identity->version = TOX_CRYPTO_VERSION_HYBRID;
    
    // Derive X25519 seed
    uint8_t x25519_seed[32];
    static const char x25519_ctx[] = "ToxX25519Seed";
    crypto_kdf_derive_from_key(x25519_seed, 32, 1, x25519_ctx, seed);
    crypto_box_seed_keypair(identity->x25519_public, identity->x25519_secret, x25519_seed);
    sodium_memzero(x25519_seed, 32);
    
    // Derive ML-KEM seed (64 bytes needed)
    uint8_t mlkem_seed[64];
    static const char mlkem_ctx[] = "ToxMLKEMSeed";
    crypto_kdf_derive_from_key(mlkem_seed, 64, 2, mlkem_ctx, seed);
    crypto_kem_mlkem768_seed_keypair(identity->mlkem_public, identity->mlkem_secret, mlkem_seed);
    sodium_memzero(mlkem_seed, 64);
    
    return 0;
}

/**
 * Export hybrid public key for sharing.
 * Format: [version byte][X25519 pubkey][ML-KEM pubkey]
 */
int tox_hybrid_public_key_export(
    uint8_t output[TOX_HYBRID_PUBLICKEYBYTES],
    const Tox_Hybrid_Identity *identity
) {
    if (output == NULL || identity == NULL) {
        return -1;
    }
    
    output[0] = identity->version;
    memcpy(output + 1, identity->x25519_public, 32);
    memcpy(output + 33, identity->mlkem_public, TOX_MLKEM_PUBLICKEYBYTES);
    
    return 0;
}

/**
 * Check if a public key is hybrid (has ML-KEM component).
 */
bool tox_public_key_is_hybrid(const uint8_t *public_key, size_t len) {
    if (public_key == NULL) {
        return false;
    }
    
    if (len == 32) {
        return false;  // Classical X25519 only
    }
    
    if (len == TOX_HYBRID_PUBLICKEYBYTES && public_key[0] == TOX_CRYPTO_VERSION_HYBRID) {
        return true;
    }
    
    return false;
}
```

### Session Establishment (Initiator Side)

```c
/**
 * Initiator creates hybrid session with peer.
 * Performs X25519 DH + ML-KEM encapsulation.
 */
int tox_hybrid_session_initiate(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_public_key,
    size_t peer_public_len
) {
    if (session == NULL || our_identity == NULL || peer_public_key == NULL) {
        return -1;
    }
    
    memset(session, 0, sizeof(Tox_Hybrid_Session));
    
    // Generate ephemeral X25519 keypair
    if (crypto_box_keypair(session->x25519_ephemeral_public, 
                           session->x25519_ephemeral_secret) != 0) {
        return -1;
    }
    
    // Check if peer supports hybrid
    session->peer_pq_capable = tox_public_key_is_hybrid(peer_public_key, peer_public_len);
    
    if (session->peer_pq_capable) {
        // Extract peer's X25519 and ML-KEM public keys
        const uint8_t *peer_x25519 = peer_public_key + 1;
        const uint8_t *peer_mlkem = peer_public_key + 33;
        
        // X25519 DH
        if (crypto_scalarmult(session->x25519_shared, 
                              session->x25519_ephemeral_secret,
                              peer_x25519) != 0) {
            goto cleanup;
        }
        
        // ML-KEM encapsulation
        if (crypto_kem_mlkem768_enc(session->mlkem_ciphertext,
                                     session->mlkem_shared,
                                     peer_mlkem) != 0) {
            goto cleanup;
        }
        
        // Combine into session key
        static const uint8_t session_ctx[] = "ToxSessionInit";
        if (tox_hybrid_kdf(session->combined_session_key,
                           session->x25519_shared,
                           session->mlkem_shared,
                           session_ctx, sizeof(session_ctx) - 1) != 0) {
            goto cleanup;
        }
    } else {
        // Classical fallback - X25519 only
        if (crypto_scalarmult(session->x25519_shared,
                              session->x25519_ephemeral_secret,
                              peer_public_key) != 0) {
            goto cleanup;
        }
        
        static const uint8_t session_ctx[] = "ToxSessionInit";
        if (tox_classical_kdf(session->combined_session_key,
                               session->x25519_shared,
                               session_ctx, sizeof(session_ctx) - 1) != 0) {
            goto cleanup;
        }
    }
    
    return 0;

cleanup:
    sodium_memzero(session, sizeof(Tox_Hybrid_Session));
    return -1;
}
```

### Session Establishment (Responder Side)

```c
/**
 * Responder completes hybrid session.
 * Performs X25519 DH + ML-KEM decapsulation.
 */
int tox_hybrid_session_respond(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_x25519_ephemeral,
    const uint8_t *mlkem_ciphertext,  // NULL if classical-only
    bool peer_is_hybrid
) {
    if (session == NULL || our_identity == NULL || peer_x25519_ephemeral == NULL) {
        return -1;
    }
    
    memset(session, 0, sizeof(Tox_Hybrid_Session));
    session->peer_pq_capable = peer_is_hybrid;
    
    // Generate our ephemeral X25519
    if (crypto_box_keypair(session->x25519_ephemeral_public,
                           session->x25519_ephemeral_secret) != 0) {
        return -1;
    }
    
    // X25519 DH with peer's ephemeral
    if (crypto_scalarmult(session->x25519_shared,
                          session->x25519_ephemeral_secret,
                          peer_x25519_ephemeral) != 0) {
        goto cleanup;
    }
    
    if (peer_is_hybrid && mlkem_ciphertext != NULL) {
        // ML-KEM decapsulation
        if (crypto_kem_mlkem768_dec(session->mlkem_shared,
                                     mlkem_ciphertext,
                                     our_identity->mlkem_secret) != 0) {
            goto cleanup;
        }
        
        // Store ciphertext for reference
        memcpy(session->mlkem_ciphertext, mlkem_ciphertext, TOX_MLKEM_CIPHERTEXTBYTES);
        
        // Hybrid key derivation
        static const uint8_t session_ctx[] = "ToxSessionResp";
        if (tox_hybrid_kdf(session->combined_session_key,
                           session->x25519_shared,
                           session->mlkem_shared,
                           session_ctx, sizeof(session_ctx) - 1) != 0) {
            goto cleanup;
        }
    } else {
        // Classical fallback
        static const uint8_t session_ctx[] = "ToxSessionResp";
        if (tox_classical_kdf(session->combined_session_key,
                               session->x25519_shared,
                               session_ctx, sizeof(session_ctx) - 1) != 0) {
            goto cleanup;
        }
    }
    
    return 0;

cleanup:
    sodium_memzero(session, sizeof(Tox_Hybrid_Session));
    return -1;
}
```

## File Modification Map

### c-toxcore Files to Modify

| File | Changes | Priority |
|------|---------|----------|
| `toxcore/crypto_core.h` | Add hybrid key size constants, new function declarations | Phase 1 |
| `toxcore/crypto_core.c` | Add hybrid KDF, key generation functions | Phase 1 |
| `toxcore/crypto_core_pq.h` | **NEW** - PQ-specific structures and constants | Phase 1 |
| `toxcore/crypto_core_pq.c` | **NEW** - Hybrid crypto implementation | Phase 1 |
| `toxcore/net_crypto.h` | Extend session structures for hybrid keys | Phase 2 |
| `toxcore/net_crypto.c` | Modify handshake to use hybrid KDF | Phase 2 |
| `toxcore/Messenger.h` | Add PQ capability to friend structures | Phase 2 |
| `toxcore/Messenger.c` | Friend key handling with hybrid support | Phase 2 |
| `toxcore/tox.h` | Public API for PQ status queries | Phase 2 |
| `toxcore/tox.c` | API implementations | Phase 2 |
| `CMakeLists.txt` | Ensure libsodium version with ML-KEM | Phase 1 |

## Quantum-Resistant Identity

### The Identity Problem

Current Tox IDs only contain X25519 public keys, which are vulnerable to quantum attack. Even with hybrid session keys (ML-KEM + X25519), a quantum attacker could:

1. Derive the private key from a Tox ID's X25519 public key
2. Impersonate the user by establishing sessions with their identity

Session security is not enough - we need quantum-resistant identity verification.

### 46-Byte PQ Tox Address

The solution is an extended Tox address that includes an ML-KEM commitment:

```
Classical (38 bytes): [X25519_pk:32][nospam:4][checksum:2]
PQ (46 bytes):        [X25519_pk:32][MLKEM_commit:8][nospam:4][checksum:2]
```

Where:
- `MLKEM_commit = SHA256(ML-KEM_public_key)[0:8]`
- Checksum covers first 44 bytes for PQ address

### Commitment Verification Flow

```
┌─────────────────┐                    ┌─────────────────┐
│   Alice (PQ)    │                    │    Bob (PQ)     │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │ 1. Alice adds Bob with 46-byte address
         │    Stores MLKEM_commit for Bob
         │                                      │
         │ 2. Cookie Request (version=0x02)     │
         ├─────────────────────────────────────>│
         │                                      │
         │ 3. Cookie Response + ML-KEM pubkey   │
         │<─────────────────────────────────────┤
         │                                      │
         │ 4. Alice verifies:                   │
         │    SHA256(Bob_mlkem_pk)[0:8] == stored_commitment?
         │    ✓ Match: Connection proceeds      │
         │    ✗ Mismatch: Reject (impersonation!)
         │                                      │
         │ 5. Hybrid Handshake (ML-KEM + X25519)│
         │<────────────────────────────────────>│
         │                                      │
         │ 6. Connection established:           │
         │    identity_status = PQ_VERIFIED     │
```

### Identity Status Levels

| Status | Meaning | UI Indicator |
|--------|---------|--------------|
| `CLASSICAL` | X25519-only connection | ⚠️ "Classical" |
| `PQ_UNVERIFIED` | Hybrid session, 38-byte address (no commitment) | "PQ" |
| `PQ_VERIFIED` | Hybrid session, commitment verified | ✅ "PQ-Verified" |

### Security Properties

- **PQ_VERIFIED**: Full quantum-resistant security
  - Session keys protected by ML-KEM + X25519
  - Identity bound to ML-KEM public key
  - Quantum attacker cannot impersonate

- **PQ_UNVERIFIED**: Partial protection
  - Session keys quantum-resistant
  - Identity NOT quantum-protected (38-byte address used)
  - Quantum attacker could theoretically impersonate during initial add

- **CLASSICAL**: No quantum protection
  - Legacy interoperability mode
  - Vulnerable to quantum attacks on both session and identity

## Backwards Compatibility Matrix

| Client A | Client B | Key Exchange | Session Security | Identity Security |
|----------|----------|--------------|------------------|-------------------|
| c-toxcore-pq (46-byte) | c-toxcore-pq | Hybrid | Quantum-resistant | PQ_VERIFIED |
| c-toxcore-pq (38-byte) | c-toxcore-pq | Hybrid | Quantum-resistant | PQ_UNVERIFIED |
| c-toxcore-pq | Legacy Tox | X25519 only | Classical | CLASSICAL |
| Legacy Tox | c-toxcore-pq | X25519 only | Classical | CLASSICAL |
| Legacy Tox | Legacy Tox | X25519 only | Classical | CLASSICAL |

The PQ-capable client initiates capability discovery and gracefully falls back when the peer doesn't support PQ extensions.
