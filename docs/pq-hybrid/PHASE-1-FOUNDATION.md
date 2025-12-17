# Phase 1: Foundation

**Goal**: Establish hybrid cryptographic primitives in c-toxcore

## Overview

Phase 1 focuses on:
1. Upgrading libsodium to a version with ML-KEM-768
2. Implementing hybrid key derivation functions
3. Creating hybrid identity structures
4. Building test harness for crypto primitives

No protocol changes yet - this phase creates the building blocks.

## Prerequisites

### Development Environment

```bash
# Required tools
sudo apt-get install build-essential cmake ninja-build
sudo apt-get install autoconf automake libtool
sudo apt-get install pkg-config
```

### libsodium with ML-KEM Support

As of your discovery, libsodium master branch includes ML-KEM-768. Verify:

```bash
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git log --oneline | head -20  # Check for ML-KEM commits

# Check API availability
grep -r "crypto_kem_mlkem768" src/
```

## Step 1: Fork and Set Up c-toxcore

### 1.1 Fork c-toxcore

```bash
# Fork TokTok/c-toxcore on GitHub first, then:
git clone --recurse-submodules https://github.com/YOUR_USERNAME/c-toxcore.git
cd c-toxcore
git remote add upstream https://github.com/TokTok/c-toxcore.git
git checkout -b feature/pq-hybrid
```

### 1.2 Update libsodium Dependency

Edit `CMakeLists.txt` to require a libsodium version with ML-KEM:

```cmake
# Find libsodium with ML-KEM support
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium>=1.0.20)

# Verify ML-KEM availability at configure time
include(CheckSymbolExists)
set(CMAKE_REQUIRED_LIBRARIES ${LIBSODIUM_LIBRARIES})
set(CMAKE_REQUIRED_INCLUDES ${LIBSODIUM_INCLUDE_DIRS})
check_symbol_exists(crypto_kem_mlkem768_keypair sodium.h HAVE_MLKEM768)
if(NOT HAVE_MLKEM768)
    message(FATAL_ERROR "libsodium does not have ML-KEM-768 support. "
                        "Please use libsodium master branch or version >= 1.0.20")
endif()
```

### 1.3 Build libsodium from Source (if needed)

```bash
# Clone and build libsodium master
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig

# Verify
pkg-config --modversion libsodium
# Should show version with ML-KEM support
```

## Step 2: Create Crypto Core PQ Module

### 2.1 Create Header File

Create `toxcore/crypto_core_pq.h`:

```c
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2024 c-toxcore-pq contributors
 *
 * Post-quantum hybrid cryptographic primitives for Tox.
 */

#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_PQ_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_PQ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Constants
 ******************************************************************************/

/** Protocol version identifiers */
#define TOX_CRYPTO_VERSION_CLASSIC  0x01
#define TOX_CRYPTO_VERSION_HYBRID   0x02

/** ML-KEM-768 sizes (NIST FIPS 203) */
#define TOX_MLKEM768_PUBLICKEYBYTES     1184
#define TOX_MLKEM768_SECRETKEYBYTES     2400
#define TOX_MLKEM768_CIPHERTEXTBYTES    1088
#define TOX_MLKEM768_SHAREDSECRETBYTES  32

/** Combined key sizes */
#define TOX_HYBRID_PUBLICKEYBYTES   (1 + 32 + TOX_MLKEM768_PUBLICKEYBYTES)
#define TOX_HYBRID_SECRETKEYBYTES   (1 + 32 + TOX_MLKEM768_SECRETKEYBYTES)

/** Session key size (output of KDF) */
#define TOX_SESSION_KEY_BYTES       32

/*******************************************************************************
 * Data Structures
 ******************************************************************************/

/**
 * Hybrid identity containing both X25519 and ML-KEM-768 keypairs.
 */
typedef struct Tox_Hybrid_Identity {
    uint8_t version;
    uint8_t x25519_public[32];
    uint8_t x25519_secret[32];
    uint8_t mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES];
    uint8_t mlkem_secret[TOX_MLKEM768_SECRETKEYBYTES];
} Tox_Hybrid_Identity;

/**
 * Hybrid session state for key exchange.
 */
typedef struct Tox_Hybrid_Session {
    /* Ephemeral X25519 keys for this session */
    uint8_t x25519_ephemeral_public[32];
    uint8_t x25519_ephemeral_secret[32];
    uint8_t x25519_shared[32];
    
    /* ML-KEM encapsulation data */
    uint8_t mlkem_ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES];
    uint8_t mlkem_shared[32];
    
    /* Final combined session key */
    uint8_t session_key[TOX_SESSION_KEY_BYTES];
    
    /* State flags */
    bool peer_pq_capable;
    bool session_established;
} Tox_Hybrid_Session;

/*******************************************************************************
 * Key Generation
 ******************************************************************************/

/**
 * Generate a new hybrid identity keypair.
 *
 * @param identity Output structure for the new identity
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_identity_generate(Tox_Hybrid_Identity *identity);

/**
 * Generate hybrid identity from a 32-byte seed (deterministic).
 *
 * @param identity Output structure
 * @param seed 32-byte random seed
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_identity_from_seed(
    Tox_Hybrid_Identity *identity,
    const uint8_t seed[32]
);

/**
 * Securely erase a hybrid identity from memory.
 *
 * @param identity Identity to erase
 */
void tox_hybrid_identity_clear(Tox_Hybrid_Identity *identity);

/*******************************************************************************
 * Public Key Operations
 ******************************************************************************/

/**
 * Export hybrid public key for sharing.
 * Format: [version][X25519 pubkey][ML-KEM pubkey]
 *
 * @param output Output buffer (TOX_HYBRID_PUBLICKEYBYTES)
 * @param identity Source identity
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_public_key_export(
    uint8_t output[TOX_HYBRID_PUBLICKEYBYTES],
    const Tox_Hybrid_Identity *identity
);

/**
 * Check if a public key is hybrid format.
 *
 * @param public_key Public key data
 * @param len Length of public key
 * @return true if hybrid, false if classical
 */
bool tox_public_key_is_hybrid(const uint8_t *public_key, size_t len);

/**
 * Extract X25519 component from a public key (works for both formats).
 *
 * @param x25519_out Output buffer (32 bytes)
 * @param public_key Input public key
 * @param len Length of input
 * @return 0 on success, -1 on failure
 */
int tox_public_key_get_x25519(
    uint8_t x25519_out[32],
    const uint8_t *public_key,
    size_t len
);

/**
 * Extract ML-KEM component from a hybrid public key.
 *
 * @param mlkem_out Output buffer (TOX_MLKEM768_PUBLICKEYBYTES)
 * @param public_key Input hybrid public key
 * @param len Length of input
 * @return 0 on success, -1 if not hybrid or invalid
 */
int tox_public_key_get_mlkem(
    uint8_t mlkem_out[TOX_MLKEM768_PUBLICKEYBYTES],
    const uint8_t *public_key,
    size_t len
);

/*******************************************************************************
 * Key Derivation Functions
 ******************************************************************************/

/**
 * Derive hybrid session key from X25519 and ML-KEM shared secrets.
 *
 * @param session_key Output 32-byte session key
 * @param x25519_shared 32-byte X25519 DH result
 * @param mlkem_shared 32-byte ML-KEM decapsulation result
 * @param context Optional context string
 * @param context_len Length of context
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_kdf(
    uint8_t session_key[TOX_SESSION_KEY_BYTES],
    const uint8_t x25519_shared[32],
    const uint8_t mlkem_shared[32],
    const uint8_t *context,
    size_t context_len
);

/**
 * Derive session key for classical-only fallback.
 *
 * @param session_key Output 32-byte session key
 * @param x25519_shared 32-byte X25519 DH result
 * @param context Optional context string
 * @param context_len Length of context
 * @return 0 on success, -1 on failure
 */
int tox_classical_kdf(
    uint8_t session_key[TOX_SESSION_KEY_BYTES],
    const uint8_t x25519_shared[32],
    const uint8_t *context,
    size_t context_len
);

/*******************************************************************************
 * Session Establishment
 ******************************************************************************/

/**
 * Initialize hybrid session as initiator.
 * Performs X25519 DH + ML-KEM encapsulation.
 *
 * @param session Output session structure
 * @param our_identity Our hybrid identity
 * @param peer_public_key Peer's public key (hybrid or classical)
 * @param peer_public_len Length of peer's public key
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_session_initiate(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_public_key,
    size_t peer_public_len
);

/**
 * Complete hybrid session as responder.
 * Performs X25519 DH + ML-KEM decapsulation.
 *
 * @param session Output session structure
 * @param our_identity Our hybrid identity
 * @param peer_x25519_ephemeral Peer's ephemeral X25519 public key
 * @param mlkem_ciphertext ML-KEM ciphertext (NULL if classical)
 * @param peer_is_hybrid Whether peer sent hybrid handshake
 * @return 0 on success, -1 on failure
 */
int tox_hybrid_session_respond(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_x25519_ephemeral,
    const uint8_t *mlkem_ciphertext,
    bool peer_is_hybrid
);

/**
 * Securely clear session state.
 *
 * @param session Session to clear
 */
void tox_hybrid_session_clear(Tox_Hybrid_Session *session);

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

/**
 * Check if crypto_core_pq is properly initialized.
 *
 * @return true if ML-KEM is available and working
 */
bool tox_pq_available(void);

/**
 * Get human-readable description of PQ support status.
 *
 * @param buffer Output buffer
 * @param size Buffer size
 */
void tox_pq_status_string(char *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* C_TOXCORE_TOXCORE_CRYPTO_CORE_PQ_H */
```

### 2.2 Create Implementation File

Create `toxcore/crypto_core_pq.c`:

```c
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2024 c-toxcore-pq contributors
 */

#include "crypto_core_pq.h"
#include "ccompat.h"

#include <sodium.h>
#include <string.h>

/*******************************************************************************
 * Internal Constants
 ******************************************************************************/

static const char HYBRID_KDF_PREFIX[] = "ToxHybridKDF";
static const uint8_t DOMAIN_SEPARATOR[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*******************************************************************************
 * Key Generation
 ******************************************************************************/

int tox_hybrid_identity_generate(Tox_Hybrid_Identity *identity)
{
    if (identity == NULL) {
        return -1;
    }
    
    memset(identity, 0, sizeof(Tox_Hybrid_Identity));
    identity->version = TOX_CRYPTO_VERSION_HYBRID;
    
    /* Generate X25519 keypair */
    if (crypto_box_keypair(identity->x25519_public, identity->x25519_secret) != 0) {
        return -1;
    }
    
    /* Generate ML-KEM-768 keypair */
    if (crypto_kem_mlkem768_keypair(identity->mlkem_public, identity->mlkem_secret) != 0) {
        sodium_memzero(identity->x25519_secret, sizeof(identity->x25519_secret));
        return -1;
    }
    
    return 0;
}

int tox_hybrid_identity_from_seed(
    Tox_Hybrid_Identity *identity,
    const uint8_t seed[32]
)
{
    if (identity == NULL || seed == NULL) {
        return -1;
    }
    
    memset(identity, 0, sizeof(Tox_Hybrid_Identity));
    identity->version = TOX_CRYPTO_VERSION_HYBRID;
    
    /* Derive X25519 seed using KDF */
    uint8_t x25519_seed[32];
    if (crypto_kdf_derive_from_key(x25519_seed, 32, 1, "ToxX25519", seed) != 0) {
        return -1;
    }
    
    if (crypto_box_seed_keypair(identity->x25519_public, identity->x25519_secret, x25519_seed) != 0) {
        sodium_memzero(x25519_seed, sizeof(x25519_seed));
        return -1;
    }
    sodium_memzero(x25519_seed, sizeof(x25519_seed));
    
    /* Derive ML-KEM seed (needs 64 bytes for ML-KEM-768) */
    uint8_t mlkem_seed[64];
    if (crypto_kdf_derive_from_key(mlkem_seed, 32, 2, "ToxMLKEM", seed) != 0) {
        tox_hybrid_identity_clear(identity);
        return -1;
    }
    if (crypto_kdf_derive_from_key(mlkem_seed + 32, 32, 3, "ToxMLKEM", seed) != 0) {
        sodium_memzero(mlkem_seed, sizeof(mlkem_seed));
        tox_hybrid_identity_clear(identity);
        return -1;
    }
    
    if (crypto_kem_mlkem768_seed_keypair(identity->mlkem_public, identity->mlkem_secret, mlkem_seed) != 0) {
        sodium_memzero(mlkem_seed, sizeof(mlkem_seed));
        tox_hybrid_identity_clear(identity);
        return -1;
    }
    sodium_memzero(mlkem_seed, sizeof(mlkem_seed));
    
    return 0;
}

void tox_hybrid_identity_clear(Tox_Hybrid_Identity *identity)
{
    if (identity != NULL) {
        sodium_memzero(identity, sizeof(Tox_Hybrid_Identity));
    }
}

/*******************************************************************************
 * Public Key Operations
 ******************************************************************************/

int tox_hybrid_public_key_export(
    uint8_t output[TOX_HYBRID_PUBLICKEYBYTES],
    const Tox_Hybrid_Identity *identity
)
{
    if (output == NULL || identity == NULL) {
        return -1;
    }
    
    output[0] = identity->version;
    memcpy(output + 1, identity->x25519_public, 32);
    memcpy(output + 33, identity->mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES);
    
    return 0;
}

bool tox_public_key_is_hybrid(const uint8_t *public_key, size_t len)
{
    if (public_key == NULL) {
        return false;
    }
    
    if (len == TOX_HYBRID_PUBLICKEYBYTES && public_key[0] == TOX_CRYPTO_VERSION_HYBRID) {
        return true;
    }
    
    return false;
}

int tox_public_key_get_x25519(
    uint8_t x25519_out[32],
    const uint8_t *public_key,
    size_t len
)
{
    if (x25519_out == NULL || public_key == NULL) {
        return -1;
    }
    
    if (len == 32) {
        /* Classical format: just X25519 */
        memcpy(x25519_out, public_key, 32);
        return 0;
    }
    
    if (tox_public_key_is_hybrid(public_key, len)) {
        /* Hybrid format: skip version byte */
        memcpy(x25519_out, public_key + 1, 32);
        return 0;
    }
    
    return -1;
}

int tox_public_key_get_mlkem(
    uint8_t mlkem_out[TOX_MLKEM768_PUBLICKEYBYTES],
    const uint8_t *public_key,
    size_t len
)
{
    if (mlkem_out == NULL || public_key == NULL) {
        return -1;
    }
    
    if (!tox_public_key_is_hybrid(public_key, len)) {
        return -1;  /* Not a hybrid key */
    }
    
    memcpy(mlkem_out, public_key + 33, TOX_MLKEM768_PUBLICKEYBYTES);
    return 0;
}

/*******************************************************************************
 * Key Derivation Functions
 ******************************************************************************/

int tox_hybrid_kdf(
    uint8_t session_key[TOX_SESSION_KEY_BYTES],
    const uint8_t x25519_shared[32],
    const uint8_t mlkem_shared[32],
    const uint8_t *context,
    size_t context_len
)
{
    if (session_key == NULL || x25519_shared == NULL || mlkem_shared == NULL) {
        return -1;
    }
    
    /* Build input keying material:
     * IKM = domain_separator || x25519_shared || mlkem_shared
     */
    uint8_t ikm[96];
    memcpy(ikm, DOMAIN_SEPARATOR, 32);
    memcpy(ikm + 32, x25519_shared, 32);
    memcpy(ikm + 64, mlkem_shared, 32);
    
    /* HKDF-SHA512 Extract */
    uint8_t prk[64];
    static const uint8_t zero_salt[64] = {0};
    
    if (crypto_kdf_hkdf_sha512_extract(prk, zero_salt, sizeof(zero_salt), ikm, sizeof(ikm)) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        return -1;
    }
    
    /* Build info string:
     * info = "ToxHybridKDF" || version || context
     */
    uint8_t info[256];
    size_t info_len = 0;
    
    memcpy(info, HYBRID_KDF_PREFIX, sizeof(HYBRID_KDF_PREFIX) - 1);
    info_len += sizeof(HYBRID_KDF_PREFIX) - 1;
    
    info[info_len++] = TOX_CRYPTO_VERSION_HYBRID;
    
    if (context != NULL && context_len > 0) {
        size_t copy_len = (context_len < 200) ? context_len : 200;
        memcpy(info + info_len, context, copy_len);
        info_len += copy_len;
    }
    
    /* HKDF-SHA512 Expand */
    if (crypto_kdf_hkdf_sha512_expand(session_key, TOX_SESSION_KEY_BYTES, 
                                       (const char *)info, info_len, prk) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        sodium_memzero(prk, sizeof(prk));
        return -1;
    }
    
    /* Clean up */
    sodium_memzero(ikm, sizeof(ikm));
    sodium_memzero(prk, sizeof(prk));
    
    return 0;
}

int tox_classical_kdf(
    uint8_t session_key[TOX_SESSION_KEY_BYTES],
    const uint8_t x25519_shared[32],
    const uint8_t *context,
    size_t context_len
)
{
    /* For classical mode, use zero ML-KEM slot */
    uint8_t zero_mlkem[32] = {0};
    
    /* Same KDF but with version byte indicating classical */
    if (session_key == NULL || x25519_shared == NULL) {
        return -1;
    }
    
    uint8_t ikm[96];
    memcpy(ikm, DOMAIN_SEPARATOR, 32);
    memcpy(ikm + 32, x25519_shared, 32);
    memcpy(ikm + 64, zero_mlkem, 32);
    
    uint8_t prk[64];
    static const uint8_t zero_salt[64] = {0};
    
    if (crypto_kdf_hkdf_sha512_extract(prk, zero_salt, sizeof(zero_salt), ikm, sizeof(ikm)) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        return -1;
    }
    
    uint8_t info[256];
    size_t info_len = 0;
    
    memcpy(info, HYBRID_KDF_PREFIX, sizeof(HYBRID_KDF_PREFIX) - 1);
    info_len += sizeof(HYBRID_KDF_PREFIX) - 1;
    
    info[info_len++] = TOX_CRYPTO_VERSION_CLASSIC;  /* Different version byte */
    
    if (context != NULL && context_len > 0) {
        size_t copy_len = (context_len < 200) ? context_len : 200;
        memcpy(info + info_len, context, copy_len);
        info_len += copy_len;
    }
    
    if (crypto_kdf_hkdf_sha512_expand(session_key, TOX_SESSION_KEY_BYTES,
                                       (const char *)info, info_len, prk) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        sodium_memzero(prk, sizeof(prk));
        return -1;
    }
    
    sodium_memzero(ikm, sizeof(ikm));
    sodium_memzero(prk, sizeof(prk));
    
    return 0;
}

/*******************************************************************************
 * Session Establishment
 ******************************************************************************/

int tox_hybrid_session_initiate(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_public_key,
    size_t peer_public_len
)
{
    if (session == NULL || our_identity == NULL || peer_public_key == NULL) {
        return -1;
    }
    
    memset(session, 0, sizeof(Tox_Hybrid_Session));
    
    /* Generate ephemeral X25519 keypair */
    if (crypto_box_keypair(session->x25519_ephemeral_public, 
                           session->x25519_ephemeral_secret) != 0) {
        return -1;
    }
    
    /* Check peer capability */
    session->peer_pq_capable = tox_public_key_is_hybrid(peer_public_key, peer_public_len);
    
    /* Extract peer's X25519 public key */
    uint8_t peer_x25519[32];
    if (tox_public_key_get_x25519(peer_x25519, peer_public_key, peer_public_len) != 0) {
        tox_hybrid_session_clear(session);
        return -1;
    }
    
    /* X25519 DH */
    if (crypto_scalarmult(session->x25519_shared, 
                          session->x25519_ephemeral_secret,
                          peer_x25519) != 0) {
        tox_hybrid_session_clear(session);
        return -1;
    }
    
    if (session->peer_pq_capable) {
        /* Extract peer's ML-KEM public key */
        uint8_t peer_mlkem[TOX_MLKEM768_PUBLICKEYBYTES];
        if (tox_public_key_get_mlkem(peer_mlkem, peer_public_key, peer_public_len) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
        
        /* ML-KEM encapsulation */
        if (crypto_kem_mlkem768_enc(session->mlkem_ciphertext,
                                     session->mlkem_shared,
                                     peer_mlkem) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
        
        /* Hybrid key derivation */
        static const uint8_t ctx[] = "ToxSessionInit";
        if (tox_hybrid_kdf(session->session_key,
                           session->x25519_shared,
                           session->mlkem_shared,
                           ctx, sizeof(ctx) - 1) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
    } else {
        /* Classical fallback */
        static const uint8_t ctx[] = "ToxSessionInit";
        if (tox_classical_kdf(session->session_key,
                               session->x25519_shared,
                               ctx, sizeof(ctx) - 1) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
    }
    
    session->session_established = true;
    return 0;
}

int tox_hybrid_session_respond(
    Tox_Hybrid_Session *session,
    const Tox_Hybrid_Identity *our_identity,
    const uint8_t *peer_x25519_ephemeral,
    const uint8_t *mlkem_ciphertext,
    bool peer_is_hybrid
)
{
    if (session == NULL || our_identity == NULL || peer_x25519_ephemeral == NULL) {
        return -1;
    }
    
    memset(session, 0, sizeof(Tox_Hybrid_Session));
    session->peer_pq_capable = peer_is_hybrid;
    
    /* Generate ephemeral X25519 */
    if (crypto_box_keypair(session->x25519_ephemeral_public,
                           session->x25519_ephemeral_secret) != 0) {
        return -1;
    }
    
    /* X25519 DH with peer's ephemeral */
    if (crypto_scalarmult(session->x25519_shared,
                          session->x25519_ephemeral_secret,
                          peer_x25519_ephemeral) != 0) {
        tox_hybrid_session_clear(session);
        return -1;
    }
    
    if (peer_is_hybrid && mlkem_ciphertext != NULL) {
        /* ML-KEM decapsulation */
        if (crypto_kem_mlkem768_dec(session->mlkem_shared,
                                     mlkem_ciphertext,
                                     our_identity->mlkem_secret) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
        
        /* Store ciphertext */
        memcpy(session->mlkem_ciphertext, mlkem_ciphertext, TOX_MLKEM768_CIPHERTEXTBYTES);
        
        /* Hybrid key derivation */
        static const uint8_t ctx[] = "ToxSessionResp";
        if (tox_hybrid_kdf(session->session_key,
                           session->x25519_shared,
                           session->mlkem_shared,
                           ctx, sizeof(ctx) - 1) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
    } else {
        /* Classical fallback */
        static const uint8_t ctx[] = "ToxSessionResp";
        if (tox_classical_kdf(session->session_key,
                               session->x25519_shared,
                               ctx, sizeof(ctx) - 1) != 0) {
            tox_hybrid_session_clear(session);
            return -1;
        }
    }
    
    session->session_established = true;
    return 0;
}

void tox_hybrid_session_clear(Tox_Hybrid_Session *session)
{
    if (session != NULL) {
        sodium_memzero(session, sizeof(Tox_Hybrid_Session));
    }
}

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

bool tox_pq_available(void)
{
    /* Test ML-KEM availability */
    return crypto_kem_mlkem768_publickeybytes() == TOX_MLKEM768_PUBLICKEYBYTES;
}

void tox_pq_status_string(char *buffer, size_t size)
{
    if (buffer == NULL || size == 0) {
        return;
    }
    
    if (tox_pq_available()) {
        snprintf(buffer, size, "PQ: ML-KEM-768 available (libsodium)");
    } else {
        snprintf(buffer, size, "PQ: Not available (libsodium lacks ML-KEM support)");
    }
}
```

## Step 3: Update Build System

### 3.1 Add to CMakeLists.txt

```cmake
# In the toxcrypto module section, add:
add_module(toxcrypto
  toxcore/crypto_core.c
  toxcore/crypto_core.h
  toxcore/crypto_core_pq.c    # NEW
  toxcore/crypto_core_pq.h)   # NEW
target_link_modules(toxcrypto ${LIBSODIUM_LIBRARIES})
```

### 3.2 Update Header Includes

In relevant files that will use PQ crypto:

```c
#include "crypto_core.h"
#include "crypto_core_pq.h"  /* Add this */
```

## Step 4: Create Test Suite

### 4.1 Unit Tests

Create `auto_tests/crypto_pq_test.c`:

```c
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../toxcore/crypto_core_pq.h"
#include <check.h>
#include <sodium.h>
#include <string.h>

START_TEST(test_pq_available)
{
    ck_assert(tox_pq_available());
}
END_TEST

START_TEST(test_hybrid_identity_generate)
{
    Tox_Hybrid_Identity identity;
    int result = tox_hybrid_identity_generate(&identity);
    
    ck_assert_int_eq(result, 0);
    ck_assert_int_eq(identity.version, TOX_CRYPTO_VERSION_HYBRID);
    
    /* Verify keys are not all zeros */
    uint8_t zeros[32] = {0};
    ck_assert(memcmp(identity.x25519_public, zeros, 32) != 0);
    ck_assert(memcmp(identity.mlkem_public, zeros, 32) != 0);
    
    tox_hybrid_identity_clear(&identity);
}
END_TEST

START_TEST(test_hybrid_identity_from_seed_deterministic)
{
    uint8_t seed[32];
    randombytes_buf(seed, 32);
    
    Tox_Hybrid_Identity id1, id2;
    
    ck_assert_int_eq(tox_hybrid_identity_from_seed(&id1, seed), 0);
    ck_assert_int_eq(tox_hybrid_identity_from_seed(&id2, seed), 0);
    
    /* Same seed should produce same keys */
    ck_assert(memcmp(id1.x25519_public, id2.x25519_public, 32) == 0);
    ck_assert(memcmp(id1.mlkem_public, id2.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0);
    
    tox_hybrid_identity_clear(&id1);
    tox_hybrid_identity_clear(&id2);
}
END_TEST

START_TEST(test_hybrid_public_key_export)
{
    Tox_Hybrid_Identity identity;
    tox_hybrid_identity_generate(&identity);
    
    uint8_t exported[TOX_HYBRID_PUBLICKEYBYTES];
    ck_assert_int_eq(tox_hybrid_public_key_export(exported, &identity), 0);
    
    ck_assert_int_eq(exported[0], TOX_CRYPTO_VERSION_HYBRID);
    ck_assert(memcmp(exported + 1, identity.x25519_public, 32) == 0);
    ck_assert(memcmp(exported + 33, identity.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0);
    
    tox_hybrid_identity_clear(&identity);
}
END_TEST

START_TEST(test_public_key_is_hybrid)
{
    Tox_Hybrid_Identity identity;
    tox_hybrid_identity_generate(&identity);
    
    uint8_t hybrid_key[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(hybrid_key, &identity);
    
    ck_assert(tox_public_key_is_hybrid(hybrid_key, TOX_HYBRID_PUBLICKEYBYTES));
    ck_assert(!tox_public_key_is_hybrid(identity.x25519_public, 32));
    
    tox_hybrid_identity_clear(&identity);
}
END_TEST

START_TEST(test_hybrid_session_roundtrip)
{
    /* Generate two identities */
    Tox_Hybrid_Identity alice, bob;
    tox_hybrid_identity_generate(&alice);
    tox_hybrid_identity_generate(&bob);
    
    /* Export Bob's public key */
    uint8_t bob_public[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(bob_public, &bob);
    
    /* Alice initiates session */
    Tox_Hybrid_Session alice_session;
    ck_assert_int_eq(
        tox_hybrid_session_initiate(&alice_session, &alice, bob_public, TOX_HYBRID_PUBLICKEYBYTES),
        0
    );
    
    ck_assert(alice_session.peer_pq_capable);
    ck_assert(alice_session.session_established);
    
    /* Bob responds */
    Tox_Hybrid_Session bob_session;
    ck_assert_int_eq(
        tox_hybrid_session_respond(&bob_session, &bob, 
                                    alice_session.x25519_ephemeral_public,
                                    alice_session.mlkem_ciphertext,
                                    true),
        0
    );
    
    ck_assert(bob_session.peer_pq_capable);
    ck_assert(bob_session.session_established);
    
    /* Both should derive the same session key */
    ck_assert(memcmp(alice_session.session_key, bob_session.session_key, 32) == 0);
    
    /* Cleanup */
    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
    tox_hybrid_session_clear(&alice_session);
    tox_hybrid_session_clear(&bob_session);
}
END_TEST

START_TEST(test_classical_fallback)
{
    /* Alice has hybrid identity, Bob only has classical */
    Tox_Hybrid_Identity alice;
    tox_hybrid_identity_generate(&alice);
    
    /* Simulate classical Bob - just X25519 public key */
    uint8_t bob_x25519_public[32];
    uint8_t bob_x25519_secret[32];
    crypto_box_keypair(bob_x25519_public, bob_x25519_secret);
    
    /* Alice initiates with classical peer */
    Tox_Hybrid_Session alice_session;
    ck_assert_int_eq(
        tox_hybrid_session_initiate(&alice_session, &alice, bob_x25519_public, 32),
        0
    );
    
    ck_assert(!alice_session.peer_pq_capable);  /* Should detect classical */
    ck_assert(alice_session.session_established);
    
    tox_hybrid_identity_clear(&alice);
    tox_hybrid_session_clear(&alice_session);
}
END_TEST

Suite *crypto_pq_suite(void)
{
    Suite *s = suite_create("CryptoPQ");
    TCase *tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_pq_available);
    tcase_add_test(tc_core, test_hybrid_identity_generate);
    tcase_add_test(tc_core, test_hybrid_identity_from_seed_deterministic);
    tcase_add_test(tc_core, test_hybrid_public_key_export);
    tcase_add_test(tc_core, test_public_key_is_hybrid);
    tcase_add_test(tc_core, test_hybrid_session_roundtrip);
    tcase_add_test(tc_core, test_classical_fallback);
    
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void)
{
    if (sodium_init() < 0) {
        return 1;
    }
    
    Suite *s = crypto_pq_suite();
    SRunner *sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (failed == 0) ? 0 : 1;
}
```

### 4.2 Add Test to CMake

```cmake
# In auto_tests section
add_executable(crypto_pq_test auto_tests/crypto_pq_test.c)
target_link_libraries(crypto_pq_test toxcrypto ${CHECK_LIBRARIES})
add_test(NAME crypto_pq_test COMMAND crypto_pq_test)
```

## Step 5: Verification

### 5.1 Build and Test

```bash
cd c-toxcore
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
make test

# Or run specific test
./crypto_pq_test
```

### 5.2 Expected Output

```
Running suite(s): CryptoPQ
100%: Checks: 7, Failures: 0, Errors: 0
```

## Phase 1 Deliverables Checklist

- [ ] libsodium upgraded/verified with ML-KEM-768 support
- [ ] `crypto_core_pq.h` header with all type definitions
- [ ] `crypto_core_pq.c` implementation of:
  - [ ] `tox_hybrid_identity_generate()`
  - [ ] `tox_hybrid_identity_from_seed()`
  - [ ] `tox_hybrid_public_key_export()`
  - [ ] `tox_public_key_is_hybrid()`
  - [ ] `tox_hybrid_kdf()`
  - [ ] `tox_classical_kdf()`
  - [ ] `tox_hybrid_session_initiate()`
  - [ ] `tox_hybrid_session_respond()`
- [ ] Unit tests passing for all primitives
- [ ] Build system updated
- [ ] Session roundtrip test demonstrates key agreement

## Next: Phase 2

With crypto primitives in place, Phase 2 integrates them into the actual Tox handshake protocol in `net_crypto.c`.
