/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2024 aqTox-PQ contributors
 *
 * Post-quantum hybrid cryptographic primitives for Tox.
 * Implements ML-KEM-768 + X25519 hybrid key exchange.
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
 * KDF construction:
 *   IKM = 0xFF[32] || x25519_shared || mlkem_shared
 *   PRK = HKDF-Extract(salt=zeros, IKM)
 *   Key = HKDF-Expand(PRK, "ToxHybridKDF" || version || context, 32)
 *
 * Security: Key remains secure if EITHER X25519 OR ML-KEM is unbroken.
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
