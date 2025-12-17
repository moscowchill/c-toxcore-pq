/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2024 aqTox-PQ contributors
 *
 * Post-quantum hybrid cryptographic primitives for Tox.
 * Implements ML-KEM-768 + X25519 hybrid key exchange.
 */

#include "crypto_core_pq.h"
#include "ccompat.h"

#include <sodium.h>
#include <stdio.h>
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

    /* Derive X25519 seed using KDF - context must be exactly 8 chars */
    uint8_t x25519_seed[32];
    if (crypto_kdf_derive_from_key(x25519_seed, 32, 1, "ToxX2519", seed) != 0) {
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
    const uint8_t zero_mlkem[32] = {0};

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
 * Identity Commitment Functions
 ******************************************************************************/

int tox_mlkem_commitment(
    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE],
    const uint8_t mlkem_pk[TOX_MLKEM768_PUBLICKEYBYTES]
)
{
    if (commitment == NULL || mlkem_pk == NULL) {
        return -1;
    }

    /* SHA256 hash of ML-KEM public key */
    uint8_t hash[crypto_hash_sha256_BYTES];
    if (crypto_hash_sha256(hash, mlkem_pk, TOX_MLKEM768_PUBLICKEYBYTES) != 0) {
        return -1;
    }

    /* Take first 8 bytes as commitment */
    memcpy(commitment, hash, TOX_MLKEM_COMMITMENT_SIZE);

    /* Clear hash from memory */
    sodium_memzero(hash, sizeof(hash));

    return 0;
}

bool tox_verify_mlkem_commitment(
    const uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE],
    const uint8_t mlkem_pk[TOX_MLKEM768_PUBLICKEYBYTES]
)
{
    if (commitment == NULL || mlkem_pk == NULL) {
        return false;
    }

    /* Compute commitment from the provided public key */
    uint8_t computed[TOX_MLKEM_COMMITMENT_SIZE];
    if (tox_mlkem_commitment(computed, mlkem_pk) != 0) {
        return false;
    }

    /* Constant-time comparison to prevent timing attacks */
    bool match = (sodium_memcmp(computed, commitment, TOX_MLKEM_COMMITMENT_SIZE) == 0);

    /* Clear computed commitment from memory */
    sodium_memzero(computed, sizeof(computed));

    return match;
}

int tox_hybrid_identity_commitment(
    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE],
    const Tox_Hybrid_Identity *identity
)
{
    if (commitment == NULL || identity == NULL) {
        return -1;
    }

    return tox_mlkem_commitment(commitment, identity->mlkem_public);
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
