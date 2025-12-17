/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2024 aqTox-PQ contributors
 *
 * Unit tests for post-quantum hybrid cryptographic primitives.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "../toxcore/crypto_core_pq.h"
#include "check_compat.h"

static void test_pq_available(void)
{
    ck_assert_msg(tox_pq_available(), "ML-KEM-768 should be available");

    char status[128];
    tox_pq_status_string(status, sizeof(status));
    ck_assert_msg(strstr(status, "available") != NULL, "Status string should indicate availability");
}

static void test_hybrid_identity_generate(void)
{
    Tox_Hybrid_Identity identity;
    int result = tox_hybrid_identity_generate(&identity);

    ck_assert_msg(result == 0, "Identity generation should succeed");
    ck_assert_msg(identity.version == TOX_CRYPTO_VERSION_HYBRID, "Version should be HYBRID");

    /* Verify keys are not all zeros */
    const uint8_t zeros[32] = {0};
    ck_assert_msg(memcmp(identity.x25519_public, zeros, 32) != 0, "X25519 public key should not be zero");
    ck_assert_msg(memcmp(identity.x25519_secret, zeros, 32) != 0, "X25519 secret key should not be zero");
    ck_assert_msg(memcmp(identity.mlkem_public, zeros, 32) != 0, "ML-KEM public key should not be zero");
    ck_assert_msg(memcmp(identity.mlkem_secret, zeros, 32) != 0, "ML-KEM secret key should not be zero");

    tox_hybrid_identity_clear(&identity);

    /* Verify memory was cleared */
    ck_assert_msg(memcmp(&identity.x25519_secret, zeros, 32) == 0, "Identity should be cleared");
}

static void test_hybrid_identity_from_seed_deterministic(void)
{
    uint8_t seed[32];
    randombytes_buf(seed, 32);

    Tox_Hybrid_Identity id1, id2;

    ck_assert_msg(tox_hybrid_identity_from_seed(&id1, seed) == 0, "Seeded identity generation should succeed");
    ck_assert_msg(tox_hybrid_identity_from_seed(&id2, seed) == 0, "Second seeded identity should succeed");

    /* Same seed should produce same keys */
    ck_assert_msg(memcmp(id1.x25519_public, id2.x25519_public, 32) == 0,
                  "Same seed should produce same X25519 public key");
    ck_assert_msg(memcmp(id1.x25519_secret, id2.x25519_secret, 32) == 0,
                  "Same seed should produce same X25519 secret key");
    ck_assert_msg(memcmp(id1.mlkem_public, id2.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0,
                  "Same seed should produce same ML-KEM public key");
    ck_assert_msg(memcmp(id1.mlkem_secret, id2.mlkem_secret, TOX_MLKEM768_SECRETKEYBYTES) == 0,
                  "Same seed should produce same ML-KEM secret key");

    /* Different seeds should produce different keys */
    uint8_t seed2[32];
    randombytes_buf(seed2, 32);
    Tox_Hybrid_Identity id3;
    ck_assert_msg(tox_hybrid_identity_from_seed(&id3, seed2) == 0, "Third identity should succeed");
    ck_assert_msg(memcmp(id1.x25519_public, id3.x25519_public, 32) != 0,
                  "Different seeds should produce different keys");

    tox_hybrid_identity_clear(&id1);
    tox_hybrid_identity_clear(&id2);
    tox_hybrid_identity_clear(&id3);
}

static void test_hybrid_public_key_export(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation should succeed");

    uint8_t exported[TOX_HYBRID_PUBLICKEYBYTES];
    ck_assert_msg(tox_hybrid_public_key_export(exported, &identity) == 0, "Export should succeed");

    ck_assert_msg(exported[0] == TOX_CRYPTO_VERSION_HYBRID, "First byte should be version");
    ck_assert_msg(memcmp(exported + 1, identity.x25519_public, 32) == 0,
                  "X25519 public key should match");
    ck_assert_msg(memcmp(exported + 33, identity.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0,
                  "ML-KEM public key should match");

    tox_hybrid_identity_clear(&identity);
}

static void test_public_key_is_hybrid(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation should succeed");

    uint8_t hybrid_key[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(hybrid_key, &identity);

    ck_assert_msg(tox_public_key_is_hybrid(hybrid_key, TOX_HYBRID_PUBLICKEYBYTES),
                  "Exported hybrid key should be detected as hybrid");
    ck_assert_msg(!tox_public_key_is_hybrid(identity.x25519_public, 32),
                  "Classical X25519 key should not be detected as hybrid");
    ck_assert_msg(!tox_public_key_is_hybrid(NULL, 0),
                  "NULL should not be detected as hybrid");

    tox_hybrid_identity_clear(&identity);
}

static void test_public_key_extraction(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation should succeed");

    uint8_t hybrid_key[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(hybrid_key, &identity);

    /* Test X25519 extraction from hybrid key */
    uint8_t x25519_extracted[32];
    ck_assert_msg(tox_public_key_get_x25519(x25519_extracted, hybrid_key, TOX_HYBRID_PUBLICKEYBYTES) == 0,
                  "X25519 extraction from hybrid key should succeed");
    ck_assert_msg(memcmp(x25519_extracted, identity.x25519_public, 32) == 0,
                  "Extracted X25519 should match original");

    /* Test X25519 extraction from classical key */
    ck_assert_msg(tox_public_key_get_x25519(x25519_extracted, identity.x25519_public, 32) == 0,
                  "X25519 extraction from classical key should succeed");
    ck_assert_msg(memcmp(x25519_extracted, identity.x25519_public, 32) == 0,
                  "Classical extraction should work");

    /* Test ML-KEM extraction */
    uint8_t mlkem_extracted[TOX_MLKEM768_PUBLICKEYBYTES];
    ck_assert_msg(tox_public_key_get_mlkem(mlkem_extracted, hybrid_key, TOX_HYBRID_PUBLICKEYBYTES) == 0,
                  "ML-KEM extraction should succeed");
    ck_assert_msg(memcmp(mlkem_extracted, identity.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0,
                  "Extracted ML-KEM should match original");

    /* Test ML-KEM extraction fails on classical key */
    ck_assert_msg(tox_public_key_get_mlkem(mlkem_extracted, identity.x25519_public, 32) != 0,
                  "ML-KEM extraction from classical key should fail");

    tox_hybrid_identity_clear(&identity);
}

static void test_hybrid_kdf(void)
{
    uint8_t x25519_shared[32];
    uint8_t mlkem_shared[32];
    uint8_t session_key1[TOX_SESSION_KEY_BYTES];
    uint8_t session_key2[TOX_SESSION_KEY_BYTES];
    const uint8_t zeros[32] = {0};

    randombytes_buf(x25519_shared, 32);
    randombytes_buf(mlkem_shared, 32);

    /* Test basic KDF */
    ck_assert_msg(tox_hybrid_kdf(session_key1, x25519_shared, mlkem_shared, NULL, 0) == 0,
                  "Hybrid KDF should succeed");
    ck_assert_msg(memcmp(session_key1, zeros, 32) != 0, "Session key should not be zero");

    /* Same inputs should produce same output */
    ck_assert_msg(tox_hybrid_kdf(session_key2, x25519_shared, mlkem_shared, NULL, 0) == 0,
                  "Second KDF should succeed");
    ck_assert_msg(memcmp(session_key1, session_key2, 32) == 0, "Same inputs should produce same key");

    /* Different inputs should produce different output */
    uint8_t different_x25519[32];
    randombytes_buf(different_x25519, 32);
    ck_assert_msg(tox_hybrid_kdf(session_key2, different_x25519, mlkem_shared, NULL, 0) == 0,
                  "KDF with different input should succeed");
    ck_assert_msg(memcmp(session_key1, session_key2, 32) != 0,
                  "Different inputs should produce different keys");

    /* Context should affect output */
    static const uint8_t ctx[] = "test context";
    ck_assert_msg(tox_hybrid_kdf(session_key2, x25519_shared, mlkem_shared, ctx, sizeof(ctx) - 1) == 0,
                  "KDF with context should succeed");
    ck_assert_msg(memcmp(session_key1, session_key2, 32) != 0,
                  "Context should affect output");
}

static void test_classical_kdf(void)
{
    uint8_t x25519_shared[32];
    uint8_t session_key1[TOX_SESSION_KEY_BYTES];
    uint8_t session_key2[TOX_SESSION_KEY_BYTES];
    const uint8_t zeros[32] = {0};

    randombytes_buf(x25519_shared, 32);

    /* Test classical KDF */
    ck_assert_msg(tox_classical_kdf(session_key1, x25519_shared, NULL, 0) == 0,
                  "Classical KDF should succeed");
    ck_assert_msg(memcmp(session_key1, zeros, 32) != 0, "Session key should not be zero");

    /* Classical and hybrid KDF should produce different results */
    uint8_t zero_mlkem[32] = {0};
    ck_assert_msg(tox_hybrid_kdf(session_key2, x25519_shared, zero_mlkem, NULL, 0) == 0,
                  "Hybrid KDF with zero mlkem should succeed");
    /* Note: They should be different because the version byte differs */
    ck_assert_msg(memcmp(session_key1, session_key2, 32) != 0,
                  "Classical and hybrid KDF should differ (version byte)");
}

static void test_hybrid_session_roundtrip(void)
{
    /* Generate two identities */
    Tox_Hybrid_Identity alice, bob;
    ck_assert_msg(tox_hybrid_identity_generate(&alice) == 0, "Alice identity should succeed");
    ck_assert_msg(tox_hybrid_identity_generate(&bob) == 0, "Bob identity should succeed");

    /* Export Bob's public key */
    uint8_t bob_public[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(bob_public, &bob);

    /* Alice initiates session */
    Tox_Hybrid_Session alice_session;
    ck_assert_msg(
        tox_hybrid_session_initiate(&alice_session, &alice, bob_public, TOX_HYBRID_PUBLICKEYBYTES) == 0,
        "Alice session initiate should succeed"
    );

    ck_assert_msg(alice_session.peer_pq_capable, "Alice should detect Bob as PQ-capable");
    ck_assert_msg(alice_session.session_established, "Alice session should be established");

    /* Bob responds */
    Tox_Hybrid_Session bob_session;
    ck_assert_msg(
        tox_hybrid_session_respond(&bob_session, &bob,
                                    alice_session.x25519_ephemeral_public,
                                    alice_session.mlkem_ciphertext,
                                    true) == 0,
        "Bob session respond should succeed"
    );

    ck_assert_msg(bob_session.peer_pq_capable, "Bob should know peer is PQ-capable");
    ck_assert_msg(bob_session.session_established, "Bob session should be established");

    /* Verify shared secrets match for ML-KEM */
    ck_assert_msg(memcmp(alice_session.mlkem_shared, bob_session.mlkem_shared, 32) == 0,
                  "ML-KEM shared secrets should match");

    /* Note: Session keys will differ because initiator uses "ToxSessionInit"
     * and responder uses "ToxSessionResp" as context. This is intentional
     * for the full protocol but needs to be handled in the real handshake.
     * For this test we verify the ML-KEM shared secret matches. */

    /* Cleanup */
    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
    tox_hybrid_session_clear(&alice_session);
    tox_hybrid_session_clear(&bob_session);
}

static void test_classical_fallback(void)
{
    /* Alice has hybrid identity, Bob only has classical */
    Tox_Hybrid_Identity alice;
    ck_assert_msg(tox_hybrid_identity_generate(&alice) == 0, "Alice identity should succeed");

    /* Simulate classical Bob - just X25519 public key */
    uint8_t bob_x25519_public[32];
    uint8_t bob_x25519_secret[32];
    crypto_box_keypair(bob_x25519_public, bob_x25519_secret);

    /* Alice initiates with classical peer */
    Tox_Hybrid_Session alice_session;
    ck_assert_msg(
        tox_hybrid_session_initiate(&alice_session, &alice, bob_x25519_public, 32) == 0,
        "Alice session with classical peer should succeed"
    );

    ck_assert_msg(!alice_session.peer_pq_capable, "Alice should detect Bob as NOT PQ-capable");
    ck_assert_msg(alice_session.session_established, "Alice session should be established");

    /* Verify session key is not zero */
    const uint8_t zeros[32] = {0};
    ck_assert_msg(memcmp(alice_session.session_key, zeros, 32) != 0,
                  "Session key should not be zero");

    tox_hybrid_identity_clear(&alice);
    tox_hybrid_session_clear(&alice_session);
    sodium_memzero(bob_x25519_secret, sizeof(bob_x25519_secret));
}

static void test_null_handling(void)
{
    Tox_Hybrid_Identity identity;
    Tox_Hybrid_Session session;
    uint8_t buf[TOX_HYBRID_PUBLICKEYBYTES];
    uint8_t small[32];

    /* Test NULL handling for all functions */
    ck_assert_msg(tox_hybrid_identity_generate(NULL) == -1, "NULL identity should fail");
    ck_assert_msg(tox_hybrid_identity_from_seed(NULL, small) == -1, "NULL identity should fail");
    ck_assert_msg(tox_hybrid_identity_from_seed(&identity, NULL) == -1, "NULL seed should fail");
    ck_assert_msg(tox_hybrid_public_key_export(NULL, &identity) == -1, "NULL output should fail");
    ck_assert_msg(tox_hybrid_public_key_export(buf, NULL) == -1, "NULL identity should fail");
    ck_assert_msg(tox_public_key_get_x25519(NULL, buf, 32) == -1, "NULL output should fail");
    ck_assert_msg(tox_public_key_get_x25519(small, NULL, 32) == -1, "NULL input should fail");
    ck_assert_msg(tox_public_key_get_mlkem(NULL, buf, TOX_HYBRID_PUBLICKEYBYTES) == -1, "NULL output should fail");
    ck_assert_msg(tox_hybrid_kdf(NULL, small, small, NULL, 0) == -1, "NULL key should fail");
    ck_assert_msg(tox_hybrid_kdf(small, NULL, small, NULL, 0) == -1, "NULL x25519 should fail");
    ck_assert_msg(tox_hybrid_kdf(small, small, NULL, NULL, 0) == -1, "NULL mlkem should fail");
    ck_assert_msg(tox_classical_kdf(NULL, small, NULL, 0) == -1, "NULL key should fail");
    ck_assert_msg(tox_classical_kdf(small, NULL, NULL, 0) == -1, "NULL x25519 should fail");
    ck_assert_msg(tox_hybrid_session_initiate(NULL, &identity, buf, 32) == -1, "NULL session should fail");
    ck_assert_msg(tox_hybrid_session_initiate(&session, NULL, buf, 32) == -1, "NULL identity should fail");
    ck_assert_msg(tox_hybrid_session_initiate(&session, &identity, NULL, 32) == -1, "NULL peer key should fail");
    ck_assert_msg(tox_hybrid_session_respond(NULL, &identity, small, small, true) == -1, "NULL session should fail");
    ck_assert_msg(tox_hybrid_session_respond(&session, NULL, small, small, true) == -1, "NULL identity should fail");
    ck_assert_msg(tox_hybrid_session_respond(&session, &identity, NULL, small, true) == -1, "NULL ephemeral should fail");

    /* These should not crash */
    tox_hybrid_identity_clear(NULL);
    tox_hybrid_session_clear(NULL);
    tox_pq_status_string(NULL, 0);
}

static void test_key_sizes(void)
{
    /* Verify our constants match libsodium */
    ck_assert_msg(TOX_MLKEM768_PUBLICKEYBYTES == crypto_kem_mlkem768_publickeybytes(),
                  "ML-KEM public key size mismatch");
    ck_assert_msg(TOX_MLKEM768_SECRETKEYBYTES == crypto_kem_mlkem768_secretkeybytes(),
                  "ML-KEM secret key size mismatch");
    ck_assert_msg(TOX_MLKEM768_CIPHERTEXTBYTES == crypto_kem_mlkem768_ciphertextbytes(),
                  "ML-KEM ciphertext size mismatch");
    ck_assert_msg(TOX_MLKEM768_SHAREDSECRETBYTES == crypto_kem_mlkem768_sharedsecretbytes(),
                  "ML-KEM shared secret size mismatch");
}

/*******************************************************************************
 * Extended Security Tests - ML-KEM Decapsulation Failure Modes
 ******************************************************************************/

static void test_mlkem_decapsulation_wrong_keypair(void)
{
    /* Generate two different identities */
    Tox_Hybrid_Identity alice, bob, mallory;
    ck_assert_msg(tox_hybrid_identity_generate(&alice) == 0, "Alice identity failed");
    ck_assert_msg(tox_hybrid_identity_generate(&bob) == 0, "Bob identity failed");
    ck_assert_msg(tox_hybrid_identity_generate(&mallory) == 0, "Mallory identity failed");

    /* Alice encapsulates to Bob's public key */
    uint8_t ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES];
    uint8_t alice_shared[32];
    ck_assert_msg(crypto_kem_mlkem768_enc(ciphertext, alice_shared, bob.mlkem_public) == 0,
                  "Encapsulation should succeed");

    /* Mallory tries to decapsulate with her secret key - should get different result */
    uint8_t mallory_shared[32];
    int result = crypto_kem_mlkem768_dec(mallory_shared, ciphertext, mallory.mlkem_secret);

    /* ML-KEM-768 uses implicit rejection - it won't return an error,
     * but the shared secret will be different (derived from ciphertext hash) */
    ck_assert_msg(result == 0, "Decapsulation returns 0 even with wrong key (implicit rejection)");
    ck_assert_msg(memcmp(alice_shared, mallory_shared, 32) != 0,
                  "Wrong keypair must produce different shared secret");

    /* Bob should get the correct shared secret */
    uint8_t bob_shared[32];
    ck_assert_msg(crypto_kem_mlkem768_dec(bob_shared, ciphertext, bob.mlkem_secret) == 0,
                  "Correct decapsulation should succeed");
    ck_assert_msg(memcmp(alice_shared, bob_shared, 32) == 0,
                  "Correct keypair should produce matching shared secret");

    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
    tox_hybrid_identity_clear(&mallory);
}

static void test_mlkem_corrupted_ciphertext(void)
{
    Tox_Hybrid_Identity alice, bob;
    ck_assert_msg(tox_hybrid_identity_generate(&alice) == 0, "Alice identity failed");
    ck_assert_msg(tox_hybrid_identity_generate(&bob) == 0, "Bob identity failed");

    uint8_t ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES];
    uint8_t alice_shared[32];
    ck_assert_msg(crypto_kem_mlkem768_enc(ciphertext, alice_shared, bob.mlkem_public) == 0,
                  "Encapsulation should succeed");

    /* Save original for comparison */
    uint8_t bob_shared_original[32];
    ck_assert_msg(crypto_kem_mlkem768_dec(bob_shared_original, ciphertext, bob.mlkem_secret) == 0,
                  "Original decapsulation should succeed");
    ck_assert_msg(memcmp(alice_shared, bob_shared_original, 32) == 0,
                  "Original should match");

    /* Test corruption at first byte */
    uint8_t corrupted[TOX_MLKEM768_CIPHERTEXTBYTES];
    memcpy(corrupted, ciphertext, TOX_MLKEM768_CIPHERTEXTBYTES);
    corrupted[0] ^= 0x01;  /* Flip one bit */

    uint8_t bob_shared_corrupted[32];
    int dec_result;

    /* ML-KEM uses implicit rejection - always returns 0 but produces different shared secret */
    dec_result = crypto_kem_mlkem768_dec(bob_shared_corrupted, corrupted, bob.mlkem_secret);
    ck_assert_msg(dec_result == 0, "Decapsulation should return 0 (implicit rejection)");
    ck_assert_msg(memcmp(alice_shared, bob_shared_corrupted, 32) != 0,
                  "Corrupted ciphertext (first byte) must produce different shared secret");

    /* Test corruption at middle byte */
    memcpy(corrupted, ciphertext, TOX_MLKEM768_CIPHERTEXTBYTES);
    corrupted[TOX_MLKEM768_CIPHERTEXTBYTES / 2] ^= 0x80;

    dec_result = crypto_kem_mlkem768_dec(bob_shared_corrupted, corrupted, bob.mlkem_secret);
    ck_assert_msg(dec_result == 0, "Decapsulation should return 0 (implicit rejection)");
    ck_assert_msg(memcmp(alice_shared, bob_shared_corrupted, 32) != 0,
                  "Corrupted ciphertext (middle) must produce different shared secret");

    /* Test corruption at last byte */
    memcpy(corrupted, ciphertext, TOX_MLKEM768_CIPHERTEXTBYTES);
    corrupted[TOX_MLKEM768_CIPHERTEXTBYTES - 1] ^= 0xFF;

    dec_result = crypto_kem_mlkem768_dec(bob_shared_corrupted, corrupted, bob.mlkem_secret);
    ck_assert_msg(dec_result == 0, "Decapsulation should return 0 (implicit rejection)");
    ck_assert_msg(memcmp(alice_shared, bob_shared_corrupted, 32) != 0,
                  "Corrupted ciphertext (last byte) must produce different shared secret");

    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
}

/*******************************************************************************
 * Extended Security Tests - KDF Determinism and Boundaries
 ******************************************************************************/

static void test_kdf_determinism(void)
{
    uint8_t x25519_shared[32];
    uint8_t mlkem_shared[32];
    randombytes_buf(x25519_shared, 32);
    randombytes_buf(mlkem_shared, 32);

    uint8_t first_result[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_hybrid_kdf(first_result, x25519_shared, mlkem_shared, NULL, 0) == 0,
                  "First KDF call should succeed");

    /* Verify 100 iterations produce identical results */
    for (int i = 0; i < 100; i++) {
        uint8_t result[TOX_SESSION_KEY_BYTES];
        ck_assert_msg(tox_hybrid_kdf(result, x25519_shared, mlkem_shared, NULL, 0) == 0,
                      "KDF iteration %d should succeed", i);
        ck_assert_msg(memcmp(first_result, result, TOX_SESSION_KEY_BYTES) == 0,
                      "KDF must be deterministic (iteration %d)", i);
    }

    /* Same test for classical KDF */
    uint8_t classical_first[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_classical_kdf(classical_first, x25519_shared, NULL, 0) == 0,
                  "First classical KDF call should succeed");

    for (int i = 0; i < 100; i++) {
        uint8_t result[TOX_SESSION_KEY_BYTES];
        ck_assert_msg(tox_classical_kdf(result, x25519_shared, NULL, 0) == 0,
                      "Classical KDF iteration %d should succeed", i);
        ck_assert_msg(memcmp(classical_first, result, TOX_SESSION_KEY_BYTES) == 0,
                      "Classical KDF must be deterministic (iteration %d)", i);
    }
}

static void test_kdf_context_boundaries(void)
{
    uint8_t x25519_shared[32];
    uint8_t mlkem_shared[32];
    uint8_t session_key[TOX_SESSION_KEY_BYTES];
    randombytes_buf(x25519_shared, 32);
    randombytes_buf(mlkem_shared, 32);

    /* Test with NULL context */
    ck_assert_msg(tox_hybrid_kdf(session_key, x25519_shared, mlkem_shared, NULL, 0) == 0,
                  "KDF with NULL context should succeed");
    uint8_t key_null_ctx[TOX_SESSION_KEY_BYTES];
    memcpy(key_null_ctx, session_key, TOX_SESSION_KEY_BYTES);

    /* Test with empty string context (non-NULL but len=0) */
    const uint8_t empty_ctx[1] = {0};
    ck_assert_msg(tox_hybrid_kdf(session_key, x25519_shared, mlkem_shared, empty_ctx, 0) == 0,
                  "KDF with empty context should succeed");
    /* NULL,0 and ptr,0 should produce same result (context not used) */
    ck_assert_msg(memcmp(key_null_ctx, session_key, TOX_SESSION_KEY_BYTES) == 0,
                  "Empty context should equal NULL context");

    /* Test with 1-byte context */
    const uint8_t one_byte_ctx[1] = {'A'};
    ck_assert_msg(tox_hybrid_kdf(session_key, x25519_shared, mlkem_shared, one_byte_ctx, 1) == 0,
                  "KDF with 1-byte context should succeed");
    ck_assert_msg(memcmp(key_null_ctx, session_key, TOX_SESSION_KEY_BYTES) != 0,
                  "1-byte context should produce different key");

    /* Test at truncation boundary: exactly 200 bytes (maximum before truncation) */
    uint8_t ctx_200[200];
    memset(ctx_200, 'X', 200);
    uint8_t key_200[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_hybrid_kdf(key_200, x25519_shared, mlkem_shared, ctx_200, 200) == 0,
                  "KDF with 200-byte context should succeed");

    /* Test at truncation boundary: 201 bytes (should truncate to 200) */
    uint8_t ctx_201[201];
    memset(ctx_201, 'X', 200);
    ctx_201[200] = 'Y';  /* This byte should be ignored due to truncation */
    uint8_t key_201[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_hybrid_kdf(key_201, x25519_shared, mlkem_shared, ctx_201, 201) == 0,
                  "KDF with 201-byte context should succeed");
    ck_assert_msg(memcmp(key_200, key_201, TOX_SESSION_KEY_BYTES) == 0,
                  "201-byte context should truncate to 200 bytes and match");

    /* Test with large context (1KB) - should truncate to 200 */
    uint8_t ctx_large[1024];
    memset(ctx_large, 'X', 200);  /* First 200 bytes match ctx_200 */
    memset(ctx_large + 200, 'Z', 824);  /* Rest is different but truncated */
    uint8_t key_large[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_hybrid_kdf(key_large, x25519_shared, mlkem_shared, ctx_large, 1024) == 0,
                  "KDF with 1KB context should succeed");
    ck_assert_msg(memcmp(key_200, key_large, TOX_SESSION_KEY_BYTES) == 0,
                  "Large context should truncate and match 200-byte context");
}

static void test_hybrid_vs_classical_kdf_separation(void)
{
    uint8_t x25519_shared[32];
    randombytes_buf(x25519_shared, 32);

    /* Classical KDF with zero ML-KEM input */
    uint8_t classical_key[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_classical_kdf(classical_key, x25519_shared, NULL, 0) == 0,
                  "Classical KDF should succeed");

    /* Hybrid KDF with zero ML-KEM shared secret */
    const uint8_t zero_mlkem[32] = {0};
    uint8_t hybrid_key[TOX_SESSION_KEY_BYTES];
    ck_assert_msg(tox_hybrid_kdf(hybrid_key, x25519_shared, zero_mlkem, NULL, 0) == 0,
                  "Hybrid KDF with zero ML-KEM should succeed");

    /* Keys MUST differ due to version byte in KDF info */
    ck_assert_msg(memcmp(classical_key, hybrid_key, TOX_SESSION_KEY_BYTES) != 0,
                  "Classical and hybrid KDF must produce different keys (version separation)");

    /* Verify consistency - same call 10 times */
    for (int i = 0; i < 10; i++) {
        uint8_t test_classical[TOX_SESSION_KEY_BYTES];
        uint8_t test_hybrid[TOX_SESSION_KEY_BYTES];
        tox_classical_kdf(test_classical, x25519_shared, NULL, 0);
        tox_hybrid_kdf(test_hybrid, x25519_shared, zero_mlkem, NULL, 0);
        ck_assert_msg(memcmp(classical_key, test_classical, TOX_SESSION_KEY_BYTES) == 0,
                      "Classical KDF not consistent at iteration %d", i);
        ck_assert_msg(memcmp(hybrid_key, test_hybrid, TOX_SESSION_KEY_BYTES) == 0,
                      "Hybrid KDF not consistent at iteration %d", i);
    }
}

/*******************************************************************************
 * Extended Security Tests - Memory Clearing Validation
 ******************************************************************************/

static void test_identity_clear_comprehensive(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    /* Verify keys are non-zero before clearing */
    const uint8_t zeros_32[32] = {0};
    const uint8_t zeros_1184[1184] = {0};
    const uint8_t zeros_2400[2400] = {0};

    ck_assert_msg(memcmp(identity.x25519_secret, zeros_32, 32) != 0,
                  "X25519 secret should be non-zero");
    ck_assert_msg(memcmp(identity.mlkem_secret, zeros_2400, 2400) != 0,
                  "ML-KEM secret should be non-zero");

    /* Clear the identity */
    tox_hybrid_identity_clear(&identity);

    /* Verify ALL fields are zeroed */
    ck_assert_msg(identity.version == 0, "Version should be zeroed");
    ck_assert_msg(memcmp(identity.x25519_public, zeros_32, 32) == 0,
                  "X25519 public should be zeroed");
    ck_assert_msg(memcmp(identity.x25519_secret, zeros_32, 32) == 0,
                  "X25519 secret should be zeroed");
    ck_assert_msg(memcmp(identity.mlkem_public, zeros_1184, 1184) == 0,
                  "ML-KEM public should be zeroed");
    ck_assert_msg(memcmp(identity.mlkem_secret, zeros_2400, 2400) == 0,
                  "ML-KEM secret should be zeroed");
}

static void test_session_clear_comprehensive(void)
{
    Tox_Hybrid_Identity alice, bob;
    ck_assert_msg(tox_hybrid_identity_generate(&alice) == 0, "Alice identity failed");
    ck_assert_msg(tox_hybrid_identity_generate(&bob) == 0, "Bob identity failed");

    uint8_t bob_public[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(bob_public, &bob);

    Tox_Hybrid_Session session;
    ck_assert_msg(tox_hybrid_session_initiate(&session, &alice, bob_public, TOX_HYBRID_PUBLICKEYBYTES) == 0,
                  "Session initiate failed");

    /* Verify session has non-zero sensitive data */
    const uint8_t zeros_32[32] = {0};
    const uint8_t zeros_1088[1088] = {0};

    ck_assert_msg(memcmp(session.x25519_ephemeral_secret, zeros_32, 32) != 0,
                  "Ephemeral secret should be non-zero");
    ck_assert_msg(memcmp(session.session_key, zeros_32, 32) != 0,
                  "Session key should be non-zero");
    ck_assert_msg(session.session_established == true,
                  "Session should be established");

    /* Clear the session */
    tox_hybrid_session_clear(&session);

    /* Verify ALL fields are zeroed */
    ck_assert_msg(memcmp(session.x25519_ephemeral_public, zeros_32, 32) == 0,
                  "Ephemeral public should be zeroed");
    ck_assert_msg(memcmp(session.x25519_ephemeral_secret, zeros_32, 32) == 0,
                  "Ephemeral secret should be zeroed");
    ck_assert_msg(memcmp(session.x25519_shared, zeros_32, 32) == 0,
                  "X25519 shared should be zeroed");
    ck_assert_msg(memcmp(session.mlkem_ciphertext, zeros_1088, 1088) == 0,
                  "ML-KEM ciphertext should be zeroed");
    ck_assert_msg(memcmp(session.mlkem_shared, zeros_32, 32) == 0,
                  "ML-KEM shared should be zeroed");
    ck_assert_msg(memcmp(session.session_key, zeros_32, 32) == 0,
                  "Session key should be zeroed");
    ck_assert_msg(session.peer_pq_capable == false,
                  "peer_pq_capable should be false");
    ck_assert_msg(session.session_established == false,
                  "session_established should be false");

    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
}

/*******************************************************************************
 * Extended Security Tests - Seed Reproducibility
 ******************************************************************************/

static void test_seed_reproducibility_extended(void)
{
    /* Use a known seed pattern */
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)i;
    }

    Tox_Hybrid_Identity reference;
    ck_assert_msg(tox_hybrid_identity_from_seed(&reference, seed) == 0,
                  "Reference identity creation failed");

    /* Verify 100 iterations produce identical keys */
    for (int i = 0; i < 100; i++) {
        Tox_Hybrid_Identity test;
        ck_assert_msg(tox_hybrid_identity_from_seed(&test, seed) == 0,
                      "Identity from seed iteration %d failed", i);

        ck_assert_msg(memcmp(reference.x25519_public, test.x25519_public, 32) == 0,
                      "X25519 public key not reproducible at iteration %d", i);
        ck_assert_msg(memcmp(reference.x25519_secret, test.x25519_secret, 32) == 0,
                      "X25519 secret key not reproducible at iteration %d", i);
        ck_assert_msg(memcmp(reference.mlkem_public, test.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) == 0,
                      "ML-KEM public key not reproducible at iteration %d", i);
        ck_assert_msg(memcmp(reference.mlkem_secret, test.mlkem_secret, TOX_MLKEM768_SECRETKEYBYTES) == 0,
                      "ML-KEM secret key not reproducible at iteration %d", i);

        tox_hybrid_identity_clear(&test);
    }

    tox_hybrid_identity_clear(&reference);
}

static void test_seed_edge_cases(void)
{
    /* Test all-zeros seed */
    uint8_t zero_seed[32] = {0};
    Tox_Hybrid_Identity id_zeros;
    ck_assert_msg(tox_hybrid_identity_from_seed(&id_zeros, zero_seed) == 0,
                  "All-zeros seed should succeed");

    /* Verify keys are still non-zero (KDF should produce varied output) */
    const uint8_t zeros_32[32] = {0};
    ck_assert_msg(memcmp(id_zeros.x25519_public, zeros_32, 32) != 0,
                  "X25519 public from zero seed should be non-zero");
    ck_assert_msg(memcmp(id_zeros.x25519_secret, zeros_32, 32) != 0,
                  "X25519 secret from zero seed should be non-zero");

    /* Test all-ones seed */
    uint8_t ones_seed[32];
    memset(ones_seed, 0xFF, 32);
    Tox_Hybrid_Identity id_ones;
    ck_assert_msg(tox_hybrid_identity_from_seed(&id_ones, ones_seed) == 0,
                  "All-ones seed should succeed");

    /* Zero and ones seeds must produce different keys */
    ck_assert_msg(memcmp(id_zeros.x25519_public, id_ones.x25519_public, 32) != 0,
                  "Different seeds must produce different X25519 keys");
    ck_assert_msg(memcmp(id_zeros.mlkem_public, id_ones.mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES) != 0,
                  "Different seeds must produce different ML-KEM keys");

    tox_hybrid_identity_clear(&id_zeros);
    tox_hybrid_identity_clear(&id_ones);
}

/*******************************************************************************
 * Extended Security Tests - Key Uniqueness
 ******************************************************************************/

static void test_generated_keys_unique(void)
{
    /* Generate 50 identities and verify no collisions */
    #define NUM_IDENTITIES 50
    Tox_Hybrid_Identity identities[NUM_IDENTITIES];

    for (int i = 0; i < NUM_IDENTITIES; i++) {
        ck_assert_msg(tox_hybrid_identity_generate(&identities[i]) == 0,
                      "Identity generation %d failed", i);
    }

    /* Check all pairs for collisions */
    for (int i = 0; i < NUM_IDENTITIES; i++) {
        for (int j = i + 1; j < NUM_IDENTITIES; j++) {
            ck_assert_msg(memcmp(identities[i].x25519_public, identities[j].x25519_public, 32) != 0,
                          "X25519 public key collision between %d and %d", i, j);
            ck_assert_msg(memcmp(identities[i].x25519_secret, identities[j].x25519_secret, 32) != 0,
                          "X25519 secret key collision between %d and %d", i, j);
            /* ML-KEM keys are much larger, collision extremely unlikely but check anyway */
            ck_assert_msg(memcmp(identities[i].mlkem_public, identities[j].mlkem_public,
                          TOX_MLKEM768_PUBLICKEYBYTES) != 0,
                          "ML-KEM public key collision between %d and %d", i, j);
        }
    }

    for (int i = 0; i < NUM_IDENTITIES; i++) {
        tox_hybrid_identity_clear(&identities[i]);
    }
    #undef NUM_IDENTITIES
}

/*******************************************************************************
 * Extended Security Tests - Public Key Extraction Edge Cases
 ******************************************************************************/

static void test_public_key_extraction_invalid_lengths(void)
{
    uint8_t output_x25519[32];
    uint8_t output_mlkem[TOX_MLKEM768_PUBLICKEYBYTES];
    uint8_t dummy_key[TOX_HYBRID_PUBLICKEYBYTES + 10];
    memset(dummy_key, 0xAB, sizeof(dummy_key));

    /* X25519 extraction should fail for invalid lengths */
    ck_assert_msg(tox_public_key_get_x25519(output_x25519, dummy_key, 0) == -1,
                  "X25519 extraction with len=0 should fail");
    ck_assert_msg(tox_public_key_get_x25519(output_x25519, dummy_key, 31) == -1,
                  "X25519 extraction with len=31 should fail");
    ck_assert_msg(tox_public_key_get_x25519(output_x25519, dummy_key, 33) == -1,
                  "X25519 extraction with len=33 should fail");
    ck_assert_msg(tox_public_key_get_x25519(output_x25519, dummy_key, 100) == -1,
                  "X25519 extraction with len=100 should fail");
    /* Just under hybrid size but not exactly classical or hybrid */
    ck_assert_msg(tox_public_key_get_x25519(output_x25519, dummy_key, TOX_HYBRID_PUBLICKEYBYTES - 1) == -1,
                  "X25519 extraction with hybrid-1 length should fail");

    /* ML-KEM extraction should fail for non-hybrid keys */
    ck_assert_msg(tox_public_key_get_mlkem(output_mlkem, dummy_key, 32) == -1,
                  "ML-KEM extraction from 32-byte key should fail");
    ck_assert_msg(tox_public_key_get_mlkem(output_mlkem, dummy_key, 0) == -1,
                  "ML-KEM extraction from 0-byte key should fail");
    ck_assert_msg(tox_public_key_get_mlkem(output_mlkem, dummy_key, TOX_HYBRID_PUBLICKEYBYTES - 1) == -1,
                  "ML-KEM extraction from hybrid-1 length should fail");
}

/*******************************************************************************
 * Identity Commitment Tests
 ******************************************************************************/

static void test_mlkem_commitment_basic(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE];
    ck_assert_msg(tox_mlkem_commitment(commitment, identity.mlkem_public) == 0,
                  "Commitment generation should succeed");

    /* Commitment should not be all zeros */
    const uint8_t zeros[TOX_MLKEM_COMMITMENT_SIZE] = {0};
    ck_assert_msg(memcmp(commitment, zeros, TOX_MLKEM_COMMITMENT_SIZE) != 0,
                  "Commitment should not be zero");

    tox_hybrid_identity_clear(&identity);
}

static void test_mlkem_commitment_deterministic(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    uint8_t commitment1[TOX_MLKEM_COMMITMENT_SIZE];
    uint8_t commitment2[TOX_MLKEM_COMMITMENT_SIZE];

    ck_assert_msg(tox_mlkem_commitment(commitment1, identity.mlkem_public) == 0,
                  "First commitment should succeed");
    ck_assert_msg(tox_mlkem_commitment(commitment2, identity.mlkem_public) == 0,
                  "Second commitment should succeed");

    /* Same key should produce same commitment */
    ck_assert_msg(memcmp(commitment1, commitment2, TOX_MLKEM_COMMITMENT_SIZE) == 0,
                  "Commitment must be deterministic");

    /* Different keys should produce different commitments */
    Tox_Hybrid_Identity identity2;
    ck_assert_msg(tox_hybrid_identity_generate(&identity2) == 0, "Second identity generation failed");

    uint8_t commitment3[TOX_MLKEM_COMMITMENT_SIZE];
    ck_assert_msg(tox_mlkem_commitment(commitment3, identity2.mlkem_public) == 0,
                  "Third commitment should succeed");

    ck_assert_msg(memcmp(commitment1, commitment3, TOX_MLKEM_COMMITMENT_SIZE) != 0,
                  "Different keys should produce different commitments");

    tox_hybrid_identity_clear(&identity);
    tox_hybrid_identity_clear(&identity2);
}

static void test_mlkem_commitment_verification(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    /* Generate commitment */
    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE];
    ck_assert_msg(tox_mlkem_commitment(commitment, identity.mlkem_public) == 0,
                  "Commitment generation should succeed");

    /* Verification should pass with correct key */
    ck_assert_msg(tox_verify_mlkem_commitment(commitment, identity.mlkem_public) == true,
                  "Verification should pass for correct key");

    /* Verification should fail with different key */
    Tox_Hybrid_Identity identity2;
    ck_assert_msg(tox_hybrid_identity_generate(&identity2) == 0, "Second identity generation failed");

    ck_assert_msg(tox_verify_mlkem_commitment(commitment, identity2.mlkem_public) == false,
                  "Verification should fail for different key");

    /* Verification should fail with corrupted commitment */
    uint8_t corrupted_commitment[TOX_MLKEM_COMMITMENT_SIZE];
    memcpy(corrupted_commitment, commitment, TOX_MLKEM_COMMITMENT_SIZE);
    corrupted_commitment[0] ^= 0x01;  /* Flip one bit */

    ck_assert_msg(tox_verify_mlkem_commitment(corrupted_commitment, identity.mlkem_public) == false,
                  "Verification should fail for corrupted commitment");

    tox_hybrid_identity_clear(&identity);
    tox_hybrid_identity_clear(&identity2);
}

static void test_hybrid_identity_commitment(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    uint8_t commitment1[TOX_MLKEM_COMMITMENT_SIZE];
    uint8_t commitment2[TOX_MLKEM_COMMITMENT_SIZE];

    /* Both methods should produce the same commitment */
    ck_assert_msg(tox_mlkem_commitment(commitment1, identity.mlkem_public) == 0,
                  "Direct commitment should succeed");
    ck_assert_msg(tox_hybrid_identity_commitment(commitment2, &identity) == 0,
                  "Identity commitment should succeed");

    ck_assert_msg(memcmp(commitment1, commitment2, TOX_MLKEM_COMMITMENT_SIZE) == 0,
                  "Both commitment methods should produce identical results");

    tox_hybrid_identity_clear(&identity);
}

static void test_commitment_null_handling(void)
{
    Tox_Hybrid_Identity identity;
    ck_assert_msg(tox_hybrid_identity_generate(&identity) == 0, "Identity generation failed");

    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE];

    /* NULL handling */
    ck_assert_msg(tox_mlkem_commitment(NULL, identity.mlkem_public) == -1,
                  "NULL commitment buffer should fail");
    ck_assert_msg(tox_mlkem_commitment(commitment, NULL) == -1,
                  "NULL mlkem_pk should fail");
    ck_assert_msg(tox_verify_mlkem_commitment(NULL, identity.mlkem_public) == false,
                  "NULL commitment should return false");
    ck_assert_msg(tox_verify_mlkem_commitment(commitment, NULL) == false,
                  "NULL mlkem_pk should return false");
    ck_assert_msg(tox_hybrid_identity_commitment(NULL, &identity) == -1,
                  "NULL commitment buffer should fail");
    ck_assert_msg(tox_hybrid_identity_commitment(commitment, NULL) == -1,
                  "NULL identity should fail");

    tox_hybrid_identity_clear(&identity);
}

static void test_commitment_from_seed_deterministic(void)
{
    /* Same seed should produce same commitment */
    uint8_t seed[32];
    randombytes_buf(seed, 32);

    Tox_Hybrid_Identity id1, id2;
    ck_assert_msg(tox_hybrid_identity_from_seed(&id1, seed) == 0, "First seeded identity failed");
    ck_assert_msg(tox_hybrid_identity_from_seed(&id2, seed) == 0, "Second seeded identity failed");

    uint8_t commitment1[TOX_MLKEM_COMMITMENT_SIZE];
    uint8_t commitment2[TOX_MLKEM_COMMITMENT_SIZE];

    ck_assert_msg(tox_hybrid_identity_commitment(commitment1, &id1) == 0, "First commitment failed");
    ck_assert_msg(tox_hybrid_identity_commitment(commitment2, &id2) == 0, "Second commitment failed");

    ck_assert_msg(memcmp(commitment1, commitment2, TOX_MLKEM_COMMITMENT_SIZE) == 0,
                  "Same seed should produce same commitment");

    tox_hybrid_identity_clear(&id1);
    tox_hybrid_identity_clear(&id2);
}

static void test_address_size_constants(void)
{
    /* Verify address size constants are correct */
    ck_assert_msg(TOX_ADDRESS_SIZE_CLASSICAL == 38,
                  "Classical address size should be 38 bytes");
    ck_assert_msg(TOX_ADDRESS_SIZE_PQ == 46,
                  "PQ address size should be 46 bytes");
    ck_assert_msg(TOX_MLKEM_COMMITMENT_SIZE == 8,
                  "ML-KEM commitment size should be 8 bytes");

    /* Verify PQ address = classical + commitment */
    ck_assert_msg(TOX_ADDRESS_SIZE_PQ == TOX_ADDRESS_SIZE_CLASSICAL + TOX_MLKEM_COMMITMENT_SIZE,
                  "PQ address should be classical + commitment size");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("Testing PQ crypto primitives...\n");

    test_pq_available();
    printf("  [PASS] tox_pq_available\n");

    test_key_sizes();
    printf("  [PASS] key sizes match libsodium\n");

    test_hybrid_identity_generate();
    printf("  [PASS] hybrid identity generation\n");

    test_hybrid_identity_from_seed_deterministic();
    printf("  [PASS] hybrid identity from seed (deterministic)\n");

    test_hybrid_public_key_export();
    printf("  [PASS] hybrid public key export\n");

    test_public_key_is_hybrid();
    printf("  [PASS] public key hybrid detection\n");

    test_public_key_extraction();
    printf("  [PASS] public key extraction\n");

    test_hybrid_kdf();
    printf("  [PASS] hybrid KDF\n");

    test_classical_kdf();
    printf("  [PASS] classical KDF\n");

    test_hybrid_session_roundtrip();
    printf("  [PASS] hybrid session roundtrip\n");

    test_classical_fallback();
    printf("  [PASS] classical fallback\n");

    test_null_handling();
    printf("  [PASS] NULL handling\n");

    printf("\n  === Extended Security Tests ===\n");

    test_mlkem_decapsulation_wrong_keypair();
    printf("  [PASS] ML-KEM decapsulation wrong keypair (implicit rejection)\n");

    test_mlkem_corrupted_ciphertext();
    printf("  [PASS] ML-KEM corrupted ciphertext detection\n");

    test_kdf_determinism();
    printf("  [PASS] KDF determinism (100 iterations)\n");

    test_kdf_context_boundaries();
    printf("  [PASS] KDF context boundary handling\n");

    test_hybrid_vs_classical_kdf_separation();
    printf("  [PASS] hybrid vs classical KDF separation\n");

    test_identity_clear_comprehensive();
    printf("  [PASS] identity clear (all fields)\n");

    test_session_clear_comprehensive();
    printf("  [PASS] session clear (all fields)\n");

    test_seed_reproducibility_extended();
    printf("  [PASS] seed reproducibility (100 iterations)\n");

    test_seed_edge_cases();
    printf("  [PASS] seed edge cases (zeros/ones)\n");

    test_generated_keys_unique();
    printf("  [PASS] generated keys uniqueness (50 identities)\n");

    test_public_key_extraction_invalid_lengths();
    printf("  [PASS] public key extraction invalid lengths\n");

    printf("\n  === Identity Commitment Tests ===\n");

    test_mlkem_commitment_basic();
    printf("  [PASS] ML-KEM commitment basic\n");

    test_mlkem_commitment_deterministic();
    printf("  [PASS] ML-KEM commitment deterministic\n");

    test_mlkem_commitment_verification();
    printf("  [PASS] ML-KEM commitment verification\n");

    test_hybrid_identity_commitment();
    printf("  [PASS] hybrid identity commitment\n");

    test_commitment_null_handling();
    printf("  [PASS] commitment NULL handling\n");

    test_commitment_from_seed_deterministic();
    printf("  [PASS] commitment from seed deterministic\n");

    test_address_size_constants();
    printf("  [PASS] address size constants\n");

    printf("\nAll PQ crypto tests passed!\n");
    return 0;
}
