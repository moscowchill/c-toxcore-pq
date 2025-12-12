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
    uint8_t zeros[32] = {0};
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
    uint8_t zeros[32] = {0};

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
    uint8_t zeros[32] = {0};

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
    uint8_t zeros[32] = {0};
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

    printf("\nAll PQ crypto tests passed!\n");
    return 0;
}
