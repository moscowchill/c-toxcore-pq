# Phase 4: Testing & Validation

**Goal**: Comprehensive testing and preparation for security audit
**Prerequisites**: Phase 1 & 2 complete (c-toxcore-pq building and passing tests)

## Testing Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    Testing Pyramid                          │
├─────────────────────────────────────────────────────────────┤
│                    ┌───────────┐                            │
│                    │  Manual   │  Interoperability tests    │
│                   ─┴───────────┴─                           │
│                 ┌─────────────────┐                         │
│                 │   Integration   │  Protocol tests         │
│               ──┴─────────────────┴──                       │
│             ┌───────────────────────────┐                   │
│             │       Unit Tests          │  Crypto primitives │
│           ──┴───────────────────────────┴──                 │
└─────────────────────────────────────────────────────────────┘
```

## 1. Unit Tests

### 1.1 C Crypto Unit Tests

```c
/* auto_tests/crypto_pq_test.c */

#include "../toxcore/crypto_core_pq.h"
#include <check.h>
#include <sodium.h>

START_TEST(test_mlkem_sizes_match)
{
    ck_assert_uint_eq(crypto_kem_mlkem768_publickeybytes(), 
                      TOX_MLKEM768_PUBLICKEYBYTES);
    ck_assert_uint_eq(crypto_kem_mlkem768_secretkeybytes(), 
                      TOX_MLKEM768_SECRETKEYBYTES);
    ck_assert_uint_eq(crypto_kem_mlkem768_ciphertextbytes(), 
                      TOX_MLKEM768_CIPHERTEXTBYTES);
}
END_TEST

START_TEST(test_identity_generation)
{
    Tox_Hybrid_Identity id;
    ck_assert_int_eq(tox_hybrid_identity_generate(&id), 0);
    ck_assert_int_eq(id.version, TOX_CRYPTO_VERSION_HYBRID);
    
    uint8_t zeros[32] = {0};
    ck_assert(memcmp(id.x25519_public, zeros, 32) != 0);
    
    tox_hybrid_identity_clear(&id);
}
END_TEST

START_TEST(test_deterministic_from_seed)
{
    uint8_t seed[32];
    randombytes_buf(seed, 32);
    
    Tox_Hybrid_Identity id1, id2;
    tox_hybrid_identity_from_seed(&id1, seed);
    tox_hybrid_identity_from_seed(&id2, seed);
    
    ck_assert(memcmp(id1.x25519_public, id2.x25519_public, 32) == 0);
    ck_assert(memcmp(id1.mlkem_public, id2.mlkem_public, 
                     TOX_MLKEM768_PUBLICKEYBYTES) == 0);
    
    tox_hybrid_identity_clear(&id1);
    tox_hybrid_identity_clear(&id2);
}
END_TEST

START_TEST(test_hybrid_kdf_deterministic)
{
    uint8_t x25519[32], mlkem[32], key1[32], key2[32];
    randombytes_buf(x25519, 32);
    randombytes_buf(mlkem, 32);
    
    tox_hybrid_kdf(key1, x25519, mlkem, (uint8_t*)"ctx", 3);
    tox_hybrid_kdf(key2, x25519, mlkem, (uint8_t*)"ctx", 3);
    
    ck_assert(memcmp(key1, key2, 32) == 0);
}
END_TEST

START_TEST(test_session_key_agreement)
{
    Tox_Hybrid_Identity alice, bob;
    tox_hybrid_identity_generate(&alice);
    tox_hybrid_identity_generate(&bob);
    
    uint8_t bob_pub[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(bob_pub, &bob);
    
    Tox_Hybrid_Session alice_sess, bob_sess;
    tox_hybrid_session_initiate(&alice_sess, &alice, bob_pub, sizeof(bob_pub));
    tox_hybrid_session_respond(&bob_sess, &bob, 
                                alice_sess.x25519_ephemeral_public,
                                alice_sess.mlkem_ciphertext, true);
    
    ck_assert(memcmp(alice_sess.session_key, bob_sess.session_key, 32) == 0);
    
    tox_hybrid_identity_clear(&alice);
    tox_hybrid_identity_clear(&bob);
    tox_hybrid_session_clear(&alice_sess);
    tox_hybrid_session_clear(&bob_sess);
}
END_TEST

START_TEST(test_classical_fallback)
{
    Tox_Hybrid_Identity alice;
    tox_hybrid_identity_generate(&alice);
    
    uint8_t bob_classical[32];
    uint8_t bob_secret[32];
    crypto_box_keypair(bob_classical, bob_secret);
    
    Tox_Hybrid_Session sess;
    tox_hybrid_session_initiate(&sess, &alice, bob_classical, 32);
    
    ck_assert(!sess.peer_pq_capable);
    ck_assert(sess.session_established);
    
    tox_hybrid_identity_clear(&alice);
}
END_TEST

Suite *crypto_pq_suite(void) {
    Suite *s = suite_create("CryptoPQ");
    TCase *tc = tcase_create("Core");
    
    tcase_add_test(tc, test_mlkem_sizes_match);
    tcase_add_test(tc, test_identity_generation);
    tcase_add_test(tc, test_deterministic_from_seed);
    tcase_add_test(tc, test_hybrid_kdf_deterministic);
    tcase_add_test(tc, test_session_key_agreement);
    tcase_add_test(tc, test_classical_fallback);
    
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    sodium_init();
    Suite *s = crypto_pq_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed ? 1 : 0;
}
```

## 2. Integration Tests

### 2.1 Protocol Tests

```c
/* auto_tests/pq_handshake_test.c */

START_TEST(test_pq_clients_establish_hybrid)
{
    Tox *tox1 = tox_new(NULL, NULL);
    Tox *tox2 = tox_new(NULL, NULL);
    
    ck_assert(tox_self_get_pq_capable(tox1));
    ck_assert(tox_self_get_pq_capable(tox2));
    
    // Add friend and wait for connection
    uint8_t addr[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, addr);
    uint32_t fn = tox_friend_add(tox1, addr, (uint8_t*)"hi", 2, NULL);
    
    // Iterate until connected
    while (tox_friend_get_connection_status(tox1, fn, NULL) == TOX_CONNECTION_NONE) {
        tox_iterate(tox1, NULL);
        tox_iterate(tox2, NULL);
        usleep(tox_iteration_interval(tox1) * 1000);
    }
    
    // Verify hybrid security
    Tox_Connection_Security sec = tox_friend_get_connection_security(tox1, fn, NULL);
    ck_assert_int_eq(sec, TOX_CONNECTION_SECURITY_HYBRID);
    
    tox_kill(tox1);
    tox_kill(tox2);
}
END_TEST
```

## 3. Manual Test Checklist

```markdown
## Manual Testing

### Setup
- [ ] Instance A: c-toxcore-pq (PQ-capable)
- [ ] Instance B: c-toxcore-pq (PQ-capable)
- [ ] Instance C: Legacy c-toxcore (classical)

### Hybrid Tests (A ↔ B)
- [ ] Friend connection establishes
- [ ] tox_friend_get_identity_status() returns PQ_VERIFIED (with 46-byte address)
- [ ] tox_friend_get_identity_status() returns PQ_UNVERIFIED (with 38-byte address)
- [ ] Messages work correctly
- [ ] Reconnection maintains hybrid session

### Fallback Tests (A ↔ C)
- [ ] Connection establishes
- [ ] tox_friend_get_identity_status() returns CLASSICAL
- [ ] Messages work correctly
- [ ] No protocol errors on legacy side

### API Tests
- [ ] tox_self_get_address_pq() returns valid 46-byte address
- [ ] tox_self_has_pq_identity() returns true when PQ available
- [ ] tox_friend_add_pq() accepts 46-byte addresses
```

## 4. CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { submodules: recursive }
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y cmake ninja-build libgtest-dev
      - name: Build libsodium from master
        run: |
          git clone https://github.com/jedisct1/libsodium.git
          cd libsodium
          ./autogen.sh && ./configure && make -j$(nproc)
          sudo make install && sudo ldconfig
      - name: Build and test c-toxcore-pq
        run: |
          mkdir _build && cd _build
          cmake .. -DAUTOTEST=ON -DUNITTEST=ON
          make -j$(nproc)
          ctest -j$(nproc) --output-on-failure
```

## 5. Performance Benchmarks

```c
/* bench/crypto_bench.c */
#define ITERATIONS 1000

void bench_hybrid_session() {
    Tox_Hybrid_Identity alice, bob;
    tox_hybrid_identity_generate(&alice);
    tox_hybrid_identity_generate(&bob);
    
    uint8_t bob_pub[TOX_HYBRID_PUBLICKEYBYTES];
    tox_hybrid_public_key_export(bob_pub, &bob);
    
    clock_t start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        Tox_Hybrid_Session a, b;
        tox_hybrid_session_initiate(&a, &alice, bob_pub, sizeof(bob_pub));
        tox_hybrid_session_respond(&b, &bob, a.x25519_ephemeral_public,
                                    a.mlkem_ciphertext, true);
    }
    double ms = ((double)(clock() - start) / CLOCKS_PER_SEC / ITERATIONS) * 1000;
    printf("Full handshake: %.2f ms\n", ms);
}
```

### Expected Performance (ARM64)
| Operation | Time |
|-----------|------|
| ML-KEM keygen | ~0.3 ms |
| ML-KEM encaps | ~0.1 ms |
| Full handshake | ~0.5 ms |

## 6. Security Audit Preparation

### Documentation Package
- Architecture overview
- Crypto design specification  
- Threat model
- Test coverage report

### Budget
$30,000 - $50,000 for professional audit

### Recommended Firms
- NCC Group
- Trail of Bits
- Cure53

## Phase 4 Checklist

- [ ] All unit tests passing (`unit_crypto_pq_test`, etc.)
- [ ] Integration tests passing (`auto_crypto_pq_test`, `auto_friend_connection_test`)
- [ ] Interoperability testing with legacy c-toxcore complete
- [ ] CI/CD pipeline working
- [ ] Performance benchmarks acceptable
- [ ] Security audit documentation prepared
- [ ] No memory leaks (ASan clean)
- [ ] No undefined behavior (UBSan clean)
