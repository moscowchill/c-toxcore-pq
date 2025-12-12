# Phase 2: Handshake Protocol Modifications

**Duration**: 6-8 weeks  
**Goal**: Integrate hybrid key exchange into Tox session establishment  
**Prerequisites**: Phase 1 complete (crypto primitives working)

## Overview

Phase 2 modifies `net_crypto.c` to:
1. Detect hybrid-capable peers from packet format
2. Perform hybrid key exchange when both peers support it
3. Fall back gracefully to classical for legacy peers
4. Expose session security status to application layer

## Understanding Current Handshake

### net_crypto.c Structure

```c
// Key structures in net_crypto.c

struct Crypto_Connection {
    uint8_t public_key[32];        // Peer's long-term public key
    uint8_t recv_nonce[24];        // Current receive nonce
    uint8_t sent_nonce[24];        // Current send nonce  
    uint8_t sessionpublic_key[32]; // Session public key
    uint8_t sessionsecret_key[32]; // Session secret key
    uint8_t peersessionpublic_key[32];  // Peer's session public key
    uint8_t shared_key[32];        // Derived session key
    // ... status, callbacks, etc.
};

// Handshake packet types
#define NET_PACKET_COOKIE_REQUEST    0x18
#define NET_PACKET_COOKIE_RESPONSE   0x19  
#define NET_PACKET_CRYPTO_HS         0x1a
#define NET_PACKET_CRYPTO_DATA       0x1b
```

### Current Handshake Flow

```
                    CURRENT TOX HANDSHAKE (Classical)

Alice                                                Bob
-----                                                ---

1. Cookie Request
   [0x18][Alice_DHT_pubkey][Alice_real_pubkey_encrypted]
   ────────────────────────────────────────────────────►

2. Cookie Response  
   [0x19][Cookie][Bob_DHT_pubkey_encrypted]
   ◄────────────────────────────────────────────────────

3. Handshake Packet
   - Generate session keypair (X25519)
   - Compute shared_key = DH(session_secret, peer_session_public)
   [0x1a][Cookie][Nonce][Encrypted_handshake_data]
   ────────────────────────────────────────────────────►

4. Handshake Response
   [0x1a][Cookie][Nonce][Encrypted_handshake_data]
   ◄────────────────────────────────────────────────────

5. Session Established
   Both sides have shared_key from X25519 DH
```

## Modified Handshake Design

### Extended Packet Formats

```c
// Hybrid detection via version byte at start of payload
// Existing packets will never have 0x02 at this position

// COOKIE REQUEST - Extended
// Classical: [0x18][pubkey(32)][dht_pubkey(32)][encrypted...]
// Hybrid:    [0x18][0x02][x25519_pub(32)][mlkem_pub(1184)][encrypted...]

// COOKIE RESPONSE - Extended  
// Classical: [0x19][cookie(...)][encrypted...]
// Hybrid:    [0x19][0x02][x25519_pub(32)][mlkem_pub(1184)][cookie(...)][encrypted...]

// HANDSHAKE - Extended
// Classical: [0x1a][cookie][nonce(24)][encrypted_hs]
// Hybrid:    [0x1a][0x02][cookie][mlkem_ct(1088)][nonce(24)][encrypted_hs]
```

### Detection Logic

```c
/**
 * Check if incoming packet uses hybrid format.
 * Safe to call on any packet - won't misidentify legacy packets.
 */
static bool packet_is_hybrid_format(const uint8_t *packet, size_t length)
{
    if (length < 2) {
        return false;
    }
    
    /* Check for hybrid version marker after packet type byte */
    return packet[1] == TOX_CRYPTO_VERSION_HYBRID;
}
```

## Implementation Steps

### Step 1: Extend Crypto_Connection Structure

```c
/* In net_crypto.h or net_crypto.c */

typedef struct Crypto_Connection {
    /* Existing fields */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE];
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE];
    uint8_t sessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sessionsecret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    
    /* NEW: Hybrid PQ fields */
    bool pq_capable;                                    /* Our capability */
    bool peer_pq_capable;                               /* Peer's capability */
    bool session_is_hybrid;                             /* Current session type */
    
    uint8_t mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES];  /* Our ML-KEM pubkey */
    uint8_t mlkem_secret[TOX_MLKEM768_SECRETKEYBYTES];  /* Our ML-KEM secret */
    uint8_t peer_mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES]; /* Peer's ML-KEM */
    uint8_t mlkem_ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES]; /* For initiator */
    uint8_t mlkem_shared[32];                           /* ML-KEM shared secret */
    
    /* Existing fields continued... */
    uint64_t cookie_request_number;
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    // ... etc
} Crypto_Connection;
```

### Step 2: Modify Cookie Request Handling

#### 2.1 Create Hybrid Cookie Request

```c
/* net_crypto_pq.c - New file or additions to net_crypto.c */

/**
 * Create a hybrid cookie request packet.
 * Larger than classical due to ML-KEM public key.
 */
static int create_cookie_request_hybrid(
    const Net_Crypto *c,
    uint8_t *packet,
    size_t max_len,
    const uint8_t *dht_public_key,
    const uint8_t *real_public_key,
    const uint8_t *mlkem_public_key,
    uint64_t number,
    uint8_t *shared_key
)
{
    /* Minimum size for hybrid request */
    const size_t HYBRID_COOKIE_REQUEST_SIZE = 1 + 1 + 32 + TOX_MLKEM768_PUBLICKEYBYTES + 
                                               COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE;
    
    if (max_len < HYBRID_COOKIE_REQUEST_SIZE) {
        return -1;
    }
    
    size_t offset = 0;
    
    /* Packet type */
    packet[offset++] = NET_PACKET_COOKIE_REQUEST;
    
    /* Hybrid version marker */
    packet[offset++] = TOX_CRYPTO_VERSION_HYBRID;
    
    /* Our X25519 public key (from DHT) */
    memcpy(packet + offset, dht_public_key, 32);
    offset += 32;
    
    /* Our ML-KEM public key */
    memcpy(packet + offset, mlkem_public_key, TOX_MLKEM768_PUBLICKEYBYTES);
    offset += TOX_MLKEM768_PUBLICKEYBYTES;
    
    /* Encrypted payload (same as classical, different encryption) */
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];
    memcpy(plain, real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, &number, sizeof(uint64_t));
    /* ... padding ... */
    
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);
    
    /* Compute shared key for encryption */
    /* For cookie request, we use peer's DHT key (pre-known) */
    /* This part needs peer's public key which we have from DHT */
    
    int encrypted_len = encrypt_data_symmetric(shared_key, nonce, plain, 
                                                sizeof(plain), packet + offset);
    if (encrypted_len < 0) {
        return -1;
    }
    
    offset += encrypted_len;
    
    return (int)offset;
}

/**
 * Handle incoming hybrid cookie request.
 */
static int handle_cookie_request_hybrid(
    Net_Crypto *c,
    const uint8_t *packet,
    size_t length,
    const IP_Port *source
)
{
    /* Parse hybrid format */
    if (length < 2 + 32 + TOX_MLKEM768_PUBLICKEYBYTES + CRYPTO_NONCE_SIZE) {
        return -1;
    }
    
    size_t offset = 2;  /* Skip packet type and version */
    
    /* Extract sender's X25519 public key */
    const uint8_t *sender_x25519 = packet + offset;
    offset += 32;
    
    /* Extract sender's ML-KEM public key */
    const uint8_t *sender_mlkem = packet + offset;
    offset += TOX_MLKEM768_PUBLICKEYBYTES;
    
    /* Store sender's PQ capability */
    /* This will be used when we establish the connection */
    
    /* Decrypt and process payload (similar to classical) */
    /* ... */
    
    /* Create hybrid cookie response */
    return send_cookie_response_hybrid(c, source, sender_x25519, sender_mlkem, /* ... */);
}
```

#### 2.2 Handle Cookie Response

```c
/**
 * Create hybrid cookie response.
 */
static int create_cookie_response_hybrid(
    const Net_Crypto *c,
    uint8_t *packet,
    size_t max_len,
    const uint8_t *request_x25519,
    const uint8_t *request_mlkem,
    /* ... other params ... */
)
{
    size_t offset = 0;
    
    packet[offset++] = NET_PACKET_COOKIE_RESPONSE;
    packet[offset++] = TOX_CRYPTO_VERSION_HYBRID;
    
    /* Our X25519 public key */
    memcpy(packet + offset, c->self_public_key, 32);
    offset += 32;
    
    /* Our ML-KEM public key */
    memcpy(packet + offset, c->self_mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES);
    offset += TOX_MLKEM768_PUBLICKEYBYTES;
    
    /* Cookie (includes binding to both keys) */
    /* ... cookie creation with hybrid binding ... */
    
    /* Encrypted response data */
    /* ... */
    
    return (int)offset;
}
```

### Step 3: Modify Handshake Packet

This is the critical part where hybrid key exchange happens.

```c
/**
 * Create hybrid handshake packet.
 * Includes ML-KEM ciphertext for encapsulation.
 */
static int create_crypto_handshake_hybrid(
    Net_Crypto *c,
    Crypto_Connection *conn,
    uint8_t *packet,
    size_t max_len,
    const uint8_t *cookie,
    size_t cookie_length
)
{
    size_t offset = 0;
    
    packet[offset++] = NET_PACKET_CRYPTO_HS;
    packet[offset++] = TOX_CRYPTO_VERSION_HYBRID;
    
    /* Cookie */
    memcpy(packet + offset, cookie, cookie_length);
    offset += cookie_length;
    
    /* Generate session X25519 keypair */
    crypto_box_keypair(conn->sessionpublic_key, conn->sessionsecret_key);
    
    /* ML-KEM encapsulation using peer's ML-KEM public key */
    if (crypto_kem_mlkem768_enc(conn->mlkem_ciphertext, 
                                 conn->mlkem_shared,
                                 conn->peer_mlkem_public) != 0) {
        return -1;
    }
    
    /* Include ML-KEM ciphertext in packet */
    memcpy(packet + offset, conn->mlkem_ciphertext, TOX_MLKEM768_CIPHERTEXTBYTES);
    offset += TOX_MLKEM768_CIPHERTEXTBYTES;
    
    /* Nonce */
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);
    memcpy(packet + offset, nonce, CRYPTO_NONCE_SIZE);
    offset += CRYPTO_NONCE_SIZE;
    
    /* Handshake data to encrypt */
    uint8_t plain[/* size */];
    /* Include our session X25519 public key */
    memcpy(plain, conn->sessionpublic_key, 32);
    /* ... other handshake data ... */
    
    /* Compute hybrid shared key for handshake encryption */
    /* At this point we have:
     * - X25519: conn->sessionsecret_key, conn->peer_mlkem_public (wait, we need peer session key)
     * - ML-KEM: conn->mlkem_shared (from encapsulation)
     * 
     * Actually, for the handshake packet encryption, we use the long-term DH.
     * The session keys are exchanged IN the handshake.
     * Let me reconsider...
     */
    
    /* 
     * Correction: The handshake packet contains our session public key.
     * Encryption uses long-term key derived shared secret.
     * After both handshakes exchanged, we compute final session key.
     */
    
    /* Encrypt with existing method (long-term DH) */
    int encrypted_len = encrypt_data(conn->public_key, c->self_secret_key,
                                      nonce, plain, sizeof(plain),
                                      packet + offset);
    if (encrypted_len < 0) {
        return -1;
    }
    offset += encrypted_len;
    
    return (int)offset;
}

/**
 * Handle incoming hybrid handshake.
 */
static int handle_crypto_handshake_hybrid(
    Net_Crypto *c,
    Crypto_Connection *conn,
    const uint8_t *packet,
    size_t length
)
{
    size_t offset = 2;  /* Skip type + version */
    
    /* Extract and verify cookie */
    /* ... */
    
    /* Extract ML-KEM ciphertext */
    if (length < offset + TOX_MLKEM768_CIPHERTEXTBYTES) {
        return -1;
    }
    const uint8_t *mlkem_ct = packet + offset;
    offset += TOX_MLKEM768_CIPHERTEXTBYTES;
    
    /* ML-KEM decapsulation */
    if (crypto_kem_mlkem768_dec(conn->mlkem_shared, mlkem_ct, c->self_mlkem_secret) != 0) {
        return -1;
    }
    
    /* Extract nonce */
    if (length < offset + CRYPTO_NONCE_SIZE) {
        return -1;
    }
    const uint8_t *nonce = packet + offset;
    offset += CRYPTO_NONCE_SIZE;
    
    /* Decrypt handshake data */
    uint8_t plain[/* size */];
    int decrypted_len = decrypt_data(c->self_public_key, conn->public_key,
                                      nonce, packet + offset, length - offset,
                                      plain);
    if (decrypted_len < 0) {
        return -1;
    }
    
    /* Extract peer's session public key from decrypted data */
    memcpy(conn->peersessionpublic_key, plain, 32);
    
    /* Mark as hybrid session */
    conn->session_is_hybrid = true;
    
    return 0;
}
```

### Step 4: Compute Final Session Key

```c
/**
 * Compute final session key after handshake exchange.
 * Called after both sides have exchanged handshake packets.
 */
static int compute_session_key_hybrid(Crypto_Connection *conn)
{
    /* X25519 session DH */
    uint8_t x25519_shared[32];
    if (crypto_scalarmult(x25519_shared, conn->sessionsecret_key, 
                          conn->peersessionpublic_key) != 0) {
        return -1;
    }
    
    /* Combine with ML-KEM shared secret */
    static const uint8_t ctx[] = "ToxSession";
    if (tox_hybrid_kdf(conn->shared_key, x25519_shared, conn->mlkem_shared,
                        ctx, sizeof(ctx) - 1) != 0) {
        sodium_memzero(x25519_shared, 32);
        return -1;
    }
    
    sodium_memzero(x25519_shared, 32);
    
    return 0;
}

/**
 * Compute classical session key (fallback).
 */
static int compute_session_key_classical(Crypto_Connection *conn)
{
    /* X25519 only */
    uint8_t x25519_shared[32];
    if (crypto_scalarmult(x25519_shared, conn->sessionsecret_key,
                          conn->peersessionpublic_key) != 0) {
        return -1;
    }
    
    static const uint8_t ctx[] = "ToxSession";
    if (tox_classical_kdf(conn->shared_key, x25519_shared, ctx, sizeof(ctx) - 1) != 0) {
        sodium_memzero(x25519_shared, 32);
        return -1;
    }
    
    sodium_memzero(x25519_shared, 32);
    
    return 0;
}
```

### Step 5: Modify Main Handshake Functions

Update the main entry points to route to hybrid or classical:

```c
/**
 * Modified handle_cookie_request - routes to appropriate handler.
 */
static int handle_cookie_request(void *object, const IP_Port *source,
                                  const uint8_t *packet, uint16_t length)
{
    Net_Crypto *c = (Net_Crypto *)object;
    
    if (packet_is_hybrid_format(packet, length)) {
        return handle_cookie_request_hybrid(c, packet, length, source);
    } else {
        return handle_cookie_request_classical(c, packet, length, source);
    }
}

/**
 * Modified handle_crypto_handshake - routes to appropriate handler.
 */
static int handle_crypto_handshake(Net_Crypto *c, Crypto_Connection *conn,
                                    const uint8_t *packet, uint16_t length)
{
    if (packet_is_hybrid_format(packet, length)) {
        return handle_crypto_handshake_hybrid(c, conn, packet, length);
    } else {
        return handle_crypto_handshake_classical(c, conn, packet, length);
    }
}

/**
 * Modified connection finalization.
 */
static int finalize_crypto_connection(Crypto_Connection *conn)
{
    if (conn->session_is_hybrid) {
        return compute_session_key_hybrid(conn);
    } else {
        return compute_session_key_classical(conn);
    }
}
```

### Step 6: Expose Security Status to API

Add to `tox.h` and `tox.c`:

```c
/* tox.h */

typedef enum Tox_Connection_Security {
    TOX_CONNECTION_SECURITY_UNKNOWN = 0,
    TOX_CONNECTION_SECURITY_CLASSICAL = 1,
    TOX_CONNECTION_SECURITY_HYBRID = 2
} Tox_Connection_Security;

/**
 * Get the security level of a friend connection.
 *
 * @param tox The Tox instance
 * @param friend_number Friend to check
 * @param error Error output
 * @return Security level of the connection
 */
Tox_Connection_Security tox_friend_get_connection_security(
    const Tox *tox,
    uint32_t friend_number,
    Tox_Err_Friend_Query *error
);

/**
 * Check if we are PQ capable.
 *
 * @param tox The Tox instance
 * @return true if PQ algorithms are available
 */
bool tox_self_get_pq_capable(const Tox *tox);
```

```c
/* tox.c */

Tox_Connection_Security tox_friend_get_connection_security(
    const Tox *tox,
    uint32_t friend_number,
    Tox_Err_Friend_Query *error
)
{
    assert(tox != NULL);
    tox_lock(tox);
    
    /* Get crypto connection for this friend */
    const int crypt_conn_id = friend_get_crypto_connection_id(tox->m->net_crypto,
                                                               friend_number);
    if (crypt_conn_id < 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        tox_unlock(tox);
        return TOX_CONNECTION_SECURITY_UNKNOWN;
    }
    
    Crypto_Connection *conn = get_crypto_connection(tox->m->net_crypto, crypt_conn_id);
    if (conn == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        tox_unlock(tox);
        return TOX_CONNECTION_SECURITY_UNKNOWN;
    }
    
    Tox_Connection_Security result;
    if (conn->session_is_hybrid) {
        result = TOX_CONNECTION_SECURITY_HYBRID;
    } else {
        result = TOX_CONNECTION_SECURITY_CLASSICAL;
    }
    
    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    tox_unlock(tox);
    return result;
}

bool tox_self_get_pq_capable(const Tox *tox)
{
    return tox_pq_available();
}
```

## Step 7: Update tox4j JNI Bindings

Create JNI bindings for new API functions:

```cpp
/* ToxCoreJni.cpp additions */

JNIEXPORT jint JNICALL Java_im_tox_tox4j_core_ToxCoreImpl_toxFriendGetConnectionSecurity(
    JNIEnv *env,
    jobject self,
    jint friendNumber
)
{
    Tox *tox = getToxPointer(env, self);
    Tox_Err_Friend_Query error;
    
    Tox_Connection_Security result = tox_friend_get_connection_security(
        tox, friendNumber, &error);
    
    if (error != TOX_ERR_FRIEND_QUERY_OK) {
        throwToxException(env, error);
        return 0;
    }
    
    return (jint)result;
}

JNIEXPORT jboolean JNICALL Java_im_tox_tox4j_core_ToxCoreImpl_toxSelfGetPqCapable(
    JNIEnv *env,
    jobject self
)
{
    Tox *tox = getToxPointer(env, self);
    return tox_self_get_pq_capable(tox) ? JNI_TRUE : JNI_FALSE;
}
```

## Testing Phase 2

### Integration Test: Hybrid Handshake

```c
/* auto_tests/crypto_handshake_pq_test.c */

START_TEST(test_hybrid_handshake_both_pq)
{
    /* Create two Tox instances with PQ support */
    Tox *tox1 = tox_new(NULL, NULL);
    Tox *tox2 = tox_new(NULL, NULL);
    
    /* Add each other as friends */
    uint8_t address2[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address2);
    
    uint32_t friend_num = tox_friend_add(tox1, address2, "hi", 2, NULL);
    ck_assert_int_ge(friend_num, 0);
    
    /* Bootstrap and iterate until connected */
    /* ... iteration loop ... */
    
    /* Check connection security */
    Tox_Connection_Security sec = tox_friend_get_connection_security(
        tox1, friend_num, NULL);
    
    ck_assert_int_eq(sec, TOX_CONNECTION_SECURITY_HYBRID);
    
    tox_kill(tox1);
    tox_kill(tox2);
}
END_TEST

START_TEST(test_hybrid_fallback_to_classical)
{
    /* Create one PQ-capable and one legacy Tox */
    /* ... */
    
    /* Verify fallback to classical */
    Tox_Connection_Security sec = tox_friend_get_connection_security(
        tox_pq, friend_num, NULL);
    
    ck_assert_int_eq(sec, TOX_CONNECTION_SECURITY_CLASSICAL);
}
END_TEST
```

### Network Test Script

```bash
#!/bin/bash
# test_pq_handshake.sh

# Start two clients in debug mode
./tox_client_pq --port 33445 --log debug &
PID1=$!

./tox_client_pq --port 33446 --log debug &
PID2=$!

# Wait for bootstrap
sleep 5

# Trigger friend add and connection
# ... test automation ...

# Check logs for:
# - "Sending hybrid cookie request"
# - "Received hybrid cookie response"  
# - "ML-KEM encapsulation successful"
# - "Session established with hybrid security"

grep "hybrid" /tmp/tox_client_*.log

kill $PID1 $PID2
```

## Phase 2 Deliverables Checklist

- [ ] Extended Crypto_Connection structure with PQ fields
- [ ] Hybrid cookie request create/handle
- [ ] Hybrid cookie response create/handle
- [ ] Hybrid handshake packet create/handle
- [ ] Session key derivation (hybrid and classical)
- [ ] Automatic fallback detection
- [ ] New API: `tox_friend_get_connection_security()`
- [ ] New API: `tox_self_get_pq_capable()`
- [ ] tox4j JNI bindings updated
- [ ] Integration tests passing
- [ ] Interoperability with legacy clients tested

## Next: Phase 3

With protocol changes complete, Phase 3 focuses on Android integration:
- Build system for ARM/x86 ABIs
- aTox UI security indicators
- User preferences for PQ policy
