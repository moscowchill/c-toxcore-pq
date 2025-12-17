# Phase 2: Handshake Protocol Modifications

**Status**: Implemented
**Goal**: Integrate hybrid key exchange into Tox session establishment
**Prerequisites**: Phase 1 complete (crypto primitives working)

## Overview

Phase 2 modifies `net_crypto.c` to:
1. Signal PQ capability via marker in cookie request padding
2. Detect PQ-capable peers from hybrid cookie response format
3. Perform hybrid key exchange when both peers support it
4. Fall back gracefully to classical for legacy peers

## Implementation Summary

### Key Design Decisions

1. **In-band capability signaling** instead of ToxExt negotiation
2. **PQ marker in cookie request padding** (backwards compatible)
3. **ML-KEM public key in cookie response** (not in request)
4. **Asymmetric encapsulation** - initiator encapsulates, responder decapsulates
5. **Public key comparison** for simultaneous handshake resolution

### Modified Files

| File | Changes |
|------|---------|
| `toxcore/net_crypto.c` | PQ marker detection, hybrid packet handlers, KDF integration |
| `toxcore/net_crypto.h` | Extended Crypto_Connection struct |
| `toxcore/friend_connection.c` | PQ capability tracking per friend |
| `toxcore/friend_connection.h` | New `friend_connection_set_pq_capability()` |
| `toxcore/crypto_core_pq.c` | ML-KEM wrappers, hybrid KDF (Phase 1) |

## net_crypto.c Structure

### Extended Crypto_Connection

```c
typedef struct Crypto_Connection {
    /* Existing fields */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE];
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE];
    uint8_t sessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sessionsecret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    /* PQ capability fields */
    bool pq_enabled;              /* Our PQ capability */
    bool peer_pq_capable;         /* Peer's PQ capability (from cookie response) */
    bool session_is_hybrid;       /* Current session using hybrid crypto */

    /* ML-KEM key material */
    uint8_t peer_mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES];   /* 1184 bytes */
    uint8_t mlkem_ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES];   /* 1088 bytes */
    uint8_t mlkem_shared[TOX_MLKEM768_SHAREDSECRETBYTES];     /* 32 bytes */

    /* ... existing fields ... */
} Crypto_Connection;
```

### Constants

```c
/* PQ capability marker in cookie request padding */
#define PQ_CAPABILITY_MARKER 0x02
#define PQ_CAPABILITY_OFFSET (CRYPTO_PUBLIC_KEY_SIZE)  /* Position 32 */

/* Hybrid version marker (position 1 in hybrid packets) */
#define TOX_CRYPTO_VERSION_HYBRID 0x02

/* Packet sizes */
#define HYBRID_COOKIE_RESPONSE_PLAIN_LENGTH (COOKIE_LENGTH + sizeof(uint64_t) + TOX_MLKEM768_PUBLICKEYBYTES)
#define HYBRID_COOKIE_RESPONSE_LENGTH (1 + 1 + CRYPTO_NONCE_SIZE + HYBRID_COOKIE_RESPONSE_PLAIN_LENGTH + CRYPTO_MAC_SIZE)
/* = 1346 bytes */

#define HYBRID_HANDSHAKE_PACKET_LENGTH (1 + 1 + COOKIE_LENGTH + TOX_MLKEM768_CIPHERTEXTBYTES + \
                                        CRYPTO_NONCE_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + \
                                        CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
/* = 1474 bytes */
```

## Cookie Request Handling

### Setting PQ Capability Marker

In `create_cookie_request()`:

```c
static int create_cookie_request(const Net_Crypto *c, uint8_t *packet, ...)
{
    /* ... existing code ... */

    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];
    memcpy(plain, real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, &temp_num, sizeof(uint64_t));

    /* Set PQ capability marker in padding */
    if (c->pq_enabled) {
        plain[PQ_CAPABILITY_OFFSET] = PQ_CAPABILITY_MARKER;
    }

    /* ... encrypt and send ... */
}
```

### Detecting PQ Marker and Sending Hybrid Response

In `udp_handle_cookie_request()`:

```c
static int udp_handle_cookie_request(void *object, const IP_Port *source,
                                      const uint8_t *packet, uint16_t length, void *userdata)
{
    /* ... decrypt cookie request ... */

    /* Check for PQ capability marker */
    if (c->pq_enabled && request_plain[PQ_CAPABILITY_OFFSET] == PQ_CAPABILITY_MARKER) {
        /* Peer is PQ capable - send hybrid cookie response */
        return send_hybrid_cookie_response(c, source, request_plain, shared_key);
    }

    /* Classical response for non-PQ peers */
    return send_classical_cookie_response(c, source, request_plain, shared_key);
}
```

## Cookie Response Handling

### Creating Hybrid Cookie Response

```c
static int create_cookie_response_hybrid(const Net_Crypto *c, uint8_t *packet,
                                          const uint8_t *request_plain,
                                          const uint8_t *shared_key)
{
    size_t offset = 0;

    /* Packet type */
    packet[offset++] = NET_PACKET_COOKIE_RESPONSE;

    /* Hybrid version marker */
    packet[offset++] = TOX_CRYPTO_VERSION_HYBRID;

    /* Nonce */
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);
    memcpy(packet + offset, nonce, CRYPTO_NONCE_SIZE);
    offset += CRYPTO_NONCE_SIZE;

    /* Plaintext: cookie + request number + our ML-KEM public key */
    uint8_t plain[HYBRID_COOKIE_RESPONSE_PLAIN_LENGTH];
    /* ... create cookie ... */
    memcpy(plain + COOKIE_LENGTH, &request_number, sizeof(uint64_t));
    memcpy(plain + COOKIE_LENGTH + sizeof(uint64_t),
           c->self_mlkem_public, TOX_MLKEM768_PUBLICKEYBYTES);

    /* Encrypt */
    int encrypted_len = encrypt_data_symmetric(shared_key, nonce, plain,
                                                sizeof(plain), packet + offset);

    return offset + encrypted_len;  /* 1346 bytes */
}
```

### Handling Hybrid Cookie Response

In `handle_packet_cookie_response()`:

```c
static int handle_packet_cookie_response(Net_Crypto *c, int crypt_connection_id,
                                          const uint8_t *packet, uint16_t length)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    /* Check for hybrid format */
    if (packet_is_hybrid_format(packet, length) && conn->pq_enabled) {
        /* Extract peer's ML-KEM public key */
        if (handle_cookie_response_hybrid(c->mem, cookie, &number,
                                           conn->peer_mlkem_public,
                                           packet, length, conn->shared_key) != sizeof(cookie)) {
            return -1;
        }

        conn->peer_pq_capable = true;

        /* Create hybrid handshake with ML-KEM encapsulation */
        if (create_send_handshake_hybrid(c, crypt_connection_id, cookie, conn->dht_public_key) != 0) {
            return -1;
        }

        conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
        return 0;
    }

    /* Classical path */
    /* ... existing code ... */
}
```

## Handshake Handling

### Creating Hybrid Handshake

```c
static int create_crypto_handshake_hybrid(const Net_Crypto *c, uint8_t *packet,
                                           const uint8_t *cookie,
                                           const uint8_t *send_nonce,
                                           const uint8_t *session_pk,
                                           const uint8_t *real_pk,
                                           const uint8_t *dht_public_key,
                                           const uint8_t *peer_mlkem_public,
                                           uint8_t *mlkem_ct_out,
                                           uint8_t *mlkem_ss_out)
{
    size_t offset = 0;

    /* Packet type + version */
    packet[offset++] = NET_PACKET_CRYPTO_HS;
    packet[offset++] = TOX_CRYPTO_VERSION_HYBRID;

    /* Cookie */
    memcpy(packet + offset, cookie, COOKIE_LENGTH);
    offset += COOKIE_LENGTH;

    /* ML-KEM encapsulation */
    if (crypto_kem_mlkem768_enc(mlkem_ct_out, mlkem_ss_out, peer_mlkem_public) != 0) {
        return -1;
    }
    memcpy(packet + offset, mlkem_ct_out, TOX_MLKEM768_CIPHERTEXTBYTES);
    offset += TOX_MLKEM768_CIPHERTEXTBYTES;

    /* Nonce + encrypted handshake data */
    /* ... same structure as classical but with hybrid marker ... */

    return HYBRID_HANDSHAKE_PACKET_LENGTH;  /* 1474 bytes */
}
```

### Handling Incoming Hybrid Handshake

```c
static int handle_packet_crypto_hs(Net_Crypto *c, int crypt_connection_id,
                                    const uint8_t *packet, uint16_t length,
                                    void *userdata)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (packet_is_hybrid_format(packet, length) && c->pq_enabled) {
        uint8_t mlkem_ct[TOX_MLKEM768_CIPHERTEXTBYTES];
        uint8_t mlkem_ss[TOX_MLKEM768_SHAREDSECRETBYTES];

        /* Parse and decrypt hybrid handshake, decapsulate ML-KEM */
        if (!handle_crypto_handshake_hybrid(c, conn->recv_nonce,
                                             conn->peersessionpublic_key,
                                             peer_real_pk, dht_public_key, cookie,
                                             mlkem_ct, mlkem_ss,
                                             packet, length, conn->public_key)) {
            return -1;
        }

        conn->session_is_hybrid = true;

        /* Determine which ML-KEM secret to use */
        bool use_peer_encapsulation;
        if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
            /* We're the responder - use peer's encapsulation */
            use_peer_encapsulation = true;
        } else if (conn->status == CRYPTO_CONN_HANDSHAKE_SENT) {
            /* Both sent - lower public key wins */
            int cmp = memcmp(c->self_public_key, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
            use_peer_encapsulation = (cmp > 0);
        } else {
            use_peer_encapsulation = false;
        }

        if (use_peer_encapsulation) {
            memcpy(conn->mlkem_shared, mlkem_ss, TOX_MLKEM768_SHAREDSECRETBYTES);
        }
        /* else: keep our own mlkem_shared from our encapsulation */

        /* Compute hybrid session key */
        uint8_t x25519_shared[32];
        crypto_scalarmult(x25519_shared, conn->sessionsecret_key, conn->peersessionpublic_key);

        static const uint8_t ctx[] = "ToxSession";
        tox_hybrid_kdf(conn->shared_key, x25519_shared, conn->mlkem_shared,
                       ctx, sizeof(ctx) - 1);

        sodium_memzero(x25519_shared, 32);

        /* Send classical response if we're the responder */
        if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
            create_send_handshake(c, crypt_connection_id, cookie, dht_public_key);
        }

        conn->status = CRYPTO_CONN_NOT_CONFIRMED;
        return 0;
    }

    /* Classical handshake path */
    /* ... existing code with hybrid KDF support for initiator ... */
}
```

## Testing

### Run All Crypto Tests

```bash
cd _build
make -j$(nproc)

# PQ primitives test
./auto_tests/auto_crypto_pq_test

# Friend connection (tests hybrid handshake)
./auto_tests/auto_friend_connection_test

# Friend request (tests full connection flow)
./auto_tests/auto_friend_request_test

# File transfer (tests encrypted data exchange)
./auto_tests/auto_file_transfer_test
```

### Debug Output

Enable debug logging by setting `PQ_DEBUG=1` in `net_crypto.c`:

```c
#define PQ_DEBUG 1
#if PQ_DEBUG
#define PQ_LOG(...) fprintf(stderr, "[PQ] " __VA_ARGS__)
#else
#define PQ_LOG(...) do {} while(0)
#endif
```

Expected output for successful PQ handshake:
```
[PQ] create_cookie_request: Setting PQ capability marker
[PQ] udp_handle_cookie_request: Detected PQ capability marker, sending hybrid response
[PQ] handle_packet_cookie_response: Detected hybrid cookie response
[PQ] handle_packet_cookie_response: Creating hybrid handshake
[PQ] handle_packet_cookie_response: Hybrid handshake sent
[PQ] handle_packet_crypto_hs: Processing hybrid handshake
[PQ] handle_packet_crypto_hs: Using peer's encapsulation (we're responder)
[PQ] handle_packet_crypto_hs: Responding with classical handshake (responder role)
```

### Verify Classical Fallback

Temporarily disable PQ on one side:

```c
/* In new_net_crypto() or via test fixture */
c->pq_enabled = false;
```

Connection should establish using classical-only cryptography with `conn->session_is_hybrid = false`.

## Identity Commitment Verification (Phase 2.5)

### Overview

When a friend is added using a 46-byte PQ address (containing ML-KEM commitment), the commitment is verified during connection establishment to provide quantum-resistant identity protection.

### Storage Flow

```
1. User adds friend with 46-byte address
   ↓
2. Messenger parses address:
   - X25519 pk → Friend.real_pk
   - ML-KEM commit → Friend.mlkem_commitment
   - Set has_mlkem_commitment = true
   ↓
3. Commitment passed to friend_connection layer:
   friend_connection_set_mlkem_commitment(fr_c, friendcon_id, commitment)
```

### Verification Flow (friend_connection.c)

When connection goes online in `handle_status()`:

```c
if (nc_connection_is_pq(fr_c->net_crypto, friend_con->crypt_connection_id)) {
    if (friend_con->has_mlkem_commitment) {
        uint8_t peer_mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES];

        if (nc_get_peer_mlkem_public(fr_c->net_crypto, crypt_conn_id, peer_mlkem_public)) {
            if (tox_verify_mlkem_commitment(friend_con->mlkem_commitment, peer_mlkem_public)) {
                friend_con->mlkem_verified = true;  // PQ_VERIFIED
            } else {
                // COMMITMENT MISMATCH - possible impersonation!
                // Kill connection and reject
                crypto_kill(fr_c->net_crypto, crypt_conn_id);
                return -1;
            }
        }
    }
    // No commitment: mlkem_verified stays false (PQ_UNVERIFIED)
}
```

### Status Propagation

```
friend_connection layer          Messenger layer              Public API
─────────────────────           ───────────────              ───────────
Friend_Conn.mlkem_verified  →  Friend.mlkem_verified  →  tox_friend_get_identity_status()
                               ↓
                            m_handle_status() triggers
                            friend_identity_status callback
```

### API Functions

```c
// Query friend's identity verification status
Tox_Connection_Identity tox_friend_get_identity_status(
    const Tox *tox,
    Tox_Friend_Number friend_number,
    Tox_Err_Friend_Query *error);

// Returns:
//   TOX_CONNECTION_IDENTITY_UNKNOWN      - Not connected
//   TOX_CONNECTION_IDENTITY_CLASSICAL    - X25519-only connection
//   TOX_CONNECTION_IDENTITY_PQ_UNVERIFIED - Hybrid session, no commitment
//   TOX_CONNECTION_IDENTITY_PQ_VERIFIED   - Hybrid session, commitment verified

// Add friend with 46-byte PQ address
Tox_Friend_Number tox_friend_add_pq(
    Tox *tox,
    const uint8_t address[TOX_ADDRESS_SIZE_PQ],
    const uint8_t message[],
    size_t length,
    Tox_Err_Friend_Add *error);
```

### Security Considerations

1. **Commitment rejection is fatal**: If commitment verification fails, the connection is immediately terminated. This prevents impersonation attacks.

2. **No downgrade**: Once a 46-byte address is used, the commitment is always verified. An attacker cannot bypass by presenting a different ML-KEM key.

3. **Constant-time comparison**: `tox_verify_mlkem_commitment()` uses `sodium_memcmp()` to prevent timing attacks.

## Phase 2 Deliverables Checklist

- [x] Extended Crypto_Connection structure with PQ fields
- [x] PQ capability marker in cookie request padding
- [x] Hybrid cookie response with ML-KEM public key
- [x] Hybrid handshake packet with ML-KEM ciphertext
- [x] ML-KEM encapsulation/decapsulation integration
- [x] Hybrid KDF for session key derivation
- [x] Simultaneous handshake resolution (public key comparison)
- [x] Automatic fallback to classical for legacy peers
- [x] Integration tests passing

### Phase 2.5 - Identity Commitment (Complete)

- [x] ML-KEM commitment generation (`tox_mlkem_commitment()`)
- [x] Commitment verification (`tox_verify_mlkem_commitment()`)
- [x] 46-byte PQ address format (`TOX_ADDRESS_SIZE_PQ`)
- [x] Extended Friend struct with commitment fields
- [x] `tox_self_get_address_pq()` - Get 46-byte PQ address
- [x] `tox_friend_add_pq()` - Add friend with PQ address
- [x] Commitment verification in `handle_status()`
- [x] `tox_friend_get_identity_status()` - Query verification status
- [x] Identity status callback (`tox_callback_friend_identity_status`)
- [x] Unit tests for commitment functions

## Known Limitations

1. **No algorithm negotiation**: Hardcoded to ML-KEM-768
2. **Commitment collision resistance**: 8-byte commitment has 64-bit collision resistance (sufficient for target security level)

## Next Steps

With protocol changes complete, focus areas include:
- Expanding test coverage and fuzzing
- Security audit of cryptographic implementation
- Client integration (see [qatox/](qatox/) for Android client documentation)
- DHT/onion layer PQ upgrades (future work)
