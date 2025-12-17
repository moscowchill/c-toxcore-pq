# Protocol Negotiation via In-Band Capability Signaling

## Overview

PQ capability negotiation in c-toxcore-pq uses **in-band signaling** during the initial handshake, rather than a separate negotiation phase. This approach:

1. Minimizes protocol changes
2. Works without ToxExt dependency
3. Enables PQ key exchange on first connection
4. Maintains backwards compatibility with legacy clients

## Design Rationale

### Why Not ToxExt?

The original design considered ToxExt for capability negotiation. However, in-band signaling was chosen because:

1. **Simplicity**: No additional framework dependency
2. **Efficiency**: PQ handshake happens immediately, no extra round-trip
3. **Compatibility**: Works with existing connection flow
4. **Minimal Changes**: Reuses existing packet types with minor extensions

### Trade-offs

| Aspect | In-Band Approach | ToxExt Approach |
|--------|------------------|-----------------|
| Complexity | Lower | Higher |
| Round-trips | Same as classical | +1 for negotiation |
| Future algorithms | Harder to add | Easier to extend |
| Downgrade protection | Via packet format | Via signed commitments |

## In-Band Capability Signaling

### PQ Capability Marker

PQ capability is signaled via a marker byte in the cookie request padding field:

```c
#define PQ_CAPABILITY_MARKER 0x02
#define PQ_CAPABILITY_OFFSET (CRYPTO_PUBLIC_KEY_SIZE)  /* Position 32 in plaintext */
```

### Cookie Request with PQ Marker

The cookie request uses the **classical format** with a PQ capability marker embedded in the padding:

```
Cookie Request Plaintext (before encryption):
+------------------+------------------+------------------+
| sender_real_pk   | request_number   | padding          |
| (32 bytes)       | (8 bytes)        | (24 bytes)       |
+------------------+------------------+------------------+
                                      ^
                                      | PQ marker at first byte of padding
                                      | 0x02 = PQ capable
                                      | 0x00 = Classical only
```

### Detection Logic

When a PQ-enabled node receives a cookie request:

```c
/* In udp_handle_cookie_request() */
if (c->pq_enabled && request_plain[PQ_CAPABILITY_OFFSET] == PQ_CAPABILITY_MARKER) {
    /* Peer is PQ capable - send hybrid cookie response */
    return send_hybrid_cookie_response(...);
} else {
    /* Peer is classical - send classical cookie response */
    return send_classical_cookie_response(...);
}
```

## Handshake Flow

### PQ ↔ PQ Connection (Both Peers PQ-Capable)

```
Alice (PQ)                                              Bob (PQ)
---------                                               -------

1. Cookie Request (classical format with PQ marker)
   [0x18][dht_pk][nonce][encrypted:{real_pk|number|0x02|padding}]
   ────────────────────────────────────────────────────────────►

2. Hybrid Cookie Response (includes Bob's ML-KEM public key)
   [0x19][0x02][nonce][encrypted:{cookie|number|mlkem_pk(1184)}]
   ◄────────────────────────────────────────────────────────────

3. Hybrid Handshake (Alice encapsulates to Bob's ML-KEM key)
   [0x1a][0x02][cookie][mlkem_ct(1088)][nonce][encrypted_hs]
   ────────────────────────────────────────────────────────────►

4. Classical Handshake Response (Bob decapsulated, uses hybrid KDF)
   [0x1a][random_byte][cookie][nonce][encrypted_hs]
   ◄────────────────────────────────────────────────────────────

5. Session Established with Hybrid Security
   shared_key = HKDF(X25519_shared || ML-KEM_shared)
```

### PQ → Classical Connection (Legacy Peer)

```
Alice (PQ)                                              Bob (Classical)
---------                                               --------------

1. Cookie Request (with PQ marker - ignored by Bob)
   [0x18][dht_pk][nonce][encrypted:{real_pk|number|0x02|padding}]
   ────────────────────────────────────────────────────────────►

2. Classical Cookie Response (no ML-KEM key)
   [0x19][nonce][encrypted:{cookie|number}]
   ◄────────────────────────────────────────────────────────────

3. Classical Handshake
   [0x1a][cookie][nonce][encrypted_hs]
   ────────────────────────────────────────────────────────────►

4. Classical Handshake Response
   [0x1a][cookie][nonce][encrypted_hs]
   ◄────────────────────────────────────────────────────────────

5. Session Established with Classical Security
   shared_key = X25519_shared (legacy derivation)
```

### Classical → PQ Connection (Legacy Initiator)

```
Alice (Classical)                                       Bob (PQ)
----------------                                        -------

1. Cookie Request (no PQ marker)
   [0x18][dht_pk][nonce][encrypted:{real_pk|number|0x00|padding}]
   ────────────────────────────────────────────────────────────►

2. Classical Cookie Response (Bob sees no marker)
   [0x19][nonce][encrypted:{cookie|number}]
   ◄────────────────────────────────────────────────────────────

3-5. Classical handshake proceeds normally
```

## Simultaneous Hybrid Handshakes

When both peers receive hybrid cookie responses simultaneously, both will attempt to send hybrid handshakes with their own ML-KEM encapsulations. This creates a conflict because each side generates a different shared secret.

### Resolution: Public Key Comparison

To ensure both sides use the same ML-KEM shared secret:

1. If we receive a hybrid handshake **before** sending ours (status = COOKIE_REQUESTING):
   - Use the peer's encapsulation (decapsulate their ciphertext)
   - Send a **classical** handshake response (no new encapsulation)

2. If we receive a hybrid handshake **after** sending ours (status = HANDSHAKE_SENT):
   - Compare public keys lexicographically
   - Lower public key "wins" - their encapsulation is used
   - Higher public key uses the decapsulated secret from peer

```c
/* In handle_packet_crypto_hs() */
if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
    /* We're the responder - use peer's encapsulation */
    use_peer_encapsulation = true;
} else if (conn->status == CRYPTO_CONN_HANDSHAKE_SENT) {
    /* Both sent - lower public key wins */
    int cmp = memcmp(c->self_public_key, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    use_peer_encapsulation = (cmp > 0);
}
```

## Implementation Details

### Key Files

- `toxcore/net_crypto.c`: Core handshake logic, PQ marker detection
- `toxcore/crypto_core_pq.c`: ML-KEM wrappers, hybrid KDF
- `toxcore/friend_connection.c`: Connection setup with PQ capability tracking

### Constants

```c
/* net_crypto.c */
#define PQ_CAPABILITY_MARKER     0x02
#define PQ_CAPABILITY_OFFSET     (CRYPTO_PUBLIC_KEY_SIZE)  /* 32 */

#define TOX_CRYPTO_VERSION_HYBRID 0x02

/* Packet sizes */
#define HYBRID_COOKIE_RESPONSE_LENGTH  1346  /* Includes ML-KEM public key */
#define HYBRID_HANDSHAKE_PACKET_LENGTH 1474  /* Includes ML-KEM ciphertext */
```

### Connection State

```c
typedef struct Crypto_Connection {
    /* ... existing fields ... */

    /* PQ capability fields */
    bool pq_enabled;              /* Our PQ capability */
    bool peer_pq_capable;         /* Peer's PQ capability */
    bool session_is_hybrid;       /* Current session type */

    /* ML-KEM key material */
    uint8_t peer_mlkem_public[TOX_MLKEM768_PUBLICKEYBYTES];
    uint8_t mlkem_ciphertext[TOX_MLKEM768_CIPHERTEXTBYTES];
    uint8_t mlkem_shared[TOX_MLKEM768_SHAREDSECRETBYTES];
} Crypto_Connection;
```

## Security Considerations

### Downgrade Attack Prevention

The current implementation provides **implicit** downgrade protection:

1. PQ-capable peers will always set the PQ marker
2. If a peer responds with hybrid cookie response, we know they're PQ-capable
3. MITM cannot forge hybrid responses without the responder's keys

**Limitation**: No explicit capability commitments. A sophisticated MITM could potentially block hybrid responses and force classical fallback. Future work may add signed capability announcements.

### Forward Secrecy

- Each session uses fresh ephemeral keys (both X25519 and ML-KEM)
- Compromise of long-term keys doesn't reveal past session keys
- ML-KEM ciphertext is unique per session (randomized encapsulation)

### Quantum Resistance

- If X25519 is broken by quantum computers, ML-KEM provides protection
- If ML-KEM is broken (e.g., new cryptanalysis), X25519 still provides classical security
- Symmetric encryption (XSalsa20-Poly1305) uses 256-bit keys, already quantum-resistant

## Testing

### Verify PQ Negotiation

```bash
# Run friend connection test - should show hybrid handshake
./auto_tests/auto_friend_connection_test

# Expected flow in debug output (when PQ_DEBUG=1):
# [PQ] create_cookie_request: Setting PQ capability marker
# [PQ] udp_handle_cookie_request: Detected PQ capability marker, sending hybrid response
# [PQ] handle_packet_cookie_response: Detected hybrid cookie response
# [PQ] handle_packet_cookie_response: Creating hybrid handshake
```

### Verify Backwards Compatibility

To test classical fallback, disable PQ on one side:

```c
/* Temporarily disable PQ for testing */
c->pq_enabled = false;
```

The connection should establish using classical-only cryptography.

## Future Enhancements

1. **Explicit Capability Commitments**: Sign capabilities with long-term key for downgrade protection
2. **Algorithm Negotiation**: Support multiple KEMs (ML-KEM-1024, etc.) with bitmask selection
3. **Key Rotation**: Periodic ML-KEM key updates during long sessions
4. **API Exposure**: `tox_friend_get_connection_security()` to query session type
