# Cryptographic Protocol Specification

## Overview

This document specifies the cryptographic protocols for hybrid post-quantum key exchange in aqTox-PQ. The design follows established patterns from Signal's PQXDH and IETF hybrid key exchange drafts.

## Design Principles

1. **Hybrid Security**: Security holds if EITHER X25519 OR ML-KEM remains secure
2. **Forward Secrecy**: Ephemeral keys per session, compromise of long-term keys doesn't reveal past sessions
3. **Implicit Downgrade Resistance**: Protocol format prevents undetected downgrades
4. **Clean Fallback**: Graceful degradation to classical with legacy peers

## Algorithm Choices

### Key Encapsulation Mechanism

**ML-KEM-768** (NIST FIPS 203)
- Security level: NIST Level 3 (~AES-192 equivalent)
- Public key: 1,184 bytes
- Ciphertext: 1,088 bytes
- Shared secret: 32 bytes
- Rationale: Balance of security and size, NIST standardized, available in libsodium

### Classical Key Exchange

**X25519** (Curve25519 ECDH)
- Security level: ~128-bit classical
- Public key: 32 bytes
- Shared secret: 32 bytes
- Rationale: Existing Tox primitive, well-audited, compact

### Key Derivation

**HKDF-SHA512**
- Extract: SHA512-based extraction from input keying material
- Expand: SHA512-based expansion with context
- Rationale: Standard construction, available in libsodium, provides domain separation

### Symmetric Encryption

**XSalsa20-Poly1305** (unchanged)
- Key: 32 bytes
- Nonce: 24 bytes
- Security: 256-bit key provides quantum resistance for symmetric operations
- Rationale: Existing Tox primitive, no modification needed

## Hybrid Key Derivation Construction

### Combined Secret Derivation

```
Inputs:
  - dh_secret: 32-byte X25519 shared secret
  - kem_secret: 32-byte ML-KEM shared secret
  - context: Variable-length context string

Process:
  1. ikm = 0xFF[32] || dh_secret || kem_secret     // 96 bytes
  2. prk = HKDF-Extract(salt=0[64], ikm)           // 64 bytes
  3. info = "ToxHybridKDF" || 0x02 || context
  4. output = HKDF-Expand(prk, info, 32)           // 32 bytes

Output:
  - 32-byte combined session key
```

### Security Analysis

The 32-byte 0xFF prefix provides domain separation:
- Prevents using a classical-only shared secret as hybrid input
- Distinguishes hybrid context from any classical Tox derivation
- If an attacker can only break ML-KEM, they still face X25519
- If an attacker can only break X25519, they still face ML-KEM

### Classical Fallback Derivation

When peer doesn't support PQ, the session uses the existing Tox key derivation (encrypt_precompute) rather than the hybrid KDF structure.

## Handshake Protocol

### Packet Types

Existing Tox packet types are extended for hybrid handshake:

```c
// Existing (unchanged packet type IDs)
#define NET_PACKET_COOKIE_REQUEST     0x18
#define NET_PACKET_COOKIE_RESPONSE    0x19
#define NET_PACKET_CRYPTO_HS          0x1a
#define NET_PACKET_CRYPTO_DATA        0x1b

// Hybrid version marker
#define TOX_CRYPTO_VERSION_HYBRID     0x02
```

### PQ Capability Signaling

PQ capability is signaled via a marker byte in the cookie request plaintext padding:

```c
#define PQ_CAPABILITY_MARKER  0x02
#define PQ_CAPABILITY_OFFSET  32   // Position in cookie request plaintext
```

### Cookie Request

The cookie request uses **classical format** with an embedded PQ capability marker:

```
Cookie Request (classical format with PQ marker):
+--------+------------------+------------------+------------------+
| type   | sender_dht_pk    | nonce            | encrypted        |
| (1)    | (32 bytes)       | (24 bytes)       | payload          |
+--------+------------------+------------------+------------------+
| 0x18   |                  |                  |                  |
+--------+------------------+------------------+------------------+

Encrypted payload plaintext:
+------------------+------------------+------------------+
| sender_real_pk   | request_number   | padding          |
| (32 bytes)       | (8 bytes)        | (24 bytes)       |
+------------------+------------------+------------------+
                                      ^
                                      | PQ marker at byte 0 of padding
                                      | 0x02 = PQ capable
```

Classical clients ignore the padding field, so this is backwards compatible.

### Cookie Response

**Classical format (legacy):**
```
+--------+------------------+------------------+
| type   | nonce            | encrypted        |
| (1)    | (24 bytes)       | (cookie+number)  |
+--------+------------------+------------------+
| 0x19   |                  |                  |
+--------+------------------+------------------+
```

**Hybrid format (includes ML-KEM public key):**
```
+--------+--------+------------------+---------------------------+
| type   | version| nonce            | encrypted                 |
| (1)    | (1)    | (24 bytes)       | (cookie+number+mlkem_pk)  |
+--------+--------+------------------+---------------------------+
| 0x19   | 0x02   |                  |                           |
+--------+--------+------------------+---------------------------+

Encrypted payload:
+------------------+------------------+------------------+
| cookie           | request_number   | mlkem_public_key |
| (112 bytes)      | (8 bytes)        | (1184 bytes)     |
+------------------+------------------+------------------+

Total hybrid cookie response length: 1346 bytes
```

Detection: Check byte at position 1. If 0x02, parse as hybrid.

### Handshake Packet

**Classical format (legacy):**
```
+--------+------------------+------------------+------------------+
| type   | cookie           | nonce            | encrypted        |
| (1)    | (112 bytes)      | (24 bytes)       | handshake_data   |
+--------+------------------+------------------+------------------+
| 0x1a   |                  |                  |                  |
+--------+------------------+------------------+------------------+

Total: 385 bytes
```

**Hybrid format (includes ML-KEM ciphertext):**
```
+--------+--------+------------------+------------------+---------------+
| type   | version| cookie           | mlkem_ciphertext | nonce +       |
| (1)    | (1)    | (112 bytes)      | (1088 bytes)     | encrypted_hs  |
+--------+--------+------------------+------------------+---------------+
| 0x1a   | 0x02   |                  |                  |               |
+--------+--------+------------------+------------------+---------------+

Encrypted handshake data:
+------------------+------------------+------------------+------------------+
| session_nonce    | session_pk       | sha512_hash      | cookie           |
| (24 bytes)       | (32 bytes)       | (64 bytes)       | (112 bytes)      |
+------------------+------------------+------------------+------------------+

Total hybrid handshake length: 1474 bytes
```

Detection: Check byte at position 1. If 0x02, parse as hybrid.

### Full Handshake Flow (PQ ↔ PQ)

```
Alice (PQ initiator)                                 Bob (PQ responder)
--------------------                                 ------------------

Has: (x25519_A, mlkem_A)                            Has: (x25519_B, mlkem_B)

1. COOKIE REQUEST (classical format with PQ marker)
   ┌─────────────────────────────────────────────────────────────────┐
   │ Payload: [0x18][dht_pk_A][nonce][Enc(real_pk_A|num|0x02|pad)]   │
   │ PQ marker 0x02 in padding signals PQ capability                 │
   └─────────────────────────────────────────────────────────────────┘
                              ─────────────────────────────────────────►

2. HYBRID COOKIE RESPONSE
   ┌─────────────────────────────────────────────────────────────────┐
   │ Bob detects PQ marker, responds with hybrid format              │
   │ Payload: [0x19][0x02][nonce][Enc(cookie|num|mlkem_B.pub)]       │
   │ Includes Bob's ML-KEM public key (1184 bytes)                   │
   └─────────────────────────────────────────────────────────────────┘
                              ◄─────────────────────────────────────────

3. HYBRID HANDSHAKE (Alice encapsulates)
   ┌─────────────────────────────────────────────────────────────────┐
   │ Generate session keypair: (session_pk_A, session_sk_A)          │
   │ Encapsulate: (ct, ss) = ML-KEM.Encaps(mlkem_B.pub)              │
   │ Compute X25519: dh = X25519(session_sk_A, session_pk_B)         │
   │ Derive: shared_key = HybridKDF(dh, ss, "ToxSession")            │
   │ Payload: [0x1a][0x02][cookie][ct][nonce][Enc(hs_data)]          │
   └─────────────────────────────────────────────────────────────────┘
                              ─────────────────────────────────────────►

4. CLASSICAL HANDSHAKE RESPONSE (Bob decapsulates)
   ┌─────────────────────────────────────────────────────────────────┐
   │ Decapsulate: ss = ML-KEM.Decaps(mlkem_B.sec, ct)                │
   │ Compute X25519: dh = X25519(session_sk_B, session_pk_A)         │
   │ Derive: shared_key = HybridKDF(dh, ss, "ToxSession")            │
   │ Payload: [0x1a][random][cookie][nonce][Enc(hs_data)]            │
   │ (Classical format - no new encapsulation needed)                │
   └─────────────────────────────────────────────────────────────────┘
                              ◄─────────────────────────────────────────

5. SESSION ESTABLISHED
   Both sides have: shared_key = HybridKDF(X25519_shared, ML-KEM_shared)
```

### Simultaneous Hybrid Handshakes

When both peers initiate simultaneously:

1. Both send cookie requests with PQ markers
2. Both respond with hybrid cookie responses
3. Both create hybrid handshakes with their own encapsulations

**Problem**: Each side has a different ML-KEM shared secret!

**Solution**: Deterministic encapsulation selection via public key comparison:

```c
/* Lower public key's encapsulation wins */
if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
    /* Haven't sent yet - use peer's encapsulation */
    use_peer_encapsulation = true;
} else if (conn->status == CRYPTO_CONN_HANDSHAKE_SENT) {
    /* Both sent - compare public keys */
    int cmp = memcmp(self_pk, peer_pk, 32);
    use_peer_encapsulation = (cmp > 0);  /* Lower pk wins */
}
```

When using peer's encapsulation:
- Decapsulate their ciphertext to get shared secret
- Send classical handshake response (no new encapsulation)

When using our encapsulation:
- Keep our ML-KEM shared secret
- Peer will decapsulate our ciphertext

### Fallback to Classical

When Bob doesn't support PQ:

```
Alice (PQ)                                           Bob (classical)
----------                                           ---------------

1. COOKIE REQUEST (with PQ marker in padding)
                              ─────────────────────────────────────────►

   Bob ignores padding (doesn't check for marker)

2. CLASSICAL COOKIE RESPONSE (no version byte, no ML-KEM key)
                              ◄─────────────────────────────────────────

3. Alice detects classical response (no 0x02 at position 1)
   Falls back to X25519-only handshake

4. CLASSICAL HANDSHAKE
                              ─────────────────────────────────────────►

5. Session established with classical security
   Alice: conn->session_is_hybrid = false
```

## Security Considerations

### Implicit Downgrade Protection

The current implementation provides implicit protection:

1. PQ-capable peers always set the PQ marker
2. Hybrid cookie responses include ML-KEM public key in encrypted payload
3. MITM cannot forge encrypted responses without knowing shared key
4. If peer sends hybrid response, initiator knows to use hybrid handshake

**Limitation**: Active MITM could block hybrid responses entirely, forcing classical fallback. See "Future Work" for explicit capability commitments.

### Timing Attacks

ML-KEM operations must be constant-time. libsodium's implementation provides this:

```c
// Good: libsodium's ML-KEM is constant-time
crypto_kem_mlkem768_enc(ct, ss, pk);  // Safe
crypto_kem_mlkem768_dec(ss, ct, sk);  // Safe
```

### Memory Handling

All secret material must be securely erased:

```c
// After use:
sodium_memzero(conn->mlkem_shared, 32);
sodium_memzero(x25519_shared, 32);
sodium_memzero(session_secret_key, 32);
```

### Key Reuse

- Identity ML-KEM keys are derived from identity seed (deterministic)
- Session ML-KEM encapsulation uses fresh randomness each time
- Ciphertexts are never reused across sessions

### Quantum Threat Model

**Protected against:**
- Future quantum computer breaking X25519
- "Harvest now, decrypt later" attacks
- Quantum attacks on key exchange

**Not protected against:**
- Quantum attacks on authentication (future ML-DSA work)
- Side-channel attacks on implementation
- Compromised endpoints

### Known Limitations

1. **Identity authentication remains classical**: Ed25519/X25519 signatures. An attacker with quantum computer could forge identity (future work: ML-DSA)

2. **DHT/onion routing remains classical**: Network layer crypto is out of MVP scope

3. **Group chats**: Separate design needed for group key exchange

## Future Work

### Explicit Capability Commitments

For stronger downgrade protection, future versions may implement signed capability commitments:

```c
typedef struct Tox_PQ_Capability_Commitment {
    uint8_t  tox_id[32];           // User's Tox public key
    uint16_t protocol_version;     // 0x0002
    uint16_t supported_kems;       // Bit 0: ML-KEM-768
    uint64_t timestamp;            // Monotonic counter
    uint8_t  signature[64];        // Ed25519 over above fields
} Tox_PQ_Capability_Commitment;
```

This would allow detecting if a previously-PQ-capable peer suddenly claims classical-only.

### Algorithm Agility

Future versions may support multiple KEMs with negotiation:

```c
#define TOXEXT_PQ_KEM_MLKEM768   (1 << 0)
#define TOXEXT_PQ_KEM_MLKEM1024  (1 << 1)  // Future
```

## Test Vectors

### Hybrid KDF Test Vector

```
Input:
  x25519_shared = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  mlkem_shared  = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  context       = "ToxSession"

Process:
  ikm = 0xFF[32] || x25519_shared || mlkem_shared
  prk = HKDF-Extract(salt=0[64], ikm)
  info = "ToxHybridKDF" || 0x02 || "ToxSession"
  output = HKDF-Expand(prk, info, 32)

Expected output:
  Run auto_tests/auto_crypto_pq_test to verify
```

## References

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. Signal PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
3. IETF draft-ietf-tls-hybrid-design: Hybrid Key Exchange in TLS 1.3
4. libsodium documentation: https://doc.libsodium.org/
5. Tox Protocol Specification: https://toktok.ltd/spec.html
