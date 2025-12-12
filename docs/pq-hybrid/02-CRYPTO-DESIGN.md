# Cryptographic Protocol Specification

## Overview

This document specifies the cryptographic protocols for hybrid post-quantum key exchange in aqTox-PQ. The design follows established patterns from Signal's PQXDH and IETF hybrid key exchange drafts.

## Design Principles

1. **Hybrid Security**: Security holds if EITHER X25519 OR ML-KEM remains secure
2. **Forward Secrecy**: Ephemeral keys per session, compromise of long-term keys doesn't reveal past sessions
3. **Downgrade Resistance**: Capability commitments prevent MITM forcing classical-only
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

When peer doesn't support PQ:

```
Inputs:
  - dh_secret: 32-byte X25519 shared secret
  - context: Variable-length context string

Process:
  1. ikm = 0xFF[32] || dh_secret || 0[32]         // Zero for KEM slot
  2. prk = HKDF-Extract(salt=0[64], ikm)
  3. info = "ToxHybridKDF" || 0x01 || context      // Version 0x01 = classical
  4. output = HKDF-Expand(prk, info, 32)

Output:
  - 32-byte session key
```

This maintains consistent derivation structure while indicating classical mode.

## Handshake Protocol

### Packet Types

Extend existing Tox packet types for hybrid handshake:

```c
// Existing
#define NET_PACKET_COOKIE_REQUEST     0x18
#define NET_PACKET_COOKIE_RESPONSE    0x19
#define NET_PACKET_CRYPTO_HS          0x1a
#define NET_PACKET_CRYPTO_DATA        0x1b

// Extended (same IDs, larger payloads)
// Detection via packet size and version byte
```

### Cookie Request (Extended)

```
Classical format (existing):
+------------------+------------------+---------------+
| sender_pubkey    | sender_dht_key   | encrypted     |
| (32 bytes)       | (32 bytes)       | padding       |
+------------------+------------------+---------------+

Hybrid format (new):
+--------+------------------+------------------+------------------+
| version| sender_x25519    | sender_mlkem     | encrypted        |
| (1)    | (32 bytes)       | (1184 bytes)     | padding          |
+--------+------------------+------------------+------------------+
| 0x02   |                  |                  |                  |
+--------+------------------+------------------+------------------+
```

Detection: Check first byte. If 0x02, parse as hybrid. Otherwise, legacy format.

### Cookie Response (Extended)

```
Classical format (existing):
+------------------+------------------+---------------+
| cookie           | nonce            | encrypted     |
| (N bytes)        | (24 bytes)       | response      |
+------------------+------------------+---------------+

Hybrid format (new):
+--------+------------------+------------------+------------------+
| version| responder_x25519 | responder_mlkem  | cookie +         |
| (1)    | (32 bytes)       | (1184 bytes)     | encrypted resp   |
+--------+------------------+------------------+------------------+
| 0x02   |                  |                  |                  |
+--------+------------------+------------------+------------------+
```

### Handshake Packet (Extended)

```
Classical format (existing):
+------------------+------------------+---------------+
| cookie           | nonce            | encrypted     |
| (N bytes)        | (24 bytes)       | handshake     |
+------------------+------------------+---------------+

Hybrid format (new):
+--------+------------------+------------------+---------------+
| version| cookie           | mlkem_ciphertext | nonce +       |
| (1)    | (N bytes)        | (1088 bytes)     | enc handshake |
+--------+------------------+------------------+---------------+
| 0x02   |                  |                  |               |
+--------+------------------+------------------+---------------+
```

### Full Handshake Flow

```
Alice (initiator)                                    Bob (responder)
-----------------                                    ---------------

Has: id_A = (x25519_A, mlkem_A)                     Has: id_B = (x25519_B, mlkem_B)
Knows: Bob's hybrid public key

1. COOKIE REQUEST
   ┌─────────────────────────────────────────────────────────────────┐
   │ Generate ephemeral: eph_x25519_A                                │
   │ Payload:                                                        │
   │   version=0x02 || x25519_A.pub || mlkem_A.pub || encrypted_pad  │
   └─────────────────────────────────────────────────────────────────┘
                              ─────────────────────────────────────────►

2. COOKIE RESPONSE
   ┌─────────────────────────────────────────────────────────────────┐
   │ Detect hybrid request (version=0x02)                            │
   │ Generate cookie with hybrid binding                             │
   │ Payload:                                                        │
   │   version=0x02 || x25519_B.pub || mlkem_B.pub || cookie         │
   └─────────────────────────────────────────────────────────────────┘
                              ◄─────────────────────────────────────────

3. HANDSHAKE PACKET
   ┌─────────────────────────────────────────────────────────────────┐
   │ Compute: dh_secret = X25519(eph_x25519_A.sec, x25519_B.pub)     │
   │ Compute: (ct, kem_secret) = ML-KEM.Encaps(mlkem_B.pub)          │
   │ Derive:  session_key = HybridKDF(dh_secret, kem_secret)         │
   │ Payload:                                                        │
   │   version=0x02 || cookie || ct || nonce || Enc(handshake_data)  │
   └─────────────────────────────────────────────────────────────────┘
                              ─────────────────────────────────────────►

4. SESSION ESTABLISHED
   ┌─────────────────────────────────────────────────────────────────┐
   │ Compute: dh_secret = X25519(x25519_B.sec, eph_x25519_A.pub)     │
   │ Compute: kem_secret = ML-KEM.Decaps(mlkem_B.sec, ct)            │
   │ Derive:  session_key = HybridKDF(dh_secret, kem_secret)         │
   │ Decrypt and verify handshake_data                               │
   │ Session ready with quantum-resistant key                        │
   └─────────────────────────────────────────────────────────────────┘
```

### Fallback to Classical

When Bob doesn't support hybrid:

```
Alice (hybrid)                                       Bob (classical)
--------------                                       ---------------

1. COOKIE REQUEST (hybrid format)
                              ─────────────────────────────────────────►
   
   Bob doesn't recognize version=0x02 or extended format
   Bob responds with classical cookie response

2. COOKIE RESPONSE (classical format)
                              ◄─────────────────────────────────────────

3. Alice detects classical response (no version byte or version=0x01)
   Falls back to X25519-only handshake
   Sets session->peer_pq_capable = false

4. HANDSHAKE PACKET (classical format)
                              ─────────────────────────────────────────►

5. Session established with classical security
   Alice UI shows "Classical" security indicator
```

## Key Commitment and Downgrade Prevention

### The Problem

A man-in-the-middle could:
1. Intercept Alice's hybrid request
2. Forward a classical-only request to Bob
3. Both sides establish classical sessions with MITM
4. MITM can read all traffic (no quantum protection)

### The Solution: Capability Commitments

Each user signs their capability set:

```c
typedef struct Tox_PQ_Capability_Commitment {
    uint8_t  tox_id[32];           // User's Tox public key
    uint16_t protocol_version;     // 0x0002
    uint16_t supported_kems;       // Bit 0: ML-KEM-768
    uint16_t supported_sigs;       // Reserved for future
    uint64_t timestamp;            // Monotonic counter
    uint8_t  signature[64];        // Ed25519 over above fields
} Tox_PQ_Capability_Commitment;
```

### Commitment Protocol

1. **Initial connection**: Alice sends capability commitment with friend request
2. **Bob stores**: Bob records Alice's stated capabilities
3. **Future connections**: If Alice suddenly claims classical-only, Bob warns user
4. **Explicit downgrade**: User must confirm intentional capability reduction

### Implementation via ToxExt

Capability commitments sent via ToxExt extension messages after friend acceptance:

```
ToxExt Message Type: TOX_EXT_PQ_CAPABILITY (0x5051)  // "PQ" in hex

Payload:
+------------------+------------------+------------------+
| commitment       | signature        | reserved         |
| (48 bytes)       | (64 bytes)       | (16 bytes)       |
+------------------+------------------+------------------+
```

## Security Considerations

### Timing Attacks

ML-KEM operations must be constant-time. libsodium's implementation provides this, but verify:

```c
// Good: libsodium's ML-KEM is constant-time
crypto_kem_mlkem768_enc(ct, ss, pk);  // Safe

// Bad: Don't roll your own
if (some_secret_dependent_condition) {  // Timing leak!
    // ...
}
```

### Memory Handling

All secret material must be securely erased:

```c
// After use:
sodium_memzero(session->x25519_secret, 32);
sodium_memzero(session->mlkem_shared, 32);
sodium_memzero(session->combined_session_key, 32);
```

### Key Reuse

- Identity ML-KEM keys are reused (like X25519 identity keys)
- Session ML-KEM encapsulation uses fresh randomness each time
- Ciphertexts are never reused

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

3. **Group chats**: ToxExt doesn't support groups yet, separate design needed

## Test Vectors

### Hybrid KDF Test Vector

```
Input:
  x25519_shared = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  mlkem_shared  = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  context       = "TestContext"

Expected output:
  session_key   = [compute and verify with implementation]
```

### Classical Fallback Test Vector

```
Input:
  x25519_shared = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  context       = "TestContext"

Expected output:
  session_key   = [compute and verify with implementation]
```

## References

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. Signal PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
3. IETF draft-ietf-tls-hybrid-design: Hybrid Key Exchange in TLS 1.3
4. libsodium documentation: https://doc.libsodium.org/
5. Tox Protocol Specification: https://toktok.ltd/spec.html
