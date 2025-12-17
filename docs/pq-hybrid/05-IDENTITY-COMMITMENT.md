# Quantum-Resistant Identity with ML-KEM Commitment

## Problem Statement

While Phase 1 and Phase 2 of aqTox-PQ provide quantum-resistant session keys through ML-KEM-768 + X25519 hybrid key exchange, the **identity** of users remains vulnerable to quantum attack.

The traditional 38-byte Tox address format:
```
[X25519_public_key: 32 bytes][nospam: 4 bytes][checksum: 2 bytes]
```

Contains only an X25519 public key. A sufficiently powerful quantum computer could:
1. Derive the X25519 private key from the public key using Shor's algorithm
2. Impersonate the user by generating valid handshakes
3. Conduct man-in-the-middle attacks even on "PQ-protected" sessions

This creates a critical gap: **session keys may be quantum-safe, but identity verification is not**.

## Solution: 46-Byte PQ Tox Address

We extend the Tox address to include an ML-KEM commitment:

```
Classical (38 bytes):
[X25519_pk: 32][nospam: 4][checksum: 2]

PQ-Hybrid (46 bytes):
[X25519_pk: 32][MLKEM_commit: 8][nospam: 4][checksum: 2]
```

Where:
```c
MLKEM_commit = SHA256(ML-KEM_public_key)[0:8]
```

This 8-byte commitment provides:
- **64-bit collision resistance** against preimage attacks
- **Quantum-resistant identity binding** during handshake
- **Backwards compatibility** with classical 38-byte addresses

## Security Model

### Identity Verification Levels

| Level | Session Type | Identity | Security |
|-------|--------------|----------|----------|
| `CLASSICAL` | X25519 only | X25519 only | No quantum protection |
| `PQ_UNVERIFIED` | Hybrid ML-KEM+X25519 | X25519 only | Session quantum-safe, identity vulnerable |
| `PQ_VERIFIED` | Hybrid ML-KEM+X25519 | ML-KEM commitment verified | Full quantum protection |

### When Each Level Applies

1. **CLASSICAL**: Peer is a classical Tox client (no PQ support)
2. **PQ_UNVERIFIED**:
   - Friend added with 38-byte classical address
   - PQ session established but no commitment to verify
   - Warning: Identity could theoretically be spoofed by quantum attacker
3. **PQ_VERIFIED**:
   - Friend added with 46-byte PQ address
   - ML-KEM commitment verified against peer's ML-KEM public key during handshake
   - Full quantum-resistant identity verification

## Implementation Details

### Commitment Generation

```c
int tox_mlkem_commitment(
    uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE],  // 8 bytes output
    const uint8_t mlkem_pk[TOX_MLKEM768_PUBLICKEYBYTES]  // 1184 bytes input
);
```

Implementation:
```c
uint8_t hash[32];
crypto_hash_sha256(hash, mlkem_pk, TOX_MLKEM768_PUBLICKEYBYTES);
memcpy(commitment, hash, 8);
sodium_memzero(hash, sizeof(hash));
```

### Commitment Verification

```c
bool tox_verify_mlkem_commitment(
    const uint8_t commitment[TOX_MLKEM_COMMITMENT_SIZE],
    const uint8_t mlkem_pk[TOX_MLKEM768_PUBLICKEYBYTES]
);
```

Uses constant-time comparison (`sodium_memcmp`) to prevent timing attacks.

### Address Generation

```c
// Classical 38-byte address (existing)
void tox_self_get_address(const Tox *tox, uint8_t address[TOX_ADDRESS_SIZE]);

// PQ 46-byte address (new)
bool tox_self_get_address_pq(const Tox *tox, uint8_t address[TOX_ADDRESS_SIZE_PQ]);

// Check if PQ identity available
bool tox_self_has_pq_identity(const Tox *tox);
```

### Checksum Calculation

For 46-byte PQ addresses, the checksum covers the first 44 bytes:
```c
uint16_t checksum = data_checksum(address, 44);
memcpy(address + 44, &checksum, 2);
```

Address format detection uses checksum validation:
1. Try 46-byte format: verify checksum at bytes 44-45
2. If invalid, try 38-byte format: verify checksum at bytes 36-37

## Verification Flow

### During Friend Add

```
User provides address (38 or 46 bytes)
  │
  ├─ 38-byte address
  │   └─ Store X25519 public key
  │   └─ has_mlkem_commitment = false
  │
  └─ 46-byte address
      └─ Store X25519 public key
      └─ Store ML-KEM commitment (8 bytes)
      └─ has_mlkem_commitment = true
```

### During Handshake

```
Hybrid handshake completes
  │
  └─ Receive peer's ML-KEM public key in cookie response
      │
      ├─ has_mlkem_commitment = false
      │   └─ identity_status = PQ_UNVERIFIED
      │
      └─ has_mlkem_commitment = true
          │
          ├─ Verify: SHA256(peer_mlkem_pk)[0:8] == stored_commitment
          │   ├─ Match: identity_status = PQ_VERIFIED
          │   └─ Mismatch: REJECT CONNECTION (possible impersonation)
```

## API Reference

### Constants

```c
#define TOX_MLKEM_COMMITMENT_SIZE   8
#define TOX_ADDRESS_SIZE_CLASSICAL  38
#define TOX_ADDRESS_SIZE_PQ         46
```

### Identity Status Query

```c
typedef enum Tox_Connection_Identity {
    TOX_CONNECTION_IDENTITY_UNKNOWN,      // Not connected
    TOX_CONNECTION_IDENTITY_CLASSICAL,    // X25519 only
    TOX_CONNECTION_IDENTITY_PQ_UNVERIFIED,// PQ session, unverified identity
    TOX_CONNECTION_IDENTITY_PQ_VERIFIED,  // Full PQ verification
} Tox_Connection_Identity;

Tox_Connection_Identity tox_friend_get_identity_status(
    const Tox *tox,
    Tox_Friend_Number friend_number,
    Tox_Err_Friend_Query *error
);
```

### Callback

```c
typedef void tox_friend_identity_status_cb(
    Tox *tox,
    Tox_Friend_Number friend_number,
    Tox_Connection_Identity identity_status,
    void *user_data
);

void tox_callback_friend_identity_status(
    Tox *tox,
    tox_friend_identity_status_cb *callback
);
```

## Backwards Compatibility

### Classical Client Behavior

- Classical clients will truncate 46-byte addresses to 38 bytes when sharing
- Classical clients ignore the ML-KEM commitment
- PQ clients detect classical peers during handshake (no PQ marker in cookie)
- Sessions with classical clients use X25519 only (CLASSICAL identity status)

### Address Sharing

| Sender | Receiver | Address Used | Result |
|--------|----------|--------------|--------|
| PQ | PQ | 46-byte | Full PQ verification possible |
| PQ | Classical | 46-byte (truncated to 38) | Classical session |
| Classical | PQ | 38-byte | PQ session but UNVERIFIED identity |
| Classical | Classical | 38-byte | Classical session |

## Security Analysis

### Why 8-Byte Commitment?

- **64-bit collision resistance**: Birthday attack requires ~2^32 operations to find collision
- **Sufficient for identity binding**: Not protecting a secret, just binding identity
- **Size tradeoff**: Keeps address increase minimal (8 bytes vs 1184 for full key)
- **One-way**: Cannot derive ML-KEM key from commitment

### Attack Scenarios Prevented

1. **Quantum MITM**: Attacker cannot forge ML-KEM commitment without knowing private key
2. **Key Substitution**: Attacker cannot substitute their ML-KEM key (commitment would fail)
3. **Replay Attacks**: Fresh ephemeral keys + ML-KEM encapsulation prevent replay

### Limitations

1. **Pre-shared addresses**: Users who shared 38-byte addresses before PQ upgrade cannot get full verification
2. **Social engineering**: Users must verify address through trusted channel
3. **Key compromise**: If ML-KEM private key is compromised, commitment provides no protection

## Future Work

### ML-DSA Signatures

For stronger identity protection, consider ML-DSA (FIPS 204) digital signatures:
- Sign the X25519 + ML-KEM public keys with ML-DSA
- Include signature in address or exchange during handshake
- Provides non-repudiation and stronger binding

### Address Migration

- Protocol for upgrading friends from 38-byte to 46-byte addresses
- User notification when friend upgrades to PQ identity
- Automatic verification when peer sends ML-KEM public key

## Files Modified

| File | Changes |
|------|---------|
| `toxcore/crypto_core_pq.h` | Added commitment constants and function declarations |
| `toxcore/crypto_core_pq.c` | Implemented commitment generation/verification |
| `toxcore/tox.h` | Added PQ address API, identity status enum and functions |
| `toxcore/tox_api.c` | Added size functions and enum to_string |
| `toxcore/tox_struct.h` | Added identity status callback field |
| `toxcore/tox.c` | Implemented public API functions |
| `toxcore/Messenger.h` | Extended Friend struct with commitment fields |
| `toxcore/Messenger.c` | Implemented getaddress_pq, identity status functions |
| `toxcore/net_crypto.h` | Added nc_connection_is_pq, nc_get_self_mlkem_public |
| `toxcore/net_crypto.c` | Implemented PQ connection query functions |
| `auto_tests/crypto_pq_test.c` | Added commitment tests |

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA Standard (future work)
- [libsodium ML-KEM](https://doc.libsodium.org/public-key_cryptography/kem) - Implementation reference
