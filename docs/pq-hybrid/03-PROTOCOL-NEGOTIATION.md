# Protocol Negotiation via ToxExt

## Overview

ToxExt is the extension negotiation framework for Tox, allowing clients to advertise and negotiate optional capabilities. We use ToxExt to negotiate PQ support without breaking compatibility with legacy clients.

## ToxExt Basics

### How ToxExt Works

1. Extensions register with unique IDs (UUIDs)
2. After friend connection established, clients exchange supported extensions
3. Extensions can send custom lossless packets (types 160-191)
4. Legacy clients ignore unknown extensions gracefully

### Current ToxExt Flow

```
Alice                                               Bob
-----                                               ---
        ─── Friend Connection Established ───►
        
        ◄── Extension Negotiation ───►
        
        Each side advertises supported extensions
        Only use extensions both sides support
```

## PQ Capability Extension

### Extension Registration

```c
// toxext_pq.h

#define TOXEXT_PQ_UUID "aqtox-pq-hybrid-v1"

// Extension packet types (within ToxExt custom packet range)
#define TOXEXT_PQ_CAPABILITY_ANNOUNCE  0x01
#define TOXEXT_PQ_CAPABILITY_ACK       0x02
#define TOXEXT_PQ_CAPABILITY_REJECT    0x03
#define TOXEXT_PQ_KEY_UPDATE           0x04

// Supported algorithms (bitmasks)
#define TOXEXT_PQ_KEM_MLKEM768         (1 << 0)
#define TOXEXT_PQ_KEM_MLKEM1024        (1 << 1)  // Future
#define TOXEXT_PQ_SIG_MLDSA65          (1 << 0)  // Future
#define TOXEXT_PQ_SIG_MLDSA87          (1 << 1)  // Future

// Extension structure
typedef struct ToxExtPQ {
    uint8_t  extension_uuid[16];
    uint16_t version;
    
    // Our capabilities
    uint16_t our_supported_kems;
    uint16_t our_supported_sigs;
    
    // Peer capabilities (learned via negotiation)
    uint16_t peer_supported_kems;
    uint16_t peer_supported_sigs;
    
    // Negotiated common capabilities
    uint16_t negotiated_kem;
    uint16_t negotiated_sig;
    
    // State
    bool negotiation_complete;
    bool peer_pq_capable;
    
    // Callbacks
    void (*on_capability_received)(uint32_t friend_number, uint16_t kems, uint16_t sigs);
    void (*on_negotiation_complete)(uint32_t friend_number, bool pq_enabled);
} ToxExtPQ;
```

### Extension Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ToxExt PQ Extension Lifecycle                    │
└─────────────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   ┌─────────────────────────────────────────────────────────────────┐
   │ toxext_pq_init()                                                │
   │   - Register with ToxExt framework                              │
   │   - Set our capabilities (ML-KEM-768)                           │
   │   - Register packet handlers                                    │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
2. FRIEND CONNECTS
   ┌─────────────────────────────────────────────────────────────────┐
   │ on_friend_connection_status()                                   │
   │   - If connected, start capability exchange                     │
   │   - Send CAPABILITY_ANNOUNCE                                    │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
3. CAPABILITY EXCHANGE
   ┌─────────────────────────────────────────────────────────────────┐
   │ Both peers send their capabilities                              │
   │ Process received capabilities                                   │
   │ Compute intersection → negotiated capabilities                  │
   │ Send CAPABILITY_ACK with agreed set                             │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
4. HANDSHAKE UPGRADE (if both support PQ)
   ┌─────────────────────────────────────────────────────────────────┐
   │ Trigger session rekeying with hybrid handshake                  │
   │ Or: Mark peer as PQ-capable for next session                    │
   └─────────────────────────────────────────────────────────────────┘
```

### Packet Formats

#### CAPABILITY_ANNOUNCE (0x01)

Sent immediately after ToxExt negotiation confirms both sides have PQ extension:

```
+--------+--------+--------+------------------+------------------+
| type   | version| flags  | supported_kems   | supported_sigs   |
| (1)    | (2)    | (2)    | (2)              | (2)              |
+--------+--------+--------+------------------+------------------+
| 0x01   | 0x0001 |        | bitmask          | bitmask          |
+--------+--------+--------+------------------+------------------+

+------------------+------------------+------------------+
| mlkem_pubkey     | timestamp        | signature        |
| (1184 bytes)     | (8 bytes)        | (64 bytes)       |
+------------------+------------------+------------------+
| Our ML-KEM       | Unix timestamp   | Ed25519 sig      |
| public key       | (monotonic)      | over all above   |
+------------------+------------------+------------------+

Total: 1265 bytes
```

#### CAPABILITY_ACK (0x02)

Confirms negotiated capabilities:

```
+--------+--------+------------------+------------------+
| type   | flags  | negotiated_kem   | negotiated_sig   |
| (1)    | (2)    | (2)              | (2)              |
+--------+--------+------------------+------------------+
| 0x02   |        | single value     | single value     |
+--------+--------+------------------+------------------+

+------------------+
| signature        |
| (64 bytes)       |
+------------------+
| Ed25519 sig      |
+------------------+

Total: 71 bytes
```

#### CAPABILITY_REJECT (0x03)

If capabilities don't intersect or policy disallows:

```
+--------+--------+------------------+
| type   | reason | reserved         |
| (1)    | (2)    | (8 bytes)        |
+--------+--------+------------------+
| 0x03   | code   |                  |
+--------+--------+------------------+

Reason codes:
  0x0001 - No common algorithms
  0x0002 - Policy requires PQ (can't fallback)
  0x0003 - Version mismatch
  0x0004 - Invalid signature
```

#### KEY_UPDATE (0x04)

For periodic key rotation (optional enhancement):

```
+--------+------------------+------------------+------------------+
| type   | new_mlkem_pubkey | timestamp        | signature        |
| (1)    | (1184 bytes)     | (8 bytes)        | (64 bytes)       |
+--------+------------------+------------------+------------------+
| 0x04   |                  |                  |                  |
+--------+------------------+------------------+------------------+
```

## Implementation

### Extension Registration

```c
// toxext_pq.c

#include "toxext_pq.h"
#include <toxext/toxext.h>

static ToxExtPQ *g_pq_ext = NULL;

// Extension UUID (must be unique)
static const uint8_t PQ_EXTENSION_UUID[16] = {
    0xa0, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
    0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9
};

/**
 * Initialize PQ extension and register with ToxExt.
 */
int toxext_pq_init(Tox *tox, ToxExt *toxext) {
    g_pq_ext = calloc(1, sizeof(ToxExtPQ));
    if (g_pq_ext == NULL) {
        return -1;
    }
    
    memcpy(g_pq_ext->extension_uuid, PQ_EXTENSION_UUID, 16);
    g_pq_ext->version = 0x0001;
    g_pq_ext->our_supported_kems = TOXEXT_PQ_KEM_MLKEM768;
    g_pq_ext->our_supported_sigs = 0;  // Not yet implemented
    
    // Register extension with ToxExt
    struct ToxExtExtension ext = {
        .uuid = PQ_EXTENSION_UUID,
        .uuid_size = 16,
        .recv_callback = toxext_pq_recv_callback,
        .negotiate_callback = toxext_pq_negotiate_callback,
        .userdata = g_pq_ext
    };
    
    if (toxext_register_extension(toxext, &ext) != 0) {
        free(g_pq_ext);
        return -1;
    }
    
    return 0;
}

/**
 * Called when ToxExt negotiation completes with a friend.
 */
static void toxext_pq_negotiate_callback(
    uint32_t friend_number,
    bool extension_supported,
    void *userdata
) {
    ToxExtPQ *pq = (ToxExtPQ *)userdata;
    
    if (extension_supported) {
        // Peer has PQ extension, send our capabilities
        toxext_pq_send_capability_announce(friend_number);
    } else {
        // Peer doesn't have PQ extension
        pq->peer_pq_capable = false;
        pq->negotiation_complete = true;
        
        if (pq->on_negotiation_complete) {
            pq->on_negotiation_complete(friend_number, false);
        }
    }
}

/**
 * Handle incoming PQ extension packets.
 */
static void toxext_pq_recv_callback(
    uint32_t friend_number,
    const uint8_t *data,
    size_t length,
    void *userdata
) {
    if (length < 1) return;
    
    ToxExtPQ *pq = (ToxExtPQ *)userdata;
    uint8_t packet_type = data[0];
    
    switch (packet_type) {
        case TOXEXT_PQ_CAPABILITY_ANNOUNCE:
            toxext_pq_handle_announce(pq, friend_number, data + 1, length - 1);
            break;
            
        case TOXEXT_PQ_CAPABILITY_ACK:
            toxext_pq_handle_ack(pq, friend_number, data + 1, length - 1);
            break;
            
        case TOXEXT_PQ_CAPABILITY_REJECT:
            toxext_pq_handle_reject(pq, friend_number, data + 1, length - 1);
            break;
            
        case TOXEXT_PQ_KEY_UPDATE:
            toxext_pq_handle_key_update(pq, friend_number, data + 1, length - 1);
            break;
            
        default:
            // Unknown packet type, ignore
            break;
    }
}
```

### Capability Announcement

```c
/**
 * Send our PQ capabilities to a friend.
 */
int toxext_pq_send_capability_announce(uint32_t friend_number) {
    ToxExtPQ *pq = g_pq_ext;
    if (pq == NULL) return -1;
    
    // Build packet
    uint8_t packet[1265];
    size_t offset = 0;
    
    packet[offset++] = TOXEXT_PQ_CAPABILITY_ANNOUNCE;
    
    // Version (big-endian)
    packet[offset++] = (pq->version >> 8) & 0xFF;
    packet[offset++] = pq->version & 0xFF;
    
    // Flags (reserved)
    packet[offset++] = 0x00;
    packet[offset++] = 0x00;
    
    // Supported KEMs
    packet[offset++] = (pq->our_supported_kems >> 8) & 0xFF;
    packet[offset++] = pq->our_supported_kems & 0xFF;
    
    // Supported signatures
    packet[offset++] = (pq->our_supported_sigs >> 8) & 0xFF;
    packet[offset++] = pq->our_supported_sigs & 0xFF;
    
    // Our ML-KEM public key
    // (Get from identity - implementation detail)
    Tox_Hybrid_Identity *identity = tox_get_hybrid_identity();
    memcpy(packet + offset, identity->mlkem_public, TOX_MLKEM_PUBLICKEYBYTES);
    offset += TOX_MLKEM_PUBLICKEYBYTES;
    
    // Timestamp
    uint64_t timestamp = time(NULL);
    for (int i = 7; i >= 0; i--) {
        packet[offset++] = (timestamp >> (i * 8)) & 0xFF;
    }
    
    // Sign the packet (excluding signature field)
    uint8_t signature[64];
    // ... signing code using Ed25519 ...
    memcpy(packet + offset, signature, 64);
    offset += 64;
    
    // Send via ToxExt
    return toxext_send(friend_number, PQ_EXTENSION_UUID, packet, offset);
}

/**
 * Handle received capability announcement.
 */
static void toxext_pq_handle_announce(
    ToxExtPQ *pq,
    uint32_t friend_number,
    const uint8_t *data,
    size_t length
) {
    if (length < 1264) {  // Minimum valid size
        return;
    }
    
    size_t offset = 0;
    
    // Parse version
    uint16_t version = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    // Skip flags
    offset += 2;
    
    // Parse supported KEMs
    uint16_t peer_kems = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    // Parse supported sigs
    uint16_t peer_sigs = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    // Extract peer's ML-KEM public key
    const uint8_t *peer_mlkem_pubkey = data + offset;
    offset += TOX_MLKEM_PUBLICKEYBYTES;
    
    // Parse timestamp
    uint64_t timestamp = 0;
    for (int i = 0; i < 8; i++) {
        timestamp = (timestamp << 8) | data[offset++];
    }
    
    // Verify signature
    const uint8_t *signature = data + offset;
    // ... signature verification ...
    
    // Store peer capabilities
    pq->peer_supported_kems = peer_kems;
    pq->peer_supported_sigs = peer_sigs;
    
    // Store peer's ML-KEM public key
    // (Store in friend's contact record)
    tox_friend_set_mlkem_pubkey(friend_number, peer_mlkem_pubkey);
    
    // Compute negotiated capabilities
    pq->negotiated_kem = pq->our_supported_kems & peer_kems;
    pq->negotiated_sig = pq->our_supported_sigs & peer_sigs;
    
    if (pq->negotiated_kem != 0) {
        // We have common KEM support!
        pq->peer_pq_capable = true;
        toxext_pq_send_capability_ack(friend_number, pq->negotiated_kem, pq->negotiated_sig);
    } else {
        // No common algorithms
        pq->peer_pq_capable = false;
        toxext_pq_send_capability_reject(friend_number, 0x0001);  // No common algorithms
    }
    
    pq->negotiation_complete = true;
    
    if (pq->on_negotiation_complete) {
        pq->on_negotiation_complete(friend_number, pq->peer_pq_capable);
    }
}
```

### Integration with Handshake

```c
/**
 * Called before initiating handshake with friend.
 * Determines whether to use hybrid or classical handshake.
 */
bool toxext_pq_should_use_hybrid(uint32_t friend_number) {
    ToxExtPQ *pq = g_pq_ext;
    if (pq == NULL) return false;
    
    // Check if we've completed negotiation with this friend
    if (!pq->negotiation_complete) {
        return false;  // Not yet negotiated, use classical
    }
    
    return pq->peer_pq_capable && (pq->negotiated_kem & TOXEXT_PQ_KEM_MLKEM768);
}

/**
 * Get peer's ML-KEM public key for hybrid handshake.
 */
int toxext_pq_get_peer_mlkem_pubkey(
    uint32_t friend_number,
    uint8_t pubkey[TOX_MLKEM_PUBLICKEYBYTES]
) {
    return tox_friend_get_mlkem_pubkey(friend_number, pubkey);
}
```

## State Machine

### Per-Friend PQ State

```
                    ┌─────────────────────┐
                    │      UNKNOWN        │
                    │ (Initial state)     │
                    └──────────┬──────────┘
                               │
                    Friend connection established
                               │
                               ▼
                    ┌─────────────────────┐
                    │    NEGOTIATING      │
                    │ Exchanging caps     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │  PQ_CAPABLE     │ │ CLASSICAL   │ │     ERROR       │
    │ Hybrid enabled  │ │ No PQ ext   │ │ Negotiation     │
    │                 │ │ or no match │ │ failed          │
    └────────┬────────┘ └─────────────┘ └─────────────────┘
             │
             │ Handshake with hybrid
             ▼
    ┌─────────────────┐
    │  PQ_ACTIVE      │
    │ Session using   │
    │ hybrid crypto   │
    └─────────────────┘
```

### State Transitions

```c
typedef enum {
    PQ_STATE_UNKNOWN,
    PQ_STATE_NEGOTIATING,
    PQ_STATE_PQ_CAPABLE,
    PQ_STATE_CLASSICAL,
    PQ_STATE_PQ_ACTIVE,
    PQ_STATE_ERROR
} ToxExtPQState;

// State stored per-friend
typedef struct FriendPQState {
    ToxExtPQState state;
    uint16_t negotiated_kem;
    uint8_t mlkem_pubkey[TOX_MLKEM_PUBLICKEYBYTES];
    uint64_t last_update;
    uint8_t capability_signature[64];  // For downgrade detection
} FriendPQState;
```

## Downgrade Attack Prevention

### Attack Scenario

1. Alice and Bob both support PQ
2. Mallory (MITM) intercepts capability announcements
3. Mallory tells each side the other only supports classical
4. Sessions established with classical-only (quantum vulnerable)

### Defense: Capability Commitment

Each peer signs their capabilities with their long-term key:

```c
/**
 * Create signed capability commitment.
 * This prevents MITM from forging capability downgrades.
 */
int toxext_pq_create_commitment(
    uint8_t commitment[128],  // Output
    const Tox_Hybrid_Identity *identity,
    uint16_t supported_kems,
    uint16_t supported_sigs,
    uint64_t timestamp
) {
    // Build commitment data
    uint8_t data[64];
    size_t offset = 0;
    
    // Tox public key (binds to identity)
    memcpy(data + offset, identity->x25519_public, 32);
    offset += 32;
    
    // Supported algorithms
    data[offset++] = (supported_kems >> 8) & 0xFF;
    data[offset++] = supported_kems & 0xFF;
    data[offset++] = (supported_sigs >> 8) & 0xFF;
    data[offset++] = supported_sigs & 0xFF;
    
    // Timestamp (monotonically increasing)
    for (int i = 7; i >= 0; i--) {
        data[offset++] = (timestamp >> (i * 8)) & 0xFF;
    }
    
    // Padding
    memset(data + offset, 0, 64 - offset);
    
    // Sign with Ed25519 (or X25519-derived signing key)
    // ... signature generation ...
    
    // Output: data || signature
    memcpy(commitment, data, 64);
    memcpy(commitment + 64, signature, 64);
    
    return 0;
}

/**
 * Verify peer's capability commitment.
 * Alert user if capabilities decreased (potential attack).
 */
int toxext_pq_verify_commitment(
    uint32_t friend_number,
    const uint8_t commitment[128],
    const uint8_t peer_pubkey[32]
) {
    // Verify signature
    // ... signature verification ...
    
    // Check timestamp is newer than stored
    uint64_t new_timestamp = /* parse from commitment */;
    uint64_t stored_timestamp = tox_friend_get_pq_timestamp(friend_number);
    
    if (new_timestamp <= stored_timestamp) {
        // Replay attack or stale commitment
        return -1;
    }
    
    // Check for capability downgrade
    uint16_t new_kems = /* parse from commitment */;
    uint16_t stored_kems = tox_friend_get_pq_kems(friend_number);
    
    if (stored_kems != 0 && new_kems == 0) {
        // Peer previously supported PQ, now claims classical-only
        // This could be a downgrade attack!
        // Alert the user
        tox_friend_pq_downgrade_warning(friend_number);
        return -2;
    }
    
    // Store new commitment
    tox_friend_set_pq_commitment(friend_number, commitment);
    
    return 0;
}
```

### User Warning on Downgrade

When a peer's capabilities decrease:

```kotlin
// In aTox UI
fun onPQDowngradeWarning(friendNumber: Int) {
    val friend = friendRepository.get(friendNumber)
    
    AlertDialog.Builder(context)
        .setTitle("Security Warning")
        .setMessage(
            "${friend.name}'s connection security has decreased. " +
            "This could indicate a network attack. " +
            "Do you want to continue with reduced security?"
        )
        .setPositiveButton("Continue (Reduced Security)") { _, _ ->
            // User accepts downgrade
            toxService.acceptPQDowngrade(friendNumber)
        }
        .setNegativeButton("Block Connection") { _, _ ->
            // User rejects, connection blocked
            toxService.blockConnection(friendNumber)
        }
        .show()
}
```

## Testing the Extension

### Unit Tests

```c
// test_toxext_pq.c

void test_capability_announce_roundtrip() {
    // Create announcement
    uint8_t packet[1265];
    int len = toxext_pq_create_announce_packet(packet);
    assert(len == 1265);
    
    // Parse it back
    uint16_t kems, sigs;
    uint8_t mlkem_pubkey[1184];
    int result = toxext_pq_parse_announce_packet(packet, len, &kems, &sigs, mlkem_pubkey);
    assert(result == 0);
    assert(kems == TOXEXT_PQ_KEM_MLKEM768);
}

void test_negotiation_both_support_pq() {
    // Simulate two clients
    ToxExtPQ *alice = toxext_pq_create();
    ToxExtPQ *bob = toxext_pq_create();
    
    // Both support ML-KEM-768
    alice->our_supported_kems = TOXEXT_PQ_KEM_MLKEM768;
    bob->our_supported_kems = TOXEXT_PQ_KEM_MLKEM768;
    
    // Exchange capabilities
    // ... simulation ...
    
    assert(alice->peer_pq_capable == true);
    assert(bob->peer_pq_capable == true);
    assert(alice->negotiated_kem == TOXEXT_PQ_KEM_MLKEM768);
}

void test_negotiation_fallback_to_classical() {
    ToxExtPQ *alice = toxext_pq_create();
    // Bob doesn't have PQ extension at all
    
    // Alice sends announce, no response
    // ... simulation ...
    
    assert(alice->peer_pq_capable == false);
    // Session proceeds with classical
}
```

### Integration Tests

```bash
# Test script for two aqTox-PQ clients

# Start first client
./atox-pq --profile alice --port 33445 &
ALICE_PID=$!

# Start second client  
./atox-pq --profile bob --port 33446 &
BOB_PID=$!

# Wait for bootstrap
sleep 10

# Add friends
# ... test automation ...

# Verify PQ negotiation succeeded
# Check logs for "PQ negotiation complete: hybrid enabled"

# Verify session uses hybrid crypto
# Check logs for "Session established with hybrid key exchange"
```
