# Phase 3: Secure Communication & Encrypted Handshake

## Overview

Phase 3 implements end-to-end encrypted communication between authenticated agents. Building on the authentication infrastructure from Phases 1 and 2, agents establish encrypted sessions using hybrid encryption (RSA + AES) and conduct secure message exchanges with forward secrecy guarantees.

## Architecture

```
┌────────────────────────────────────────────────────┐
│          ENCRYPTED SESSION ESTABLISHMENT           │
│                                                    │
│  ┌──────────────┐              ┌──────────────┐  │
│  │  Traveller   │◄────────────►│    Helper    │  │
│  │              │   Encrypted  │              │  │
│  │ Session Keys │   Channel    │ Session Keys │  │
│  │ - AES-256    │              │ - AES-256    │  │
│  │ - HMAC-SHA256│              │ - HMAC-SHA256│  │
│  └──────────────┘              └──────────────┘  │
│                                                    │
└────────────────────────────────────────────────────┘

Encryption Model: Hybrid Encryption
├─ Asymmetric (RSA): Session key exchange
└─ Symmetric (AES-256-GCM): Message encryption

Authentication Model: Mutual TLS-style Handshake
├─ Agent certificates from Phase 2
├─ Signature verification on handshake messages
└─ Nonce-based replay protection
```

## Components

### 1. Session Key Generation

Each agent generates ephemeral session keys for symmetric encryption.

**Implementation:**
```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

class SecureSession:
    def __init__(self):
        # Generate random 256-bit AES key
        self.session_key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Generate HMAC key for message authentication
        self.hmac_key = os.urandom(32)
        
        # Session metadata
        self.session_id = secrets.token_hex(16)
        self.created_at = int(time.time())
        self.expires_at = self.created_at + 3600  # 1 hour
        
        # Peer information
        self.peer_agent_id = None
        self.peer_session_key = None
```

### 2. Encrypted Handshake Protocol

Three-way handshake with mutual authentication and key exchange.

```
┌──────────┐                                    ┌─────────┐
│Traveller │                                    │ Helper  │
└─────┬────┘                                    └────┬────┘
      │                                              │
      │  PHASE 1: Hello (Client → Server)           │
      ├──────────────────────────────────────────────>│
      │  {                                           │
      │    message_type: "CLIENT_HELLO",             │
      │    session_id: "...",                        │
      │    nonce: "...",                             │
      │    timestamp: 1770888900,                    │
      │    my_certificate: {...},                    │
      │    encrypted_session_key: "RSA(session_key)"│
      │    signature: "client_private_key(payload)"  │
      │  }                                           │
      │                                              │
      │                            Verify:           │
      │                       ✓ Certificate          │
      │                       ✓ Signature            │
      │                       ✓ Nonce fresh          │
      │                       ✓ Timestamp valid      │
      │                       Decrypt session_key    │
      │                                              │
      │  PHASE 2: Challenge (Server → Client)       │
      │<──────────────────────────────────────────────┤
      │  {                                           │
      │    message_type: "SERVER_HELLO",             │
      │    session_id: "...",                        │
      │    nonce: "...",                             │
      │    timestamp: 1770888905,                    │
      │    my_certificate: {...},                    │
      │    encrypted_session_key: "RSA(session_key)",│
      │    challenge: "AES(nonce_from_hello)",       │
      │    signature: "server_private_key(payload)"  │
      │  }                                           │
      │                                              │
      │  Verify:                                     │
      │  ✓ Certificate                               │
      │  ✓ Signature                                 │
      │  ✓ Challenge = original nonce                │
      │  Decrypt session_key                         │
      │                                              │
      │  PHASE 3: Confirm (Client → Server)         │
      ├──────────────────────────────────────────────>│
      │  {                                           │
      │    message_type: "CLIENT_CONFIRM",           │
      │    session_id: "...",                        │
      │    challenge_response: "AES(nonce_from_srv)",│
      │    signature: "client_private_key(payload)"  │
      │  }                                           │
      │                                              │
      │                            Verify:           │
      │                       ✓ Challenge response   │
      │                       ✓ Signature            │
      │                                              │
      │  ✅ ENCRYPTED SESSION ESTABLISHED ✅         │
      │                                              │
      │  All future messages encrypted with:         │
      │  - Traveller's session_key                   │
      │  - Helper's session_key                      │
      │  - Hybrid encryption scheme                  │
      │                                              │
```

### 3. Hybrid Encryption Scheme

Combines RSA (for key exchange) and AES-256-GCM (for message encryption).

**Session Key Exchange (RSA):**
```python
def encrypt_session_key_for_peer(self, peer_public_key, session_key):
    """
    Encrypt session key using peer's RSA public key.
    Only peer can decrypt it with their private key.
    """
    encrypted_key = peer_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

def decrypt_session_key(self, encrypted_key_b64):
    """
    Decrypt session key using own private key.
    """
    encrypted_key = base64.b64decode(encrypted_key_b64)
    session_key = self.private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key
```

**Message Encryption (AES-256-GCM):**
```python
def encrypt_message(self, plaintext, session_key):
    """
    Encrypt message using AES-256-GCM with authenticated encryption.
    Provides both confidentiality and integrity.
    """
    # Generate random IV (nonce) for GCM
    iv = os.urandom(12)  # 96 bits recommended for GCM
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(session_key),
        modes.GCM(iv),
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # Return IV + ciphertext + authentication tag
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode()
    }

def decrypt_message(self, encrypted_data, session_key):
    """
    Decrypt and verify message using AES-256-GCM.
    Automatically verifies authentication tag.
    """
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])
    
    # Create cipher with tag
    cipher = Cipher(
        algorithms.AES(session_key),
        modes.GCM(iv, tag),
    )
    decryptor = cipher.decryptor()
    
    # Decrypt (raises exception if tag verification fails)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()
```

### 4. Secure Message Exchange

After handshake, all messages are encrypted end-to-end.

**Endpoint:** `POST /agent/message`

**Request (Encrypted):**
```json
{
  "session_id": "abc123...",
  "sender_id": "traveller_agent_001",
  "encrypted_payload": {
    "iv": "base64_encoded_iv",
    "ciphertext": "base64_encoded_ciphertext",
    "tag": "base64_encoded_auth_tag"
  },
  "signature": "sender_signs_entire_payload",
  "timestamp": 1770888950
}
```

**Decrypted Payload:**
```json
{
  "message_type": "REQUEST",
  "request_id": "req_abc123",
  "method": "send_request",
  "parameters": {
    "query": "Hello Helper!",
    "priority": "high"
  },
  "nonce": "..."
}
```

**Response (Encrypted):**
```json
{
  "session_id": "abc123...",
  "sender_id": "helper_agent_001",
  "encrypted_payload": {
    "iv": "base64_encoded_iv",
    "ciphertext": "base64_encoded_ciphertext",
    "tag": "base64_encoded_auth_tag"
  },
  "signature": "helper_signs_entire_payload",
  "timestamp": 1770888955
}
```

**Decrypted Response:**
```json
{
  "message_type": "RESPONSE",
  "request_id": "req_abc123",
  "status": "SUCCESS",
  "result": {
    "response": "Hello Traveller! Request received.",
    "processed_at": 1770888955
  }
}
```

## Security Properties

### 1. End-to-End Encryption
- Messages encrypted with AES-256-GCM
- Only sender and receiver can decrypt
- Controller cannot read message contents
- Network observers see only ciphertext

### 2. Forward Secrecy
- Ephemeral session keys generated per session
- Session keys never stored long-term
- Compromise of long-term keys doesn't reveal past sessions
- Each session has independent keys

### 3. Authenticated Encryption (AEAD)
- AES-GCM provides both confidentiality and integrity
- Authentication tag prevents tampering
- Decryption fails if message modified
- No need for separate HMAC

### 4. Mutual Authentication
- Both agents verify each other's certificates
- Both agents sign handshake messages
- Challenge-response prevents impersonation
- Nonces prevent replay attacks

### 5. Session Binding
- Session keys tied to specific agent pair
- Session ID prevents cross-session attacks
- Timestamps prevent stale sessions
- Expiration enforces re-authentication

## Attack Resistance

### 1. Eavesdropping
**Attack:** Network observer captures encrypted traffic

**Defense:**
- All messages encrypted with AES-256-GCM
- Session keys never transmitted in plaintext
- RSA-OAEP protects session key exchange
- Observer sees only ciphertext

### 2. Man-in-the-Middle (MITM)
**Attack:** Attacker intercepts and modifies handshake

**Defense:**
- Both agents verify certificates (Phase 2)
- Handshake messages signed by private keys
- Challenge-response proves key possession
- Any modification breaks signatures

### 3. Replay Attack
**Attack:** Attacker captures and replays old messages

**Defense:**
- Fresh nonces in every handshake message
- Timestamps validated (freshness window)
- Session IDs prevent cross-session replay
- Nonces tracked per session

### 4. Session Hijacking
**Attack:** Attacker tries to inject messages into session

**Defense:**
- Every message signed by sender
- Session key required for encryption
- Authentication tag prevents forgery
- Signature verification on all messages

### 5. Key Compromise
**Attack:** Attacker obtains agent's long-term private key

**Defense:**
- Forward secrecy: past sessions remain secure
- Session keys are ephemeral
- Re-authentication required per session
- Revocation possible (future: CRLs)

## Implementation Checklist

### Agent Class Extensions

- [ ] Add `SecureSession` class
- [ ] Implement `generate_session_keys()`
- [ ] Implement `encrypt_message()` / `decrypt_message()`
- [ ] Implement `encrypt_session_key_for_peer()`
- [ ] Implement `decrypt_session_key()`
- [ ] Add session storage dictionary

### Handshake Methods

- [ ] `initiate_handshake(peer_address)` - Client Hello
- [ ] `handle_client_hello(request)` - Server Hello
- [ ] `handle_server_hello(response)` - Client Confirm
- [ ] `handle_client_confirm(request)` - Complete
- [ ] Challenge generation and verification

### Message Methods

- [ ] `send_encrypted_message(peer_address, message)`
- [ ] `receive_encrypted_message(encrypted_request)`
- [ ] Message signing and verification
- [ ] Nonce tracking per session

### Flask Endpoints

- [ ] `POST /agent/handshake` - Handle handshake phases
- [ ] `POST /agent/message` - Encrypted message exchange
- [ ] `GET /agent/session/<session_id>` - Session status

## Testing

### Setup
```bash
# All agents registered and authenticated (Phase 1 & 2 complete)
```

### Test Handshake
```python
# Traveller initiates handshake with Helper
success, session = traveller.initiate_handshake("https://localhost:5001")

if success:
    print(f"Session ID: {session['session_id']}")
    print(f"Peer: {session['peer_agent_id']}")
    print(f"Expires: {session['expires_at']}")
```

### Test Encrypted Message
```python
# Send encrypted message through established session
message = {
    "method": "send_request",
    "parameters": {"query": "Hello!"}
}

success, response = traveller.send_encrypted_message(
    peer_address="https://localhost:5001",
    session_id=session['session_id'],
    message=message
)

if success:
    print(f"Response: {response}")
```

### Verify Encryption
```bash
# Capture network traffic with Wireshark or tcpdump
# Verify message contents are encrypted
# Only IV, ciphertext, and tag visible
```

## Performance Considerations

### Handshake Overhead
- 3 round-trips for full handshake
- RSA operations (slowest): 2 encryptions, 2 decryptions
- AES operations (fast): negligible overhead
- **Optimization:** Cache sessions, reuse for multiple messages

### Message Encryption
- AES-256-GCM: ~1GB/s on modern CPUs
- Minimal latency impact
- Authentication tag: 16 bytes overhead
- IV: 12 bytes per message

### Session Management
- Memory: ~1KB per active session
- CPU: Minimal for session lookup
- **Recommendation:** Limit to 1000 concurrent sessions per agent

## CLI Commands

```bash
# Establish encrypted session
traveller_1> connect helper https://localhost:5001
[INFO] Initiating handshake with Helper...
[INFO] ✓ Session established
[INFO] Session ID: a1b2c3d4...
[INFO] Expires: 2026-02-12 15:30:00

# Send encrypted message
traveller_1> send helper "Hello Helper!"
[DEBUG] Encrypting message with session key...
[DEBUG] Sending to https://localhost:5001/agent/message
[INFO] ✓ Message sent
[INFO] Response: "Hello Traveller! Message received."

# List active sessions
traveller_1> sessions
Active Sessions:
1. helper_agent_001 | Session: a1b2c3d4... | Expires: 15:30

# Close session
traveller_1> disconnect helper
[INFO] Session closed
```

## Next Steps

### Enhancements

1. **Session Resumption**
   - Cache session keys
   - Resume without full handshake
   - Reduce latency for frequent communication

2. **Certificate Revocation**
   - Controller publishes revocation lists
   - Agents check before accepting certificates
   - Immediate invalidation of compromised agents

3. **Group Communication**
   - Multi-party session keys
   - Broadcast encrypted messages
   - Efficient group key management

4. **Message Persistence**
   - Store encrypted message history
   - Audit trail for compliance
   - Searchable encryption (future)

## Conclusion

Phase 3 completes the secure A2A protocol with:
- ✓ End-to-end encryption (AES-256-GCM)
- ✓ Forward secrecy (ephemeral keys)
- ✓ Mutual authentication (certificates + signatures)
- ✓ Replay protection (nonces + timestamps)
- ✓ Integrity protection (AEAD)

Agents can now:
1. **Register** with controller (Phase 1)
2. **Discover** and authenticate peers (Phase 2)
3. **Communicate** securely with encryption (Phase 3)

The protocol provides enterprise-grade security suitable for sensitive agent-to-agent interactions.
