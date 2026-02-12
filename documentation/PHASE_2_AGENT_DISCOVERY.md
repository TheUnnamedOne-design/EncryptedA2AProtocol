# Phase 2: Agent-to-Agent Discovery & Certificate Exchange

## Overview

Phase 2 builds on the trust infrastructure established in Phase 1, enabling agents to discover, authenticate, and establish trust with peer agents. Using controller-signed certificates as proof of authenticity, agents can verify each other's identities through the shared trust anchor (controller's public key).

## Architecture

```
┌─────────────────────────────────────────────┐
│         CONTROLLER (Trust Anchor)           │
│  • All agents have controller_public_key    │
│  • Certificates signed by controller        │
└─────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────▼────────┐         ┌───▼─────────────┐
│  TRAVELLER     │◄────────►│    HELPER       │
│    AGENT       │  Mutual  │    AGENT        │
│                │   Auth   │                 │
│  Certificate:  │          │  Certificate:   │
│  - agent_card  │          │  - agent_card   │
│  - agent_sig   │          │  - agent_sig    │
│  - ctrl_sig ✓  │          │  - ctrl_sig ✓   │
└────────────────┘          └─────────────────┘
        │                            │
        │  1. Request certificate    │
        ├───────────────────────────>│
        │                            │
        │  2. Return certificate     │
        │<───────────────────────────┤
        │                            │
        │  3. Verify both signatures:│
        │     - Agent signature      │
        │     - Controller signature │
        │                            │
        │  4. Share my certificate   │
        ├───────────────────────────>│
        │                            │
        │  5. Verify both signatures │
        │                            │
        │  ✓ Mutual Trust Established│
        │                            │
```

## Components

### 1. Certificate Storage

Each agent stores their issued certificate for sharing with peers.

**Implementation:**
```python
# In agent's __init__()
self.my_certificate = None      # Stored after registration
self.trusted_peers = {}         # Cache of verified peers
```

**Certificate Structure:**
```json
{
  "registration_version": 1,
  "agent_card": {
    "agent_id": "traveller_agent_001",
    "name": "Traveller Agent",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "methods": ["send_request", "receive_response"],
    "method_descriptions": {...},
    "issued_at": 1770888800,
    "expires_at": 1770892400,
    "protocol_version": 1
  },
  "agent_signature": "base64_agent_signature",
  "controller_signature": "base64_controller_signature",
  "certificate_issued_at": 1770888835,
  "certificate_expires_at": 1770975235,
  "nonce": "..."
}
```

### 2. Certificate Sharing Endpoint

Each agent exposes their certificate for peer retrieval.

**Endpoint:** `GET /agent/certificate`

**Response (Success - 200):**
```json
{
  "registration_version": 1,
  "agent_card": {...},
  "agent_signature": "...",
  "controller_signature": "...",
  "certificate_issued_at": 1770888835,
  "certificate_expires_at": 1770975235
}
```

**Response (Not Registered - 404):**
```json
{
  "error": "Not registered yet"
}
```

**Implementation:**
```python
# Add to each agent's Flask app
@app.route('/agent/certificate', methods=['GET'])
def get_certificate():
    if agent.my_certificate:
        return jsonify(agent.my_certificate), 200
    else:
        return jsonify({"error": "Not registered yet"}), 404
```

### 3. Peer Certificate Verification

Generic method to verify ANY agent's certificate using controller's signature.

**Method:** `verify_peer_certificate(certificate)`

**Purpose:** Establish trust in peer agents through controller's endorsement

**Implementation:**
```python
def verify_peer_certificate(self, certificate):
    """
    Verify any agent's certificate by checking controller's signature.
    
    Returns:
        (success: bool, message: str, agent_info: dict or None)
    """
    # Step 1: Check trust anchor
    if not self.controller_public_key:
        return False, "Controller public key not loaded", None
    
    try:
        agent_card = certificate["agent_card"]
        agent_signature = certificate["agent_signature"]
        controller_signature = certificate["controller_signature"]
        
        # Step 2: Verify certificate hasn't expired
        current_time = int(time.time())
        expires_at = certificate.get("certificate_expires_at")
        
        if expires_at and current_time > expires_at:
            return False, "Certificate has expired", None
        
        # Step 3: Verify AGENT's signature
        agent_public_key_pem = agent_card["public_key"]
        agent_public_key = load_pem_public_key(agent_public_key_pem.encode())
        
        data_bytes = self.canonical_json(agent_card)
        
        agent_public_key.verify(
            base64.b64decode(agent_signature),
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Step 4: Verify CONTROLLER's signature
        self.controller_public_key.verify(
            base64.b64decode(controller_signature),
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Step 5: Extract verified agent info
        agent_info = {
            "agent_id": agent_card["agent_id"],
            "name": agent_card["name"],
            "methods": agent_card["methods"],
            "public_key": agent_card["public_key"],
            "issued_at": certificate.get("certificate_issued_at"),
            "expires_at": certificate.get("certificate_expires_at")
        }
        
        return True, f"Certificate verified - {agent_card['name']} authenticated", agent_info
        
    except Exception as e:
        return False, f"Verification error: {e}", None
```

### 4. Peer Authentication

Fetch and verify peer's certificate in one operation.

**Method:** `authenticate_peer(peer_address)`

**Implementation:**
```python
def authenticate_peer(self, peer_address):
    """
    Fetch and verify another agent's certificate.
    
    Returns:
        (success: bool, message: str, agent_info: dict or None)
    """
    try:
        # Fetch peer's certificate
        response = requests.get(
            f"{peer_address}/agent/certificate",
            verify=False
        )
        
        if response.status_code != 200:
            return False, f"Cannot fetch certificate: {response.status_code}", None
        
        peer_certificate = response.json()
        
        # Verify the certificate
        success, message, agent_info = self.verify_peer_certificate(peer_certificate)
        
        if success:
            # Cache verified peer
            peer_id = agent_info["agent_id"]
            self.trusted_peers[peer_id] = {
                "certificate": peer_certificate,
                "info": agent_info,
                "verified_at": int(time.time()),
                "address": peer_address
            }
            
        return success, message, agent_info
        
    except Exception as e:
        return False, f"Authentication error: {e}", None
```

## Discovery Flow

### Peer-to-Peer Authentication Sequence

```
┌──────────┐                                    ┌─────────┐
│ Traveller│                                    │ Helper  │
└─────┬────┘                                    └────┬────┘
      │                                              │
      │ 1. Discover peer at https://localhost:5001  │
      │                                              │
      ├────── GET /agent/certificate ───────────────>│
      │                                              │
      │                                              │  Has my_certificate?
      │                                              │  ✓ Yes (registered)
      │                                              │
      │<────── Helper's Certificate ─────────────────┤
      │  {                                           │
      │    agent_card: {...},                        │
      │    agent_signature: "...",                   │
      │    controller_signature: "..."               │
      │  }                                           │
      │                                              │
      │  Verify Helper's Certificate:                │
      │  ✓ Agent signature valid                     │
      │  ✓ Controller signature valid                │
      │  ✓ Not expired                               │
      │  ✓ Issued by trusted controller              │
      │                                              │
      │  Cache Helper in trusted_peers               │
      │                                              │
      │ 2. Now Helper authenticates Traveller       │
      │                                              │
      │<────── GET /agent/certificate ───────────────┤
      │                                              │
      │                                              │  Has my_certificate?
      │                                              │  ✓ Yes (registered)
      │                                              │
      ├────── Traveller's Certificate ──────────────>│
      │                                              │
      │                                              │  Verify Traveller's Certificate:
      │                                              │  ✓ Agent signature valid
      │                                              │  ✓ Controller signature valid
      │                                              │  ✓ Not expired
      │                                              │  ✓ Issued by trusted controller
      │                                              │
      │                                              │  Cache Traveller in trusted_peers
      │                                              │
      │  ✅ MUTUAL TRUST ESTABLISHED ✅              │
      │                                              │
```

## Security Analysis

### Verification Chain

For Traveller to trust Helper:

```
1. Traveller has controller_public_key (from Phase 1)
2. Helper presents certificate with controller_signature
3. Traveller verifies:
   a. Helper's signature on agent_card
      → Proves Helper created this identity
   b. Controller's signature on agent_card
      → Proves controller validated Helper
4. If both signatures valid:
   → Traveller trusts Helper is legitimate
```

### Trust Transitivity

```
Traveller trusts Controller (trust anchor)
    ↓
Controller validated and signed Helper's certificate
    ↓
Traveller trusts Helper (transitive trust)
```

This is identical to SSL/TLS:
```
Browser trusts Certificate Authority (CA)
    ↓
CA validated and signed website's certificate
    ↓
Browser trusts website (transitive trust)
```

## Attack Resistance

### 1. Fake Agent Attack
**Attack:** Malicious actor creates fake agent and tries to impersonate Helper

**Defense:**
- Fake agent cannot forge controller_signature
- Controller's private key never leaves controller
- Signature verification fails
- Traveller rejects fake agent

### 2. Certificate Tampering
**Attack:** Attacker modifies Helper's agent_card in transit

**Defense:**
- Any modification breaks signatures
- Both agent_signature and controller_signature become invalid
- Traveller detects tampering
- Connection rejected

### 3. Man-in-the-Middle (MITM)
**Attack:** Attacker intercepts certificate exchange and injects their own

**Defense:**
- Attacker cannot create valid controller_signature
- Attacker's certificate fails verification
- HTTPS/TLS provides transport security
- Cryptographic signatures provide end-to-end security

### 4. Replay Attack
**Attack:** Attacker captures and replays old certificate

**Defense:**
- Certificates have expiration timestamps
- Expired certificates rejected during verification
- Fresh registration required periodically

### 5. Compromised Agent
**Attack:** One agent is compromised and tries to attack others

**Defense:**
- Compromised agent can only present its own valid certificate
- Cannot forge other agents' certificates
- Cannot forge controller signatures
- Can be revoked by controller (future: revocation lists)

## Implementation Checklist

### Agent Class Modifications

- [ ] Add `my_certificate` storage
- [ ] Add `trusted_peers` dictionary
- [ ] Store certificate after successful registration
- [ ] Implement `verify_peer_certificate()` method
- [ ] Implement `authenticate_peer()` method

### Flask Application Updates

- [ ] Add `GET /agent/certificate` endpoint
- [ ] Return stored certificate or 404
- [ ] Add CORS headers if needed

### CLI Commands (Optional)

- [ ] `discover <peer_address>` - Authenticate peer
- [ ] `peers` - List trusted peers
- [ ] `verify <peer_address>` - Re-verify peer certificate

## Testing

### Setup
```bash
# All three services running and registered
# (Controller, Traveller, Helper)
```

### Test Certificate Retrieval
```bash
# PowerShell
Invoke-RestMethod -Uri https://localhost:5002/agent/certificate -SkipCertificateCheck
Invoke-RestMethod -Uri https://localhost:5001/agent/certificate -SkipCertificateCheck
```

### Test Peer Authentication
```python
# In Python REPL or test script
import requests
import urllib3
urllib3.disable_warnings()

# Traveller authenticates Helper
response = requests.get(
    "https://localhost:5001/agent/certificate",
    verify=False
)
helper_cert = response.json()

# Verify helper_cert contains:
# - agent_card
# - agent_signature
# - controller_signature
# - certificate_issued_at
# - certificate_expires_at
```

## Usage Example

```python
# Traveller wants to communicate with Helper
traveller = TravellerAgent()

# Step 1: Authenticate Helper
success, message, helper_info = traveller.authenticate_peer("https://localhost:5001")

if success:
    print(f"✓ Helper authenticated: {helper_info['name']}")
    print(f"  Methods: {helper_info['methods']}")
    print(f"  Verified at: {helper_info['verified_at']}")
    
    # Step 2: Now safe to communicate with Helper
    # (Phase 3: Establish encrypted session)
else:
    print(f"✗ Authentication failed: {message}")
```

## Next Phase

**Phase 3: Secure Communication & Encrypted Handshake**

With Phase 2 complete, agents can now:
- ✓ Discover peers
- ✓ Exchange certificates
- ✓ Verify peer authenticity
- ✓ Establish mutual trust

Phase 3 will implement:
- Encrypted session establishment
- Secure message exchange
- Session key negotiation
- Encrypted three-way handshake

See: [PHASE_3_SECURE_COMMUNICATION.md](PHASE_3_SECURE_COMMUNICATION.md)
