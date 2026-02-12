# Phase 1: Agent Registration & Trust Establishment

## Overview

Phase 1 establishes the foundational trust infrastructure for the Agent-to-Agent (A2A) protocol. This phase implements a Public Key Infrastructure (PKI) where the Controller acts as a Certificate Authority (CA), validating agents and issuing signed certificates that enable secure peer-to-peer communication.

## Architecture

```
┌─────────────────────────────────────────────┐
│         CONTROLLER (Trust Anchor)           │
│  ┌──────────────────────────────────────┐  │
│  │  RSA 2048-bit Key Pair               │  │
│  │  - controller_private_key (secret)   │  │
│  │  - controller_public_key (published) │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  Functions:                                 │
│  • Validate agent identity                  │
│  • Verify agent signatures                  │
│  • Issue signed certificates                │
│  • Publish public key                       │
└─────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────▼────────┐    ┌────────▼────────┐
│  TRAVELLER     │    │    HELPER       │
│    AGENT       │    │    AGENT        │
│                │    │                 │
│  • Generate    │    │  • Generate     │
│    RSA keys    │    │    RSA keys     │
│  • Create card │    │  • Create card  │
│  • Sign card   │    │  • Sign card    │
│  • Register    │    │  • Register     │
│  • Get cert    │    │  • Get cert     │
└────────────────┘    └─────────────────┘
```

## Components

### 1. Controller (Trust Anchor)

**Location:** `A2AControlServer/routes/verify_validate_agent.py`

**Responsibilities:**
- Generate and maintain controller RSA key pair
- Expose public key at `/verify/public-key` endpoint
- Validate agent registration requests
- Issue signed certificates
- Track used nonces to prevent replay attacks

**Key Endpoints:**

#### `GET /verify/public-key`
Exposes controller's public key for agents to establish trust anchor.

**Response:**
```json
{
  "key_id": "controller_001",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "public_key_oneline": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
  "issued_at": 1770888835
}
```

#### `POST /verify/register`
Validates agent identity and issues signed certificate.

**Request:**
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
  "agent_signature": "base64_encoded_signature",
  "nonce": "64_char_hex_string",
  "timestamp": 1770888800
}
```

**Validation Steps:**
1. ✓ Check registration version is supported (version 1)
2. ✓ Verify nonce is unique (not previously used)
3. ✓ Validate timestamp freshness (within 5-minute window)
4. ✓ Check agent_id uniqueness (not already registered)
5. ✓ Verify agent_card hasn't expired
6. ✓ Cryptographically verify agent's signature using their public key
7. ✓ Track nonce to prevent replay attacks

**Response (Success - 200):**
```json
{
  "registration_version": 1,
  "agent_card": {...},
  "agent_signature": "...",
  "controller_signature": "base64_encoded_controller_signature",
  "certificate_issued_at": 1770888835,
  "certificate_expires_at": 1770975235,
  "nonce": "..."
}
```

**Response (Error - 400/409):**
```json
{
  "error": "Descriptive error message"
}
```

#### `POST /verify/reset`
Development/testing endpoint to clear registered agents.

**Response:**
```json
{
  "status": "success",
  "message": "Agent database reset",
  "cleared_agents": 2,
  "cleared_nonces": 5,
  "timestamp": 1770888900
}
```

#### `GET /verify/cards`
Lists all registered agent certificates.

### 2. Agent (Traveller/Helper)

**Location:** 
- `A2ATraveller/routes/register_agent.py`
- `A2AHelper/routes/register_agent.py`

**Responsibilities:**
- Generate RSA key pair at initialization
- Create agent card with identity and capabilities
- Sign agent card cryptographically
- Download controller's public key (trust anchor)
- Register with controller
- Verify controller's signature on certificate

## Cryptographic Details

### Key Generation
```python
# Both Controller and Agents use RSA 2048-bit keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
```

### Signing Algorithm
**Algorithm:** RSA-PSS (Probabilistic Signature Scheme)
**Hash:** SHA-256
**Salt Length:** Maximum allowable (PSS.MAX_LENGTH)

```python
signature = private_key.sign(
    data_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

### Canonical JSON Serialization
Critical for signature consistency across systems.

```python
def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,          # Alphabetical key ordering
        separators=(",", ":")    # No whitespace
    ).encode()
```

**Example:**
```json
{"agent_id":"traveller_agent_001","expires_at":1770892400,"issued_at":1770888800}
```

### Nonce Generation
256-bit cryptographically secure random nonces prevent replay attacks.

```python
nonce = secrets.token_hex(32)  # 64 hex characters
```

## Registration Flow

### Step-by-Step Process

```
┌─────────┐                                    ┌────────────┐
│  Agent  │                                    │ Controller │
└────┬────┘                                    └─────┬──────┘
     │                                               │
     │ 1. trust                                      │
     ├──────────GET /verify/public-key──────────────>│
     │                                               │
     │<───────── Controller's Public Key ────────────┤
     │          (Trust Anchor Established)           │
     │                                               │
     │ 2. register                                   │
     │                                               │
     │  Generate nonce + timestamp                   │
     │  Sign agent_card                              │
     │                                               │
     ├───────POST /verify/register───────────────────>│
     │  {                                            │
     │    registration_version: 1,                   │
     │    agent_card: {...},                         │
     │    agent_signature: "...",                    │
     │    nonce: "...",                              │
     │    timestamp: 1770888800                      │
     │  }                                            │
     │                                               │
     │                                    Validate:  │
     │                               ✓ Version       │
     │                               ✓ Nonce unique  │
     │                               ✓ Timestamp     │
     │                               ✓ Agent ID      │
     │                               ✓ Not expired   │
     │                               ✓ Signature     │
     │                                               │
     │                               Issue Certificate
     │                               Sign with controller_private
     │                                               │
     │<────── Certificate with Controller Sig ───────┤
     │  {                                            │
     │    agent_card: {...},                         │
     │    agent_signature: "...",                    │
     │    controller_signature: "...", <<<<<<        │
     │    certificate_issued_at: 1770888835,         │
     │    certificate_expires_at: 1770975235         │
     │  }                                            │
     │                                               │
     │  Verify controller_signature                  │
     │  using controller_public_key                  │
     │  ✓ Cryptographic verification PASSED          │
     │  ✓ Bidirectional Trust Established            │
     │                                               │
```

### CLI Commands

**Traveller Agent:**
```bash
traveller_1> help
Commands: help | status | trust | register | exit

traveller_1> status
Agent: traveller_agent_001, Port: 5002, Status: Active
Trust Anchor: ✗ Not established

traveller_1> trust
Establishing trust with controller at https://localhost:5000...
[INFO] Downloading controller public key from https://localhost:5000...
[INFO] ✓ Controller public key loaded successfully
[INFO] Key ID: controller_001
[INFO] Trust anchor established
✓ Controller public key loaded

traveller_1> status
Agent: traveller_agent_001, Port: 5002, Status: Active
Trust Anchor: ✓ Established

traveller_1> register
Registering agent with controller at https://localhost:5000...
[INFO] Certificate received from controller

[DEBUG] ═══════════════════════════════════════════════════
[DEBUG] Starting Controller Signature Verification
[DEBUG] ═══════════════════════════════════════════════════
[DEBUG] ✓ Controller public key is loaded
[DEBUG] Agent ID in certificate: traveller_agent_001
[DEBUG] Certificate issued at: 1770888835
[DEBUG] Certificate expires at: 1770975235
[DEBUG] Controller signature (first 50 chars): YNVrUGyV...
[DEBUG] Canonical JSON size: 795 bytes
[DEBUG] Verifying controller's RSA-PSS signature...
[DEBUG] ✓ Cryptographic verification PASSED
[DEBUG] ✓ Controller signature is valid
[DEBUG] ✓ Certificate authenticity confirmed
[DEBUG] ✓ Issued by trusted controller
[DEBUG] ═══════════════════════════════════════════════════
[DEBUG] Bidirectional Trust Established (Agent ↔ Controller)
[DEBUG] ═══════════════════════════════════════════════════

[INFO] ✓ Controller signature verified successfully
✓ Registration successful!
```

## Security Properties

### 1. Mutual Authentication
- **Agent → Controller:** Agent proves ownership of private key by signing agent_card
- **Controller → Agent:** Controller proves authenticity by signing certificate with controller_private_key

### 2. Non-Repudiation
- Agent signatures prove agent created and endorsed their identity
- Controller signatures prove controller validated and issued certificate
- All signatures are cryptographically verifiable

### 3. Replay Attack Prevention
- Unique nonces tracked by controller
- Timestamp freshness validation (5-minute window)
- Nonces never reused

### 4. Certificate Tampering Detection
- Any modification to agent_card breaks both signatures
- Agents verify controller signature before trusting certificate
- Canonical JSON ensures consistent serialization

### 5. Trust Anchor Security
- Controller's private key never leaves controller
- Controller's public key distributed securely
- Agents verify all certificates using trusted controller_public_key

### 6. Time-Bound Validity
- Agent cards expire after 1 hour
- Certificates expire after 24 hours
- Fresh registration required after expiry

## Implementation Files

### Controller
- `A2AControlServer/routes/verify_validate_agent.py` - Registration logic
- `A2AControlServer/server.py` - Flask application

### Traveller Agent
- `A2ATraveller/routes/register_agent.py` - TravellerAgent class
- `A2ATraveller/traveller.py` - CLI and Flask app

### Helper Agent
- `A2AHelper/routes/register_agent.py` - HelperAgent class
- `A2AHelper/helper.py` - CLI and Flask app

## Testing

### Start Services
```bash
# Terminal 1 - Controller
cd A2AControlServer
.\venv\Scripts\Activate.ps1
python server.py

# Terminal 2 - Traveller
cd A2ATraveller
.\venv\Scripts\Activate.ps1
python traveller.py

# Terminal 3 - Helper
cd A2AHelper
.\venv\Scripts\Activate.ps1
python helper.py
```

### Test Registration Flow
```bash
# In Traveller CLI
traveller_1> trust
traveller_1> register

# In Helper CLI
helper_1> trust
helper_1> register
```

### Reset Database (Development)
```powershell
Invoke-RestMethod -Uri https://localhost:5000/verify/reset -Method POST -SkipCertificateCheck
```

## Next Phase

**Phase 2: Agent-to-Agent Discovery & Certificate Exchange**

With Phase 1 complete, agents now have:
- ✓ Validated identities
- ✓ Controller-signed certificates
- ✓ Trust anchor established

Phase 2 will enable:
- Agents discovering each other
- Exchanging certificates
- Verifying peer authenticity using controller signatures
- Establishing peer-to-peer trust

See: [PHASE_2_AGENT_DISCOVERY.md](PHASE_2_AGENT_DISCOVERY.md)
