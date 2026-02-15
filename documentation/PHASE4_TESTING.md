# Phase 4 Testing Guide

## Manual Testing Instructions

### Prerequisites
1. **Start all services:**
   ```bash
   cd "C:\Users\adity\OneDrive\Desktop\All Folders\Git projects\EncryptedA2AProtocol"
   .\start_all.bat
   ```

2. **Register both agents** (if not already done):
   - In Traveller terminal: `setup`
   - In Helper terminal: `setup`

---

## Test 1: Basic Communication Request Flow

### Step 1: Open Two Terminals

**Terminal 1 - Traveller:**
```bash
cd A2ATraveller
# Should already be running from start_all.bat
```

**Terminal 2 - Helper:**
```bash
cd A2AHelper  
# Should already be running from start_all.bat
```

### Step 2: Test Using Python (In Traveller Terminal)

After you see the `traveller_agent_001>` prompt, test the request:

```python
# In Traveller's Python console (after starting traveller.py):
traveller_agent_001> cards
# Note Helper's address (should be https://localhost:5001)

# Now switch to Python to test the method directly:
# Press Ctrl+C to stop the CLI, then run Python:
python

>>> from routes.traveller_agent import TravellerAgent
>>> agent = TravellerAgent()
>>> 
>>> # Setup agent
>>> agent.download_controller_public_key("https://localhost:5000")
>>> agent.register_with_controller("https://localhost:5000")
>>>
>>> # Send request
>>> success, result = agent.send_communication_request("https://localhost:5001", "helper_agent_001")
```

### Step 3: Watch Helper Terminal

In Helper's terminal, you should immediately see:

```
============================================================
[!] INCOMING COMMUNICATION REQUEST
From: traveller_agent_001
============================================================
Accept communication request? (y/n): 
```

### Step 4: Accept the Request

Type `y` in Helper's terminal:
```
Accept communication request? (y/n): y
[INFO] Request accepted. Waiting for secure channel setup...
```

### Step 5: Verify Traveller Gets Response

In Traveller's Python console, you should see:
```python
>>> success, result = agent.send_communication_request("https://localhost:5001", "helper_agent_001")
[INFO] Sending communication request to helper_agent_001...
[INFO] ✓ Response signature verified
[INFO] ✓ Request accepted! Session ID: a1b2c3d4-...

>>> print(f"Success: {success}, Session ID: {result}")
Success: True, Session ID: a1b2c3d4-e5f6-...
```

---

## Test 2: Request Rejection

### Repeat Test 1, but this time:

In Helper's terminal, type `n` to reject:
```
Accept communication request? (y/n): n
[INFO] Request rejected.
```

Traveller should receive:
```python
>>> success, result = agent.send_communication_request("https://localhost:5001", "helper_agent_001")
[INFO] Sending communication request to helper_agent_001...

>>> print(f"Success: {success}, Result: {result}")
Success: False, Result: Request was rejected by peer
```

---

## Test 3: Automated Test Suite

Run the comprehensive test script:

```bash
cd A2ATraveller
python test_phase4.py
```

**What the test does:**
1. ✓ Tests certificate fetching (automatic)
2. ✓ Tests missing fields validation (automatic)
3. ✓ Tests timestamp validation (automatic)
4. ⚠️  Tests direct endpoint (requires you to accept in Helper CLI)
5. ⚠️  Tests agent method (requires you to accept in Helper CLI)

**During the test:**
- Test will pause and prompt you to press Enter
- Switch to Helper's terminal
- Accept the incoming request when prompted
- Switch back to test terminal and press Enter

---

## Test 4: Endpoint Testing with curl

Test the endpoint directly using curl:

```bash
# Generate a test request (you'll need valid signature)
curl -X POST https://localhost:5001/agent/communicate/request \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "test-123",
    "agent_id": "traveller_agent_001", 
    "timestamp": 1739577600,
    "signature": "base64_signature_here"
  }' \
  --insecure
```

**Expected response (if rejected):**
```json
{
  "accepted": false,
  "reason": "Request timed out or was rejected"
}
```

**Expected response (if accepted):**
```json
{
  "accepted": true,
  "session_id": "uuid-here",
  "timestamp": 1739577601,
  "signature": "base64_signature"
}
```

---

## Test 5: Verify Signatures

### Test Request Signature Verification:

```python
from routes.traveller_agent import TravellerAgent
import base64, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

agent = TravellerAgent()

# Create and sign a request
import uuid
request_payload = {
    "request_id": str(uuid.uuid4()),
    "agent_id": agent.agent_id,
    "timestamp": int(time.time())
}

payload_bytes = agent.canonical_json(request_payload)
signature = agent.private_key.sign(
    payload_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify signature
try:
    agent.public_key.verify(
        signature,
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✓ Signature valid")
except:
    print("✗ Signature invalid")
```

---

## Test 6: Timeout Testing

### Test that endpoint times out after 60 seconds:

1. Send a request from Traveller
2. **Don't accept or reject** in Helper's terminal
3. Wait 60 seconds
4. Traveller should receive timeout error

```python
>>> success, result = agent.send_communication_request("https://localhost:5001", "helper_agent_001")
# Wait 60+ seconds without responding in Helper...

>>> print(f"Success: {success}, Result: {result}")
Success: False, Result: Request was rejected by peer
```

---

## Test 7: Invalid Timestamp

Test that old timestamps are rejected:

```python
import requests, time

# Request with 10-minute-old timestamp
old_request = {
    "request_id": "test-old",
    "agent_id": "traveller_agent_001",
    "timestamp": int(time.time()) - 600,  # 10 minutes ago
    "signature": "dummy"
}

response = requests.post(
    "https://localhost:5001/agent/communicate/request",
    json=old_request,
    verify=False,
    timeout=5
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
# Expected: {"error": "Request timestamp expired"}
```

---

## Expected Outputs Summary

### ✅ Successful Request Flow:

**Traveller output:**
```
[INFO] Sending communication request to helper_agent_001...
[INFO] ✓ Response signature verified
[INFO] ✓ Request accepted! Session ID: abc123...
```

**Helper output:**
```
[INCOMING] Communication request from traveller_agent_001

============================================================
[!] INCOMING COMMUNICATION REQUEST
From: traveller_agent_001
============================================================
Accept communication request? (y/n): y
[INFO] Request accepted. Waiting for secure channel setup...
[INFO] Communication request accepted. Session: abc123...
```

### ❌ Rejected Request:

**Helper output:**
```
Accept communication request? (y/n): n
[INFO] Request rejected.
```

**Traveller output:**
```
Success: False, Result: Request was rejected by peer
```

### ⏱️ Timeout (60 seconds):

**Helper output:**
```
(No response given for 60 seconds)
```

**Traveller output:**
```
Success: False, Result: Request was rejected by peer
```

---

## Troubleshooting

### Issue: "Cannot connect to peer"
- Verify Helper is running on port 5001
- Check firewall isn't blocking connections
- Verify URL is exactly `https://localhost:5001`

### Issue: "Certificate not yet issued"
- Run `setup` command in both agents
- Verify controller is running
- Check agent registration succeeded

### Issue: Request not showing in Helper CLI
- Verify Flask is running (should see "Running on https://0.0.0.0:5001")
- Check the pending_requests queue isn't full
- Verify threading is working (Flask runs in daemon thread)

### Issue: Signature verification failed
- Ensure both agents are registered
- Verify certificates haven't expired
- Check controller signature is valid

---

## Success Criteria

Phase 4 is working correctly if:

- ✅ Traveller can send requests to Helper
- ✅ Helper receives notification in CLI
- ✅ User can accept/reject requests
- ✅ Acceptance creates session with valid session_id
- ✅ Response signatures are verified
- ✅ Old timestamps are rejected (>5 minutes)
- ✅ Missing fields return 400 error
- ✅ Timeout works after 60 seconds
- ✅ Both agents track session state

**All tests passing = Ready for Phase 5 (Key Exchange)! 🎉**
