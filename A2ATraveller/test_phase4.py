"""
Phase 4 Integration Test: Communication Request Flow

Tests the endpoints and flow without importing agent classes (avoids import issues).

Tests:
1. POST /agent/communicate/request endpoint
2. Timestamp validation
3. Missing fields validation
4. Certificate fetching

Prerequisites:
- Controller running on port 5000
- Traveller running on port 5002  
- Helper running on port 5001
- Both agents registered (have certificates)
"""

import time
import uuid
import requests

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Agent addresses
TRAVELLER_URL = "https://localhost:5002"
HELPER_URL = "https://localhost:5001"
HELPER_AGENT_ID = "helper_agent_001"
TRAVELLER_AGENT_ID = "traveller_agent_001"


def check_services():
    """Verify all services are running"""
    print("\n" + "="*60)
    print("PHASE 4 TEST: Communication Request Flow")
    print("="*60)
    
    print("\n[1] Checking services...")
    services = {
        "Traveller": f"{TRAVELLER_URL}/health",
        "Helper": f"{HELPER_URL}/health"
    }
    
    all_running = True
    for name, url in services.items():
        try:
            response = requests.get(url, verify=False, timeout=2)
            if response.status_code == 200:
                print(f"  ✓ {name} is running")
            else:
                print(f"  ✗ {name} responded with status {response.status_code}")
                all_running = False
        except Exception as e:
            print(f"  ✗ {name} is not reachable: {e}")
            all_running = False
    
    return all_running


def test_certificate_fetch():
    """Test that certificates can be fetched"""
    print("\n" + "="*60)
    print("TEST 1: Certificate Fetching")
    print("="*60)
    
    try:
        print("\n[1] Fetching Helper's certificate...")
        
        response = requests.get(
            f"{HELPER_URL}/agent/certificate",
            verify=False,
            timeout=5
        )
        
        if response.status_code == 200:
            cert_data = response.json()
            agent_id = cert_data.get('agent_card', {}).get('agent_id')
            print(f"✓ Certificate fetched successfully")
            print(f"  Agent ID: {agent_id}")
            print(f"  Has agent_card: {'agent_card' in cert_data}")
            print(f"  Has controller_signature: {'controller_signature' in cert_data}")
            return True
        elif response.status_code == 404:
            print(f"✗ Helper not registered")
            print(f"  Run 'setup' in Helper's CLI")
            return False
        else:
            print(f"✗ Failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_missing_fields():
    """Test that requests with missing fields are rejected"""
    print("\n" + "="*60)
    print("TEST 2: Missing Fields Validation")
    print("="*60)
    
    try:
        print("\n[1] Sending request without signature field...")
        
        request_payload = {
            "request_id": "test-123",
            "agent_id": TRAVELLER_AGENT_ID,
            "timestamp": int(time.time())
            # Missing "signature" field
        }
        
        response = requests.post(
            f"{HELPER_URL}/agent/communicate/request",
            json=request_payload,
            verify=False,
            timeout=5
        )
        
        if response.status_code == 400:
            error = response.json().get('error', '')
            if 'missing' in error.lower() or 'required' in error.lower():
                print(f"✓ Missing fields correctly rejected")
                print(f"  Error: {error}")
                return True
            else:
                print(f"✗ Wrong error: {error}")
                return False
        else:
            print(f"✗ Expected 400, got {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_timestamp_validation():
    """Test that expired timestamps are rejected"""
    print("\n" + "="*60)
    print("TEST 3: Timestamp Validation")
    print("="*60)
    
    try:
        print("\n[1] Sending request with expired timestamp...")
        
        # Timestamp from 10 minutes ago
        expired_timestamp = int(time.time()) - 600
        
        request_payload = {
            "request_id": str(uuid.uuid4()),
            "agent_id": TRAVELLER_AGENT_ID,
            "timestamp": expired_timestamp,
            "signature": "dummy"
        }
        
        print(f"  Timestamp: {expired_timestamp} (current: {int(time.time())})")
        
        response = requests.post(
            f"{HELPER_URL}/agent/communicate/request",
            json=request_payload,
            verify=False,
            timeout=5
        )
        
        if response.status_code == 400:
            error = response.json().get('error', '')
            if 'expired' in error.lower() or 'timestamp' in error.lower():
                print(f"✓ Expired timestamp rejected")
                print(f"  Error: {error}")
                return True
            else:
                print(f"✗ Wrong error: {error}")
                return False
        else:
            print(f"✗ Expected 400, got {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_endpoint_manual():
    """Test endpoint with user acceptance (manual)"""
    print("\n" + "="*60)
    print("TEST 4: Endpoint with User Acceptance (Manual)")
    print("="*60)
    
    print("""
⚠️  MANUAL TEST - This requires interaction

INSTRUCTIONS:
1. The test will send a request to Helper 
2. Go to Helper's CLI terminal
3. You should see: "[!] INCOMING COMMUNICATION REQUEST"
4. Type 'y' to accept the request
5. Come back here

""")
    
    input("Press Enter when ready to send request...")
    
    try:
        print("\n[1] Sending communication request...")
        
        request_payload = {
            "request_id": str(uuid.uuid4()),
            "agent_id": TRAVELLER_AGENT_ID,
            "timestamp": int(time.time()),
            "signature": "test_signature"
        }
        
        print("  Waiting for Helper to accept (60s timeout)...")
        
        response = requests.post(
            f"{HELPER_URL}/agent/communicate/request",
            json=request_payload,
            verify=False,
            timeout=65
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('accepted'):
                print(f"✓ Request accepted!")
                print(f"  Session ID: {data.get('session_id')}")
                return True
            else:
                print(f"✗ Request rejected")
                return False
        else:
            print(f"✗ Failed: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"✗ Timeout (user didn't respond)")
        return False
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_cli_method():
    """Test the CLI method (manual verification)"""
    print("\n" + "="*60)
    print("TEST 5: CLI Method Testing (Manual)")
    print("="*60)
    
    print("""
⚠️  MANUAL TEST - Test send_communication_request() method

INSTRUCTIONS:
1. Open a new terminal in: A2ATraveller
2. Run: python
3. Execute these commands:

from routes.traveller_agent import TravellerAgent
agent = TravellerAgent()
agent.download_controller_public_key("https://localhost:5000")
agent.register_with_controller("https://localhost:5000")
success, result = agent.send_communication_request("https://localhost:5001", "helper_agent_001")
print(f"Success: {success}, Session: {result}")

4. Accept the request in Helper's CLI
5. Verify Traveller shows success with session ID

""")
    
    response = input("Did the test succeed? (y/n): ").strip().lower()
    
    if response in ['y', 'yes']:
        print("✓ CLI method test PASSED")
        return True
    else:
        print("✗ CLI method test FAILED")
        return False


def run_all_tests():
    """Run complete test suite"""
    print("\n" + "="*70)
    print("PHASE 4 INTEGRATION TEST SUITE")
    print("="*70)
    
    if not check_services():
        print("\n❌ Services check failed!")
        return
    
    results = []
    
    # Automated tests
    results.append(("Certificate Fetching", test_certificate_fetch()))
    results.append(("Missing Fields Validation", test_missing_fields()))
    results.append(("Timestamp Validation", test_timestamp_validation()))
    
    # Manual tests
    print("\n" + "="*70)
    print("MANUAL TESTS - User interaction required")
    print("="*70)
    
    results.append(("Endpoint with Acceptance", test_endpoint_manual()))
    results.append(("CLI Method Test", test_cli_method()))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "="*70)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED!")
    else:
        print(f"⚠️  {total - passed} test(s) failed.")
    print("="*70 + "\n")


if __name__ == "__main__":
    print("""
======================================================================
PHASE 4 TESTING
======================================================================

This tests the Communication Request Flow:
- Certificate fetching
- Input validation  
- Timestamp validation
- User acceptance flow
- CLI integration

Automated tests run first, then manual tests that require you to
accept requests in Helper's CLI.

Starting in 2 seconds...
    """)
    
    time.sleep(2)
    run_all_tests()
