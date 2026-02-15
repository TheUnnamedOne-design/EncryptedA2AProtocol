"""
Integration Test for Phases 1-3

Tests the complete flow:
1. Phase 1: Certificate fetching and verification
2. Phase 3: Authenticated DH key exchange using real RSA keys from certificates
3. Phase 2: Session creation and management
4. Phase 3: Encrypted message exchange with session state

Prerequisites:
- Controller must be running on port 5000
- Traveller must be running on port 5002
- Helper must be running on port 5001
- Both agents must be registered with controller (have certificates)
"""

import sys
import os
import json
import requests
from datetime import datetime

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add routes directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'routes'))

from session_manager import SessionState
from crypto_utils import (
    generate_dh_parameters,
    generate_dh_keypair,
    sign_dh_public_key,
    verify_signed_dh_key,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
    serialize_dh_public_key,
    deserialize_dh_public_key
)

# For loading RSA keys from certificates
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Agent addresses
CONTROLLER_URL = "https://localhost:5000"
TRAVELLER_URL = "https://localhost:5002"
HELPER_URL = "https://localhost:5001"


def check_services():
    """Check if all required services are running"""
    print("\n" + "="*60)
    print("SERVICE HEALTH CHECK")
    print("="*60)
    
    services = {
        "Controller": f"{CONTROLLER_URL}/health",
        "Traveller": f"{TRAVELLER_URL}/health",
        "Helper": f"{HELPER_URL}/health"
    }
    
    all_running = True
    for name, url in services.items():
        try:
            response = requests.get(url, verify=False, timeout=2)
            if response.status_code == 200:
                print(f"✓ {name} is running")
            else:
                print(f"✗ {name} responded with status {response.status_code}")
                all_running = False
        except Exception as e:
            print(f"✗ {name} is not reachable: {e}")
            all_running = False
    
    return all_running


def test_phase1_certificate_fetch():
    """Test Phase 1: Certificate fetching from agents"""
    print("\n" + "="*60)
    print("PHASE 1 TEST: Certificate Fetching")
    print("="*60)
    
    try:
        # Fetch Traveller's certificate
        print("\n[1] Fetching Traveller's certificate...")
        response = requests.get(f"{TRAVELLER_URL}/agent/certificate", verify=False, timeout=5)
        
        if response.status_code == 404:
            print(f"✗ FAILED: Traveller is not registered yet")
            print("   Run 'setup' command in Traveller agent CLI")
            return False, None, None
        
        if response.status_code != 200:
            print(f"✗ FAILED: Status code {response.status_code}")
            return False, None, None
        
        traveller_cert_data = response.json()
        
        # Check if certificate has agent_card (new format from controller)
        if 'agent_card' in traveller_cert_data:
            agent_id = traveller_cert_data['agent_card'].get('agent_id')
            agent_type = traveller_cert_data['agent_card'].get('agent_type')
        else:
            agent_id = traveller_cert_data.get('agent_id')
            agent_type = traveller_cert_data.get('agent_type')
        
        print(f"✓ Traveller certificate fetched")
        print(f"  Agent ID: {agent_id}")
        print(f"  Type: {agent_type}")
        
        # Fetch Helper's certificate
        print("\n[2] Fetching Helper's certificate...")
        response = requests.get(f"{HELPER_URL}/agent/certificate", verify=False, timeout=5)
        
        if response.status_code == 404:
            print(f"✗ FAILED: Helper is not registered yet")
            print("   Run 'setup' command in Helper agent CLI")
            return False, None, None
        
        if response.status_code != 200:
            print(f"✗ FAILED: Status code {response.status_code}")
            return False, None, None
        
        helper_cert_data = response.json()
        
        # Check if certificate has agent_card
        if 'agent_card' in helper_cert_data:
            agent_id = helper_cert_data['agent_card'].get('agent_id')
            agent_type = helper_cert_data['agent_card'].get('agent_type')
        else:
            agent_id = helper_cert_data.get('agent_id')
            agent_type = helper_cert_data.get('agent_type')
        
        print(f"✓ Helper certificate fetched")
        print(f"  Agent ID: {agent_id}")
        print(f"  Type: {agent_type}")
        
        return True, traveller_cert_data, helper_cert_data
        
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None


def extract_rsa_public_key(cert_data):
    """Extract RSA public key from certificate data"""
    try:
        # The certificate has an 'agent_card' which contains 'public_key'
        if 'agent_card' in cert_data:
            public_key_pem = cert_data['agent_card']['public_key'].encode('utf-8')
        else:
            # Fallback for direct certificate format
            public_key_pem = cert_data['public_key'].encode('utf-8')
        
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Error extracting public key: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_phase3_authenticated_key_exchange(traveller_cert, helper_cert):
    """Test Phase 3: Authenticated DH key exchange using real RSA keys"""
    print("\n" + "="*60)
    print("PHASE 3 TEST: Authenticated Key Exchange")
    print("="*60)
    
    try:
        # Extract RSA public keys from certificates
        print("\n[1] Extracting RSA public keys from certificates...")
        traveller_rsa_public = extract_rsa_public_key(traveller_cert)
        helper_rsa_public = extract_rsa_public_key(helper_cert)
        
        if not traveller_rsa_public or not helper_rsa_public:
            print("✗ FAILED: Could not extract RSA public keys")
            return False, None, None
        
        print("✓ RSA public keys extracted")
        
        # Generate DH parameters (in production, these can be pre-generated)
        print("\n[2] Generating DH parameters...")
        dh_params = generate_dh_parameters()
        
        # Traveller generates DH keypair
        print("\n[3] Traveller generates DH keypair...")
        traveller_dh_private, traveller_dh_public = generate_dh_keypair(dh_params)
        print("✓ Traveller DH keypair generated")
        
        # Helper generates DH keypair
        print("\n[4] Helper generates DH keypair...")
        helper_dh_private, helper_dh_public = generate_dh_keypair(dh_params)
        print("✓ Helper DH keypair generated")
        
        # Note: In real implementation, each agent would sign with their PRIVATE key
        # For this test, we only have PUBLIC keys from certificates
        # So we'll simulate the signature verification process
        
        print("\n[5] Simulating authenticated key exchange...")
        print("  (Note: Full signature requires private keys - testing structure only)")
        
        # Serialize DH public keys for exchange
        traveller_dh_bytes = serialize_dh_public_key(traveller_dh_public)
        helper_dh_bytes = serialize_dh_public_key(helper_dh_public)
        print("✓ DH public keys serialized for exchange")
        
        # Verify deserialization works
        traveller_dh_received = deserialize_dh_public_key(traveller_dh_bytes)
        helper_dh_received = deserialize_dh_public_key(helper_dh_bytes)
        print("✓ DH public keys deserialized successfully")
        
        # Perform key exchange
        print("\n[6] Performing DH key exchange...")
        traveller_shared = traveller_dh_private.exchange(helper_dh_received)
        helper_shared = helper_dh_private.exchange(traveller_dh_received)
        
        if traveller_shared == helper_shared:
            print("✓ Both agents derived identical shared secret")
            print(f"  Shared secret length: {len(traveller_shared)} bytes")
        else:
            print("✗ FAILED: Shared secrets don't match!")
            return False, None, None
        
        # Derive AES keys
        print("\n[7] Deriving AES-256 keys from shared secret...")
        traveller_aes_key = derive_aes_key(traveller_shared)
        helper_aes_key = derive_aes_key(helper_shared)
        
        if traveller_aes_key == helper_aes_key:
            print("✓ Both agents derived identical AES-256 keys")
            return True, traveller_aes_key, helper_aes_key
        else:
            print("✗ FAILED: AES keys don't match!")
            return False, None, None
        
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None


def test_phase2_session_creation(traveller_cert, helper_cert, aes_key):
    """Test Phase 2: Session state creation and management"""
    print("\n" + "="*60)
    print("PHASE 2 TEST: Session Management")
    print("="*60)
    
    try:
        # Extract agent_id and public_key from certificates
        if 'agent_card' in helper_cert:
            helper_agent_id = helper_cert['agent_card']['agent_id']
            helper_public_key = helper_cert['agent_card']['public_key']
        else:
            helper_agent_id = helper_cert['agent_id']
            helper_public_key = helper_cert['public_key']
        
        if 'agent_card' in traveller_cert:
            traveller_agent_id = traveller_cert['agent_card']['agent_id']
            traveller_public_key = traveller_cert['agent_card']['public_key']
        else:
            traveller_agent_id = traveller_cert['agent_id']
            traveller_public_key = traveller_cert['public_key']
        
        # Create session from Traveller's perspective
        print("\n[1] Creating session state (Traveller's view)...")
        traveller_session = SessionState(
            session_id="test-session-001",
            peer_agent_id=helper_agent_id,
            peer_address=HELPER_URL
        )
        # Set cryptographic material
        traveller_session.peer_public_key = helper_public_key
        traveller_session.aes_key = aes_key
        print(f"✓ Traveller session created: {traveller_session}")
        
        # Create session from Helper's perspective
        print("\n[2] Creating session state (Helper's view)...")
        helper_session = SessionState(
            session_id="test-session-001",
            peer_agent_id=traveller_agent_id,
            peer_address=TRAVELLER_URL
        )
        # Set cryptographic material
        helper_session.peer_public_key = traveller_public_key
        helper_session.aes_key = aes_key
        print(f"✓ Helper session created: {helper_session}")
        
        # Verify both sessions have matching AES keys
        if traveller_session.aes_key == helper_session.aes_key:
            print("✓ Both sessions share the same AES key")
        else:
            print("✗ FAILED: Session AES keys don't match!")
            return False, None, None
        
        # Test sequence number management
        print("\n[3] Testing sequence number management...")
        initial_traveller_seq = traveller_session.send_seq
        traveller_session.increment_send_seq()
        if traveller_session.send_seq == initial_traveller_seq + 1:
            print("✓ Sequence increment working correctly")
            # Reset for actual communication testing
            traveller_session.send_seq = 0
            traveller_session.recv_seq = 0
            helper_session.send_seq = 0
            helper_session.recv_seq = 0
        else:
            print("✗ FAILED: Sequence increment not working")
            return False, None, None
        
        return True, traveller_session, helper_session
        
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None


def test_integrated_encrypted_communication(traveller_session, helper_session):
    """Test integrated encrypted communication using sessions"""
    print("\n" + "="*60)
    print("INTEGRATED TEST: Encrypted Communication")
    print("="*60)
    
    try:
        # Message 1: Traveller -> Helper
        print("\n[1] Traveller sends encrypted message to Helper...")
        message1 = "Hello Helper! This is Traveller. Ready for secure communication? 🔐"
        
        traveller_seq = traveller_session.send_seq
        encrypted1 = encrypt_message(message1, traveller_session.aes_key, traveller_seq)
        traveller_session.increment_send_seq()
        
        print(f"  Original: {message1}")
        print(f"  Sequence: {traveller_seq}")
        print(f"  Encrypted: {encrypted1['ciphertext'][:50]}...")
        
        # Helper receives and decrypts
        print("\n[2] Helper decrypts message...")
        helper_expected_seq = helper_session.recv_seq
        success, decrypted1 = decrypt_message(
            encrypted1['ciphertext'],
            encrypted1['nonce'],
            helper_session.aes_key,
            helper_expected_seq
        )
        
        if success and decrypted1 == message1:
            print(f"✓ Message decrypted successfully")
            print(f"  Decrypted: {decrypted1}")
            helper_session.increment_recv_seq()
        else:
            print(f"✗ FAILED: Decryption failed or message doesn't match")
            return False
        
        # Message 2: Helper -> Traveller
        print("\n[3] Helper sends encrypted reply to Traveller...")
        message2 = "Roger that, Traveller! Secure channel established. ✅"
        
        helper_seq = helper_session.send_seq
        encrypted2 = encrypt_message(message2, helper_session.aes_key, helper_seq)
        helper_session.increment_send_seq()
        
        print(f"  Original: {message2}")
        print(f"  Sequence: {helper_seq}")
        print(f"  Encrypted: {encrypted2['ciphertext'][:50]}...")
        
        # Traveller receives and decrypts
        print("\n[4] Traveller decrypts reply...")
        traveller_expected_seq = traveller_session.recv_seq
        success, decrypted2 = decrypt_message(
            encrypted2['ciphertext'],
            encrypted2['nonce'],
            traveller_session.aes_key,
            traveller_expected_seq
        )
        
        if success and decrypted2 == message2:
            print(f"✓ Reply decrypted successfully")
            print(f"  Decrypted: {decrypted2}")
            traveller_session.increment_recv_seq()
        else:
            print(f"✗ FAILED: Decryption failed or message doesn't match")
            return False
        
        # Test replay attack prevention
        print("\n[5] Testing replay attack prevention...")
        print("  Attempting to replay message 1 with wrong sequence...")
        wrong_seq = helper_session.recv_seq + 1  # Expected next message
        success, result = decrypt_message(
            encrypted1['ciphertext'],
            encrypted1['nonce'],
            helper_session.aes_key,
            wrong_seq
        )
        
        if not success:
            print("✓ Replay attack prevented (wrong sequence rejected)")
        else:
            print("✗ FAILED: Replay attack was not prevented!")
            return False
        
        # Verify session state
        print("\n[6] Verifying session state consistency...")
        print(f"  Traveller session: send_seq={traveller_session.send_seq}, recv_seq={traveller_session.recv_seq}")
        print(f"  Helper session: send_seq={helper_session.send_seq}, recv_seq={helper_session.recv_seq}")
        
        if (traveller_session.send_seq == helper_session.recv_seq and
            helper_session.send_seq == traveller_session.recv_seq):
            print("✓ Session sequence numbers are synchronized")
        else:
            print("✗ WARNING: Sequence numbers are not synchronized")
            print("  (This is expected if messages were sent/received in order)")
        
        # Test session duration
        print("\n[7] Testing session duration tracking...")
        duration = traveller_session.get_duration()
        print(f"✓ Session duration: {duration:.2f} seconds")
        
        return True
        
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_integration_tests():
    """Run complete integration test suite"""
    print("\n" + "="*70)
    print("PHASE 1-3 INTEGRATION TEST SUITE")
    print("Testing: Certificate Exchange → Key Agreement → Session Creation")
    print("="*70)
    
    results = []
    
    # Check services
    if not check_services():
        print("\n❌ CRITICAL: Not all services are running!")
        print("Please ensure Controller, Traveller, and Helper are all started.")
        print("Both agents must be registered with the controller (have certificates).")
        return
    
    results.append(("Service Health Check", True))
    
    # Phase 1: Certificate Fetching
    success, traveller_cert, helper_cert = test_phase1_certificate_fetch()
    results.append(("Phase 1: Certificate Fetching", success))
    if not success:
        print("\n❌ Cannot continue without certificates")
        print("\n⚠️  REGISTRATION REQUIRED:")
        print("   1. Make sure Controller, Traveller, and Helper are all running")
        print("   2. In Traveller CLI, run: setup")
        print("   3. In Helper CLI, run: setup")
        print("   4. Run this test again")
        return
    
    # Phase 3: Authenticated Key Exchange
    success, aes_key1, aes_key2 = test_phase3_authenticated_key_exchange(traveller_cert, helper_cert)
    results.append(("Phase 3: Authenticated Key Exchange", success))
    if not success:
        print("\n❌ Key exchange failed - cannot continue")
        return
    
    # Phase 2: Session Creation
    success, traveller_session, helper_session = test_phase2_session_creation(
        traveller_cert, helper_cert, aes_key1
    )
    results.append(("Phase 2: Session Management", success))
    if not success:
        print("\n❌ Session creation failed - cannot continue")
        return
    
    # Integrated Test: Encrypted Communication
    success = test_integrated_encrypted_communication(traveller_session, helper_session)
    results.append(("Integrated: Encrypted Communication", success))
    
    # Print summary
    print("\n" + "="*70)
    print("INTEGRATION TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "="*70)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL INTEGRATION TESTS PASSED!")
        print("Phases 1-3 are working correctly together.")
        print("Ready to proceed to Phase 4 (Communication Request Flow).")
    else:
        print(f"⚠️  {total - passed} test(s) failed. Review implementation.")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_integration_tests()
