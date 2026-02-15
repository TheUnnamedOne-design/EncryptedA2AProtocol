"""
Test suite for crypto_utils.py

Tests all cryptographic functions:
1. DH parameter and keypair generation
2. DH key signing and verification
3. Shared secret derivation (key exchange)
4. AES-GCM encryption/decryption
5. Replay protection (sequence number verification)
6. Tampering detection
"""

import sys
import os

# Add routes directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'routes'))

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

# For RSA key generation (needed for signing tests)
from cryptography.hazmat.primitives.asymmetric import rsa


def test_dh_parameters():
    """Test DH parameter generation"""
    print("\n" + "="*60)
    print("TEST 1: DH Parameter Generation")
    print("="*60)
    
    try:
        params = generate_dh_parameters()
        print("✓ DH parameters generated successfully")
        print(f"  Key size: {params.parameter_numbers().p.bit_length()} bits")
        return True, params
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False, None


def test_dh_keypair(params):
    """Test DH keypair generation"""
    print("\n" + "="*60)
    print("TEST 2: DH Keypair Generation")
    print("="*60)
    
    try:
        # Generate keypairs for two agents (Alice and Bob)
        alice_private, alice_public = generate_dh_keypair(params)
        bob_private, bob_public = generate_dh_keypair(params)
        
        print("✓ Alice's DH keypair generated")
        print("✓ Bob's DH keypair generated")
        
        return True, (alice_private, alice_public, bob_private, bob_public)
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False, None


def test_shared_secret(alice_private, alice_public, bob_private, bob_public):
    """Test that both parties derive the same shared secret"""
    print("\n" + "="*60)
    print("TEST 3: Shared Secret Derivation")
    print("="*60)
    
    try:
        # Alice computes shared secret using her private key and Bob's public key
        alice_shared = alice_private.exchange(bob_public)
        
        # Bob computes shared secret using his private key and Alice's public key
        bob_shared = bob_private.exchange(alice_public)
        
        # Both should derive the same shared secret
        if alice_shared == bob_shared:
            print("✓ Both parties derived the same shared secret")
            print(f"  Shared secret length: {len(alice_shared)} bytes")
            return True, alice_shared
        else:
            print("✗ FAILED: Shared secrets don't match!")
            return False, None
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False, None


def test_dh_signing(alice_public, bob_public):
    """Test DH public key signing and verification"""
    print("\n" + "="*60)
    print("TEST 4: DH Key Signing and Verification")
    print("="*60)
    
    try:
        # Generate RSA keys for Alice and Bob (simulating agent identities)
        print("[Setup] Generating RSA keys for Alice and Bob...")
        alice_rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alice_rsa_public = alice_rsa_private.public_key()
        
        bob_rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bob_rsa_public = bob_rsa_private.public_key()
        
        # Alice signs her DH public key
        alice_dh_bytes = serialize_dh_public_key(alice_public)
        alice_signature = sign_dh_public_key(alice_public, alice_rsa_private)
        print("✓ Alice signed her DH public key")
        
        # Bob verifies Alice's signature
        alice_verified = verify_signed_dh_key(alice_dh_bytes, alice_signature, alice_rsa_public)
        if alice_verified:
            print("✓ Bob successfully verified Alice's DH key signature")
        else:
            print("✗ FAILED: Alice's signature verification failed")
            return False
        
        # Bob signs his DH public key
        bob_dh_bytes = serialize_dh_public_key(bob_public)
        bob_signature = sign_dh_public_key(bob_public, bob_rsa_private)
        print("✓ Bob signed his DH public key")
        
        # Alice verifies Bob's signature
        bob_verified = verify_signed_dh_key(bob_dh_bytes, bob_signature, bob_rsa_public)
        if bob_verified:
            print("✓ Alice successfully verified Bob's DH key signature")
        else:
            print("✗ FAILED: Bob's signature verification failed")
            return False
        
        # Test invalid signature detection
        print("\n[Attack Simulation] Testing tampered signature detection...")
        tampered_signature = alice_signature[::-1]  # Reverse bytes
        tampered_verified = verify_signed_dh_key(alice_dh_bytes, tampered_signature, alice_rsa_public)
        if not tampered_verified:
            print("✓ Tampered signature correctly rejected")
        else:
            print("✗ FAILED: Tampered signature was accepted!")
            return False
        
        # Test wrong key detection (MITM simulation)
        print("[Attack Simulation] Testing MITM detection (wrong RSA key)...")
        mitm_verified = verify_signed_dh_key(alice_dh_bytes, alice_signature, bob_rsa_public)
        if not mitm_verified:
            print("✓ Signature with wrong RSA key correctly rejected (MITM prevented)")
        else:
            print("✗ FAILED: Wrong RSA key was accepted!")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_aes_key_derivation(shared_secret):
    """Test AES key derivation from shared secret"""
    print("\n" + "="*60)
    print("TEST 5: AES Key Derivation")
    print("="*60)
    
    try:
        aes_key = derive_aes_key(shared_secret)
        
        if len(aes_key) == 32:
            print("✓ AES-256 key derived (32 bytes)")
            return True, aes_key
        else:
            print(f"✗ FAILED: Wrong key length: {len(aes_key)} bytes (expected 32)")
            return False, None
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False, None


def test_encryption_decryption(aes_key):
    """Test AES-GCM encryption and decryption"""
    print("\n" + "="*60)
    print("TEST 6: AES-GCM Encryption/Decryption")
    print("="*60)
    
    try:
        test_message = "Hello from Agent Alice to Agent Bob! 🔐"
        sequence_number = 1
        
        # Encrypt
        print(f"[Original] Message: {test_message}")
        encrypted_data = encrypt_message(test_message, aes_key, sequence_number)
        print(f"✓ Message encrypted")
        print(f"  Ciphertext: {encrypted_data['ciphertext'][:50]}...")
        print(f"  Nonce: {encrypted_data['nonce']}")
        print(f"  Sequence: {encrypted_data['sequence_number']}")
        
        # Decrypt with correct sequence number
        success, plaintext = decrypt_message(
            encrypted_data['ciphertext'],
            encrypted_data['nonce'],
            aes_key,
            sequence_number
        )
        
        if success and plaintext == test_message:
            print(f"✓ Message decrypted successfully")
            print(f"  Decrypted: {plaintext}")
            return True, encrypted_data
        else:
            print(f"✗ FAILED: Decryption failed or message mismatch")
            print(f"  Expected: {test_message}")
            print(f"  Got: {plaintext}")
            return False, None
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False, None


def test_replay_protection(aes_key, encrypted_data):
    """Test replay attack protection (wrong sequence number)"""
    print("\n" + "="*60)
    print("TEST 7: Replay Attack Protection")
    print("="*60)
    
    try:
        original_seq = encrypted_data['sequence_number']
        wrong_seq = original_seq + 1
        
        print(f"[Attack Simulation] Using wrong sequence number...")
        print(f"  Original sequence: {original_seq}")
        print(f"  Attempting with: {wrong_seq}")
        
        success, result = decrypt_message(
            encrypted_data['ciphertext'],
            encrypted_data['nonce'],
            aes_key,
            wrong_seq  # Wrong sequence number
        )
        
        if not success:
            print("✓ Replay attack prevented (wrong sequence rejected)")
            print(f"  Error: {result}")
            return True
        else:
            print("✗ FAILED: Wrong sequence number was accepted!")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_tampering_detection(aes_key, encrypted_data):
    """Test tampering detection (modified ciphertext)"""
    print("\n" + "="*60)
    print("TEST 8: Tampering Detection")
    print("="*60)
    
    try:
        print("[Attack Simulation] Tampering with ciphertext...")
        
        # Tamper with ciphertext by modifying one character
        import base64
        original_ct = base64.b64decode(encrypted_data['ciphertext'])
        tampered_ct = bytearray(original_ct)
        tampered_ct[0] ^= 0xFF  # Flip bits in first byte
        tampered_ct_b64 = base64.b64encode(bytes(tampered_ct)).decode('utf-8')
        
        success, result = decrypt_message(
            tampered_ct_b64,
            encrypted_data['nonce'],
            aes_key,
            encrypted_data['sequence_number']
        )
        
        if not success:
            print("✓ Tampering detected (authentication tag verification failed)")
            print(f"  Error: {result}")
            return True
        else:
            print("✗ FAILED: Tampered ciphertext was accepted!")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def test_serialization(params):
    """Test DH public key serialization/deserialization"""
    print("\n" + "="*60)
    print("TEST 9: DH Key Serialization")
    print("="*60)
    
    try:
        # Generate a keypair
        private_key, public_key = generate_dh_keypair(params)
        
        # Serialize
        serialized = serialize_dh_public_key(public_key)
        print(f"✓ Serialized to PEM format ({len(serialized)} bytes)")
        
        # Deserialize
        deserialized = deserialize_dh_public_key(serialized)
        print("✓ Deserialized from PEM format")
        
        # Verify they match by re-serializing
        reserialized = serialize_dh_public_key(deserialized)
        if serialized == reserialized:
            print("✓ Serialization/deserialization preserves key data")
            return True
        else:
            print("✗ FAILED: Keys don't match after round-trip")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False


def run_all_tests():
    """Run complete test suite"""
    print("\n" + "="*60)
    print("CRYPTOGRAPHIC UTILITIES TEST SUITE")
    print("Testing Phase 3 Implementation")
    print("="*60)
    
    results = []
    
    # Test 1: DH Parameters
    success, params = test_dh_parameters()
    results.append(("DH Parameter Generation", success))
    if not success:
        print("\n❌ Critical failure - cannot continue tests")
        return
    
    # Test 2: DH Keypairs
    success, keys = test_dh_keypair(params)
    results.append(("DH Keypair Generation", success))
    if not success:
        print("\n❌ Critical failure - cannot continue tests")
        return
    alice_private, alice_public, bob_private, bob_public = keys
    
    # Test 3: Shared Secret
    success, shared_secret = test_shared_secret(alice_private, alice_public, bob_private, bob_public)
    results.append(("Shared Secret Derivation", success))
    if not success:
        print("\n❌ Critical failure - cannot continue tests")
        return
    
    # Test 4: DH Signing
    success = test_dh_signing(alice_public, bob_public)
    results.append(("DH Key Signing/Verification", success))
    
    # Test 5: AES Key Derivation
    success, aes_key = test_aes_key_derivation(shared_secret)
    results.append(("AES Key Derivation", success))
    if not success:
        print("\n❌ Critical failure - cannot continue tests")
        return
    
    # Test 6: Encryption/Decryption
    success, encrypted_data = test_encryption_decryption(aes_key)
    results.append(("AES-GCM Encryption/Decryption", success))
    if not success:
        print("\n❌ Critical failure - cannot continue tests")
        return
    
    # Test 7: Replay Protection
    success = test_replay_protection(aes_key, encrypted_data)
    results.append(("Replay Attack Protection", success))
    
    # Test 8: Tampering Detection
    success = test_tampering_detection(aes_key, encrypted_data)
    results.append(("Tampering Detection", success))
    
    # Test 9: Serialization
    success = test_serialization(params)
    results.append(("DH Key Serialization", success))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "="*60)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Phase 3 implementation is correct.")
    else:
        print(f"⚠️  {total - passed} test(s) failed. Review implementation.")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_all_tests()
