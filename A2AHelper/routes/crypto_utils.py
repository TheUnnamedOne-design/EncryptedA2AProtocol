"""
Cryptographic Utilities for Secure Agent-to-Agent Communication

This module provides cryptographic functions for:
1. Authenticated Diffie-Hellman Key Exchange (prevents MITM attacks)
2. AES-GCM Authenticated Encryption (confidentiality + integrity)

Security Features:
- Ephemeral DH keys for forward secrecy
- RSA signatures on DH public keys (MITM prevention)
- HKDF for key derivation (cryptographic strength)
- AES-256-GCM for authenticated encryption
- Sequence numbers as AAD (replay protection)
"""

import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    ParameterFormat,
    load_pem_parameters,
    load_pem_public_key
)


# ========================================
# Diffie-Hellman Key Exchange Functions
# ========================================

def generate_dh_parameters():
    """
    Generate Diffie-Hellman parameters (2048-bit).
    
    Note: DH parameter generation is computationally expensive (~1-2 seconds).
    In production, parameters can be pre-generated and reused across sessions
    as they don't need to be secret.
    
    Returns:
        DHParameters object from cryptography library
    """
    print("[CRYPTO] Generating DH parameters (2048-bit)... This may take a moment.")
    parameters = dh.generate_parameters(
        generator=2,      # Standard generator value
        key_size=2048     # 2048-bit for strong security
    )
    print("[CRYPTO] ✓ DH parameters generated")
    return parameters


def generate_dh_keypair(parameters):
    """
    Generate an ephemeral Diffie-Hellman keypair.
    
    Ephemeral keys provide forward secrecy - if a key is compromised later,
    past communications remain secure.
    
    Args:
        parameters: DHParameters object from generate_dh_parameters()
        
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_dh_public_key(dh_public_key, rsa_private_key):
    """
    Sign a DH public key with an RSA private key.
    
    This prevents man-in-the-middle attacks by proving ownership of the
    DH public key. The signature can be verified using the corresponding
    RSA public key (from the agent's certificate).
    
    Args:
        dh_public_key: DHPublicKey object to sign
        rsa_private_key: RSA private key (from agent's identity)
        
    Returns:
        bytes: RSA-PSS signature
    """
    # Serialize DH public key to PEM format
    dh_public_bytes = dh_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Sign with RSA-PSS (Probabilistic Signature Scheme)
    signature = rsa_private_key.sign(
        dh_public_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signed_dh_key(dh_public_bytes, signature, rsa_public_key):
    """
    Verify the RSA signature on a DH public key.
    
    This ensures the DH public key came from the expected peer and hasn't
    been substituted by an attacker.
    
    Args:
        dh_public_bytes: Serialized DH public key (PEM format)
        signature: RSA signature bytes
        rsa_public_key: RSA public key (from peer's certificate)
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        rsa_public_key.verify(
            signature,
            dh_public_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"[CRYPTO] DH signature verification failed: {e}")
        return False


def derive_aes_key(shared_secret):
    """
    Derive a 256-bit AES key from a DH shared secret using HKDF.
    
    HKDF (HMAC-based Key Derivation Function) is a cryptographically strong
    method to derive keys. Even if the shared secret has some weaknesses,
    HKDF produces uniformly random key material.
    
    Args:
        shared_secret: bytes from DH key exchange
        
    Returns:
        bytes: 32-byte (256-bit) AES key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits / 8 = 32 bytes
        salt=None,  # Salt is optional; using None is acceptable
        info=b'A2A-Communication-Key'  # Context-specific info
    )
    
    aes_key = hkdf.derive(shared_secret)
    print(f"[CRYPTO] ✓ Derived AES-256 key ({len(aes_key)} bytes)")
    return aes_key


# ========================================
# AES-GCM Authenticated Encryption
# ========================================

def encrypt_message(message, aes_key, sequence_number):
    """
    Encrypt a message using AES-256-GCM with authenticated data.
    
    AES-GCM provides:
    - Confidentiality: Message content is encrypted
    - Integrity: Authentication tag prevents tampering
    - Associated Data: Sequence number prevents replay attacks
    
    Args:
        message: String message to encrypt
        aes_key: 32-byte AES key
        sequence_number: Integer sequence number for replay protection
        
    Returns:
        dict: {
            'ciphertext': base64 encoded ciphertext+tag,
            'nonce': base64 encoded 12-byte nonce,
            'sequence_number': int
        }
    """
    # Generate a unique 96-bit (12-byte) nonce
    # GCM requires unique nonces for security
    nonce = os.urandom(12)
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(aes_key)
    
    # Use sequence number as Associated Authenticated Data (AAD)
    # This binds the sequence number to the message cryptographically
    associated_data = str(sequence_number).encode('utf-8')
    
    # Encrypt message (returns ciphertext + 16-byte authentication tag)
    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode('utf-8'),
        associated_data
    )
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'sequence_number': sequence_number
    }


def decrypt_message(ciphertext_b64, nonce_b64, aes_key, expected_seq):
    """
    Decrypt and verify an AES-GCM encrypted message.
    
    This function:
    1. Decodes base64 data
    2. Verifies the authentication tag
    3. Verifies the sequence number (AAD)
    4. Decrypts the message
    
    If any verification fails, decryption is rejected.
    
    Args:
        ciphertext_b64: Base64 encoded ciphertext+tag
        nonce_b64: Base64 encoded nonce
        aes_key: 32-byte AES key
        expected_seq: Expected sequence number (for replay protection)
        
    Returns:
        tuple: (success: bool, plaintext: str or error_message: str)
    """
    try:
        # Decode from base64
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(aes_key)
        
        # AAD must match what was used during encryption
        associated_data = str(expected_seq).encode('utf-8')
        
        # Decrypt and verify
        # This will raise an exception if:
        # - Authentication tag is invalid (message was tampered)
        # - Sequence number doesn't match (replay attack)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        
        return True, plaintext.decode('utf-8')
        
    except Exception as e:
        # Decryption failure could mean:
        # - Invalid authentication tag (tampering detected)
        # - Wrong key
        # - Wrong sequence number
        # - Corrupted data
        error_msg = f"Decryption failed: {str(e)}"
        print(f"[CRYPTO] {error_msg}")
        return False, error_msg


# ========================================
# Helper Functions
# ========================================

def serialize_dh_public_key(dh_public_key):
    """
    Serialize a DH public key to PEM format for transmission.
    
    Args:
        dh_public_key: DHPublicKey object
        
    Returns:
        bytes: PEM formatted public key
    """
    return dh_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_dh_public_key(pem_bytes):
    """
    Deserialize a PEM formatted DH public key.
    
    Args:
        pem_bytes: PEM formatted public key bytes
        
    Returns:
        DHPublicKey object
    """
    return load_pem_public_key(pem_bytes)


# ========================================
# Module Information
# ========================================

__all__ = [
    # DH functions
    'generate_dh_parameters',
    'generate_dh_keypair',
    'sign_dh_public_key',
    'verify_signed_dh_key',
    'derive_aes_key',
    # AES-GCM functions
    'encrypt_message',
    'decrypt_message',
    # Helper functions
    'serialize_dh_public_key',
    'deserialize_dh_public_key'
]
