import time
import json
import base64
import requests
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key
)


class HelperAgent:

    def __init__(self):

        # -----------------------------
        # Core Identity
        # -----------------------------
        self.name = "Helper Agent"
        self.agent_id = "helper_agent_001"

        # -----------------------------
        # Functional Description
        # -----------------------------
        self.methods = ["assist_request", "provide_support"]

        self.method_descriptions = {
            "assist_request": "Assists with processing requests from other agents.",
            "provide_support": "Provides support services to other agents."
        }

        # -----------------------------
        # Generate Cryptographic Identity
        # -----------------------------
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        self.public_key = self.private_key.public_key()

        self.public_key_pem = self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # -----------------------------
        # Controller Trust Anchor
        # -----------------------------
        self.controller_public_key = None  # Will be loaded dynamically

        # -----------------------------
        # Timestamps
        # -----------------------------
        current_time = int(time.time())

        # -----------------------------
        # Secure Agent Card
        # -----------------------------
        self.agent_card = {
            # Identity
            "agent_id": self.agent_id,
            "name": self.name,

            # Cryptographic Binding
            "public_key": self.public_key_pem,

            # Functional Metadata
            "methods": self.methods,
            "method_descriptions": self.method_descriptions,

            # Protocol Metadata
            "issued_at": current_time,
            "expires_at": current_time + 3600,  # 1 hour validity
            "protocol_version": 1
        }

    # -----------------------------------
    # Canonical JSON
    # -----------------------------------
    def canonical_json(self, data):
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

    # -----------------------------------
    # Sign Agent Card
    # -----------------------------------
    def sign_agent_card(self):
        data_bytes = self.canonical_json(self.agent_card)

        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    # -----------------------------------
    # Download Controller Public Key
    # -----------------------------------
    def download_controller_public_key(self, controller_address):
        """
        Download and load the controller's public key from /verify/public-key endpoint.
        This establishes the trust anchor for certificate verification.
        
        Args:
            controller_address: Base URL of controller (e.g., "https://127.0.0.1:5000")
            
        Returns:
            (success: bool, message: str)
        """
        try:
            print(f"[INFO] Downloading controller public key from {controller_address}...")
            
            response = requests.get(
                f"{controller_address}/verify/public-key",
                verify=False  # For self-signed certificates
            )
            
            if response.status_code != 200:
                return False, f"Failed to download public key: HTTP {response.status_code}"
            
            data = response.json()
            public_key_pem = data.get("public_key")
            
            if not public_key_pem:
                return False, "Public key not found in response"
            
            # Load the public key
            self.controller_public_key = load_pem_public_key(public_key_pem.encode())
            
            print(f"[INFO] ✓ Controller public key loaded successfully")
            print(f"[INFO] Key ID: {data.get('key_id')}")
            print(f"[INFO] Trust anchor established")
            
            return True, "Controller public key loaded"
            
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to controller at {controller_address}"
        except Exception as e:
            return False, f"Error loading controller public key: {str(e)}"

    # -----------------------------------
    # Verify Controller Certificate
    # -----------------------------------
    def verify_controller_certificate(self, certificate):
        """
        Verify controller's signature on the certificate.
        This establishes that the certificate was issued by the trusted controller.
        
        Args:
            certificate: Dict containing agent_card, agent_signature, controller_signature
            
        Returns:
            (success: bool, message: str)
        """
        print("\n[DEBUG] ═══════════════════════════════════════════════════")
        print("[DEBUG] Starting Controller Signature Verification")
        print("[DEBUG] ═══════════════════════════════════════════════════")
        
        # Step 1: Check if controller public key is loaded
        if not self.controller_public_key:
            print("[DEBUG] ❌ No controller public key found")
            print("[DEBUG] Run 'trust' command first to establish trust anchor\n")
            return False, "Controller public key not loaded - run 'trust' command first"
        
        print("[DEBUG] ✓ Controller public key is loaded")
        
        try:
            agent_card = certificate["agent_card"]
            controller_signature = certificate["controller_signature"]
            
            print(f"[DEBUG] Agent ID in certificate: {agent_card.get('agent_id')}")
            print(f"[DEBUG] Certificate issued at: {certificate.get('certificate_issued_at')}")
            print(f"[DEBUG] Certificate expires at: {certificate.get('certificate_expires_at')}")
            print(f"[DEBUG] Controller signature (first 50 chars): {controller_signature[:50]}...")
            
            # Step 2: Serialize agent_card using canonical JSON
            data_bytes = self.canonical_json(agent_card)
            print(f"[DEBUG] Canonical JSON size: {len(data_bytes)} bytes")
            print(f"[DEBUG] Canonical JSON hash: {hash(data_bytes)}")
            
            # Step 3: Verify controller's signature
            print("[DEBUG] Verifying controller's RSA-PSS signature...")
            
            self.controller_public_key.verify(
                base64.b64decode(controller_signature),
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("[DEBUG] ✓ Cryptographic verification PASSED")
            print("[DEBUG] ✓ Controller signature is valid")
            print("[DEBUG] ✓ Certificate authenticity confirmed")
            print("[DEBUG] ✓ Issued by trusted controller")
            print("[DEBUG] ═══════════════════════════════════════════════════")
            print("[DEBUG] Bidirectional Trust Established (Agent ↔ Controller)")
            print("[DEBUG] ═══════════════════════════════════════════════════\n")
            
            return True, "Controller signature verified successfully"
            
        except Exception as e:
            print(f"[DEBUG] ❌ Signature verification FAILED")
            print(f"[DEBUG] Error: {str(e)}")
            print("[DEBUG] ═══════════════════════════════════════════════════\n")
            return False, f"Controller signature verification failed: {str(e)}"

    # -----------------------------------
    # Register with Controller
    # -----------------------------------
    def register_with_controller(self, controller_address):
        """
        Send registration request to controller
        Returns: (success: bool, response_data: dict or error_message: str)
        """
        try:
            # Sign the agent card
            agent_signature = self.sign_agent_card()
            
            # Generate cryptographic nonce for replay attack prevention
            nonce = secrets.token_hex(32)  # 256-bit random nonce
            
            # Prepare enhanced registration payload
            registration_payload = {
                "registration_version": 1,
                "agent_card": self.agent_card,
                "agent_signature": agent_signature,
                "nonce": nonce,
                "timestamp": int(time.time())  # Additional freshness indicator
            }
            
            # Send registration request to controller
            response = requests.post(
                f"{controller_address}/verify/register",
                json=registration_payload,
                verify=False  # For self-signed certificates
            )
            
            if response.status_code == 200:
                certificate = response.json()
                print(f"[INFO] Certificate received from controller")
                
                # Verify controller's signature on certificate
                verified, verify_msg = self.verify_controller_certificate(certificate)
                
                # Add verification result to response
                certificate["controller_verified"] = verified
                certificate["controller_verify_message"] = verify_msg
                
                if verified:
                    print(f"[INFO] ✓ {verify_msg}")
                else:
                    print(f"[WARNING] ✗ {verify_msg}")
                
                return True, certificate
            else:
                return False, f"Status {response.status_code}: {response.text}"
                
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to controller at {controller_address}"
        except Exception as e:
            return False, f"Registration error: {str(e)}"
