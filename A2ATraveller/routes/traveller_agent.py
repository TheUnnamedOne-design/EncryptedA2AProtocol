import time
import json
import base64
from urllib import response
import requests
import secrets
import queue

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key
)

from .session_manager import SessionState


class TravellerAgent:

    def __init__(self):

        # -----------------------------
        # Core Identity
        # -----------------------------
        self.name = "Traveller Agent"
        self.agent_id = "traveller_agent_001"

        # -----------------------------
        # Functional Description
        # -----------------------------
        self.methods = ["send_request", "receive_response"]

        self.method_descriptions = {
            "send_request": "Sends a request to another agent.",
            "receive_response": "Handles the response received from another agent."
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
        # Certificate Storage
        # -----------------------------
        self.my_certificate = None  # Stores certificate issued by controller
        self.peer_certificates = {}  # {agent_id: certificate_data}

        # -----------------------------
        # Session Management
        # -----------------------------
        self.active_sessions = {}  # {session_id: SessionState}
        self.pending_requests = queue.Queue()  # Thread-safe queue for incoming requests

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
                    # Store certificate after successful verification
                    self.my_certificate = certificate
                    print(f"[INFO] Certificate stored successfully")
                else:
                    print(f"[WARNING] ✗ {verify_msg}")
                
                return True, certificate
            else:
                return False, f"Status {response.status_code}: {response.text}"
                
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to controller at {controller_address}"
        except Exception as e:
            return False, f"Registration error: {str(e)}"
        
    # -----------------------------------
    # Fetch Peer Certificate
    # -----------------------------------
    def fetch_peer_certificate(self, peer_address):
        """
        Fetch a peer agent's certificate from their /agent/certificate endpoint.
        
        Args:
            peer_address: Base URL of peer agent (e.g., "https://127.0.0.1:5001")
            
        Returns:
            (success: bool, certificate: dict or error_message: str)
        """
        try:
            print(f"[INFO] Fetching certificate from {peer_address}...")
            
            response = requests.get(
                f"{peer_address}/agent/certificate",
                verify=False,  # For self-signed certificates
                timeout=5
            )
            
            if response.status_code == 200:
                certificate = response.json()
                agent_id = certificate.get('agent_card', {}).get('agent_id', 'unknown')
                
                # Store in peer certificates cache
                self.peer_certificates[agent_id] = certificate
                print(f"[INFO] ✓ Certificate retrieved for agent: {agent_id}")
                
                return True, certificate
            elif response.status_code == 404:
                return False, "Peer agent has not registered with controller yet"
            else:
                return False, f"Failed to fetch certificate: Status {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to peer at {peer_address}"
        except requests.exceptions.Timeout:
            return False, f"Connection timeout to {peer_address}"
        except Exception as e:
            return False, f"Error fetching certificate: {str(e)}"
    
    # -----------------------------------
    # Verify Peer Certificate
    # -----------------------------------
    def verify_peer_certificate(self, certificate):
        """
        Verify a peer agent's certificate by checking the controller's signature.
        
        Args:
            certificate: Certificate dictionary from peer agent
            
        Returns:
            (success: bool, message: str)
        """
        try:
            # Check if we have the controller's public key
            if self.controller_public_key is None:
                return False, "Controller public key not loaded. Run 'trust' command first."
            
            # Extract certificate components
            agent_card = certificate.get('agent_card')
            controller_signature = certificate.get('controller_signature')
            expires_at = certificate.get('expires_at')
            
            if not all([agent_card, controller_signature, expires_at]):
                return False, "Invalid certificate format: missing required fields"
            
            # Check expiry
            current_time = int(time.time())
            if current_time > expires_at:
                return False, f"Certificate expired at {expires_at}"
            
            # Prepare data for signature verification
            # The controller signs the entire certificate minus the signature field
            cert_data = {
                'agent_card': agent_card,
                'agent_signature': certificate.get('agent_signature'),
                'controller_signature': controller_signature,
                'issued_at': certificate.get('issued_at'),
                'expires_at': expires_at,
                'nonce': certificate.get('nonce')
            }
            
            # Remove controller_signature for verification (it signs everything else)
            verification_data = {
                'agent_card': agent_card,
                'agent_signature': certificate.get('agent_signature'),
                'issued_at': certificate.get('issued_at'),
                'expires_at': expires_at,
                'nonce': certificate.get('nonce')
            }
            
            # Canonical JSON serialization
            data_bytes = self.canonical_json(verification_data)
            
            # Decode signature
            signature_bytes = base64.b64decode(controller_signature)
            
            # Verify signature
            try:
                self.controller_public_key.verify(
                    signature_bytes,
                    data_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                agent_id = agent_card.get('agent_id', 'unknown')
                return True, f"Certificate valid for agent: {agent_id}"
                
            except Exception as verify_error:
                return False, f"Invalid controller signature: {str(verify_error)}"
            
        except Exception as e:
            return False, f"Certificate verification error: {str(e)}"
    

    def get_all_agent_cards(self, controller_address): 
        """
        Retrieve all registered agent cards from the controller.
        
        Args:
            controller_address: Base URL of controller (e.g., "https://127.0.0.1:5000")
            
        Returns:
            (success: bool, agent_cards: dict or error_message: str)
        """
        try:
            print(f"[INFO] Fetching registered agent cards from {controller_address}...")
            
            response = requests.get(
                f"{controller_address}/verify/cards",
                verify=False  # For self-signed certificates
            )

            if response.status_code == 200:
                agent_cards = response.json()
                
                if not agent_cards:
                    print("[INFO] No agents registered yet")
                    return True, {}
                
                print(f"[INFO] ✓ Retrieved {len(agent_cards)} registered agent(s)\n")
                print("=" * 70)
                print("REGISTERED AGENTS")
                print("=" * 70)
                
                for agent_id, certificate in agent_cards.items():
                    agent_card = certificate.get("agent_card", {})
                    
                    print(f"\nAgent ID: {agent_id}")
                    print(f"  Name: {agent_card.get('name', 'N/A')}")
                    print(f"  Methods: {', '.join(agent_card.get('methods', []))}")
                    print(f"  Protocol Version: {agent_card.get('protocol_version', 'N/A')}")
                    print(f"  Card Issued: {agent_card.get('issued_at', 'N/A')}")
                    print(f"  Card Expires: {agent_card.get('expires_at', 'N/A')}")
                    print(f"  Certificate Issued: {certificate.get('certificate_issued_at', 'N/A')}")
                    print(f"  Certificate Expires: {certificate.get('certificate_expires_at', 'N/A')}")
                    print(f"  Has Controller Signature: {'✓' if certificate.get('controller_signature') else '✗'}")
                    print(f"  Has Agent Signature: {'✓' if certificate.get('agent_signature') else '✗'}")
                
                print("\n" + "=" * 70)
                
                return True, agent_cards
            else:
                error_msg = f"Failed to fetch agent cards: HTTP {response.status_code}"
                print(f"[ERROR] {error_msg}")
                try:
                    error_detail = response.json().get('error', response.text)
                    print(f"[ERROR] Details: {error_detail}")
                except:
                    pass
                return False, error_msg

        except requests.exceptions.ConnectionError:
            error_msg = f"Cannot connect to controller at {controller_address}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error retrieving agent cards: {str(e)}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg

    # -----------------------------------
    # Phase 4: Communication Request
    # -----------------------------------
    def send_communication_request(self, peer_address, peer_agent_id):
        """
        Send a communication request to a peer agent.
        
        Args:
            peer_address: HTTPS address of peer (e.g., "https://localhost:5001")
            peer_agent_id: Agent ID of the peer
            
        Returns:
            (success: bool, session_id: str or error_message: str)
        """
        try:
            import uuid
            
            # Generate unique request ID
            request_id = str(uuid.uuid4())
            timestamp = int(time.time())
            
            # Create request payload
            request_payload = {
                "request_id": request_id,
                "agent_id": self.agent_id,
                "timestamp": timestamp
            }
            
            # Sign the entire payload
            payload_bytes = self.canonical_json(request_payload)
            signature = self.private_key.sign(
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            request_payload["signature"] = base64.b64encode(signature).decode()
            
            print(f"[INFO] Sending communication request to {peer_agent_id}...")
            
            # Send POST request
            response = requests.post(
                f"{peer_address}/agent/communicate/request",
                json=request_payload,
                verify=False,  # Self-signed certificates
                timeout=30  # 30 second timeout
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Verify response signature
                if not response_data.get('accepted'):
                    return False, "Request was rejected by peer"
                
                # Extract session_id
                session_id = response_data.get('session_id')
                response_signature = response_data.get('signature')
                response_timestamp = response_data.get('timestamp')
                
                if not all([session_id, response_signature, response_timestamp]):
                    return False, "Invalid response format from peer"
                
                # Verify signature using peer's public key
                # First, fetch peer's certificate if not cached
                if peer_agent_id not in self.peer_certificates:
                    cert_success, cert_or_error = self.fetch_peer_certificate(peer_address)
                    if not cert_success:
                        return False, f"Failed to fetch peer certificate: {cert_or_error}"
                
                peer_cert = self.peer_certificates[peer_agent_id]
                peer_public_key_pem = peer_cert['agent_card']['public_key']
                peer_public_key = load_pem_public_key(peer_public_key_pem.encode())
                
                # Verify response signature
                response_data_for_sig = {
                    "accepted": response_data['accepted'],
                    "session_id": session_id,
                    "timestamp": response_timestamp
                }
                response_bytes = self.canonical_json(response_data_for_sig)
                
                try:
                    peer_public_key.verify(
                        base64.b64decode(response_signature),
                        response_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print(f"[INFO] ✓ Response signature verified")
                except Exception as e:
                    return False, f"Response signature verification failed: {e}"
                
                print(f"[INFO] ✓ Request accepted! Session ID: {session_id}")
                return True, session_id
                
            else:
                error_msg = f"Request failed with status {response.status_code}"
                try:
                    error_detail = response.json().get('error', response.text)
                    error_msg += f": {error_detail}"
                except:
                    pass
                return False, error_msg
                
        except requests.exceptions.Timeout:
            return False, "Request timed out - peer may be unreachable"
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to peer at {peer_address}"
        except Exception as e:
            return False, f"Error sending request: {str(e)}"