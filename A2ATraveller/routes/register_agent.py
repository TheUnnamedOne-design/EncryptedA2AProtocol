import time
import json
import base64
import requests
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)


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
                return True, response.json()
            else:
                return False, f"Status {response.status_code}: {response.text}"
                
        except requests.exceptions.ConnectionError:
            return False, f"Cannot connect to controller at {controller_address}"
        except Exception as e:
            return False, f"Registration error: {str(e)}"
