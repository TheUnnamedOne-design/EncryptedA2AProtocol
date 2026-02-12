from flask import Flask, request, Blueprint, jsonify
import json, base64, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key



verify_bp = Blueprint('verify', __name__)



# Controller key pair (root)
controller_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
controller_public = controller_private.public_key()




# In-memory storage
agent_db = {}
used_nonces = set()  # Track used nonces to prevent replay attacks

def sign(private_key, data):
    data_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    sig = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()





def verify(public_key, data, signature):
    data_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    try:
        public_key.verify(
            base64.b64decode(signature),
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False




@verify_bp.route("/register", methods=["POST"])
def register():
    payload = request.json
    
    # Validate registration version
    registration_version = payload.get("registration_version", 0)
    if registration_version != 1:
        return jsonify({"error": "Unsupported registration version"}), 400
    
    # Extract fields
    agent_card = payload["agent_card"]
    agent_signature = payload["agent_signature"]
    nonce = payload.get("nonce")
    timestamp = payload.get("timestamp")
    
    # Validate nonce (replay attack prevention)
    if not nonce:
        return jsonify({"error": "Nonce required"}), 400
    if nonce in used_nonces:
        return jsonify({"error": "Nonce already used (replay attack detected)"}), 403
    
    # Validate timestamp freshness (within 5 minutes)
    if timestamp:
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5 minutes
            return jsonify({"error": "Timestamp too old or in future"}), 400
    
    # Validate agent_id uniqueness
    if agent_card["agent_id"] in agent_db:
        return jsonify({"error": "Agent ID already registered"}), 409
    
    # Validate expiry
    current_time = int(time.time())
    if agent_card.get("expires_at", 0) <= current_time:
        return jsonify({"error": "Agent card already expired"}), 400

    # Load agent public key
    agent_public = load_pem_public_key(
        agent_card["public_key"].encode()
    )

    # Verify agent signature
    if not verify(agent_public, agent_card, agent_signature):
        return jsonify({"error": "Invalid agent signature"}), 400

    # Mark nonce as used
    used_nonces.add(nonce)

    # Controller signs the card
    controller_signature = sign(controller_private, agent_card)
    
    # Create certificate with metadata
    current_time = int(time.time())
    certificate = {
        "registration_version": 1,
        "agent_card": agent_card,
        "agent_signature": agent_signature,
        "controller_signature": controller_signature,
        "certificate_issued_at": current_time,
        "certificate_expires_at": current_time + 86400,  # 24 hours
        "nonce": nonce
    }

    # Store certificate
    agent_db[agent_card["agent_id"]] = certificate

    return jsonify(certificate)





@verify_bp.route("/cards", methods=["GET"])
def get_cards():
    return jsonify(agent_db)



@verify_bp.route("/public-key", methods=["GET"])
def get_public_key():
    """
    Expose controller's public key for agents to download.
    Agents use this to verify controller signatures on certificates.
    """
    # Export controller public key as PEM
    controller_public_pem = controller_public.public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # Also provide escaped version for easy .env file usage
    controller_public_pem_escaped = controller_public_pem.replace("\n", "\\n")
    
    return jsonify({
        "key_id": "controller_001",
        "public_key": controller_public_pem,
        "public_key_oneline": controller_public_pem_escaped,
        "issued_at": int(time.time())
    })


@verify_bp.route("/reset", methods=["POST"])
def reset_database():
    """
    Clear all registered agents and nonces.
    Useful for development/testing - allows re-registration without server restart.
    """
    global agent_db, used_nonces
    
    agent_count = len(agent_db)
    nonce_count = len(used_nonces)
    
    agent_db.clear()
    used_nonces.clear()
    
    return jsonify({
        "status": "success",
        "message": "Agent database reset",
        "cleared_agents": agent_count,
        "cleared_nonces": nonce_count,
        "timestamp": int(time.time())
    }), 200
