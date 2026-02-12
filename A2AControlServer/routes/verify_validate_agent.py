from flask import Flask, request, Blueprint, jsonify
import json, base64
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

def sign(private_key, data):
    data_bytes = json.dumps(data, sort_keys=True).encode()
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
    data_bytes = json.dumps(data, sort_keys=True).encode()
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
    except:
        return False




@verify_bp.route("/register", methods=["POST"])
def register():
    agent_card = request.json["agent_card"]
    agent_signature = request.json["agent_signature"]

    # Load agent public key
    agent_public = load_pem_public_key(
        agent_card["public_key"].encode()
    )

    if not verify(agent_public, agent_card, agent_signature):
        return jsonify({"error": "Invalid agent signature"}), 400

    # Controller signs the card
    controller_signature = sign(controller_private, agent_card)

    certificate = {
        "agent_card": agent_card,
        "agent_signature": agent_signature,
        "controller_signature": controller_signature
    }

    agent_db[agent_card["agent_id"]] = certificate

    return jsonify(certificate)





@verify_bp.route("/cards", methods=["GET"])
def get_cards():
    return jsonify(agent_db)
