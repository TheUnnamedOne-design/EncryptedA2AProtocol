from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import threading
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from routes.traveller_agent import TravellerAgent

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get port from .env
PORT = int(os.getenv("PORT", 5002))
AGENT_ID = os.getenv("AGENT_ID", "traveller_1")
CONTROLLER_ADDRESS = os.getenv("CONTROLLER_ADDRESS", "https://localhost:5000")

# Initialize agent with address
agent = TravellerAgent(my_address=f"https://localhost:{PORT}")

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the A2A Traveller Agent"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/message', methods=['POST'])
def receive_message():
    data = request.json
    print(f"\n[RECEIVED] {data}")
    return jsonify({"status": "received"}), 200

@app.route('/agent/certificate', methods=['GET'])
def get_certificate():
    """
    Endpoint to retrieve this agent's certificate issued by the controller.
    Used by peer agents for certificate verification.
    """
    if agent.my_certificate is None:
        return jsonify({
            "error": "Certificate not yet issued",
            "message": "Agent must register with controller first"
        }), 404
    
    return jsonify(agent.my_certificate), 200


@app.route('/agent/communicate/request', methods=['POST'])
def handle_communication_request():
    """
    Handle incoming communication request from a peer agent.
    Verifies signature, fetches certificate, and waits for user acceptance.
    """
    import uuid
    import threading
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    
    try:
        data = request.json
        
        # Extract request data
        request_id = data.get('request_id')
        requester_agent_id = data.get('agent_id')
        requester_address = data.get('address')
        timestamp = data.get('timestamp')
        signature = data.get('signature')
        
        if not all([request_id, requester_agent_id, requester_address, timestamp, signature]):
            return jsonify({"error": "Missing required fields"}), 400
        
        print(f"\n[INCOMING] Communication request from {requester_agent_id}")
        
        # Verify timestamp freshness (within 5 minutes)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5 minutes = 300 seconds
            return jsonify({"error": "Request timestamp expired"}), 400
        
        # Fetch requester's certificate from controller if not cached
        if requester_agent_id not in agent.peer_certificates:
            print(f"[INFO] Fetching {requester_agent_id}'s certificate from {requester_address}...")
            success, cert_or_error = agent.fetch_peer_certificate(requester_address)
            if not success:
                return jsonify({"error": f"Failed to fetch certificate: {cert_or_error}"}), 400
            # Verify the fetched certificate is for the expected agent
            fetched_agent_id = cert_or_error.get('agent_card', {}).get('agent_id')
            if fetched_agent_id != requester_agent_id:
                return jsonify({"error": f"Certificate mismatch: expected {requester_agent_id}, got {fetched_agent_id}"}), 400
            print(f"[INFO] Certificate cached successfully")
        
        # Verify signature using requester's public key
        
        # Create request object for user acceptance
        request_info = {
            "request_id": request_id,
            "requester_agent_id": requester_agent_id,
            "timestamp": timestamp,
            "response_event": threading.Event(),
            "user_response": None
        }
        
        # Add to pending requests queue
        agent.pending_requests.put(request_info)
        
        # Wait for user response (with 60 second timeout)
        response_received = request_info["response_event"].wait(timeout=60)
        
        if not response_received or not request_info["user_response"]:
            return jsonify({
                "accepted": False,
                "reason": "Request timed out or was rejected"
            }), 200
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        response_timestamp = int(time.time())
        
        # Create response payload
        response_payload = {
            "accepted": True,
            "session_id": session_id,
            "timestamp": response_timestamp
        }
        
        # Sign response
        response_bytes = agent.canonical_json(response_payload)
        response_signature = agent.private_key.sign(
            response_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        response_payload["signature"] = base64.b64encode(response_signature).decode()
        
        # Create session state
        from routes.session_manager import SessionState
        session = SessionState(
            session_id=session_id,
            peer_agent_id=requester_agent_id,
            peer_address=None  # Will be set during key exchange
        )
        agent.active_sessions[session_id] = session
        
        print(f"[INFO] Communication request accepted. Session: {session_id}")
        
        return jsonify(response_payload), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to handle communication request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/agent/communicate/keyexchange', methods=['POST'])
def handle_key_exchange():
    """
    Handle authenticated Diffie-Hellman key exchange.
    Verifies peer's signed DH public key, generates own keypair,
    derives shared AES key, and returns signed DH public key.
    """
    from routes.crypto_utils import (
        generate_dh_parameters,
        generate_dh_keypair,
        sign_dh_public_key,
        verify_signed_dh_key,
        derive_aes_key,
        deserialize_dh_public_key,
        serialize_dh_public_key
    )
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    
    try:
        data = request.json
        
        # Extract key exchange data
        session_id = data.get('session_id')
        dh_public_b64 = data.get('dh_public')
        timestamp = data.get('timestamp')
        signature_b64 = data.get('signature')
        
        if not all([session_id, dh_public_b64, timestamp, signature_b64]):
            return jsonify({"error": "Missing required fields"}), 400
        
        print(f"\n[KEY EXCHANGE] Received request for session: {session_id}")
        
        # Verify session exists
        if session_id not in agent.active_sessions:
            return jsonify({"error": "Session not found"}), 404
        
        session = agent.active_sessions[session_id]
        
        # Get peer's public key for signature verification
        if session.peer_agent_id not in agent.peer_certificates:
            return jsonify({"error": "Peer certificate not found"}), 400
        
        peer_cert = agent.peer_certificates[session.peer_agent_id]
        peer_public_key_pem = peer_cert['agent_card']['public_key']
        peer_public_key = load_pem_public_key(peer_public_key_pem.encode())
        
        # Decode peer's DH public key
        dh_public_bytes = base64.b64decode(dh_public_b64)
        signature = base64.b64decode(signature_b64)
        
        # Verify signature on peer's DH public key
        if not verify_signed_dh_key(dh_public_bytes, signature, peer_public_key):
            return jsonify({"error": "Invalid signature on DH public key"}), 400
        
        print(f"[KEY EXCHANGE] ✓ Peer's DH signature verified")
        
        # Deserialize peer's DH public key
        peer_dh_public = deserialize_dh_public_key(dh_public_bytes)
        
        # Generate our own DH keypair (using same parameters as peer!)
        print(f"[KEY EXCHANGE] Generating DH keypair...")
        dh_parameters = peer_dh_public.parameters()
        dh_private, dh_public = generate_dh_keypair(dh_parameters)
        
        # Compute shared secret
        print(f"[KEY EXCHANGE] Computing shared secret...")
        shared_secret = dh_private.exchange(peer_dh_public)
        
        # Derive AES key from shared secret
        aes_key = derive_aes_key(shared_secret)
        session.aes_key = aes_key
        
        print(f"[KEY EXCHANGE] ✓ AES-256 key derived and stored")
        
        # Serialize and sign our DH public key
        our_dh_public_bytes = serialize_dh_public_key(dh_public)
        our_signature = sign_dh_public_key(dh_public, agent.private_key)
        
        # Create response
        response_data = {
            "dh_public": base64.b64encode(our_dh_public_bytes).decode(),
            "timestamp": int(time.time()),
            "signature": base64.b64encode(our_signature).decode()
        }
        
        print(f"[KEY EXCHANGE] ✓ Key exchange complete for session: {session_id}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"[ERROR] Key exchange failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def run_flask():
        app.run(
        host='0.0.0.0',
        port=PORT,
        debug=False,
        use_reloader=False,
        ssl_context=("cert.pem", "key.pem")  
    )


if __name__ == "__main__":
    # Start Flask server in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    print(f"Traveller Agent ({AGENT_ID}) running on port {PORT}")
    print("Type 'help' for commands\n")
    
    # Interactive CLI loop
    while True:
        # Check for incoming communication requests
        if not agent.pending_requests.empty():
            try:
                request_info = agent.pending_requests.get_nowait()
                requester_id = request_info.get('requester_agent_id')
                
                print(f"\n{'='*60}")
                print(f"[!] INCOMING COMMUNICATION REQUEST")
                print(f"From: {requester_id}")
                print(f"{'='*60}")
                
                # Prompt user for acceptance
                while True:
                    response = input("Accept communication request? (y/n): ").strip().lower()
                    if response in ['y', 'yes']:
                        request_info["user_response"] = True
                        request_info["response_event"].set()
                        print("[INFO] Request accepted. Waiting for secure channel setup...\n")
                        break
                    elif response in ['n', 'no']:
                        request_info["user_response"] = False
                        request_info["response_event"].set()
                        print("[INFO] Request rejected.\n")
                        break
                    else:
                        print("Please enter 'y' or 'n'")
            except:
                pass  # Queue was empty, continue
        
        cmd = input(f"{AGENT_ID}> ").strip().lower()
        
        if cmd == "help":
            print("Commands: help | status | info | setup | trust | register | cards | sessions | request | keyexchange | exit")
        elif cmd == "status":
            print(f"Agent: {AGENT_ID}, Port: {PORT}, Status: Active")
            trust_status = "✓ Established" if agent.controller_public_key else "✗ Not established"
            print(f"Trust Anchor: {trust_status}")
        elif cmd == "setup":
            print(f"Setting up agent with controller at {CONTROLLER_ADDRESS}...\n")
            
            # Step 1: Establish trust
            print("[1/2] Establishing trust...")
            success, message = agent.download_controller_public_key(CONTROLLER_ADDRESS)
            if success:
                print(f"✓ {message}\n")
            else:
                print(f"✗ {message}")
                print("Setup failed at trust establishment step.")
                continue
            
            # Step 2: Register
            print("[2/2] Registering with controller...")
            success, result = agent.register_with_controller(CONTROLLER_ADDRESS)
            if success:
                print("✓ Registration successful!")
                print(f"Certificate received from controller")
                print(f"Agent ID: {result['agent_card']['agent_id']}")
                print(f"Controller signature: {result['controller_signature'][:50]}...\n")
                print("✅ Setup complete! Agent is ready.")
            else:
                print(f"✗ Registration failed: {result}")
                print("Setup failed at registration step.")
        elif cmd == "trust":
            print(f"Establishing trust with controller at {CONTROLLER_ADDRESS}...")
            success, message = agent.download_controller_public_key(CONTROLLER_ADDRESS)
            
            if success:
                print(f"✓ {message}")
            else:
                print(f"✗ {message}")
        elif cmd == "register":
            print(f"Registering agent with controller at {CONTROLLER_ADDRESS}...")
            success, result = agent.register_with_controller(CONTROLLER_ADDRESS)
            
            if success:
                print("✓ Registration successful!")
                print(f"Certificate received from controller")
                print(f"Agent ID: {result['agent_card']['agent_id']}")
                print(f"Controller signature: {result['controller_signature'][:50]}...")
            else:
                print(f"✗ Registration failed: {result}")
        elif cmd == "cards":
            success, result = agent.get_all_agent_cards(CONTROLLER_ADDRESS)
            if not success:
                print(f"✗ Failed to retrieve cards: {result}")
        elif cmd == "info":
            print(f"\n{'='*60}")
            print(f"Agent Information")
            print(f"{'='*60}")
            print(f"Agent ID: {agent.agent_id}")
            print(f"Port: {PORT}")
            print(f"Status: Active")
            
            if agent.controller_public_key:
                print(f"Trust Anchor: ✓ Established (Controller: controller_001)")
            else:
                print(f"Trust Anchor: ✗ Not established")
            
            if agent.my_certificate:
                cert = agent.my_certificate
                print(f"\nCertificate Status: ✓ Registered")
                print(f"  Issued: {cert.get('certificate_issued_at', 'N/A')}")
                print(f"  Expires: {cert.get('certificate_expires_at', 'N/A')}")
                print(f"  Methods: {', '.join(cert.get('agent_card', {}).get('methods', []))}")
            else:
                print(f"\nCertificate Status: ✗ Not registered")
            
            print(f"\nActive Sessions: {len(agent.active_sessions)}")
            print(f"Peer Certificates Cached: {len(agent.peer_certificates)}")
            print(f"{'='*60}\n")
        elif cmd == "sessions":
            if not agent.active_sessions:
                print("No active sessions.")
            else:
                print(f"\n{'='*60}")
                print(f"Active Sessions ({len(agent.active_sessions)})")
                print(f"{'='*60}")
                for session_id, session in agent.active_sessions.items():
                    print(f"\nSession ID: {session_id}")
                    print(f"  Peer: {session.peer_agent_id}")
                    print(f"  Address: {session.peer_address}")
                    print(f"  Status: {'Active' if session.is_active else 'Inactive'}")
                    print(f"  Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.created_at))}")
                    print(f"  AES Key: {'Established' if session.aes_key else 'Pending'}")
                print(f"{'='*60}\n")
        elif cmd == "request":
            if not agent.my_certificate:
                print("✗ Agent not registered. Run 'setup' first.")
                continue
            
            print("\nSend Communication Request")
            print("="*60)
            peer_address = input("Enter peer agent address (e.g., https://localhost:5001): ").strip()
            peer_agent_id = input("Enter peer agent ID (e.g., helper_agent_001): ").strip()
            
            if not peer_address or not peer_agent_id:
                print("✗ Both address and agent ID are required.")
                continue
            
            print(f"\nSending communication request to {peer_agent_id}...")
            success, result = agent.send_communication_request(peer_address, peer_agent_id)
            
            if success:
                print(f"✓ Communication request accepted!")
                print(f"Session ID: {result}")
                print(f"\nSession created. Use 'sessions' to view details.")
            else:
                print(f"✗ Communication request failed: {result}")
        elif cmd == "keyexchange":
            if not agent.my_certificate:
                print("✗ Agent not registered. Run 'setup' first.")
                continue
            
            if not agent.active_sessions:
                print("✗ No active sessions. Use 'request' to create a session first.")
                continue
            
            print("\nPerform Key Exchange")
            print("="*60)
            print("\nActive Sessions:")
            for i, (session_id, session) in enumerate(agent.active_sessions.items(), 1):
                key_status = "Established" if session.aes_key else "Pending"
                print(f"  {i}. {session_id[:16]}... (Peer: {session.peer_agent_id}, Key: {key_status})")
            
            session_input = input("\nEnter session number: ").strip()
            
            if not session_input.isdigit():
                print("✗ Invalid input. Please enter a number.")
                continue
            
            session_idx = int(session_input) - 1
            session_list = list(agent.active_sessions.items())
            
            if session_idx < 0 or session_idx >= len(session_list):
                print("✗ Invalid session number.")
                continue
            
            session_id, session = session_list[session_idx]
            
            if session.aes_key:
                print(f"✗ AES key already established for this session.")
                continue
            
            if not session.peer_address:
                peer_address = input("Enter peer address (e.g., https://localhost:5001): ").strip()
                session.peer_address = peer_address
            else:
                peer_address = session.peer_address
            
            print(f"\nInitiating key exchange with {session.peer_agent_id}...")
            success, message = agent.perform_key_exchange(session_id, peer_address)
            
            if success:
                print(f"✓ {message}")
                print(f"✓ Session ready for encrypted communication")
            else:
                print(f"✗ Key exchange failed: {message}")
        elif cmd == "exit":
            print("Shutting down...")
            break
        else:
            print(f"Unknown command: {cmd}")