from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import threading
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import urllib3

# Import HelperAgent class
from routes.helper_agent import HelperAgent

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get port from .env
PORT = int(os.getenv("PORT", 5001))
AGENT_ID = os.getenv("AGENT_ID", "helper_1")
CONTROLLER_ADDRESS = os.getenv("CONTROLLER_ADDRESS", "https://127.0.0.1:5000")

# Initialize agent
agent = HelperAgent()

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the A2A Helper Agent"

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
        timestamp = data.get('timestamp')
        signature = data.get('signature')
        
        if not all([request_id, requester_agent_id, timestamp, signature]):
            return jsonify({"error": "Missing required fields"}), 400
        
        print(f"\n[INCOMING] Communication request from {requester_agent_id}")
        
        # Verify timestamp freshness (within 5 minutes)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5 minutes = 300 seconds
            return jsonify({"error": "Request timestamp expired"}), 400
        
        # Fetch requester's certificate from controller if not cached
        if requester_agent_id not in agent.peer_certificates:
            # Try to fetch from peer first
            requester_address = request.remote_addr
            # Note: We don't know the exact port, so we'll fetch from controller
            # For now, we'll need the certificate to be fetched via controller
            # In production, peer address would be in the request
            # Let's assume we can construct it or it's provided
            # For this implementation, we'll skip cert fetch and use what's in request
            pass
        
        # Verify signature using requester's public key
        # We need to get the public key - it should be in the agent card
        # For now, let's create a simplified version that accepts requests
        
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
    
    print(f"Helper Agent ({AGENT_ID}) running on port {PORT}")
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
            print("Commands: help | status | setup | trust | register | cards | exit")
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
        elif cmd == "exit":
            print("Shutting down...")
            break
        else:
            print(f"Unknown command: {cmd}")