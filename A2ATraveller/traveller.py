from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import threading
from routes.traveller_agent import TravellerAgent

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get port from .env
PORT = int(os.getenv("PORT", 5002))
AGENT_ID = os.getenv("AGENT_ID", "traveller_1")
CONTROLLER_ADDRESS = os.getenv("CONTROLLER_ADDRESS", "https://localhost:5000")

# Initialize agent
agent = TravellerAgent()

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